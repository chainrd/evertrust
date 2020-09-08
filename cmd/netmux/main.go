// Copyright 2017 The CRD Blockchain Hybercloud Authors
// This file is part of the CRD chainmux implementation.
//
// The CRD Blcockchain Hypercloud is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The CRD Blockchain Hypercloud is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the software. If not, see <http://www.gnu.org/licenses/>.

// CRD chainmux, a lighweight whitelist-protected TCP & HTTP proxy service
// Credit to https://medium.com/@mlowicki for the original https-proxy work

package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const timeout = int64(15) // 15 秒

type (
	rewriteRules struct {
		lock sync.Mutex
		data map[string]string
		// add by liangc : 如果是自动注册过来的服务，可以不在 conf 中，需定期心跳
		ponglog map[string]int64 // k 不存在或 v <= 0 则表示静态服务，无需检测心跳
	}
	sessionManager struct {
		sessions *sync.Map
	}
	session struct {
		id, realip string
		ts         time.Time
	}
)

func (self *sessionManager) Get(sid string) (*session, bool) {
	v, ok := self.sessions.Load(sid)
	if ok {
		return v.(*session), ok
	}
	return nil, ok
}

func (self *sessionManager) Del(sid string) {
	self.sessions.Delete(sid)
}

func (self *sessionManager) Put(s *session) {
	self.sessions.Store(s.id, s)
}

func NewSession(src, dest net.Conn) *session {
	l := strings.Split(dest.LocalAddr().String(), ":")[1]
	r := strings.Split(dest.RemoteAddr().String(), ":")[1]
	sid := fmt.Sprintf("%s%s", l, r)
	realip := strings.Split(src.RemoteAddr().String(), ":")[0]
	session := &session{
		id:     sid,
		realip: realip,
		ts:     time.Now(),
	}
	sessions.Put(session)
	log.Println("open session :", session)
	return session
}

func (s *session) String() string {
	return fmt.Sprintf("session : %s , %s , %d", s.id, s.realip, s.ts.Unix())
}

func (s *session) Close() {
	log.Println("close session :", s)
	sessions.Del(s.id)
}

func (o *rewriteRules) handlePing(r *http.Request) string {
	o.lock.Lock()
	defer o.lock.Unlock()
	k := r.Header.Get("k")
	if k == "" {
		return "pang"
	}
	v := r.Header.Get("v")
	if v == "" {
		return "pang"
	}
	o.data[k] = v
	o.ponglog[k] = time.Now().Unix()
	log.Println("- ping ->", k, v)
	//log.Println(o.data)
	//log.Println(o.ponglog)
	return "pong"
}

func (o *rewriteRules) validate(k string) bool {
	if v, ok := o.ponglog[k]; ok && v > 0 {
		if time.Now().Unix()-v > timeout {
			return false
		}
	}
	return true
}

var (
	fconf    string
	rules    = &rewriteRules{data: make(map[string]string), ponglog: make(map[string]int64)}
	sessions = &sessionManager{sessions: new(sync.Map)}
)

func loadRules() {
	file, err := os.OpenFile(fconf, os.O_RDONLY, os.ModeExclusive)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	data := make(map[string]string)

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {

		text := scanner.Text()

		if strings.HasPrefix(text, "#") {
			continue
		}

		el := strings.Fields(scanner.Text())

		if el == nil || len(el) <= 0 || len(el) > 2 {
			continue
		}

		if len(el) == 1 { //allow

			data[el[0]] = el[0]

		} else if len(el) == 2 { //rewrite

			data[el[0]] = el[1]
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	rules.lock.Lock()
	rules.data = data
	rules.lock.Unlock()
}

func rewriteTo(asked string) string {

	asked = strings.TrimSpace(asked)

	rules.lock.Lock()
	defer rules.lock.Unlock()

	for k, v := range rules.data {

		matched, err := filepath.Match(k, asked)

		if err == nil && rules.validate(k) && matched {
			if strings.EqualFold(k, v) { //allowed
				return asked
			} else { //rewrite
				return v
			}
		}
	}

	return ""
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	dst := rewriteTo(r.RequestURI)

	log.Println("CONN: requested ", r.RequestURI, ", redirected to:", dst)

	if dst == "" {
		fmt.Println("netmux dst == nil")
		http.Error(w, r.RequestURI+" is not allowed", http.StatusServiceUnavailable)
		return
	}
	dest_conn, err := net.DialTimeout("tcp", dst, 10*time.Second)
	if err != nil {
		fmt.Println("netmux net.DialTimeout", "err", err)
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	client_conn, _, err := hijacker.Hijack()
	session := NewSession(client_conn, dest_conn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	go transfer(session, dest_conn, client_conn)
	go transfer(session, client_conn, dest_conn)
}

func transfer(s *session, dst io.WriteCloser, src io.ReadCloser) {
	defer s.Close()
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {

	url, err := url.Parse(r.RequestURI)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if strings.EqualFold(r.RequestURI, "/chainmux/ping") &&
		strings.HasPrefix(r.RemoteAddr, "127.0.0.1:") {
		w.Write([]byte(rules.handlePing(r)))
		return
	}

	if strings.EqualFold(r.RequestURI, "/chainmux/realip") &&
		strings.HasPrefix(r.RemoteAddr, "127.0.0.1:") {
		sid := r.Header.Get("sessionid")
		fmt.Println("handle-query-realip-request", sid)
		session, ok := sessions.Get(sid)
		if !ok {
			w.WriteHeader(404)
			return
		}
		fmt.Println("handle-query-realip-response", session.realip)
		w.Write([]byte(session.realip))
		return
	}

	if strings.EqualFold(r.RequestURI, "/chainmux/reconf") &&
		strings.HasPrefix(r.RemoteAddr, "127.0.0.1:") {
		log.Println("reloading rewrite conf file")
		loadRules()
		return
	}

	asked := "http://" + url.Host
	/*	if url.Port() != "" {
			asked += ":" + url.Port()
		} else {
			asked += ":80"
		}*/

	dst := rewriteTo(asked) //host:port
	if dst == "" {
		http.Error(w, r.RequestURI+" is not allowed", http.StatusServiceUnavailable)
		return
	}

	asked = r.RequestURI

	r.RequestURI = "http://" + dst + url.RequestURI()
	r.Host = dst
	log.Println("HTTP: requested ", asked, ", redirected to:", r.RequestURI)

	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func main() {

	flag.Usage = func() {
		fmt.Println("")
		fmt.Println("CRD chainmux, a lighweight whitelist-protected TCP & HTTP proxy service, ver. 1.0")
		fmt.Println("")
		fmt.Println("-conf	The configuration file. Or set via the CRD_CHAINMUX_CONF_FILE environment variable.")
		fmt.Println("	Call http://localhost:{port}/chainmux/reconf to reload it on configuration change.")
		fmt.Println("")
		fmt.Println("	Configuration file syntax:")
		fmt.Println("		1) One line for each access granted (as-is or rewrite), honoring the first match")
		fmt.Println("		2) Line format: proto://request_host:request_port \\t [service_host:service_port]\\n")
		fmt.Println("		3) proto is conn for HTTP-CONNECT based tunneling, http for http proxy.")
		fmt.Println("		4) proto://request_host:request_port can be a glob match pattern")
		fmt.Println("		5) If no rewrite is desired, no service_host:service_port should be specified")
		fmt.Println("		6) A comment line (one starts with #) or an empty line is ignored by the parser.")
		fmt.Println("")
		fmt.Println("	For example,")
		fmt.Println("		conn://chain-x:30303 localhost:30308")
		fmt.Println("		http://view.CRD.ltd:80 http://localhost:8080")
		fmt.Println("		http://chain.CRD.link*")
		fmt.Println("")
		fmt.Println("-addr	The [host]:port chainmux listens on")
		fmt.Println("")
		fmt.Println("Please visit https://github.com/CRDbaap/chainmux to get the latest version.")
		fmt.Println("")
	}

	flag.StringVar(&fconf, "conf", "", "conf file for CONNECT redirect")

	var addr string
	flag.StringVar(&addr, "addr", ":5978", "proxy listening address, in host:addr format")

	flag.Parse()

	if fconf == "" {
		fconf = os.Getenv("CRD_CHAINMUX_CONF_FILE")
	}

	if fconf == "" {
		log.Fatalln("no configuration file is specified, exiting")
		os.Exit(-1)
	}

	loadRules()

	server := &http.Server{
		//ReadTimeout:  10 * time.Second,
		//WriteTimeout: 10 * time.Second,
		//IdleTimeout:  10 * time.Second,
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		})}

	log.Println("started CRD chainmux")

	log.Fatal(server.ListenAndServe())

	log.Println("shutdown CRD chainmux")

	os.Exit(0)
}
