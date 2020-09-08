/*************************************************************************
 * Copyright (C) 2016-2019 CRD Technologies, Inc. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @Time   : 2020/3/24 11:35 上午
 * @Author : liangc
 *************************************************************************/

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/rs/cors"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"net"
	"net/http"
	"CRD-chain/rpc"
	"strings"
)

const (
	contentType                 = "application/json"
	maxHTTPRequestContentLength = 1024 * 128
)

type Server struct {
	cfg        *Config
	network    *Network
	servicemap map[string]Service
}

func NewRPCServer(network *Network) *Server {
	s := &Server{
		cfg:        &Config{Ctx: context.Background(), Rpcport: 18545},
		servicemap: make(map[string]Service),
	}
	s.SetNetwork(network)
	return s
}

func (srv *Server) serviceReg(s Service) {
	srv.servicemap[s.APIs().Namespace] = s
}
func (srv *Server) getRpcFn(method string) RpcFn {
	args := strings.Split(method, "_")
	if len(args) != 2 {
		return nil
	}
	ns, fn := args[0], args[1]
	if s, ok := srv.servicemap[ns]; ok {
		return s.APIs().Api[fn]
	}
	return nil
}

func (srv *Server) GetNetwork() *Network {
	return srv.network
}

func (srv *Server) SetNetwork(network *Network) {
	if network != nil {
		srv.network = network
		srv.cfg = network.cfg
	}
}

func (srv *Server) Startup() {
	if srv.network != nil {
		srv.network.Start()
		srv.serviceReg(NewAdminService(srv))
		srv.serviceReg(NewAccountService(srv.cfg))
	}
}

func (srv *Server) Start() error {
	srv.Startup()
	var (
		listener net.Listener
		err      error
		endpoint = fmt.Sprintf(":%d", srv.cfg.Rpcport)
	)
	if listener, err = net.Listen("tcp", endpoint); err != nil {
		return err
	}
	fmt.Println("rpc-endpoint", endpoint)
	/*
		go func() {
			<-srv.cfg.Ctx.Done()
			if listener != nil {
				listener.Close()
			}
		}()
	*/
	return (&http.Server{Handler: newCorsHandler(srv, []string{"*"})}).Serve(listener)
}

func (srv *Server) adminHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*") //允许访问所有域
	w.Header().Set("content-type", "application/json") //返回数据格式是json

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("ws_error", "err", err)
		return
	}
	fmt.Println("-> admin-api-req : ", string(data))
	req := new(Req).FromBytes(data)

	if _fn := srv.getRpcFn(req.Method); _fn != nil {
		_fn(req).WriteTo(w)
	} else {
		NewRsp(req.Id, nil, &RspError{
			Code:    "1000",
			Message: "method_not_support",
		}).WriteTo(w)
	}
}

func newCorsHandler(srv *Server, allowedOrigins []string) http.Handler {
	// disable CORS support if user has not specified a custom CORS configuration
	if len(allowedOrigins) == 0 {
		return srv
	}

	c := cors.New(cors.Options{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{http.MethodPost, http.MethodGet},
		MaxAge:         600,
		AllowedHeaders: []string{"*"},
	})
	return c.Handler(srv)
}

type httpReadWriteNopCloser struct {
	io.Reader
	io.Writer
}

// Close does nothing and returns always nil
func (t *httpReadWriteNopCloser) Close() error {
	return nil
}

// ServeHTTP serves JSON-RPC requests over HTTP.
func (srv *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.LastIndex(r.URL.Path, "admin") > 0 {
		srv.adminHandler(w, r)
		return
	}
	// Permit dumb empty requests for remote health-checks (AWS)
	if r.Method == http.MethodGet && r.ContentLength == 0 && r.URL.RawQuery == "" {
		return
	}
	if code, err := validateRequest(r); err != nil {
		fmt.Println("Error ------>", "err=", err, "code=", code)
		http.Error(w, err.Error(), code)
		return
	}
	// All checks passed, create a codec that reads direct from the request body
	// untilEOF and writes the response to w and order the server to process a
	// single request.
	codec := rpc.NewJSONCodec(&httpReadWriteNopCloser{r.Body, w})
	defer codec.Close()
	w.Header().Set("content-type", contentType)
	buff := make([]byte, r.ContentLength)
	_, err := io.ReadFull(r.Body, buff)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Println("request->", string(buff))
	ret, err := srv.network.Request(buff)
	if err != nil {
		fmt.Println("request-error-1->", err)
		http.Error(w, err.Error(), 500)
		return
	}

	_, err = w.Write(ret)
	if err != nil {
		fmt.Println("request-error-2->", err)
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Println("response<-", string(ret))
}

func validateRequest(r *http.Request) (int, error) {
	if r.Method == http.MethodPut || r.Method == http.MethodDelete {
		return http.StatusMethodNotAllowed, errors.New("method not allowed")
	}
	if r.ContentLength > maxHTTPRequestContentLength {
		err := fmt.Errorf("content length too large (%d>%d)", r.ContentLength, maxHTTPRequestContentLength)
		return http.StatusRequestEntityTooLarge, err
	}
	mt, _, err := mime.ParseMediaType(r.Header.Get("content-type"))
	if r.Method != http.MethodOptions && (err != nil || mt != contentType) {
		err := fmt.Errorf("invalid content type, only %s is supported", contentType)
		return http.StatusUnsupportedMediaType, err
	}
	return 0, nil
}

func CallRPC(rpcport int, req *Req) (*Rsp, error) {
	buf := new(bytes.Buffer)
	req.WriteTo(buf)
	request, err := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/admin", rpcport), buf)
	if err != nil {
		return nil, err
	}
	response, err := new(http.Client).Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	rtn, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	rsp, err := new(Rsp).FromBytes(rtn)
	if err != nil {
		return nil, err
	}
	return rsp, nil
}
