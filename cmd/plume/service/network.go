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
 * @Time   : 2020/3/25 1:44 下午
 * @Author : liangc
 *************************************************************************/

package service

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bitly/go-simplejson"
	"io/ioutil"
	"math/big"
	"math/rand"
	"path"
	"CRD-chain/crypto"
	"CRD-chain/log"
	"CRD-chain/p2p"
	"runtime"
	"sort"
	"sync"
	"time"
)

var (
	PLATEFORM = "pc"
)

const N, M = 30, 5

//`json:"Id,omitempty"`

type lastCommitHash struct {
	Id   string
	Hash string
	Ttl  time.Duration
}

type Network struct {
	cfg     *Config
	alibp2p *p2p.Alibp2p
	fnodes  *Fnodes
}

type FnodeItem struct {
	Id  string
	Ttl time.Duration
}

type FnodeItems []*FnodeItem

func (f FnodeItems) Len() int {
	return len(f)
}

func (f FnodeItems) Less(i, j int) bool {
	return f[i].Ttl < f[j].Ttl
}

func (f FnodeItems) Swap(i, j int) {
	f[i], f[j] = f[j], f[i]
}

type Fnodes struct {
	lock   *sync.Mutex
	nodes  FnodeItems
	trusts map[string]interface{}
}

func NewFnodes() *Fnodes {
	return &Fnodes{
		lock:   new(sync.Mutex),
		nodes:  make([]*FnodeItem, 0),
		trusts: make(map[string]interface{}),
	}
}

func (f *Fnodes) append(item ...*FnodeItem) {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.nodes = append(f.nodes, item...)
	sort.Sort(f.nodes)
}

func (f *Fnodes) reset() {
	f.lock.Lock()
	defer f.lock.Unlock()
	f.nodes = make([]*FnodeItem, 0)
}

func (f *Fnodes) forward(n *Network, msg []byte) ([]byte, error) {
	f.lock.Lock()
	defer f.lock.Unlock()
	for t, v := range f.trusts {
		ret, err := n.alibp2p.Plume(t, msg)
		if err == nil {
			return ret, nil
		}
		fmt.Println("request trust node fail :", v, err)
	}
	for _, itm := range f.nodes {
		ret, err := n.alibp2p.Plume(itm.Id, msg)
		if err == nil {
			return ret, nil
		}
		fmt.Println("request full node fail :", itm.Id, itm.Ttl, err)
	}
	return nil, nil
}

func NewNetwork(cfg *Config) (*Network, error) {
	cfg.Ctx, cfg.cancel = context.WithCancel(cfg.Ctx)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	n := &Network{
		cfg:    cfg,
		fnodes: NewFnodes(),
	}
	srv := &p2p.Server{}
	srv.PrivateKey = n.loadprv()
	srv.Alibp2pBootstrapNodes = cfg.Bootnodes
	var disableRelay = big.NewInt(1)
	var disableInbound = big.NewInt(1)
	if cfg.EnableRelay {
		disableRelay = nil
	}
	if cfg.EnableInbound {
		disableInbound = nil
	}
	n.alibp2p = p2p.NewAlibp2p(cfg.Ctx, cfg.Port, cfg.Muxport, 0, big.NewInt(cfg.Networkid), srv, disableRelay, disableInbound, nil)
	n.alibp2p.Alibp2pService().SetAdvertiseTTL(p2p.FULLNODE.String(), 60*time.Second)
	n.alibp2p.Alibp2pService().SetHandler(p2p.ProtocolPlume, nil)
	return n, nil
}

func (n *Network) Stop() {
	if n.alibp2p != nil {
		n.cfg.cancel()
		n.alibp2p = nil
	}
}

func (n *Network) Start() {
	//swarm.SetGlobalDialTimeout(15 * time.Second)
	n.alibp2p.Start()
	go func() {
		<-n.cfg.Ctx.Done()
		if n.alibp2p != nil {
			n.alibp2p.Stop()
		}
	}()
	if n.cfg.Trusts != nil {
		for i, t := range n.cfg.Trusts {
			n.fnodes.trusts[t] = i
		}
	}
	go n.loop()
}

func (n *Network) loop() {
	var (
		p        = 3
		t        = time.NewTimer(time.Duration(p) * time.Second)
		resetpFn = func(err error) {
			if err != nil {
				p = 5
			} else if p < 60 {
				p = 2*p + 30
			}
			t.Reset(time.Duration(p) * time.Second)
		}
		randomFn = func(n []string) []string {
			if len(n) <= M {
				return n
			}
			// TODO
			rand.Seed(time.Now().UnixNano())
			ret := make([]string, 0)
			for i := 0; i < M; i++ {
				l := len(n)
				j := rand.Int() % l
				ret = append(ret, n[j])
				n = append(n[:j], n[j+1:]...)
			}
			return ret
		}

		lastCommitHashFn = func(m []string) []*lastCommitHash {
			rch := make(chan *lastCommitHash, len(m))
			wg := new(sync.WaitGroup)
			for _, to := range m {
				wg.Add(1)
				go func(id string) {
					defer wg.Done()
					s := time.Now()
					ret, err := n.alibp2p.Plume(id, []byte(`{"Id":0,"jsonrpc":"2.0","method":"eth_currentCommitHash","params":[]}`))
					if err != nil {
						log.Error("lastCommitHashFn-error1", "err", err)
						return
					}
					log.Info("lastCommitHashFn-rsp", "ret", string(ret))
					ttl := time.Since(s)
					jobj, err := simplejson.NewJson(ret)
					if err != nil {
						log.Error("lastCommitHashFn-error2", "err", err)
						return
					}
					commitHex, err := jobj.Get("result").String()
					if err != nil {
						log.Error("lastCommitHashFn-error3", "err", err)
						return
					}
					if commitHex != "" {
						rch <- &lastCommitHash{
							Id:   id,
							Hash: commitHex,
							Ttl:  ttl,
						}
					}
				}(to)
			}
			wg.Wait()
			close(rch)
			ret := make([]*lastCommitHash, 0)
			for r := range rch {
				ret = append(ret, r)
			}
			return ret
		}
		/*
			output : { hash : [ Id , ... ] , ... }
		*/
		counterFn = func(r []*lastCommitHash) map[string][]*lastCommitHash {
			m := make(map[string][]*lastCommitHash)
			for _, obj := range r {
				ids, ok := m[obj.Hash]
				if !ok {
					ids = make([]*lastCommitHash, 0)
				}
				ids = append(ids, obj)
				m[obj.Hash] = ids
			}
			return m
		}
		loopFn = func() error {
			// findproviders
			// TODO Advertise
			nl, err := n.alibp2p.Alibp2pService().FindProviders(context.Background(), p2p.FULLNODE.String(), N)
			if err != nil {
				log.Error("loopFn-error1", "err", err)
				return err
			}
			log.Info("FindProviders", "nodes", nl)
			ml := randomFn(nl)
			log.Info("randomFn", "nodes", ml)
			r := lastCommitHashFn(ml)
			log.Info("lastCommitHashFn", "r", r)
			//ml := randomFn(n.cfg.Trusts)
			//r := lastCommitHashFn(n.cfg.Trusts)
			km := counterFn(r)
			log.Info("counterFn", "k", km)
			for _, objs := range km {
				if len(objs) >= len(ml)*2/3 {
					items := make([]*FnodeItem, 0)
					for _, obj := range objs {
						if _, ok := n.fnodes.trusts[obj.Id]; ok {
							log.Info("skip-trust", "Id", obj.Id, "Ttl", obj.Ttl)
							continue
						}
						items = append(items, &FnodeItem{
							Id:  obj.Id,
							Ttl: obj.Ttl,
						})
					}
					n.fnodes.reset()
					n.fnodes.append(items...)
					return nil
				}
			}
			n.fnodes.reset()
			return errors.New("no good fullnodes")
		}
	)
	defer t.Stop()
	for {
		var err error
		select {
		case <-n.cfg.Ctx.Done():
			return
		case <-t.C:
			err = loopFn()
		}
		resetpFn(err)
	}
}

func (n *Network) loadprv() *ecdsa.PrivateKey {
	fp := path.Join(n.cfg.Homedir, "nodekey")
	buf, err := ioutil.ReadFile(fp)
	if err == nil {
		if prv, err := crypto.ToECDSA(buf); err == nil {
			return prv
		}
	}
	prv, _ := crypto.GenerateKey()
	ioutil.WriteFile(fp, crypto.FromECDSA(prv), 0755)
	return prv
}

func (n *Network) Request(data []byte) ([]byte, error) {
	// IOS 会传数组过来，回也要回数组
	reqs, err := jsonsplit(data)
	if err != nil {
		return nil, err
	}
	if _, _, t := n.alibp2p.ConnInfos(); t == 0 {
		return nil, errors.New("Plume_node_offline")
	}

	// IOS 的输入输出是数组
	if PLATEFORM == "mobile" {
		switch runtime.GOOS {
		case "darwin", "Darwin":
			rsps := make([]interface{}, 0)
			for _, req := range reqs {
				rsp, err := n.fnodes.forward(n, []byte(req))
				if err != nil {
					return nil, err
				}
				m := make(map[string]interface{})
				err = json.Unmarshal(rsp, &m)
				if err != nil {
					return nil, err
				}
				rsps = append(rsps, m)
			}
			return json.Marshal(rsps)
		}
	}

	// 非 IOS 不会传数组进来
	rsp, err := n.fnodes.forward(n, []byte(reqs[0]))
	if err != nil {
		return rsp, err
	}
	return rsp, err
}

func jsonsplit(j []byte) ([]string, error) {
	dict := make(map[string]interface{})
	err1 := json.Unmarshal(j, &dict)
	if err1 == nil {
		return []string{string(j)}, nil
	}
	list := make([]interface{}, 0)
	err2 := json.Unmarshal(j, &list)
	if err2 == nil && len(list) > 0 {
		reqs := make([]string, 0)
		for _, l := range list {
			j, err := json.Marshal(l)
			if err != nil {
				return nil, err
			}
			reqs = append(reqs, string(j))
		}
		return reqs, nil
	}
	return nil, errors.New("error format")
}
