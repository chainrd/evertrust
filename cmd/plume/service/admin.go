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
 * @Time   : 2020/3/25 2:57 下午
 * @Author : liangc
 *************************************************************************/

package service

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cc14514/go-alibp2p"
	"math/big"
	"path"
	"CRD-chain/accounts"
	"CRD-chain/accounts/keystore"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/p2p"
	"CRD-chain/rlp"
	"strconv"
	"time"
)

type AdminService struct {
	network *Network
	srv     *Server
}

type AccountService struct {
	cfg    *Config
	n, p   int
	keydir string
	ks     *keystore.KeyStore
}

var (
	_     Service = (*AdminService)(nil)
	_     Service = (*AccountService)(nil)
	s2iFn         = func(s string) (*big.Int, bool) {
		if s == "" {
			return big.NewInt(0), true
		} else if len(s) > 2 && s[:2] == "0x" {
			if buf, err := hex.DecodeString(s[2:]); err == nil {
				i := new(big.Int).SetBytes(buf)
				return i, true
			}
		} else {
			i, ok := new(big.Int).SetString(s, 10)
			return i, ok
		}
		return nil, false
	}
)

func NewAdminService(srv *Server) Service {
	return &AdminService{srv.network, srv}
}

func NewAccountService(cfg *Config) Service {
	scryptN := keystore.StandardScryptN
	scryptP := keystore.StandardScryptP
	as := &AccountService{cfg, scryptN, scryptP, path.Join(cfg.Homedir, "keystore"), nil}
	as.ks = keystore.NewKeyStore(as.keydir, as.n, as.p)
	return as
}

func (u *AdminService) Conns(req *Req) *Rsp {
	s := time.Now()
	dpis, rpis, total := u.network.alibp2p.ConnInfos()
	entity := struct {
		TimeUsed string
		Total    int
		Direct   []p2p.ConnInfo
		Relay    map[string][]p2p.ConnInfo
	}{time.Since(s).String(), total, dpis, rpis}
	return NewRsp(req.Id, entity, nil)
}

func mustNotNil(req *Req) *Rsp {
	if len(req.Params) == 0 {
		return NewRsp(req.Id, nil, &RspError{
			Code:    "2001",
			Message: "params can not nil",
		})
	}
	return nil
}

func (u *AdminService) Findpeer(req *Req) *Rsp {
	if rsp := mustNotNil(req); rsp != nil {
		return rsp
	}
	f := req.Params[0].(string)
	pk, err := alibp2p.ECDSAPubDecode(f)
	if err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "3001", Message: err.Error()})
	}
	id, addrs, err := u.network.alibp2p.Findpeer(pk)
	if err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "3002", Message: err.Error()})
	}
	return NewRsp(req.Id, map[string]interface{}{
		"Id":    id,
		"addrs": addrs,
	}, nil)
}

func (u *AdminService) Addrs(req *Req) *Rsp {
	if rsp := mustNotNil(req); rsp != nil {
		return rsp
	}
	f := req.Params[0].(string)
	pk, err := alibp2p.ECDSAPubDecode(f)
	if err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "3001", Message: err.Error()})
	}

	id, addrs, err := u.network.alibp2p.Addrs(pk)
	if err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "3002", Message: err.Error()})
	}
	return NewRsp(req.Id, map[string]interface{}{
		"Id":    id,
		"addrs": addrs,
	}, nil)
}

func (u *AdminService) RoutingTable(req *Req) *Rsp {
	tab, err := u.network.alibp2p.Alibp2pService().RoutingTable()
	if err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "4001", Message: err.Error()})
	}
	ret := make([]string, 0)
	for _, t := range tab {
		ret = append(ret, t.Pretty())
	}
	return NewRsp(req.Id, ret, nil)
}

func (u *AdminService) Connect(req *Req) *Rsp {
	if rsp := mustNotNil(req); rsp != nil {
		return rsp
	}
	url := req.Params[0].(string)
	pk, err := alibp2p.ECDSAPubDecode(url)
	if err == nil {
		err := u.network.alibp2p.PreConnect(pk)
		if err != nil {
			return NewRsp(req.Id, nil, &RspError{Code: "2002", Message: err.Error()})
		}
	} else {
		err := u.network.alibp2p.Connect(url)
		if err != nil {
			return NewRsp(req.Id, nil, &RspError{Code: "2002", Message: err.Error()})
		}
	}
	return NewRsp(req.Id, "success", nil)
}
func (u *AdminService) Myid(req *Req) *Rsp {
	id, addrs := u.network.alibp2p.Myid()
	return NewRsp(req.Id, map[string]interface{}{
		"Id":    id,
		"addrs": addrs,
	}, nil)
}

func (u *AdminService) Findproviders(req *Req) *Rsp {
	// TODO split to atomic process
	//swarm.SetGlobalDialTimeout(5 * time.Second)
	//defer swarm.SetGlobalDialTimeout(15 * time.Second)

	var (
		err   error
		limit = N
		start = time.Now()
	)
	if len(req.Params) > 0 {
		if limit, err = strconv.Atoi(req.Params[0].(string)); err != nil {
			return NewRsp(req.Id, nil, &RspError{Code: "4000", Message: err.Error()})
		}
	}
	nodes, err := u.network.alibp2p.Alibp2pService().FindProviders(context.Background(), p2p.FULLNODE.String(), limit)
	if err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "4001", Message: err.Error()})
	}
	return NewRsp(req.Id, map[string]interface{}{
		"nodes":    nodes,
		"total":    len(nodes),
		"timeused": time.Since(start).String(),
	}, nil)
}

func (u *AdminService) Fnodes(req *Req) *Rsp {
	return NewRsp(req.Id, map[string]interface{}{"trusts": u.network.cfg.Trusts, "nodes": u.network.fnodes.nodes}, nil)
}

func (u *AdminService) Config(req *Req) *Rsp {
	m := u.network.cfg.AsMap()
	if PLATEFORM == "pc" {
		m["keystore"] = path.Join(u.network.cfg.Homedir, "keystore")
	}
	return NewRsp(req.Id, m, nil)
}

func (u *AdminService) Report(req *Req) *Rsp {
	var (
		id     string
		jbuf   []byte
		entity map[string]interface{}
	)
	if len(req.Params) > 0 {
		id = req.Params[0].(string)
	}
	if id != "" {
		jbuf = u.network.alibp2p.Alibp2pService().Report(id)
	} else {
		jbuf = u.network.alibp2p.Alibp2pService().Report()
	}
	if err := json.Unmarshal(jbuf, &entity); err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "5001", Message: err.Error()})
	}
	return NewRsp(req.Id, entity, nil)
}

/*
func (u *AdminService) Reset(req *Req) *Rsp {
	if len(req.Params) > 0 {
		_m, ok := req.Params[0].(map[string]interface{})
		if !ok {
			return NewRsp(req.Id, nil, &RspError{Code: "7011", Message: "params format error"})
		}
		if _bootnodes, ok := _m["bootnodes"]; ok {
			u.network.cfg.Bootnodes = SplitFn(_bootnodes.(string))
		}
		if _tructs, ok := _m["tructs"]; ok {
			u.network.cfg.Trusts = SplitFn(_tructs.(string))
		}
		if _networkid, ok := _m["networkid"]; ok {
			if n, ok := s2iFn(_networkid.(string)); ok {
				u.network.cfg.Networkid = n.Int64()
			}
		}
		if _chainid, ok := _m["chainid"]; ok {
			if c, ok := s2iFn(_chainid.(string)); ok {
				u.network.cfg.Chainid = c.Int64()
			}
		} else {
			u.network.cfg.Chainid = u.network.cfg.Networkid
		}
	}
	return u.Config(req)
}

func (u *AdminService) Reboot(req *Req) *Rsp {
	u.network.Stop()
	var err error
	u.network.cfg.Ctx = context.Background()
	u.network, err = NewNetwork(u.network.cfg)
	if err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "8001", Message: err.Error()})
	}
	u.srv.SetNetwork(u.network)
	u.srv.Startup()
	return u.Config(req)
}
*/

func (u *AdminService) Protocols(req *Req) *Rsp {
	if rsp := mustNotNil(req); rsp != nil {
		return rsp
	}
	id := req.Params[0].(string)
	ps, err := u.network.alibp2p.Alibp2pService().GetProtocols(id)
	if err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "9001", Message: err.Error()})
	}
	return NewRsp(req.Id, ps, nil)
}

func (a *AdminService) APIs() *API {
	return &API{
		Namespace: "admin",
		Api: map[string]RpcFn{
			"config":        a.Config,
			"conns":         a.Conns,
			"myid":          a.Myid,
			"connect":       a.Connect,
			"findpeer":      a.Findpeer,
			"addrs":         a.Addrs,
			"findproviders": a.Findproviders,
			"fnodes":        a.Fnodes,
			"report":        a.Report,
			"routingtable":  a.RoutingTable,
			"protocols":     a.Protocols,
			//"reset":         a.Reset,
			//"reboot":        a.Reboot,
		},
	}
}

func (k *AccountService) Create(req *Req) *Rsp {
	pwd := ""
	if len(req.Params) > 0 {
		pwd = req.Params[0].(string)
	} else {
		return NewRsp(req.Id, nil, &RspError{Code: "6001", Message: "passwd not nil"})
	}
	address, err := keystore.StoreKey(k.keydir, pwd, k.n, k.p)
	if err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "6002", Message: err.Error()})
	}
	fmt.Println("create new account : ", address.Hex())
	return NewRsp(req.Id, address.Hex(), nil)
}

func (k *AccountService) List(req *Req) *Rsp {
	al := make([]string, 0)
	for _, a := range k.ks.Accounts() {
		al = append(al, a.Address.Hex())
	}
	return NewRsp(req.Id, al, nil)
}

func (k *AccountService) SignTx(req *Req) *Rsp {
	var (
		params  = make(map[string]interface{})
		passwd  string
		chainid = big.NewInt(k.cfg.Chainid)
	)
	fmt.Println("req", req)
	fmt.Println("req.params", req.Params)
	if len(req.Params) > 0 {
		_m, ok := req.Params[0].(map[string]interface{})
		if !ok {
			return NewRsp(req.Id, nil, &RspError{Code: "7011", Message: "params format error"})
		}
		params = _m
		_passwd, ok := params["passwd"]
		if !ok {
			return NewRsp(req.Id, nil, &RspError{Code: "7012", Message: "password format error"})
		}
		passwd = _passwd.(string)
		if _chainid, ok := params["chainid"]; ok {
			if chainid, ok = new(big.Int).SetString(_chainid.(string), 10); !ok {
				return NewRsp(req.Id, nil, &RspError{Code: "7014", Message: "chainid format error"})
			}
		}
	} else {
		return NewRsp(req.Id, nil, &RspError{Code: "7002", Message: "params not nil"})
	}

	txArgs, err := new(SendTxArgs).fromMap(params)
	if err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "7003", Message: err.Error()})
	}
	tx, err := txArgs.toTransaction()
	if err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "7004", Message: err.Error()})
	}
	err = k.ks.Unlock(accounts.Account{Address: txArgs.from()}, passwd)
	if err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "7005", Message: err.Error()})
	}
	tx, err = k.ks.SignTxWithPassphrase(accounts.Account{Address: txArgs.from()}, passwd, tx, chainid)
	if err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "7006", Message: err.Error()})
	}
	rtn, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "7007", Message: err.Error()})
	}
	return NewRsp(req.Id, "0x"+hex.EncodeToString(rtn), nil)
}

func (k *AccountService) Delete(req *Req) *Rsp {
	var addr, pwd string
	if len(req.Params) > 1 {
		addr = req.Params[0].(string)
		pwd = req.Params[1].(string)
	} else {
		return NewRsp(req.Id, nil, &RspError{Code: "8001", Message: "account/passwd not nil"})
	}
	err := k.ks.Delete(accounts.Account{Address: common.HexToAddress(addr)}, pwd)
	if err != nil {
		return NewRsp(req.Id, nil, &RspError{Code: "8002", Message: err.Error()})
	}
	fmt.Println("delete account : ", addr)
	return NewRsp(req.Id, "success", nil)
}

func (k *AccountService) APIs() *API {
	return &API{
		Namespace: "account",
		Api: map[string]RpcFn{
			"create": k.Create,
			"list":   k.List,
			"signtx": k.SignTx,
			"delete": k.Delete,
		},
	}
}

// SendTxArgs represents the arguments to sumbit a new transaction into the transaction pool.
type SendTxArgs struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Gas      string `json:"gas"`
	GasPrice string `json:"gasPrice"`
	Value    string `json:"value"`
	Nonce    string `json:"nonce"`
	// We accept "data" and "input" for backwards-compatibility reasons. "input" is the
	// newer name and should be preferred by clients.
	Data  string `json:"data"`
	Input string `json:"input"`
	// plume sign tx
	Passwd  string `json:"passwd"`
	Chainid string `json:"chainid"`
}

func (args *SendTxArgs) from() common.Address {
	return common.HexToAddress(args.From)
}

func (args *SendTxArgs) fromMap(m map[string]interface{}) (*SendTxArgs, error) {
	j, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(j, args)
	return args, err
}

func (args *SendTxArgs) toTransaction() (*types.Transaction, error) {
	var (
		ok                          bool
		input                       string
		nonce, gas, gasprice, value *big.Int
		payloadFn                   = func(data string) ([]byte, error) {
			if len(data) > 2 && data[:2] == "0x" {
				data = data[2:]
			}
			return hex.DecodeString(data)
		}
	)
	if args.Data != "" {
		input = args.Data
	} else if args.Input != "" {
		input = args.Input
	}
	if nonce, ok = s2iFn(args.Nonce); !ok {
		return nil, errors.New("nonce format error :" + args.Nonce)
	}
	if value, ok = s2iFn(args.Value); !ok {
		return nil, errors.New("value format error :" + args.Value)
	}
	if gas, ok = s2iFn(args.Gas); !ok {
		return nil, errors.New("gas format error :" + args.Gas)
	}
	if gasprice, ok = s2iFn(args.GasPrice); !ok {
		return nil, errors.New("gasprice format error :" + args.GasPrice)
	}
	payload, err := payloadFn(input)
	if err != nil {
		return nil, err
	}
	if args.To == "" {
		return types.NewContractCreation(nonce.Uint64(), value, gas.Uint64(), gasprice, payload), nil
	}
	return types.NewTransaction(nonce.Uint64(), common.HexToAddress(args.To), value, gas.Uint64(), gasprice, payload), nil
}
