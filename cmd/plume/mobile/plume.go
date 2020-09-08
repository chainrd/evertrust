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
 * @Time   : 2020/4/7 4:49 下午
 * @Author : liangc
 *************************************************************************/

package plume

import (
	"context"
	"fmt"
	"os"
	"CRD-chain/cmd/plume/service"
	"CRD-chain/log"
	"runtime"
	"strings"
)

var (
	ctx     context.Context
	cancel  context.CancelFunc
	ostream log.Handler
	glogger *log.GlogHandler
	splitFn = func(s string) []string {
		if s != "" {
			return strings.Split(s, ",")
		}
		return nil
	}
	_rpcport = 28545
)

func Start(bootnodes, trusts, homedir string, networkid int64, rpcport int) {
	service.PLATEFORM = "mobile"
	Stop()
	go func() {
		if rpcport != 0 {
			_rpcport = rpcport
		}
		ctx = context.Background()
		ctx, cancel = context.WithCancel(ctx)

		cfg := &service.Config{
			Ctx:           ctx,
			Bootnodes:     splitFn(bootnodes),
			Trusts:        splitFn(trusts),
			Networkid:     networkid,
			Rpcport:       _rpcport,
			EnableRelay:   false,
			EnableInbound: false,
			Homedir:       homedir,
		}
		fmt.Println(cfg)
		os.MkdirAll(homedir, 0755)
		network, err := service.NewNetwork(cfg)
		if err != nil {
			cancel()
			fmt.Println("new network error :", err.Error())
			return
		}
		rpcserver := service.NewRPCServer(network)
		err = rpcserver.Start()
		fmt.Println("plume-start:", "err", err)
		if err != nil {
			cancel()
			fmt.Println("start rpc server error :", err.Error())
		}
	}()
}

func Stop() {
	if cancel != nil {
		cancel()
		ctx, cancel = nil, nil
	}
}

// TODO Admin API for mobile

func Version() string {
	return service.NewRsp("vsn", map[string]interface{}{
		"version": service.Version(),
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
	}, nil).String()
}

func Myid() string {
	req := service.NewReq("admin_myid", nil)
	rsp, err := service.CallRPC(_rpcport, req)
	if err != nil {
		return service.NewRsp(req.Id, nil, &service.RspError{Code: "-1", Message: err.Error()}).String()
	}
	return rsp.String()
}

func Conns() string {
	req := service.NewReq("admin_conns", nil)
	rsp, err := service.CallRPC(_rpcport, req)
	if err != nil {
		return service.NewRsp(req.Id, nil, &service.RspError{Code: "-1", Message: err.Error()}).String()
	}
	return rsp.String()
}

func Config() string {
	req := service.NewReq("admin_config", nil)
	rsp, err := service.CallRPC(_rpcport, req)
	if err != nil {
		return service.NewRsp(req.Id, nil, &service.RspError{Code: "-1", Message: err.Error()}).String()
	}
	return rsp.String()
}

func Fnodes() string {
	req := service.NewReq("admin_fnodes", nil)
	rsp, err := service.CallRPC(_rpcport, req)
	if err != nil {
		return service.NewRsp(req.Id, nil, &service.RspError{Code: "-1", Message: err.Error()}).String()
	}
	return rsp.String()
}

func Report() string {
	req := service.NewReq("admin_report", nil)
	rsp, err := service.CallRPC(_rpcport, req)
	if err != nil {
		return service.NewRsp(req.Id, nil, &service.RspError{Code: "-1", Message: err.Error()}).String()
	}
	return rsp.String()
}
