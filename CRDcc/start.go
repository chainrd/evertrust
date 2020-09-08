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
 *************************************************************************/
package CRDcc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"CRD-chain/common"
	"CRD-chain/core/state"
	"CRD-chain/ethdb"
	"CRD-chain/CRDcc/protos"
	"CRD-chain/evertrust"
	"CRD-chain/evertrust/utils"
	"strings"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/golang/protobuf/proto"

	pb "CRD-chain/CRDcc/protos"
	"CRD-chain/CRDcc/util"

	"CRD-chain/CRDcc/conf"

	"CRD-chain/common/hexutil"
	"CRD-chain/log"
)

func Apply(inv *pb.Invocation, extra map[string][]byte, txd []byte, stateFunc func(fcn string, key string, value []byte) []byte) error {
	txid := hexutil.Encode(extra[conf.BaapTxid][:])[2:]

	if inv == nil {
		return errors.New("invocation is nil")
	}
	meta := inv.Meta

	for key := range meta {
		if extra[key] == nil || len(extra[key]) == 0 {
			extra[key] = meta[key]
		}
	}

	execTime := conf.ApplyTime

	//contractAddr := strings.ToLower(common.BytesToAddress(extra[conf.BaapDst]).String())
	contractAddr := common.BytesToAddress(extra[conf.BaapDst])
	key, find := theChaincodeSupport.chaincodeHasRan(contractAddr)
	if !find {
		log.Error("!!!!!chaincode not register error", "contractAddr", contractAddr)
		return errors.New("chaincode not register")
	}

	ccEnv, _ := theChaincodeSupport.chaincodeHasBeenLaunched(contractAddr)
	if !(key != "" && ccEnv != nil) {
		log.Error("!!!!! chaincode not running", "contractAddr", contractAddr, "key", key)
		return errors.New("chaincode not running")
	}

	_, err := execMessage(txd, inv, txid, stateFunc, execTime, extra, key)
	if err != nil {
		log.Error("!!!!!!!!!!execMessage error", "err", err)
		return err
	}

	return nil
}

func cacheResult(txid string, ccresp *pb.ChaincodeMessage, errStr string) {
	db := *ethdb.ChainDb
	key := fmt.Sprintf("executedTx:%s", txid)

	result := ExecReslt{ccresp, errStr}
	value, err := json.Marshal(result)
	if err != nil {
		log.Error("json Marshal error", "err", err)
		return
	}
	err = db.Put([]byte(key), value)
	if err != nil {
		log.Error("db put error", "err", err)
		return
	}
}

//note:return err is nil for preventing tx exec again
func execMessage(payload []byte, tx *pb.Invocation, txId string,
	stateFunc func(fcn string, key string, value []byte) []byte, time time.Duration, extra map[string][]byte, key string) (ccresp *pb.ChaincodeMessage, err error) {

	cpy := make(map[string][]byte, len(extra))
	for k, v := range extra {
		b := make([]byte, len(v))
		copy(b, v)
		cpy[k] = b
	}

	//cpy[conf.BaapSpbk] = []byte(hexutil.Encode(extra[conf.BaapSpbk][:])[2:])//transit hex

	param, err := proto.Marshal(&pb.Meta{Meta: cpy})

	if err != nil {
		return nil, nil
	}

	params := append(tx.Args, param)
	ccInput := &pb.ChaincodeInput{Args: util.MakeChaincodeArgs(tx.Fcn, params), Decorations: extra}
	finalData, err := proto.Marshal(ccInput)
	if err != nil {
		return nil, nil
	}

	baapTxType := string(tx.Meta[conf.BaapTxType])

	var chaincodeMessageType pb.ChaincodeMessage_Type

	switch baapTxType {
	case conf.Exec:
		chaincodeMessageType = pb.ChaincodeMessage_TRANSACTION
	case conf.Init:
		chaincodeMessageType = pb.ChaincodeMessage_INIT
	case conf.Query:
		chaincodeMessageType = pb.ChaincodeMessage_BAAP_QUERY
	default:
		log.Error("baap tx type no match", "type", baapTxType)
		return nil, nil
	}
	msg := &pb.ChaincodeMessage{Type: chaincodeMessageType, Payload: finalData, Txid: txId, ChannelId: conf.ChainId.String()}

	cccid, err := NewCCContext(conf.ChainId.String(), key, txId, false, nil, &pb.Proposal{Payload: payload}, &CRDDataSupport{stateFunc:stateFunc})
	if err != nil {
		log.Error("new cc context error", "err", err)
		return nil, nil
	}
	ccresp, err = theChaincodeSupport.Execute(context.Background(), cccid, msg, time)
	return ccresp, err
}

func BaapQuery(stateDB *state.StateDB, qStr []byte) (string, error) {
	if qStr == nil || len(qStr) == 0 {
		return "", errors.New("qStr can't nil")
	}

	ptx := &pb.Transaction{}
	err := proto.Unmarshal(qStr, ptx)
	if err != nil {
		return "", err
	}

	inv := &pb.Invocation{}
	err = proto.Unmarshal(ptx.Payload, inv)
	if err != nil {
		log.Error("proto unmarshal inv error", "err", err)
		return "", err
	}
	inv.Meta[conf.BaapTxType] = []byte(conf.Query)
	extra := map[string][]byte{conf.BaapEngineID: []byte(conf.ChainId.String())}
	to := strings.ToLower(string(inv.Meta["to"]))
	if !strings.HasPrefix(to, "0x") {
		to = "0x" + to
	}
	chaincodeAddr := common.HexToAddress(to)
	extra[conf.BaapDst] = chaincodeAddr.Bytes()
	log.Info("baap query to", "buf", inv.Meta["to"], "str", to)
	key, find := theChaincodeSupport.chaincodeHasRan(chaincodeAddr)
	if !find {
		log.Warn("!!!!!chaincode not register when query, so run it", "to", to)
		contractAddr := common.HexToAddress(to)
		err = runCCWhenQuery(stateDB, &contractAddr, extra) //todo maybe goroutine
		if err != nil {
			log.Error("run cc error", "err", err)
			return "", errors.New("run cc err when query")
		}else {
			return "", errors.New("cc is booting")
		}
	}

	ccresp, err := execMessage(qStr, inv, util.GenerateUUID(), nil, conf.ApplyTime, extra, key)
	if err != nil {
		log.Error("exec msg error", "err", err)
		return "", err
	}

	var resp pb.Response
	err = proto.Unmarshal(ccresp.Payload, &resp)
	if err != nil {
		log.Error("cc resp payload unmarshal error", "err", err)
		return "", err
	}

	//log.Trace("!!!!!!!resp", "resp", hexutil.Encode(resp.Payload))
	return hexutil.Encode(resp.Payload), nil
}

func runCCWhenQuery(stateDB *state.StateDB, contractAddr *common.Address, extra map[string][]byte) (err error) {
	//keyHash := utils.CCKeyHash
	//ccBuf := stateDB.GetCRDState(*contractAddr, keyHash)
	ccBuf := stateDB.GetCode(*contractAddr)
	if len(ccBuf) == 0 {
		return errors.New("no cc contract addr")
	}
	var deploy protos.Deployment
	err = proto.Unmarshal(ccBuf, &deploy)
	if err != nil {
		log.Error("ccBuf unmarshal error", "err", err)
		return
	}

	//让cc启动
	stateFunc := func(fcn string, key string, value []byte) []byte {
		//note: do nothing
		return nil
	}

	extra[conf.BaapDst] = utils.CCBaapDeploy.Bytes()

	ptx := &protos.Transaction{
		Type:    1, //1invoke 2deploy
		Payload: ccBuf,
	}
	ccDeployInput, err := proto.Marshal(ptx)
	if err != nil {
		log.Error("!!!!!!!!proto marshal error:%v", err)
		return
	}

	err = Apply(deploy.Payload, extra, ccDeployInput, stateFunc)
	if err != nil {
		log.Error("cc apply error", "err", err)
		return
	}

	return
}

func Duplicate(txid string) (result ExecReslt, find bool) {
	if len(txid) > 0 {
		db := *ethdb.ChainDb
		key := fmt.Sprintf("executedTx:%s", txid)
		res, err := db.Get([]byte(key))
		if err != nil {
			log.Error("db get error", "err", err)
			return
		}

		err = json.Unmarshal(res, &result)
		if err != nil {
			log.Error("json unmarshal error", "err", err)
			return
		}
		find = true
		return
	}
	return
}

func CanExec(addr common.Address) bool {
	// 只有当联盟链或者内置的cc时， 才可以执行chaincode。
	isBaapChainIaas := utils.IsBaapChainIaas(&addr)
	if evertrust.Consortium || isBaapChainIaas || evertrust.CCEnable {
		log.Debug("can exec", "consortium", evertrust.Consortium,
			"baapchain", isBaapChainIaas, "ccEnable", evertrust.CCEnable)
		_, running := theChaincodeSupport.chaincodeHasRan(addr)
		if running {
			//log.Info("running is ok", "contract", contract)
			return true
		}

		if ch := isHanding(addr); ch != nil {
			select {
			case <-ch:
				return true
			}
		}

	}

	//log.Info("cc running not ok", "contract", nameHash)
	return false
}

func Start(port int) {
	conf.InitConf() //在init中，编译bootnode时，会报conf文件找不到，所以移到此处
	go func() {
		lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
		if err != nil {
			log.Error(fmt.Sprintf("failed to listen: %v", err))
		} else {
			log.Info(fmt.Sprintf("Success to listen: %d", port))
		}

		var opts []grpc.ServerOption

		gRpcServer := grpc.NewServer(opts...)

		registerChaincodeSupportServer(gRpcServer)

		gRpcServer.Serve(lis)
	}()

	for {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			log.Info("!!!!! watch grpc server staring...")
			time.Sleep(time.Second * 2)
			continue
		}

		log.Info("!!!!! watch grpc server started")
		conn.Close()
		break
	}
}
