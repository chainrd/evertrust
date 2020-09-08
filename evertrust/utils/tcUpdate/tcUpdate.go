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
package tcUpdate

import (
	"encoding/json"
	"github.com/golang/protobuf/proto"
	"github.com/pkg/errors"
	"CRD-chain/core/types"
	"CRD-chain/ethdb"
	"CRD-chain/log"
	"CRD-chain/CRDcc/protos"
	"sync"
)

type TrustChains struct {
	TargetChain     TrustChainUpdTxModel   `json:"targetChain"`
	TargetChainSide []TrustChainUpdTxModel `json:"targetChainSide"`
	PreChain        TrustChainUpdTxModel   `json:"preChain"`
	PreChainSide    []TrustChainUpdTxModel `json:"PreChainSide"`
	Signature       string                 `json:"signature"`
	Timestamp       int64                  `json:"timestamp"`
	Random          string                 `json:"random"`
	TcadmCrt        string                 `json:"tcadmCrt"`
}

type TrustChainUpdTxModel struct {
	ChainId    string `json:"chainId"`
	ChainOwner string `json:"chainOwner"`
	//Timestamp      int64    `json:"timestamp"`
	//Random         string   `json:"random"`
	//TcAdmCrt       string   `json:"tcadmCrt"`
	//Signature      string   `json:"signature"`
	//EnodeList      []string `json:"enodeList"`
	HostList []string `json:"hostList"`
	//PrevChainID    string   `json:"prevChainID"`
	//PrevChainOwner string   `json:"prevChainOwner"`
	//SelfHost       string   `json:"selfHost"`
}

//缓存Lssa传来的信任链信息
var TrustHosts TrustChainHosts

type TrustChainHosts struct {
	TargetChain     TrustChainUpdTxModel   `json:"targetChain"`
	TargetChainSide []TrustChainUpdTxModel `json:"targetChainSide"`
	PreChain        TrustChainUpdTxModel   `json:"preChain"`
	PreChainSide    []TrustChainUpdTxModel `json:"PreChainSide"`
	Lock            sync.RWMutex           `json:"-"`
}

func (t *TrustChainHosts) ReadHosts() (targetHosts, targetHostsSide1, targetHostsSide2 []string) {
	t.Lock.RLock()
	defer t.Lock.RUnlock()

	//copy 信任链
	targetHosts = append(targetHosts, t.TargetChain.HostList...)
	for index, tc := range t.TargetChainSide {
		//冗余信任链的host
		if index == 0 {
			//保存冗余链1
			targetHostsSide1 = append(targetHostsSide1, tc.HostList...)
		} else {
			//保存冗余链2
			targetHostsSide2 = append(targetHostsSide2, tc.HostList...)
		}
	}
	return
}

func (t *TrustChainHosts) ReadChainID() (string, string) {
	t.Lock.RLock()
	defer t.Lock.RUnlock()

	return t.TargetChain.ChainId, t.PreChain.ChainId

}

func (t *TrustChainHosts) ReadAllChainID() (chainID []string) {
	t.Lock.RLock()
	defer t.Lock.RUnlock()
	chainID = append(chainID, t.TargetChain.ChainId)
	//保存冗余链chainID
	for _, tc := range t.TargetChainSide {
		chainID = append(chainID, tc.ChainId)
	}

	return
}

//func (t *TrustChainHosts) WriteHosts(chainID string, hosts []string) {
//	t.Lock.Lock()
//	defer t.Lock.Unlock()
//
//	t.HostList = hosts
//
//}

func (t *TrustChainHosts) WriteCache(tc, pc TrustChainUpdTxModel, tcs, pcs []TrustChainUpdTxModel) {
	t.Lock.Lock()
	defer t.Lock.Unlock()
	t.TargetChain = tc
	t.TargetChainSide = tcs
	t.PreChain = pc
	t.PreChainSide = pcs
}

func (t *TrustChainHosts) WriteTrustChain(tc *TrustChains) {
	t.WriteCache(tc.TargetChain, tc.PreChain, tc.TargetChainSide, tc.PreChainSide)
	log.Info("write trust chain", "chainID", t.TargetChain.ChainId, "hosts", t.TargetChain.HostList, "preChainID", t.PreChain.ChainId)
	//save db
	db := *ethdb.ChainDb
	trustChainHosts, err := json.Marshal(t)
	if err != nil {
		log.Error("marshal trustChainHosts err")
	}
	err = db.Put([]byte("TxChain"), trustChainHosts)
	if err != nil {
		log.Error("db put txChain error", "err", err)
		return
	}

}

//序列化传来的信任链信息
func TrustChainUpdTxModelDecode(input []byte) (updModel *TrustChains, err error) {
	if input == nil {
		return nil, errors.New("input is nil")
	}

	ftx := &protos.Transaction{}
	err = proto.Unmarshal(input, ftx)
	if err != nil {
		log.Error("unmarshal finalTx error", "err", err)
		return
	}
	if ftx.Type != types.Transaction_invoke {
		log.Error("transaction type error", "type", ftx.Type)
		return nil, errors.New("transaction type error")
	}
	inv := &protos.Invocation{}
	err = proto.Unmarshal(ftx.Payload, inv)
	if err != nil {
		log.Error("proto unmarshal invocation error", "err", err)
		return
	}

	if len(inv.Args) != 1 {
		log.Error("params is empty")
		return
	}
	err = json.Unmarshal(inv.Args[0], &updModel)
	if err != nil {
		log.Error("unmarshal payload error", "err", err)
		return
	}

	return
}

func GetTrustHosts() (targetHosts, targetHostsSide1, targetHostsSide2 []string) {
	db := *ethdb.ChainDb
	if db == nil {
		log.Error("db为空")
		return
	}

	targetHosts, targetHostsSide1, targetHostsSide2 = TrustHosts.ReadHosts()
	if len(targetHosts) == 0 {
		data, err := db.Get([]byte("TxChain"))
		if err != nil {
			return
		}
		var trustChain TrustChainHosts
		err = json.Unmarshal(data, &trustChain)
		if err != nil {
			log.Error("unmarshal TrustChainHosts error", "err", err)
			return
		}

		//copy
		targetHosts = append(targetHosts, trustChain.TargetChain.HostList...)
		for index, tc := range trustChain.TargetChainSide {
			//冗余信任链的host
			if index == 0 {
				//保存冗余链1
				targetHostsSide1 = append(targetHostsSide1, tc.HostList...)
			} else {
				//保存冗余链2
				targetHostsSide2 = append(targetHostsSide2, tc.HostList...)
			}
		}
		//set cache
		TrustHosts.WriteCache(trustChain.TargetChain, trustChain.PreChain,
			trustChain.TargetChainSide, trustChain.PreChainSide)
	}

	return
}
