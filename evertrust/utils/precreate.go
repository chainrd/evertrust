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
 * @Time   : 2019-08-06 15:30
 * @Author : liangc
 *************************************************************************/

package utils

import (
	lru "github.com/hashicorp/golang-lru"
	"CRD-chain/common"
	"CRD-chain/common/hexutil"
)

// copy 自 types.Log 为了躲避循环引用
type Log struct {
	// Consensus fields:
	// address of the contract that generated the event
	Address common.Address `json:"address" gencodec:"required"`
	// list of topics provided by the contract.
	Topics []common.Hash `json:"topics" gencodec:"required"`
	// supplied by the contract, usually ABI-encoded
	Data []byte `json:"data" gencodec:"required"`

	// Derived fields. These fields are filled in by the node
	// but not secured by consensus.
	// block in which the transaction was included
	BlockNumber uint64 `json:"blockNumber"`
	// hash of the transaction
	TxHash common.Hash `json:"transactionHash" gencodec:"required"`
	// index of the transaction in the block
	TxIndex uint `json:"transactionIndex" gencodec:"required"`
	// hash of the block in which the transaction was included
	BlockHash common.Hash `json:"blockHash"`
	// index of the log in the receipt
	Index uint `json:"logIndex" gencodec:"required"`

	// The Removed field is true if this log was reverted due to a chain reorganisation.
	// You must pay attention to this field if you receive logs through a filter query.
	Removed bool `json:"removed"`
}

type PrecreateRequest struct {
	Hash     common.Hash
	From     common.Address
	To       *common.Address
	Gas      hexutil.Uint64
	GasPrice hexutil.Big
	Value    hexutil.Big
	Data     hexutil.Bytes
	RespCh   chan *PrecreateResponse
}

type PrecreateResponse struct {
	BlockNumber uint64
	Logs        []*Log
	State       map[common.Address]map[common.Hash]common.Hash
	StateCRDMap map[common.Address]map[common.Hash][]byte
	Ret         []byte
	Gas         uint64
	Failed      bool
	Err         error
}

var (
	precreateCh       = make(chan PrecreateRequest, 512)
	precreateCache, _ = lru.New(512)

	// 内部调用 ethapi 时为了躲避循环引用
	Precreate = &precreate{make(chan struct{}), precreateCh, precreateCache}
)

type precreate struct {
	Started chan struct{}
	TaskCh  chan PrecreateRequest
	cache   *lru.Cache
}

// call by : internal/ethapi/api.go : func (s *PublicBlockChainAPI) loop()
func (self *precreate) Start() {
	defer func() { recover() }()
	close(self.Started)
}

func (self *precreate) Has(k common.Hash) bool {
	select {
	case <-Precreate.Started:
		_, ok := self.cache.Get(k)
		return ok
	default:
		return false
	}
	return false
}

//get and delete
func (self *precreate) Det(k common.Hash) *PrecreateResponse {
	select {
	case <-Precreate.Started:
		v, ok := self.cache.Get(k)
		if ok {
			defer self.Del(k)
			return v.(*PrecreateResponse)
		}
	default:
		return nil
	}
	return nil
}

func (self *precreate) Put(k common.Hash, v *PrecreateResponse) {
	select {
	case <-Precreate.Started:
		self.cache.Add(k, v)
	default:
	}
}

func (self *precreate) Del(k common.Hash) {
	select {
	case <-Precreate.Started:
		//log.Debug("precreate-del", "key", k.Hex())
		self.cache.Remove(k)
	default:
	}
}
