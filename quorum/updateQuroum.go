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
package quorum

import (
	"encoding/json"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/ethdb"
	"CRD-chain/log"
	"sync"
)

const (
	//updateMixHeight = 8192 //最小更新高度 2^13
	//updateHashIndex = 4    //更新高度取当前commitHash的前几位
	//afterMixHeight  = 16   //最小等待高度 2^4
	//afterHashIndex  = 2	 //最小等待高度取当前commitHash的前几位

	updateMixHeight = 2000 //最小值2000
	updateHashIndex = 3    //最大值4095
	afterHashIndex  = 1
	afterMixHeight  = 1

	LessCommit = 5555 //前期每个高度都更新委员会

)

type UpdateQuorum struct {
	HistoryUpdateHeight *big.Int //上次更新委员会的高度
	NextUpdateHeight    *big.Int //下次更新委员会的高度
	AfterHeight         *big.Int //成为委员会后,需要经过多少个高度,才能参与挖矿
}

var UpdateQuorums = NewUpdateQuorum()
var VerifyUpdateQuorums = NewUpdateQuorum()

func NewUpdateQuorum() *UpdateQuorum {
	return &UpdateQuorum{
		big.NewInt(0),
		big.NewInt(0),
		big.NewInt(0),
	}
}

//下次更新委员会的高度
func (u *UpdateQuorum) CalculateNextUpdateHeight(commitHash common.Hash, block *types.Block, UIP *big.Int) {
	hash := commitHash.String()[len(commitHash.String())-updateHashIndex:]
	num := big.NewInt(0)
	num.SetString(hash, 16)
	if num.Cmp(big.NewInt(updateMixHeight)) == -1 {
		num = big.NewInt(updateMixHeight)
	}

	if block.Number().Cmp(UIP) >= 0 {
		//
		u.NextUpdateHeight.Add(block.Number(), num)
	} else {
		u.NextUpdateHeight.Add(u.NextUpdateHeight, num)

	}

}

//需要经过多少个高度,才能参与挖矿
func (u *UpdateQuorum) CalculateNextAfterHeight(commitHash common.Hash) {
	hash := commitHash.String()[len(commitHash.String())-afterHashIndex:]
	num := big.NewInt(0)
	num.SetString(hash, 16)
	if num.Cmp(big.NewInt(afterMixHeight)) == -1 {
		num = big.NewInt(afterMixHeight)
	}
	u.AfterHeight = big.NewInt(0)
	u.AfterHeight.Add(u.AfterHeight, num)
}
func (u *UpdateQuorum) CopyUpdateQuorum(copyQuorum UpdateQuorum) {
	//复制bigInt
	u.NextUpdateHeight.Set(copyQuorum.NextUpdateHeight)
	u.AfterHeight.Set(copyQuorum.AfterHeight)
	u.HistoryUpdateHeight.Set(copyQuorum.HistoryUpdateHeight)
}

type UpdateQuorumSnapshot struct {
	UpdateQuorumMap map[string]UpdateQuorum
	Lock            sync.RWMutex
}

func NewUpdateQuorumSnapshot() UpdateQuorumSnapshot {
	return UpdateQuorumSnapshot{
		UpdateQuorumMap: make(map[string]UpdateQuorum),
	}
}

var UpdateQuorumSnapshots = NewUpdateQuorumSnapshot()

func (q *UpdateQuorumSnapshot) SetUpdateQuorum(u *UpdateQuorum, db ethdb.Database) bool {
	q.Lock.Lock()
	s := NewUpdateQuorum()
	s.HistoryUpdateHeight.Set(u.HistoryUpdateHeight)
	s.AfterHeight.Set(u.AfterHeight)
	s.NextUpdateHeight.Set(u.NextUpdateHeight)
	q.UpdateQuorumMap[s.HistoryUpdateHeight.String()] = *s
	q.Lock.Unlock()
	log.Info("SetUpdateQuorum 存储的key和value", "key", s.HistoryUpdateHeight.String(), "s.NextUpdateHeight", s.NextUpdateHeight)
	bytes, err := json.Marshal(q.UpdateQuorumMap)
	if err != nil {
		log.Error("SetUpdateQuorum rlp.EncodeToBytes fail", "err", err)
		return false
	}
	if err = db.Put([]byte(s.HistoryUpdateHeight.String()+"UpdateQuorumSnapshot"), bytes); err != nil {
		log.Error("SetUpdateQuorum db.Put fail", "err", err)
		return false

	}
	return true
}

func (q *UpdateQuorumSnapshot) GetUpdateQuorum(height *big.Int, db ethdb.Database) (UpdateQuorum, bool) {
	q.Lock.Lock()
	defer q.Lock.Unlock()
	if height.String() == "0" {
		height = big.NewInt(LessCommit + 1)
	}
	var up UpdateQuorum
	if up, ok := q.UpdateQuorumMap[height.String()]; ok {
		log.Info("GetUpdateQuorum1", "GetUpdateQuorum的kye", height.String(), "up", up.NextUpdateHeight)

		return up, true
	}

	bytes, err := db.Get([]byte(height.String() + "UpdateQuorumSnapshot"))
	if err != nil {
		log.Error("GetUpdateQuorum db.Get fail", "err", err)
		return UpdateQuorum{}, false
	}
	var set map[string]UpdateQuorum
	err = json.Unmarshal(bytes, &set)
	if err != nil {
		log.Error("rlp.DecodeBytes fail", "err", err)
		return UpdateQuorum{}, false
	}
	q.UpdateQuorumMap = set
	up = q.UpdateQuorumMap[height.String()]
	log.Info("GetUpdateQuorum2", "GetUpdateQuorum的kye", height.String(), "up", up.NextUpdateHeight)
	return up, true
}
