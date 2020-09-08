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
	"math"
	"CRD-chain/common"
	"CRD-chain/ethdb"
	"CRD-chain/log"
	"CRD-chain/CRDcc/util"
	"sort"
	"sync"
)

type PrepareQuorum struct {
	//commit块Hash->[委员会地址string]委员会地址common.Address
	PrepareQuorumMap map[common.Hash]map[string]common.Address
	lock             sync.RWMutex
}

var PrepareQuorums = newPrepareQuorum()       //正常上链预备委员会列表
var VerifyPrepareQuorums = newPrepareQuorum() //验证commit预备委员会列表

func newPrepareQuorum() *PrepareQuorum {
	return &PrepareQuorum{
		PrepareQuorumMap: make(map[common.Hash]map[string]common.Address),
	}

}

func (p *PrepareQuorum) SetPrepareQuorum(commitHash common.Hash, addressList []common.Address, db ethdb.Database) bool {
	p.lock.Lock()
	defer p.lock.Unlock()
	for _, address := range addressList {
		log.Info("预备委员会新增成员","add",address.String())
		if _, ok := p.PrepareQuorumMap[commitHash]; !ok {
			//第一次需要make
			quorum := make(map[string]common.Address)
			quorum[address.String()] = address
			p.PrepareQuorumMap[commitHash] = quorum
		}
		p.PrepareQuorumMap[commitHash][address.String()] = address

	}
	if db != nil {
		//rlp不支持map
		bytes, err := json.Marshal(p.PrepareQuorumMap[commitHash])
		if err != nil {
			log.Error("AddPrepareQuorum Marshal fail", "err", err)
			return false
		}

		err = db.Put([]byte("PrepareQuorum"+commitHash.String()), bytes)
		if err != nil {
			log.Error("AddPrepareQuorum db Put fail", "err", err)
			return false
		}
	}
	return true
}

func (p *PrepareQuorum) GetPrepareQuorum(commitHash common.Hash, db ethdb.Database) (set []common.Address, ok bool) {
	p.lock.Lock()
	defer p.lock.Unlock()
	var setMap map[string]common.Address
	if setMap, ok = p.PrepareQuorumMap[commitHash]; ok {
		for _, add := range setMap {
			set = append(set, add)
		}
		return set, true
	}
	if db != nil {
		bytes, err := db.Get([]byte("PrepareQuorum" + commitHash.String()))
		if err != nil {
			log.Error("GetPrepareQuorum db Get fail", "err", err)
		}
		err = json.Unmarshal(bytes, &setMap)
		if err != nil {
			log.Error("rlp Marshal fail", "err", err)
			return nil, false
		}
		p.PrepareQuorumMap[commitHash] = setMap
		for _, add := range setMap {

			set = append(set, add)
		}

		return set, true
	}
	return set, false
}

func (p *PrepareQuorum) DelPrepareQuorum(commitHash common.Hash, delAddress []common.Address, db ethdb.Database) bool {
	p.lock.Lock()
	defer p.lock.Unlock()
	//删除已经加入委员会的节点
	if setMap, ok := p.PrepareQuorumMap[commitHash]; ok {
		for _, add := range delAddress {
			delete(setMap, add.String())
		}
		if db != nil {
			bytes, err := json.Marshal(setMap)
			if err != nil {
				log.Error("DelPrepareQuorum Marshal fail", "err", err)
				return false
			}
			if db != nil {
				err := db.Put([]byte("PrepareQuorum"+commitHash.String()), bytes)
				if err != nil {
					log.Error("DelPrepareQuorum db Put fail", "err", err)
					return false
				}
			}

			return true
		}

	}
	return true
}

func (p *PrepareQuorum) SortPrepareQuorum(quorumAddress []common.Address,commitHash common.Hash,db ethdb.Database) (set []common.Address) {
	//if quorumAddress, ok := p.GetPrepareQuorum(commitHash, db); ok {
		addStrAndAddress := make(map[string]common.Address)
		var quorumStr []string
		for _, add := range quorumAddress {
			addString := util.EthHash([]byte(add.String() + commitHash.String())).String()
			addStrAndAddress[addString] = add //hash+add对应的common.Address
			quorumStr = append(quorumStr, addString)
		}
		sort.Strings(quorumStr)
		//本次委员会要更新的委员会成员数量
		needSum := int(math.Ceil(float64(len(quorumStr)) * 0.05))
		for i := 0; i <= needSum-1; i++ {
			set = append(set, addStrAndAddress[quorumStr[i]])
		}
	//	//删除要加入委员会的成员
	//	p.DelPrepareQuorum(commitHash, set, db)
	//	return set
	//}

	return
}


func SortPrepareQuorum(quorumAddress []common.Address,commitHash common.Hash,db ethdb.Database) (set []common.Address) {
	//if quorumAddress, ok := p.GetPrepareQuorum(commitHash, db); ok {
	addStrAndAddress := make(map[string]common.Address)
	var quorumStr []string
	for _, add := range quorumAddress {
		addString := util.EthHash([]byte(add.String() + commitHash.String())).String()
		addStrAndAddress[addString] = add //hash+add对应的common.Address
		quorumStr = append(quorumStr, addString)
	}
	sort.Strings(quorumStr)
	//本次委员会要更新的委员会成员数量
	needSum := int(math.Ceil(float64(len(quorumStr)) * 0.05))
	for i := 0; i <= needSum-1; i++ {
		set = append(set, addStrAndAddress[quorumStr[i]])
	}
	//	//删除要加入委员会的成员
	//	p.DelPrepareQuorum(commitHash, set, db)
	//	return set
	//}

	return
}
