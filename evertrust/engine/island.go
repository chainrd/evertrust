/*************************************************************************
 * Copyright (C) 2016-2019 CRD Technologies, Inc. All Rights Reserved.
 *
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
package engine

import (
	"encoding/json"
	"CRD-chain/ethdb"
	"CRD-chain/log"
	"strconv"
	"sync"
)

const landKey = "LocalLandMap"
const ErrLandMapGetNil = "LandMapGet is nil"

type LocalLand struct {
	IslandIDState string   //岛屿Id  空是大陆
	IslandState   bool     //岛屿状态
	IslandCNum    uint64   //分叉前CNum,如果在100块分叉,那么cNum=99
	IslandQuorum  []string //分叉前保存委员会数量
}

func NewLocalLand() LocalLand {
	return LocalLand{IslandQuorum: make([]string, 0)}
}

func (l *LocalLand) LandSet(stateID string, state bool, cNum uint64,
	quorum []string) {
	l.IslandIDState = stateID
	l.IslandState = state
	l.IslandCNum = cNum
	l.IslandQuorum = quorum
}

func (l *LocalLand) LandEncode() ([]byte, error) {
	return json.Marshal(l)
}

func (l *LocalLand) LandDecode(data []byte) error {
	return json.Unmarshal(data, &l)
}

type LocalLandMap struct {
	LocalLandSet map[uint64]LocalLand
	Lock         sync.RWMutex
}

//缓存岛屿信息
func NewLocalLandMap() LocalLandMap {
	return LocalLandMap{LocalLandSet: make(map[uint64]LocalLand)}
}

var LocalLandSetMap = NewLocalLandMap()

//按高度存缓存和数据库
func (l *LocalLandMap) LandMapSet(height uint64, param LocalLand, db ethdb.Database) error {
	l.Lock.Lock()
	defer l.Lock.Unlock()
	l.LocalLandSet[height] = param
	data, err := param.LandEncode()
	if err != nil {
		log.Error("LandSet LandEncode err", "err", err)
		return err
	}
	err = db.Put([]byte(landKey+strconv.FormatUint(height, 10)), data)
	if err != nil {
		log.Error("LandSet dbPut err", "err", err)
		return err
	}
	return nil
}

//取缓存,取不到从数据库中取
func (l *LocalLandMap) LandMapGet(height uint64, db ethdb.Database) (LocalLand, bool) {
	l.Lock.RLock()
	defer l.Lock.RUnlock()
	if LandParam, ok := l.LocalLandSet[height]; ok {
		return LandParam, true
	}
	data, err := db.Get([]byte(landKey + strconv.FormatUint(height, 10)))
	if err != nil {
		log.Trace("LandGet db.Get err", "err", err)
		return LocalLand{}, false
	}
	land := NewLocalLand()
	err = land.LandDecode(data)
	if err != nil {
		log.Error("LandDecode err", "err", err)
		return LocalLand{}, false
	}
	l.LocalLandSet[height] = land

	return land, true
}

//删除高度对应的岛屿信息
func (l *LocalLandMap) LandMapDel(height uint64, db ethdb.Database) error {
	l.Lock.Lock()
	defer l.Lock.Unlock()
	delete(l.LocalLandSet, height)
	return db.Delete([]byte(landKey + strconv.FormatUint(height, 10)))
}

//清除缓存
func (l *LocalLandMap) LandMapClean(height uint64) {
	l.Lock.Lock()
	defer l.Lock.Unlock()
	delete(l.LocalLandSet, height)
}
