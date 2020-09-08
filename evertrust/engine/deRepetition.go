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
package engine

import (
	"CRD-chain/common"
	"sync"
)

type DeRepetition struct {
	DeRepetitionMap map[uint64][]common.Hash
	Lock            sync.RWMutex
}

//区块是否接收过
var NormalDeRepetition *DeRepetition
var CommitDeRepetition *DeRepetition
var AssociatedCommitDeRepetition *DeRepetition

func NewDeRepetition() *DeRepetition {
	return &DeRepetition{DeRepetitionMap: make(map[uint64][]common.Hash)}
}

func (r *DeRepetition) Add(height uint64, hash common.Hash) bool {
	r.Lock.Lock()
	defer r.Lock.Unlock()
	if blockHashs, ok := r.DeRepetitionMap[height]; !ok {
		r.DeRepetitionMap[height] = append(r.DeRepetitionMap[height], hash)
		return true
	} else {
		for _, blockHash := range blockHashs {
			if blockHash == hash {
				return false
			}

		}
		r.DeRepetitionMap[height] = append(r.DeRepetitionMap[height], hash)

	}
	return true
}

func (r *DeRepetition) Del(height uint64) {
	r.Lock.Lock()
	defer r.Lock.Unlock()
	delete(r.DeRepetitionMap, height)
}
