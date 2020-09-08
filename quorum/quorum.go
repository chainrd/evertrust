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
	"CRD-chain/common"
	"CRD-chain/ethdb"
	"CRD-chain/log"
	"CRD-chain/rlp"
	"CRD-chain/evertrust/utils"
	"sort"
	"strconv"
	//"evertrust-chain/evertrust/utils"
	"sync"
)

//type BlockchainNode struct {
//	ID discover.NodeID // the node's public key
//
//	Address common.Address
//
//	IP       net.IP // len 4 for IPv4 or 16 for IPv6
//	UDP, TCP uint16 // port numbers
//
//	//last time this record gets accessed. TODO house-keeping to purge unused nodes
//	lastAccessedAt time.Time
//
//	// Time when the node was added to the table.
//	addedAt time.Time
//}

var EmptyAddress = [20]byte{}

type NodeAddress struct {
	Hmap map[string]common.Address
	lock sync.RWMutex
}

// NewSafeSet creates a new set to track the active objects.
func NewNodeAddress() *NodeAddress {
	return &NodeAddress{
		Hmap: make(map[string]common.Address),
	}
}

// Add injects a new object into the working set, or returns an error if the
// object is already known.
func (na *NodeAddress) Add(id string, p common.Address) error {
	na.lock.Lock()
	defer na.lock.Unlock()

	if _, ok := na.Hmap[id]; ok {
		return utils.ErrAlreadySet
	}
	na.Hmap[id] = p

	return nil
}

// Del removes a object from the active set.
func (na *NodeAddress) Del(id string) error {
	na.lock.Lock()
	defer na.lock.Unlock()

	_, ok := na.Hmap[id]
	if !ok {
		return utils.ErrNotSet
	}
	delete(na.Hmap, id)

	return nil
}

// Get retrieves the registered object with the given id.
func (na *NodeAddress) Get(id string) common.Address {
	na.lock.RLock()
	defer na.lock.RUnlock()

	val, ok := na.Hmap[id]

	if ok {
		return val
	}

	return EmptyAddress
}

// Len returns if the current number of objects in the set.
func (na *NodeAddress) Len() int {
	na.lock.RLock()
	defer na.lock.RUnlock()

	return len(na.Hmap)
}

func (na *NodeAddress) Keys() []string {
	na.lock.RLock()
	defer na.lock.RUnlock()
	keys := make([]string, 0)
	for k, _ := range na.Hmap {
		keys = append(keys, k)
	}
	return keys
}

func (na *NodeAddress) KeysCommonAddress() []common.Address {
	na.lock.RLock()
	defer na.lock.RUnlock()
	keys := make([]common.Address, 0)
	for _, v := range na.Hmap {
		keys = append(keys, v)
	}
	return keys
}

func (na *NodeAddress) KeysOrdered() []string {
	keys := na.Keys()

	sort.Strings(keys)

	return keys
}

func (na *NodeAddress) Copy() *NodeAddress {
	na.lock.RLock()
	defer na.lock.RUnlock()
	set := NewNodeAddress()
	for k, val := range na.Hmap {
		if val != [20]byte{} {
			set.Add(k, val)
		}
	}
	return set
}

func (na *NodeAddress) CopyAddress() map[common.Address]struct{} {
	na.lock.RLock()
	defer na.lock.RUnlock()
	set := make(map[common.Address]struct{})
	for _, val := range na.Hmap {
		if val != [20]byte{} {
			set[val] = struct{}{}
		}
	}
	return set
}

func (na *NodeAddress) Contains(local common.Address) bool {
	na.lock.RLock()
	defer na.lock.RUnlock()
	if _, ok := na.Hmap[local.String()]; ok {
		return true
	}
	return false
}

func (na *NodeAddress) Encode() ([]byte, error) {
	var adds []common.Address
	for _, add := range na.Hmap {
		adds = append(adds, add)
	}
	return rlp.EncodeToBytes(adds)
}

func (na *NodeAddress) Decode(data []byte) error {
	var adds []common.Address

	err := rlp.DecodeBytes(data, &adds)
	if err != nil {
		log.Error("NodeAddress fail", "err", err)
	}
	for _, add := range adds {
		na.Hmap[add.String()] = add
	}
	return nil
}

var CommitHeightToConsensusQuorum = &CommitHeight2ConsensusQuorum{Height2NodeSet: make(map[uint64]*NodeAddress)}

type CommitHeight2ConsensusQuorum struct {
	lock sync.RWMutex
	// safeset is composed of consensus nodes (address.hex -> address.hex)
	Height2NodeSet map[uint64]*NodeAddress
}

func (q *CommitHeight2ConsensusQuorum) Set(height uint64, set *NodeAddress, db ethdb.Database) {

	q.lock.Lock()
	defer q.lock.Unlock()

	q.Height2NodeSet[height] = set

	if db == nil {
		return
	}

	data, err := set.Encode()
	if err == nil {
		db.Put([]byte("commit-quorum:"+strconv.FormatUint(height, 10)), data)
	}
}

func (q *CommitHeight2ConsensusQuorum) Get(height uint64, db ethdb.Database) (*NodeAddress, bool) {
	q.lock.Lock()
	defer q.lock.Unlock()
	set, ok := q.Height2NodeSet[height]
	if ok {
		return set, ok
	}

	if db == nil {
		return nil, false
	}

	data, err := db.Get([]byte("commit-quorum:" + strconv.FormatUint(height, 10)))

	if err != nil {
		log.Warn("NOT found consensus quorum from database for commit height:", "height", height, "err", err.Error())
		return nil, false
	}

	set2 := NewNodeAddress()

	err = set2.Decode(data)

	if err != nil {
		log.Error("decode error for consensus quorum from database for commit height:", "height", height, "err", err.Error())
		return nil, false
	}

	log.Info("found consensus quorum from database for commit height:", "height", height, "size:", set2.Len())

	// update cache
	q.Height2NodeSet[height] = set2

	return set2, true
}

func (q *CommitHeight2ConsensusQuorum) Del(height uint64, db ethdb.Database) {
	q.lock.Lock()
	defer q.lock.Unlock()

	delete(q.Height2NodeSet, height)
	if db != nil {
		db.Delete([]byte("commit-quorum:" + strconv.FormatUint(height, 10)))
	}
}

func (q *CommitHeight2ConsensusQuorum) CleanUpConsensusQuorum(height uint64) {
	q.lock.Lock()
	defer q.lock.Unlock()
	delete(q.Height2NodeSet, height)
}

func (q *CommitHeight2ConsensusQuorum) Keys() []uint64 {
	q.lock.RLock()
	defer q.lock.RUnlock()
	keys := make([]uint64, 0)
	for k, _ := range q.Height2NodeSet {
		keys = append(keys, k)
	}
	return keys
}
