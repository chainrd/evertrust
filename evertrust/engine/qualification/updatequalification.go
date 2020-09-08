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
package qualification

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"CRD-chain/common"
	"CRD-chain/crypto"
	"CRD-chain/ethdb"
	"CRD-chain/log"
	"CRD-chain/rlp"
	"sort"
	"strconv"
	"sync"
)

var (
	errClosed     = errors.New("object set is closed")
	errAlreadySet = errors.New("object is already set")
	errNotSet     = errors.New("object is not set")
)

const (
	//评判资格的区间距离  2880个区间内判断委员会（近期的可靠性）（24小时）
	DistantOfCfd uint64 = 2880

	//不能成为委员会成员
	CantBeMaster uint64 = 0
	//能成为委员会成员
	CanBeMaster uint64 = 1
	//需要被惩罚
	ShouldBePunished uint64 = 2
)

/* disqualifiedAtResaon */
const (
	//LossOfConsensus = "The right to a loss of consensus"
	ActivityNotEnough = "Activity is not enough to be removed."
	ExitOnHisOwn      = "Exit on his own initiative."
	MultSign          = "Multiple signatures."
	ExceptStorage     = "Exception storage penalty."
	EmptyString       = ""

	ShouldStacking    = "Should hypothecation again"
	ShouldNotStacking = "Should not hypothecation again"
)

type NodeDetail struct {
	Address common.Address `json:"address"`

	//nil if no assertion for this commit height  - collect assertnum
	NumAssertionsAccepted uint64 `json:"num_assertions_accepted"`

	//number of assertions for the past 100 commit heights
	//need to adjust whenever commit height increases
	NumAssertionsTotal uint64 `json:"num_assertions_total"`

	//number of blocks accepted for this commit height
	NumBlocksAccepted uint64 `json:"num_blocks_accepted"`

	//number of blocks accepted for the past 100 commit heights
	//need to adjust whenever commit height increases
	NumBlocksAcceptedTotal uint64 `json:"num_blocks_accepted_total"`

	//number of blocks failed to verify for this commit height
	NumBlocksFailed uint64 `json:"num_blocks_failed"`

	//节点出块失败次数
	NumBlocksFailedTotal uint64 `json:"num_blocks_failed_total"`

	//same as numAssertionsTotal for now
	ActivenessIndex uint64 `json:"activeness_index"`

	//80*numBlocksAcceptedTotal + 20*numAssertionsTotal
	ContributionIndex uint64 `json:"contribution_index"`

	//probed by each node, default to 100 for now
	CapabilitiesIndex uint64 `json:"capabilities_index"`

	//60*activenessIndex + 20*contributionIndex + 20*capabilitiesIndex
	//nodes are ordered as such, then pick the ones joining consensus quorum
	QualificationIndex uint64 `json:"qualification_index"`

	//the commit height this node gets pre-qualified but deferred
	//a pre-qualified node must wait for at 1000 commit height
	//and must be within the 5% increase on each consensus quorum addition
	//if more than 5% is qualified, sort based on the Address.Hex()
	//and select the 5% of them
	PrequalifiedAt uint64 `json:"prequalified_at"`

	//the commit height this node gets qualified as consensus node
	QualifiedAt uint64 `json:"qualified_at"`

	//the commit height this node get disqualified as consensus node
	DisqualifiedAt uint64 `json:"disqualified_at"`

	//disqualified because of
	DisqualifiedReason string `json:"disqualified_reason"`

	//能否成为共识委员会    0  不能  1 能  2 需要被惩罚
	CanBeMaster uint64 `json:"can_be_master"`

	//在哪个高度进入惩罚名单
	PunishedHeight uint64 `json:"PunishedHeight"`

	//无效的assertion统计  不再共识委员会中的活跃度统计
	UselessAssertions uint64 `json:"useless_assertions"`
}

type SafeNodeDetailSet struct {
	lock    sync.RWMutex
	NodeMap map[string]*NodeDetail
}

func NewNodeSet() *SafeNodeDetailSet {
	return &SafeNodeDetailSet{
		NodeMap: make(map[string]*NodeDetail),
	}
}

// Add injects a new object into the working set, or returns an error if the
// object is already known.
func (n *SafeNodeDetailSet) Add(id string, p *NodeDetail) error {
	n.lock.Lock()
	defer n.lock.Unlock()

	n.NodeMap[id] = p

	return nil
}

// Del removes a object from the active set.
func (n *SafeNodeDetailSet) Del(id string) error {
	n.lock.Lock()
	defer n.lock.Unlock()
	delete(n.NodeMap, id)
	return nil
}

// Get retrieves the registered object with the given id.
func (n *SafeNodeDetailSet) Get(id string) *NodeDetail {
	n.lock.RLock()
	defer n.lock.RUnlock()

	val, ok := n.NodeMap[id]

	if ok {
		return val
	}

	return nil
}

// Len returns if the current number of objects in the set.
func (n *SafeNodeDetailSet) Len() int {
	n.lock.RLock()
	defer n.lock.RUnlock()

	return len(n.NodeMap)
}

func (n *SafeNodeDetailSet) Keys() []string {
	n.lock.RLock()
	defer n.lock.RUnlock()
	keys := make([]string, 0)
	for k, _ := range n.NodeMap {
		keys = append(keys, k)
	}

	return keys
}

func (n *SafeNodeDetailSet) KeysOrdered() []string {
	keys := n.Keys()

	sort.Strings(keys)

	return keys
}

func (n *SafeNodeDetailSet) Copy() *SafeNodeDetailSet {

	set := NewNodeSet()

	n.lock.RLock()
	defer n.lock.RUnlock()
	for k, _ := range n.NodeMap {
		val := n.Get(k)
		if val != nil {
			set.Add(k, val)
		}
	}
	return set
}

func (n *SafeNodeDetailSet) Encode() ([]byte, error) {
	var nodeDetails []*NodeDetail
	for _, nodeDetail := range n.NodeMap {
		nodeDetails = append(nodeDetails, nodeDetail)
	}
	return rlp.EncodeToBytes(nodeDetails)
}

func (n *SafeNodeDetailSet) Decode(data []byte) error {
	var nodeDetails []*NodeDetail
	err := rlp.DecodeBytes(data, &nodeDetails)
	if err != nil {
		log.Error("SafeNodeDetailSet Decode fail", "err", err)
	}
	for _, nodeDetail := range nodeDetails {
		n.NodeMap[nodeDetail.Address.String()] = nodeDetail
	}

	return nil
}

func (n *SafeNodeDetailSet) DecodeToString() (string, error) {
	//encode, err := n.Encode()
	marshal, err := json.Marshal(n)
	if err != nil {
		log.Error("nodeDetails Encode fail", "err", err)
		return "", errors.New("nodeDetails Encode fail")
	}
	qualifi := hex.EncodeToString(crypto.Keccak256(marshal))
	return qualifi, nil
}

type ByQualificationIndex []*NodeDetail

func (q ByQualificationIndex) Len() int {
	return len(q)
}

func (q ByQualificationIndex) Less(i, j int) bool {
	return q[i].QualificationIndex > q[j].QualificationIndex
}

func (q ByQualificationIndex) Swap(i, j int) {
	q[i], q[j] = q[j], q[i]
}

var CommitHeight2NodeDetailSetCache = &CommitHeight2NodeDetailSet{Height2NodeDetailSet: make(map[uint64]*SafeNodeDetailSet)}

type CommitHeight2NodeDetailSet struct {
	Lock              sync.RWMutex
	commitBlockHeight uint64 // commitBlockHeight of commit block
	// safeset is composed of consensus nodes (address.hex -> NodeDetail)
	Height2NodeDetailSet map[uint64]*SafeNodeDetailSet
}

func (q *CommitHeight2NodeDetailSet) Set(height uint64, set *SafeNodeDetailSet, db ethdb.Database) {
	q.Lock.Lock()
	defer q.Lock.Unlock()

	hash, _ := set.DecodeToString()
	log.Info("保存了活跃度高度", "height", height, "hash", hash)
	q.Height2NodeDetailSet[height] = set

	if height > q.commitBlockHeight {
		q.commitBlockHeight = height
	}

	if db == nil {
		return
	}

	data, err := set.Encode()
	if err == nil {
		db.Put([]byte("commit-statistics:"+strconv.FormatUint(height, 10)), data)
	}
}

func (q *CommitHeight2NodeDetailSet) Get(height uint64, db ethdb.Database) (*SafeNodeDetailSet, bool) {
	q.Lock.RLock()
	defer q.Lock.RUnlock()
	set, ok := q.Height2NodeDetailSet[height]
	if ok {
		return set, ok
	}

	if db == nil {
		return nil, false
	}

	data, err := db.Get([]byte("commit-statistics:" + strconv.FormatUint(height, 10)))
	if err != nil {
		return nil, false
	}

	var set2 = NewNodeSet()
	err = set2.Decode(data)
	if err != nil {
		return nil, false
	}

	if height > q.commitBlockHeight {
		q.commitBlockHeight = height
	}
	return set2, true
}

func (q *CommitHeight2NodeDetailSet) Dup(height uint64, db ethdb.Database) (*SafeNodeDetailSet, bool) {
	set, ok := q.Get(height, db)
	if !ok {
		return nil, false
	}

	q.Lock.Lock()
	defer q.Lock.Unlock()

	data, err := set.Encode()
	if err != nil {
		log.Info("encode error", "err", err.Error())
		return nil, false
	}

	set2 := NewNodeSet()
	err = set2.Decode(data)

	if err != nil {
		log.Info("decode error", "err", err.Error())
		return nil, false
	}

	return set2, true
}

func (q *CommitHeight2NodeDetailSet) Del(height uint64, db ethdb.Database) {
	q.Lock.Lock()
	defer q.Lock.Unlock()

	if height == q.commitBlockHeight {
		q.commitBlockHeight--
	}

	delete(q.Height2NodeDetailSet, height)
	if db != nil {
		db.Delete([]byte("commit-statistics:" + strconv.FormatUint(height, 10)))
	}
}

func (q *CommitHeight2NodeDetailSet) CleanUpNodeDetail(startNum uint64) {
	q.Lock.Lock()
	defer q.Lock.Unlock()

	delete(q.Height2NodeDetailSet, startNum)
}

func (q *CommitHeight2NodeDetailSet) Keys() []uint64 {
	q.Lock.RLock()
	defer q.Lock.RUnlock()

	keys := make([]uint64, 0)
	for k, _ := range q.Height2NodeDetailSet {
		keys = append(keys, k)
	}

	return keys
}

func (q *CommitHeight2NodeDetailSet) SortKey() []int {
	q.Lock.Lock()
	defer q.Lock.Unlock()
	keys := make([]int, 0)
	for k, _ := range q.Height2NodeDetailSet {
		keys = append(keys, int(k))
	}

	sort.Ints(keys)
	return keys
}

//清理活跃度
func CleanUpNodeDetailInfo(nodeDetail *NodeDetail, commitHeight uint64, reson string) *NodeDetail {
	nodeDetail.NumAssertionsTotal = 0
	nodeDetail.NumAssertionsAccepted = 0
	nodeDetail.NumBlocksAccepted = 0
	nodeDetail.NumBlocksAcceptedTotal = 0
	//nodeDetail.QualifiedAt = 0
	nodeDetail.PrequalifiedAt = 0
	nodeDetail.DisqualifiedAt = commitHeight
	nodeDetail.DisqualifiedReason = reson
	return nodeDetail
}
