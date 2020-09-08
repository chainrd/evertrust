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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/crypto"
	"CRD-chain/ethdb"
	"CRD-chain/log"
	"CRD-chain/quorum"
	evertrust_types "CRD-chain/evertrust/types"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	NormalBlock = 1
	CommitBlock = 2
)

type MultiSignBlock struct {
	BlockMap       map[common.Hash][]types.Header //normal block
	CommitBlockMap map[common.Hash][]types.Header //commit block
	sync.RWMutex
}

var MultiSign = &MultiSignBlock{BlockMap: make(map[common.Hash][]types.Header), CommitBlockMap: make(map[common.Hash][]types.Header)}

func (m *MultiSignBlock) DelMultiSign() {
	m.Lock()
	defer m.Unlock()
	MultiSign.BlockMap = nil
	MultiSign.BlockMap = make(map[common.Hash][]types.Header)

	MultiSign.CommitBlockMap = nil
	MultiSign.CommitBlockMap = make(map[common.Hash][]types.Header)
}

type normalBlockQueue struct {
	NormalBlockQueueMap     map[uint64]*ToProcessBlock
	normalBlockQueueMapLock sync.RWMutex
}

func newNormalBlockQueue() *normalBlockQueue {
	return &normalBlockQueue{NormalBlockQueueMap: make(map[uint64]*ToProcessBlock)}
}

func (n *normalBlockQueue) read(block *types.Block, processFunction func(block *types.Block, sync bool) error, broadcastFunction func(block *types.Block)) *ToProcessBlock {
	n.normalBlockQueueMapLock.Lock()
	defer n.normalBlockQueueMapLock.Unlock()
	toProcessBlocks, ok := n.NormalBlockQueueMap[block.NumberU64()]
	if !ok {
		blockExtra := evertrust_types.BlockExtraDecode(block)
		toProcessBlocks = newToProcessBlock(processFunction, broadcastFunction, blockExtra.Rank)
		toProcessBlocks.num = block.NumberU64()
		n.NormalBlockQueueMap[block.NumberU64()] = toProcessBlocks
	}
	return toProcessBlocks
}

func (n *normalBlockQueue) DelToProcessNormalBlockQueueMap(Height uint64) {
	n.normalBlockQueueMapLock.Lock()
	defer n.normalBlockQueueMapLock.Unlock()
	delete(n.NormalBlockQueueMap, Height)
}

func (n *normalBlockQueue) write(block *types.Block, toProcessBlocks *ToProcessBlock) {
	n.normalBlockQueueMapLock.Lock()
	defer n.normalBlockQueueMapLock.Unlock()
	n.NormalBlockQueueMap[block.NumberU64()] = toProcessBlocks
}

func (n *normalBlockQueue) del(height uint64) {
	n.normalBlockQueueMapLock.Lock()
	defer n.normalBlockQueueMapLock.Unlock()
	delete(n.NormalBlockQueueMap, height)
}

var NormalBlockQueued *normalBlockQueue

type CommitBlockQueue struct {
	CommitBlockQueueMap map[uint64]*ToProcessBlock

	commitBlockQueueMapLock sync.RWMutex
}

var CommitBlockQueued *CommitBlockQueue

func (c *CommitBlockQueue) DelToProcessCommitBlockQueueMap(Height uint64) {
	c.commitBlockQueueMapLock.Lock()
	defer c.commitBlockQueueMapLock.Unlock()
	delete(c.CommitBlockQueueMap, Height)
}

func newCommitBlockQueueMap() *CommitBlockQueue {
	return &CommitBlockQueue{CommitBlockQueueMap: make(map[uint64]*ToProcessBlock)}
}

func (c *CommitBlockQueue) read(block *types.Block, processFunction func(block *types.Block, sync bool) error, broadcastFunction func(block *types.Block)) *ToProcessBlock {
	c.commitBlockQueueMapLock.Lock()
	defer c.commitBlockQueueMapLock.Unlock()
	toProcessBlocks, ok := c.CommitBlockQueueMap[block.NumberU64()]
	if !ok {
		blockExtra, _ := evertrust_types.CommitExtraDecode(block)
		toProcessBlocks = newToProcessBlock(processFunction, broadcastFunction, blockExtra.Rank)
		toProcessBlocks.num = block.NumberU64()
		c.CommitBlockQueueMap[block.NumberU64()] = toProcessBlocks
	}

	return toProcessBlocks
}

func (c *CommitBlockQueue) del(height uint64) {
	c.commitBlockQueueMapLock.Lock()
	defer c.commitBlockQueueMapLock.Unlock()
	delete(c.CommitBlockQueueMap, height)
}

func init() {
	CommitBlockQueued = newCommitBlockQueueMap()
	NormalBlockQueued = newNormalBlockQueue()
}

func newToProcessBlock(processFunction func(block *types.Block, sync bool) error, broadcastFunction func(block *types.Block), blockRank uint32) *ToProcessBlock {
	return &ToProcessBlock{
		blockQueue:        make([]*types.Block, NumMasters+int32(blockRank)), //先收到的可能是r=0 在收自己无效的是4(NumMasters)+1(委员会)
		processFunction:   processFunction,
		BroadcastFunction: broadcastFunction,
		waitCh:            make(chan *types.Block, 10),
	}
}

func ProcessCommitBlock(block *types.Block, c *Evertrust, processFunction func(block *types.Block, sync bool) error, broadcastFunction func(block *types.Block), isCommit bool) {
	//验证出块时间
	blockNumU64 := block.NumberU64()
	minedCommitBlockTime := block.Time().Int64()
	currentTime := time.Now().Unix() + 1
	// miniTime <= minedCommitBlockTime <= currentTime
	// 如果打commit block的minedCommitBlockTime大于接收到该块的currentTime说明该块的时间戳有问题，
	if currentTime < minedCommitBlockTime {
		log.Error("commit block time incorrect", "cur", currentTime,
			"mined", minedCommitBlockTime, "num", blockNumU64)
		return
	}
	curCommitBlock := c.blockchain.CommitChain.CurrentBlock()
	if curCommitBlock == nil {
		log.Error("parent commit block nil", "num", blockNumU64)
		return
	}
	// 两个commit block的最短间隔时间
	currentNum := curCommitBlock.NumberU64()
	parentTime := curCommitBlock.Time().Int64()
	blockDelay := int64(BlockDelay) / 1000
	miniTime := parentTime + c.config.Cfd*blockDelay + blockDelay - 1
	//log.Debug("--#####################-----", "minedCommitBlockTime", minedCommitBlockTime, "miniTime", miniTime,
	//	"parentTime", parentTime, "cfd", c.config.Cfd, "blockDelay", blockDelay)
	if minedCommitBlockTime < miniTime {
		log.Error("commit block minedTime too quick",
			"mCBlockTime", minedCommitBlockTime, "mini", miniTime,
			"parent", parentTime, "cfd", c.config.Cfd, "bd", blockDelay, "num", blockNumU64, "curN", currentNum)
		return
	}

	blockExtra, commitExtra := evertrust_types.CommitExtraDecode(block)
	log.Info("开启了commitBlock处理流程", "处理的是高度为", blockNumU64, "rank", blockExtra.Rank)

	//记录双签的块头（两个块的块号，打块的地址，rank都一样，但是块hash不一样）
	recordMultiSignBlock(block, blockExtra.Rank, CommitBlock)

	if blockNumU64 != currentNum+1 {
		CommitDeRepetition.Del(blockNumU64) //commit删除缓存
		log.Debug("toProcessCommit高度无效,什么都不做", "num", blockNumU64)
		return
	}
	if !blockExtra.Empty {
		if !c.Worker().verifyBlock(block, blockExtra, int64(blockNumU64-1), true) {
			log.Error("toProcess commit verifyBlock fail")
			return
		}
	}

	toProcessBlocks := CommitBlockQueued.read(block, processFunction, broadcastFunction)
	//去重
	if len(toProcessBlocks.blockQueue) > int(blockExtra.Rank) && toProcessBlocks.blockQueue[blockExtra.Rank] != nil && block.Coinbase().String() != c.signer.String() {
		log.Debug("当前Rank的commit块已经接收过", "高度", blockNumU64, "rank", blockExtra.Rank)
		return
	}

	if blockNumU64 > 1 {
		currentQuorum, ok := quorum.CommitHeightToConsensusQuorum.Get(blockNumU64-1, c.db)
		if !ok {
			log.Error("no quorum existed on commit block height", "height", blockNumU64-1)
			return
		}
		//判断rank是否有效 无效的直接跳过
		if blockExtra.Rank < uint32(NumMasters) {
			needNodes := int(math.Ceil(float64(currentQuorum.Len()) * 2 / 3))
			sumQuorum := 0
			for _, condensedEvidence := range commitExtra.Evidences {
				if _, ok := currentQuorum.Hmap[condensedEvidence.Address().String()]; ok {
					sumQuorum++
				}
			}
			//验证commit中assertion的数量是否大于共识节点的多数 岛屿状态是大陆
			log.Info("toProcessCommit信息", "height", blockNumU64, "Evidences数量", len(commitExtra.Evidences), "neededNodes数量", needNodes, "rank", blockExtra.Rank,
				"符合本地的委员会成员数量", sumQuorum, "取委员会的高度", blockNumU64-1)
			//验证收到的commit是否是岛屿状态
			if sumQuorum < needNodes {
				log.Info("分叉commit进入冬眠", "commit高度", blockNumU64)
				go broadcastFunction(block)
				if !toProcessBlocks.getExecuting() {
					go toProcessBlocks.executeBlock(c, isCommit)
					toProcessBlocks.setExecuting(true)
				}
				max := int64(BlockDelay) * int64((NumMasters+1)*4) //4*M个master
				time.Sleep(time.Duration(max) * time.Millisecond)  //等待所有的rank时间
				//判断是否有其他的区块存上
				if blockNumU64 <= c.blockchain.CommitChain.CurrentBlock().NumberU64() {
					return
				}
			}
		}
	}

	if !blockExtra.Empty {
		go broadcastFunction(block)
		if uint32(atomic.LoadInt32(&toProcessBlocks.index)) >= blockExtra.Rank {
			toProcessBlocks.waitCh <- block
			toProcessBlocks.add(int(blockExtra.Rank), block)
		} else {
			toProcessBlocks.add(int(blockExtra.Rank), block)
		}
	}

	//是否开启了for
	toProcessBlocks.executeBlockLock.Lock()
	if !toProcessBlocks.getExecuting() {
		go toProcessBlocks.executeBlock(c, isCommit)
		toProcessBlocks.setExecuting(true)
	}
	toProcessBlocks.executeBlockLock.Unlock()

}

func ProcessNormalBlock(block *types.Block, c *Evertrust, processFunction func(block *types.Block, sync bool) error, broadcastFunction func(block *types.Block), isCommit bool) {
	//normal块走这里

	blockExtra := evertrust_types.BlockExtraDecode(block)
	//log.Debug("第一个空块可以扔掉","blockExtra.Empty",blockExtra,"block.NumberU64()",block.NumberU64())
	if blockExtra.Empty && block.NumberU64() == 1 {
		return
	}

	//记录双签的块头（两个块的块号，打块的地址，rank都一样，但是块hash不一样）
	recordMultiSignBlock(block, blockExtra.Rank, NormalBlock)

	currentNum := c.blockchain.CurrentBlock().NumberU64()
	if block.NumberU64() != currentNum+1 {
		log.Debug("this Normal height is invalid,so do nothing!", "num", block.NumberU64())
		return
	}
	if !blockExtra.Empty {
		if !c.Worker().verifyBlock(block, blockExtra, -1, false) {
			log.Error("toProcess normal verifyBlock fail")
			return
		}
	}

	toProcessBlocks := NormalBlockQueued.read(block, processFunction, broadcastFunction)

	//去重
	if len(toProcessBlocks.blockQueue) > int(blockExtra.Rank) && toProcessBlocks.blockQueue[blockExtra.Rank] != nil {
		log.Debug("当前Rank的normal块已经接收过")
		return
	}

	if !blockExtra.Empty {
		//时间戳验证 验证本地和当前区块时间戳
		gap := big.NewInt(0) //本地差值
		//parentGap := big.NewInt(0)                       //当前块 和 父块
		currentTime := big.NewInt(time.Now().Unix())     //本地时间
		mixTime := big.NewInt(int64(BlockDelay) / 1000)  //最小时间 两个blockDelay(父块的生成时间,本区块的生成时间)
		blockTime := block.Time()                        //当前区块时间戳
		parentTime := c.blockchain.CurrentBlock().Time() //父块时间戳
		if parentTime.Cmp(big.NewInt(0)) == 1 {
			gap.Add(parentTime, mixTime)
			//父块生成时间+最小生成时间<=当前区块生成时间<=当前收到区块的时间
			log.Info("父块时间戳和收到区块时间", "当前区块时间", currentTime, "父块时间戳", parentTime,
				"时间间隔", gap, "最小出块时间", mixTime, "收到的区块时间戳", blockTime)

			if blockTime.Cmp(gap) == -1 {
				log.Error("时间戳验证出问题1")
				return
			}
			//当前时间>=block生成时间
			if currentTime.Cmp(blockTime) == -1 {
				log.Error("时间戳验证出问题2")
				return
			}
		}

		go broadcastFunction(block)
		if uint32(atomic.LoadInt32(&toProcessBlocks.index)) >= blockExtra.Rank {
			toProcessBlocks.waitCh <- block
			toProcessBlocks.add(int(blockExtra.Rank), block)
		} else {
			toProcessBlocks.add(int(blockExtra.Rank), block)
		}
	}

	//是否开启了for
	toProcessBlocks.executeBlockLock.Lock()
	if !toProcessBlocks.getExecuting() {
		go toProcessBlocks.executeBlock(c, isCommit)
		toProcessBlocks.setExecuting(true)
	}
	toProcessBlocks.executeBlockLock.Unlock()
}

func recordMultiSignBlock(block *types.Block, rank uint32, blockType uint8) {
	//log.Debug("record multiSign")
	rankBuffer := new(bytes.Buffer)
	err := binary.Write(rankBuffer, binary.BigEndian, rank)
	if err != nil {
		log.Error("rank to bytes", "err", err)
		return
	}

	join := bytes.Join([][]byte{block.Number().Bytes(), block.Header().Coinbase.Bytes(), rankBuffer.Bytes()}, nil)
	joinHash := crypto.Keccak256Hash(join)

	MultiSign.Lock() //add lock----
	switch blockType {
	case NormalBlock: //normal block
		if headers, ok := MultiSign.BlockMap[joinHash]; !ok {
			MultiSign.BlockMap[joinHash] = append(MultiSign.BlockMap[joinHash], *block.Header())
		} else {
			//just putin 2 headers at most
			if len(headers) <= 1 {
				for _, header := range headers {
					if header.Hash() != block.Hash() {
						//record this multi sign block
						log.Warn("!!!record this multi sign normal block", "num", block.Number().String(),
							"coinbase", block.Header().Coinbase.String(), "rank", rank)
						MultiSign.BlockMap[joinHash] = append(MultiSign.BlockMap[joinHash], *block.Header())
					}
				}
			}
		}
	case CommitBlock: //commit block
		if headers, ok := MultiSign.CommitBlockMap[joinHash]; !ok {
			MultiSign.CommitBlockMap[joinHash] = append(MultiSign.CommitBlockMap[joinHash], *block.Header())
		} else {
			//just putin 2 headers at most
			if len(headers) <= 1 {
				for _, header := range headers {
					if header.Hash() != block.Hash() {
						//record this multi sign block
						log.Warn("!!!record this multi sign commit block", "num", block.Number().String(),
							"coinbase", block.Header().Coinbase.String(), "rank", rank)
						MultiSign.CommitBlockMap[joinHash] = append(MultiSign.CommitBlockMap[joinHash], *block.Header())
					}
				}
			}
		}
	default:
		log.Error("type error", "t", blockType)
		return

	}

	MultiSign.Unlock() //unlock---
}

type ToProcessBlock struct {
	blockQueue        []*types.Block //收集的block
	executing         bool           //是否开启for循环
	queueLock         sync.RWMutex
	executingLock     sync.Mutex
	executeBlockLock  sync.Mutex
	index             int32 //选出的循环下标
	processFunction   func(block *types.Block, sync bool) error
	BroadcastFunction func(block *types.Block)
	num               uint64
	waitCh            chan *types.Block
}

func (t *ToProcessBlock) getExecuting() bool {
	t.executingLock.Lock()
	defer t.executingLock.Unlock()
	return t.executing
}

func (t *ToProcessBlock) setExecuting(v bool) {
	t.executingLock.Lock()
	defer t.executingLock.Unlock()
	t.executing = v
}

//循环找从rank0开始找block
func (t *ToProcessBlock) executeBlock(c *Evertrust, isCommit bool) {
	//是否要停止循环 外面收到了比现在rank高的区块
	queueSize := len(t.blockQueue)
	waitTime := time.Duration(BlockDelay+1000) * time.Millisecond
	log.Info("开启循环等待Rank", "高度", t.num)
	for i := 0; i < queueSize; i++ {
		atomic.StoreInt32(&t.index, int32(i))
		switch {
		case len(t.waitCh) > 0:
			b := <-t.waitCh
			start := time.Now()
			log.Info("加塞路线")
			if err := t.processFunction(b, false); err != nil {
				t.del(b)
				log.Error("加塞路线processed block err,continue next", "err", err.Error())
				time.Sleep(waitTime - time.Now().Sub(start))
				continue
			} else {
				t.overState(isCommit, b.NumberU64())
				return
			}
		case t.get(i) == nil:
			delay := time.NewTimer(waitTime)
			start := time.Now()
			select {
			case b := <-t.waitCh:
				log.Info("加塞路线1")
				err := t.processFunction(b, false)
				if err != nil {
					log.Error("加塞路线1processed block err,continue next", "err", err.Error())
					t.del(b)
					time.Sleep(waitTime - time.Now().Sub(start))
					continue
				} else {
					t.overState(isCommit, b.NumberU64())
					return
				}
			case <-delay.C:
				continue
			}
		case t.get(i) != nil:
			log.Info("正常路线")
			block := t.get(i)
			start := time.Now()
			err := t.processFunction(t.get(i), false)
			if err != nil {
				log.Error("正常路线processed block err,continue next", "err", err.Error())
				t.del(block)
				time.Sleep(waitTime - time.Now().Sub(start))
				continue
			} else {
				t.overState(isCommit, t.get(i).NumberU64())
				return
			}
		}
	}
	log.Warn("没有发现有效的区块!")

	t.overState(isCommit, 0)
}

func (t *ToProcessBlock) overState(isCommit bool, height uint64) {
	t.setExecuting(false)
	if isCommit {
		CommitBlockQueued.del(height)
	} else {
		NormalBlockQueued.del(height)
	}
}

func (t *ToProcessBlock) get(index int) *types.Block {
	t.queueLock.RLock()
	defer t.queueLock.RUnlock()
	blockQueue := t.blockQueue[index]
	if blockQueue == nil {
		return nil
	}
	block := types.CopyNewBlock(blockQueue.Header(), blockQueue.Transactions(), blockQueue.Uncles())
	return block
}
func (t *ToProcessBlock) del(block *types.Block) {
	t.queueLock.RLock()
	defer t.queueLock.RUnlock()
	decode := evertrust_types.BlockExtraDecode(block)
	t.blockQueue[decode.Rank] = nil
}

func (t *ToProcessBlock) add(index int, block *types.Block) {
	t.queueLock.Lock()
	defer t.queueLock.Unlock()
	if index >= len(t.blockQueue) {
		for i := len(t.blockQueue); i <= index; i++ {
			t.blockQueue = append(t.blockQueue, nil)
		}
	}

	t.blockQueue[index] = block
	log.Info("block 加入 ToProcessBlock", "block高度", block.NumberU64(), "blockHash", block.Hash(), "rank", index,
		"blockQueue", t.blockQueue)
}

var FinishToProcessNextMap = NewFinishToProcessNext()

// 保存处理完的结果集
type finishToProcessNext struct {
	finishedProcessMap map[uint64]bool
	lock               sync.RWMutex
}

func NewFinishToProcessNext() *finishToProcessNext {
	return &finishToProcessNext{
		finishedProcessMap: make(map[uint64]bool),
	}
}

func (f *finishToProcessNext) Encode() ([]byte, error) {
	return json.Marshal(f.finishedProcessMap)
}

func (f *finishToProcessNext) Decode(data []byte) error {
	return json.Unmarshal(data, &f.finishedProcessMap)
}

func (f *finishToProcessNext) Set(height uint64, isFinished bool, db ethdb.Database) error {

	f.lock.Lock()
	defer f.lock.Unlock()

	_, ok := f.finishedProcessMap[height]
	if ok {
		return errors.New("this height already seted")
	}

	f.finishedProcessMap[height] = isFinished

	if db == nil {
		return nil
	}

	data, err := f.Encode()
	if err == nil {
		db.Put([]byte("commit-finished:"+strconv.FormatUint(height, 10)), data)
	}
	return err
}

func (f *finishToProcessNext) Get(height uint64, db ethdb.Database) bool {
	f.lock.Lock()
	defer f.lock.Unlock()
	set, ok := f.finishedProcessMap[height]
	if ok {
		return set
	}

	if db == nil {
		return false
	}

	data, err := db.Get([]byte("commit-finished:" + strconv.FormatUint(height, 10)))
	if err != nil {
		//log.Error("NOT found commit-finished date")
		return false
	}

	set2 := NewFinishToProcessNext()

	err = set2.Decode(data)
	if err != nil {
		log.Error("decode error")
		return false
	}

	// update cache
	f.finishedProcessMap[height] = set2.finishedProcessMap[height]

	return set2.finishedProcessMap[height]
}
