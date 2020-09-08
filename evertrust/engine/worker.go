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
	"bytes"
	"container/list"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"CRD-chain/accounts"
	"CRD-chain/accounts/keystore"
	"CRD-chain/cacheBlock"
	"CRD-chain/common"
	"CRD-chain/core"
	core_types "CRD-chain/core/types"
	"CRD-chain/core/vm"
	"CRD-chain/crypto"
	"CRD-chain/examineSync"
	"CRD-chain/log"
	"CRD-chain/p2p"
	"CRD-chain/p2p/discover"
	"CRD-chain/p2p/router"

	"CRD-chain/CRDcc/conf"
	"CRD-chain/quorum"
	"CRD-chain/rlp"
	"CRD-chain/evertrust"
	"CRD-chain/evertrust/engine/qualification"
	"CRD-chain/evertrust/iaasconn"

	"CRD-chain/core/publicBC"
	"CRD-chain/evertrust/types"
	"CRD-chain/evertrust/utils"
	"CRD-chain/evertrust/utils/client"
	"CRD-chain/evertrust/utils/frequency"
	"CRD-chain/evertrust/utils/tcUpdate"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	observer_only = ^uint32(0)

	Simple    = 1 //简单共识
	Twothirds = 0 //三分之二共识
)

var CommitHeightToLow = errors.New("CommitHeight To Low")

// number of masters for each block
var NumMasters int32

var BlockDelay int32 // in millisecond

//block confirmation window
var Cnfw *big.Int = new(big.Int)

var BecameQuorumLimt int32

var ConsensusQuorumLimt int32

var Majority int

var PerQuorum bool //每个commit更新委员会

var UIP1 *big.Int

// Record for an unconfirmed block
type blockTask struct {
	CNumber *big.Int
	masters []common.Address
	pubkeys []*ecdsa.PublicKey
	// miner and its rank for this block
	miner     common.Address
	rank      uint32
	block     *core_types.Block
	newHeight uint64 //打包assertion的时候以父commit的newHeight为起点
	empty     bool
}

type examineBlock struct {
	block       *core_types.Block
	masterBatch map[common.Hash]int //[当前Normal高度]第几批master
	RWLock      *sync.RWMutex
}

var ExamineBlock *examineBlock

func init() {
	NormalDeRepetition = NewDeRepetition()                                                        //normalBlock的去重
	CommitDeRepetition = NewDeRepetition()                                                        //commitBlock的去重
	AssociatedCommitDeRepetition = NewDeRepetition()                                              //AssociatedCommit的去重
	ExamineBlock = &examineBlock{masterBatch: make(map[common.Hash]int), RWLock: &sync.RWMutex{}} //第几批master
	examineSync.PeerExamineSync = examineSync.NewExamineSync()                                    //peer删除的时候别删同步的
	vm.NodeMap = vm.NewNodeUpdateMap()
}

type evertrustWorker struct {
	commitCh       chan *core_types.Block //act on successfully saved a normal block
	examineCh      chan *core_types.Block //从insert 接收最新块更新时间
	syncJoinCH     chan core_types.Block
	syncCh         chan struct{}
	isWaitSync     bool
	evertrust1     *Evertrust
	blockchain     *core.BlockChain
	timer          *time.Timer
	CommitRw       sync.RWMutex
	trustNodeList  []*discover.Node
	examineBlockCh chan *examineBlock
	preConnectCh   chan int64
}

func newWorker(evertrust *Evertrust) *evertrustWorker {
	// TODO : add by liangc : 根据用户的选择，实例化不同的 assert 通道
	// assertchannel := mq.NewAssertBlockChannel() // default channel

	w := &evertrustWorker{
		commitCh:       make(chan *core_types.Block, 10),
		examineCh:      make(chan *core_types.Block, 10),
		syncJoinCH:     make(chan core_types.Block, 1),
		evertrust1:     evertrust,
		timer:          &time.Timer{},
		blockchain:     evertrust.blockchain,
		syncCh:         make(chan struct{}, 1),
		trustNodeList:  make([]*discover.Node, 0),
		examineBlockCh: make(chan *examineBlock),
		preConnectCh:   make(chan int64, 10),
		//assertchannel:  assertchannel, // add by liangc
	}
	evertrust.blockchain.SubscribeCommitCHEvent(w.commitCh)
	evertrust.blockchain.SubscribeCommitCHEvent(w.examineCh)
	return w
}

type TrustTxData struct {
	ChainID             string      `json:"chainID"` //as registered in Registry
	CommitBlockNo       uint64      `json:"commitBlockNo"`
	CommitBlockHash     common.Hash `json:"commitBlockHash"`
	PrevCommitBlockHash common.Hash `json:"prevCommitBlockHash"`
	NodeAddress         string      `json:"nodeAddress"`
}

func (w *evertrustWorker) SyncJoin(block core_types.Block) {
	w.syncJoinCH <- block
}

func (w *evertrustWorker) waitSync() {
	w.isWaitSync = true
}

func (w *evertrustWorker) StopWaitSync() {
	if w.isWaitSync {
		w.syncCh <- struct{}{}
		w.isWaitSync = false
	}
}

func (w *evertrustWorker) Start() {
	// receive Assertion loop from p2p UniCast
	go func() {
		rt := router.NewRouter()
		assertType := router.UniCastMsgType(1)
		assertNum := 500
		assertCh := make(chan []byte, assertNum)
		rt.RegisterMsgListener(assertType, assertCh)
		log.Debug("UniCast Listener registered", "UniCastMsgType", assertType)

		for {
			select {
			case assertData := <-assertCh:
				var assert types.AssertExtra
				if err := rlp.DecodeBytes(assertData, &assert); err != nil {
					log.Error("decode assertion block", "err", err, "assertData", assertData)
				}

				err := w.evertrust1.OnAssertBlock(assert, "222")
				if err != nil {
					log.Error("onAssertBlock return", "err", err)
				}
			}
		}
	}()

	go w.commitLoop()
	go w.examineBlockLoop()
	go w.preConnect()
	//读取trustedNode配置文件 如果不需要trustedNode列表就将TrustedNodes改成StaticNodes
	w.startWithLocalTrustedNodeConfig()
}

func (w *evertrustWorker) startWithLocalTrustedNodeConfig() {
	atomic.StoreInt32(&w.evertrust1.start, 1)       //设置启动标识
	defer atomic.StoreInt32(&w.evertrust1.start, 0) //启动完成
	//读取trustedNode配置文件 如果不需要trustedNode列表就将TrustedNodes改成StaticNodes
	currentCommitBlockNum := w.blockchain.CommitChain.CurrentBlock().NumberU64()
	currentNormalBlockNum := w.blockchain.CurrentBlock().NumberU64()
	firstMiner := w.blockchain.GetBlockByNumber(0).Extra()
	if firstMiner == nil || len(firstMiner) == 0 {
		panic("error genesis block")
	}
	log.Info("firstMiner", "firstMiner", common.BytesToAddress(firstMiner).Hash(), "本机miner", w.evertrust1.signer.Hash(), "currentCommitBlockNum", currentCommitBlockNum, "currentNormalBlockNum", currentNormalBlockNum)
	// add by liangc : 通过 block 0 extraData 来判断是否为出块节点

	if currentCommitBlockNum <= 1 && currentNormalBlockNum == 0 && w.Signer() == common.BytesToAddress(firstMiner) {
		w.createNormalBlockAndCommitBlock()
	} else if currentCommitBlockNum <= 1 && currentNormalBlockNum == 0 {
		var blockMiningReq = &types.BlockMiningReq{Number: 0, Empty: true, Kind: types.NORNAML_BLOCK}
		w.evertrust1.MinerCh <- blockMiningReq //打一个空块
	} else {
		w.continueBlock() //先同步然后打块
	}
}

func (w *evertrustWorker) createNormalBlockAndCommitBlock() {
	commitBlock, _, _ := w.createCommitBlockWithOutTrustNode()

	if commitBlock == nil {
		return
	}
	w.evertrust1.BroadcastCommitBlock(commitBlock)

	err := w.ProcessCommitBlock(commitBlock, false)
	if err != nil {
		log.Error("1st commit block NOT saved, panic-ing now", "error", err)
	}

	if commitBlock.NumberU64() == 1 && !evertrust.Consortium && w.evertrust1.config.Hypothecation {
		w.UpdateNodeDetailWithFirstCommit()
	}

	//打一个normal块
	w.createAndBoradcastNormalBlockWithTask(0, 0, nil, false, 0)
}

func (w *evertrustWorker) UpdateNodeDetailWithFirstCommit() {
	nodeDetails, ok := qualification.CommitHeight2NodeDetailSetCache.Dup(1, w.evertrust1.db)
	if !ok {
		nodeDetails = qualification.NewNodeSet()
		nodeDetail := qualification.NodeDetail{Address: w.evertrust1.signer}
		qualification.CommitHeight2NodeDetailSetCache.Lock.Lock()
		nodeDetail.CanBeMaster = qualification.CanBeMaster
		qualification.CommitHeight2NodeDetailSetCache.Lock.Unlock()
		nodeDetails.Add(w.evertrust1.signer.Hex(), &nodeDetail)
	} else {
		minerDetail := nodeDetails.Get(w.evertrust1.signer.Hex())
		if minerDetail == nil {
			minerDetail = &qualification.NodeDetail{Address: w.evertrust1.signer}
		}
		qualification.CommitHeight2NodeDetailSetCache.Lock.Lock()
		minerDetail.CanBeMaster = qualification.CanBeMaster
		qualification.CommitHeight2NodeDetailSetCache.Lock.Unlock()
		nodeDetails.Add(w.evertrust1.signer.Hex(), minerDetail)
	}
	qualification.CommitHeight2NodeDetailSetCache.Set(1, nodeDetails, w.evertrust1.db)
}

func (w *evertrustWorker) createAndBoradcastNormalBlockWithTask(number int64, rank uint32, block *core_types.Block, empty bool, batch int) {
	if batch != 0 && empty {
		return
	}
	task := &blockTask{CNumber: big.NewInt(number), rank: rank, block: block, empty: empty}
	w.createAndBroadcastNormalBlock(task)
}

func (w *evertrustWorker) examineQuorums() (flag bool) {
	currentCommitBlock := w.blockchain.CommitChain.CurrentBlock()
	examineQuorums, ok := quorum.CommitHeightToConsensusQuorum.Get(currentCommitBlock.NumberU64()-1, w.evertrust1.db)
	if !ok {
		return flag
	}
	//验证

	_, ok = examineQuorums.Hmap[w.evertrust1.signer.Hex()]
	if ok {
		return true
	}
	return false

}

func (w *evertrustWorker) preConnect() {

	for {
		select {

		case commitBlockNum := <-w.preConnectCh:
			//计算下一次的CommitRank
			masters, _, _, err := w.masterRank(nil, w.Signer(), commitBlockNum, 0)
			if err != nil {
				log.Error("PeerConnect masterRank Fail ", "num", commitBlockNum)
				break
			}
			//把计算出来的地址转成公钥

			for _, address := range masters {
				//flag := false
				if address.Hash() == w.evertrust1.signer.Hash() {
					continue
				}
				ok, toPubkey := cacheBlock.AddrAndPubkeyMap.AddrAndPubkeyGet(address)
				if !ok {
					continue
				}
				//使用peerConnect创建通道
				err := w.Evertrust().stack.Server().Alibp2pServer().PreConnect(toPubkey)
				if err != nil {
					log.Error("PeerConnect Fail", "num", err)
					break
				}
				log.Info("创建preConnect完成", "Num", commitBlockNum)
			}
		}
	}
}

func (w *evertrustWorker) examineBlockLoop() {
	var blockHash common.Hash
	resetTime := time.Duration(BlockDelay*(NumMasters+1)) * time.Millisecond
	timer := time.NewTimer(resetTime)
	for {

		log.Info("examineBlockLoop重置")
		select {
		case <-timer.C:
			timer.Reset(resetTime)
			if atomic.LoadInt32(w.evertrust1.Syncing) == 1 {
				log.Info("正在同步不会重置")
				continue
			}
			if atomic.LoadInt32(&w.evertrust1.start) == 1 {
				log.Info("启动未完成")
				continue
			}
			w.SetLandState() //修改岛屿状态

			if !w.examineQuorums() {
				log.Warn("还没有加入委员会,改变自己本地状态")
				continue
			}
			currentNormalBlock := w.blockchain.CurrentBlock()
			currentCommitBlock := w.blockchain.CommitChain.CurrentBlock()
			quorums, _ := quorum.CommitHeightToConsensusQuorum.Get(currentCommitBlock.NumberU64()-1, w.evertrust1.db)
			quorumLen := int32(quorums.Len())
			//如果委员会成员小于NumMasters,那么batch一直就是0
			var batch int
			if quorumLen < NumMasters {
				batch = 0
			} else {
				batch = 1
			}

			//验证commit是否正常
			if !w.relativeBlock(currentNormalBlock, currentCommitBlock) {
				ExamineBlock.RWLock.Lock() //ExamineBlock.masterBatch exist race---
				if num, ok := ExamineBlock.masterBatch[currentCommitBlock.Hash()]; !ok {
					ExamineBlock.masterBatch[currentCommitBlock.Hash()] = batch
				} else {
					//取一下共识委员会，看看我在不在里面
					masterBatchNum := quorumLen / NumMasters
					if int32(num) < masterBatchNum && masterBatchNum > 1 {
						ExamineBlock.masterBatch[currentCommitBlock.Hash()]++
					}
				}
				batch := ExamineBlock.masterBatch[currentCommitBlock.Hash()]
				log.Error("Commit打块异常", "commit高度", currentCommitBlock.NumberU64(), "master批次", ExamineBlock.masterBatch[currentCommitBlock.Hash()], "commitHash", currentCommitBlock.Hash(), "batch", batch)
				ExamineBlock.RWLock.Unlock() //unlock-----

				normalBlockNum := w.evertrust1.blockchain.CurrentBlock().NumberU64()
				//从新开始打commit块
				normalBlock := w.blockchain.GetBlockByNumber(normalBlockNum)
				w.ProcessCommitLogic(normalBlock, batch, true)
			}

			ExamineBlock.block = currentNormalBlock

			ExamineBlock.RWLock.Lock() //add lock----
			if num, ok := ExamineBlock.masterBatch[currentNormalBlock.Hash()]; !ok {
				ExamineBlock.masterBatch[currentNormalBlock.Hash()] = batch
			} else {
				masterBatchNum := quorumLen / NumMasters
				if int32(num) < masterBatchNum && masterBatchNum > 1 {
					ExamineBlock.masterBatch[currentNormalBlock.Hash()]++
				}
			}
			log.Error("Normal打快异常", "原始Hash", blockHash.String(), "最新hash", currentNormalBlock.Hash().String(), "master批次", ExamineBlock.masterBatch[currentNormalBlock.Hash()])
			ExamineBlock.RWLock.Unlock() //unlock------

			w.examineBlockCh <- ExamineBlock
		case block := <-w.examineCh:
			log.Info("开始更新时间戳", "block", block.Number())
			timer.Reset(resetTime)
			land, _ := LocalLandSetMap.LandMapGet(w.blockchain.CommitChain.CurrentBlock().NumberU64(), w.evertrust1.db)
			log.Info("显示岛屿信息", "land", land)
			//ExamineBlock.RWLock.Lock()                  //add lock----
			//delete(ExamineBlock.masterBatch, blockHash) //清除批次
			//ExamineBlock.RWLock.Unlock()                //unlock----

		}
	}
}

//判断当前commit是否正常
func (w *evertrustWorker) relativeBlock(currentNormalBlock *core_types.Block, commitBlock *core_types.Block) bool {
	//先判断commit是否正常,如果正常走正常流程,不正常先去发第二批的assertion和打第二批的commit
	_, commitExtra := types.CommitExtraDecode(commitBlock)
	relativeNum := commitExtra.NewBlockHeight.Uint64() //当前commit对应的Normal
	log.Debug("验证commit", "当前commit对应的Normal高度+cfd+5", relativeNum+Cnfw.Uint64()+5, "当前的Normal高度", currentNormalBlock.NumberU64())
	if currentNormalBlock.NumberU64() > relativeNum+Cnfw.Uint64()+5 {
		return false //commit不正常
	} else {
		return true
	}
}

func (w *evertrustWorker) SetLandState() {
	//当前commit高度
	commitNum := w.blockchain.CommitChain.CurrentBlock().NumberU64()
	log.Info("SetLandState 要修改岛屿状态的commit高度", "commitNum", commitNum)
	db := w.evertrust1.db
	land, ok := LocalLandSetMap.LandMapGet(commitNum, db)
	if !ok {
		//如果岛屿状态是空,创建岛屿状态
		consensusQuorum, ok := quorum.CommitHeightToConsensusQuorum.Get(commitNum, w.evertrust1.db)
		quorum := make([]string, 0)
		if ok {
			quorum = consensusQuorum.Keys()
		}
		land := NewLocalLand()
		land.LandSet(w.evertrust1.signer.String(), true, commitNum, quorum)
		LocalLandSetMap.LandMapSet(commitNum, land, w.evertrust1.db)
	} else {
		log.Info("SetLandState 要修改岛屿状态的commit高度找到对应的岛屿信息", "commitNum", commitNum, "岛屿状态", land.IslandState)
	}

}

func (w *evertrustWorker) continueBlock() {
	// restart as the ONLY node of the chain
	//从新启动后改变自己的岛屿状态
	w.SetLandState()
	wait := time.Duration(20*BlockDelay) * time.Millisecond
	timeout := time.NewTimer(wait) //超过时间后自己打快
	w.waitSync()
	for {
		select {
		case <-w.syncCh:
			log.Info("启动后同步完成")
			return
		case <-timeout.C:
			if atomic.LoadInt32(w.evertrust1.Syncing) == 1 {
				log.Info("正在同步,不会触发 selfWork")
				timeout.Reset(wait)
				continue
			}
			w.selfWork()
			return
		}
	}
}

func (w *evertrustWorker) selfWork() {
	commitBlock := w.blockchain.CommitChain.CurrentBlock()
	blockExtra, _ := types.CommitExtraDecode(commitBlock)
	//重启后打块 获取下次更新高度
	if testQuorum, ok := quorum.UpdateQuorumSnapshots.GetUpdateQuorum(blockExtra.HistoryHeight, w.evertrust1.db); !ok {
		quorum.UpdateQuorums = quorum.NewUpdateQuorum()
	} else {
		quorum.UpdateQuorums.CopyUpdateQuorum(testQuorum)
	}
	w.commitCh <- w.blockchain.CurrentBlock()
	log.Info("selfWork 完成")

}

func (w *evertrustWorker) createCommitBlockWithOutTrustNode() (*core_types.Block, *types.BlockExtra, *types.CommitExtra) {
	address := w.evertrust1.signer

	//需要rank和区块高度
	commitExtra := types.CommitExtra{NewBlockHeight: big.NewInt(0), MinerAdditions: []common.Address{address}}
	commitExtraByte, err := rlp.EncodeToBytes(commitExtra)
	if err != nil {
		log.Error("err rlp encode error", "error", err)
	}

	blockExtra := &types.BlockExtra{Rank: 0, CNumber: big.NewInt(1), Extra: commitExtraByte}

	if !evertrust.Perf {
		blockExtra.Signature = nil
		data, err := rlp.EncodeToBytes(blockExtra)
		if err != nil {
			return nil, nil, nil
		}

		hash := crypto.Keccak256Hash(data)

		if address == quorum.EmptyAddress {
			return nil, nil, nil
		}

		sig, err := w.evertrust1.signFn(accounts.Account{Address: address}, hash.Bytes())
		blockExtra.Signature = sig
	} else {
		log.Trace("perf mode no sign in commit blockExtra")
	}

	currentBlock := w.blockchain.CommitChain.CurrentBlock()

	genesisBlockHash := currentBlock.Hash()
	commitBlock, err := types.NewCommitblock(blockExtra, genesisBlockHash, address, w.evertrust1.signFn)
	if err != nil {
		return nil, nil, nil
	}

	return commitBlock, blockExtra, &commitExtra
}

//find next block of masters
func (w *evertrustWorker) getMasterOfNextBlock(isCommit int64, block *core_types.Block, batch int) ([]common.Address, int, error) {
	var commitHeight int64
	var masters int32
	//等待x个块之后,在用新的委员会
	afterHeight := int64(1)

	if isCommit != -1 {
		//commitHeight = isCommit - afterHeight
		commitHeight = isCommit
	} else {
		blockExtra := types.BlockExtraDecode(block)
		if blockExtra.CNumber == nil {
			return nil, 0, errors.New("CNumber is nil")
		}
		commitHeight = blockExtra.CNumber.Int64() - afterHeight
	}

	if commitHeight <= 0 {
		commitHeight = 1
	}
	log.Info("本次需要等待", "等待高度", afterHeight, "commitHeight", commitHeight)
	consensusQuorum, ok := quorum.CommitHeightToConsensusQuorum.Get(uint64(commitHeight), w.evertrust1.db)
	if !ok {
		log.Error("cannot get consensus quorum for commit height:", "commitHeight", commitHeight)
		return nil, 0, errors.New("cannot get consensus quorum for commit height")
	}
	log.Info("取出委员会的高度和数量", "取委员会的高度", commitHeight, "取出委员会的数量", consensusQuorum.Len(), "batch", batch)

	consensusNodesOrdered := consensusQuorum.KeysOrdered()

	consensusNodesOrderedLen := len(consensusNodesOrdered)

	masters = int32(consensusNodesOrderedLen)
	//增加master限制
	if masters >= NumMasters {
		masters = NumMasters
	}
	var nextBlockMasters = make([]common.Address, int(masters)+batch*int(masters))

	log.Info("计算本次的", "要计算的Commit高度", isCommit, "Commit高度是", commitHeight)
	//获取一段距离的所有blockhash和打块地址哈希
	tempHash, err := w.get2cfdBlockHashAndMasterAddressHash(isCommit, block)
	if err != nil {
		return nil, consensusQuorum.Len(), err
	}

	var alreadyUsedNum = make([]uint32, 0)
	log.Info("计算master的终点值是多少", "num", int(masters)+batch*int(masters), "batch", batch)
	for r := 0; r < int(masters)+batch*int(masters); r++ {
		if r >= consensusNodesOrderedLen { //防止越界
			break
		}
		var data []byte
		if isCommit != -1 {
			prevCommitBlock := w.blockchain.CommitChain.GetBlockByNum(uint64(commitHeight))
			if prevCommitBlock == nil {
				return nil, consensusQuorum.Len(), errors.New("prevCommitBlock is nil")
			}
			prevCommitBlockHash := prevCommitBlock.Hash()
			prevHash := prevCommitBlockHash[:]
			data = bytes.Join([][]byte{tempHash[:], common.IntToHex(int64(r)), prevHash}, []byte{})
		} else {
			data = bytes.Join([][]byte{tempHash[:], common.IntToHex(int64(r)), common.IntToHex(block.Number().Int64())}, []byte{})
		}
		tempTotalHash := crypto.Keccak256Hash(data)
		tempInt := common.BytesToUint32(tempTotalHash[:])
	cLoop:
		i := tempInt % uint32(consensusNodesOrderedLen)
		for _, value := range alreadyUsedNum {
			if i == value {
				tempInt += 1
				goto cLoop
			}
		}
		alreadyUsedNum = append(alreadyUsedNum, i)
		address := common.HexToAddress(consensusNodesOrdered[i])
		nextBlockMasters[r] = address
		log.Info("计算rank", "Rank", r, "地址", address, "委员会consensusNodesOrderedLen", consensusNodesOrderedLen)
	}

	if len(nextBlockMasters) < batch*int(masters) {
		ExamineBlock.RWLock.Lock() //add lock---
		delete(ExamineBlock.masterBatch, block.Hash())
		ExamineBlock.RWLock.Unlock() //unlock---
		return nil, consensusQuorum.Len(), err
	}
	return nextBlockMasters, consensusQuorum.Len(), nil
}

func (w *evertrustWorker) get2cfdBlockHashAndMasterAddressHash(isCommit int64, block *core_types.Block) (common.Hash, error) {
	blockHash, addressHash, err := w.get2cfdBlockHash(isCommit, block)
	if err != nil {
		return common.Hash{}, err
	}
	hash := bytes.Join([][]byte{blockHash, addressHash}, []byte{})
	tempHash := crypto.Keccak256Hash(hash)

	return tempHash, nil
}

//根据masters们获得判断自己的rank
func (w *evertrustWorker) masterRank(block *core_types.Block, addr common.Address, isCommit int64, batch int) ([]common.Address, uint32, int, error) {
	if block != nil {
		log.Info("计算masterRank", "高度", block.NumberU64()+1)
	}
	//获得下一个区块的masters
	masters, consensusQuorumLen, err := w.getMasterOfNextBlock(isCommit, block, batch)
	if err != nil {
		//如果 没有取到委员会,就取自己当前的委员会数量
		if consensusQuorumLen == 0 {
			currentCommitNum := w.blockchain.CommitChain.CurrentBlock().NumberU64()
			consensusQuorum, ok := quorum.CommitHeightToConsensusQuorum.Get(uint64(currentCommitNum), w.evertrust1.db)
			if !ok {
				consensusQuorumLen = int(NumMasters)
			} else {
				consensusQuorumLen = consensusQuorum.Len()
			}
		}
		log.Error("cant get masters", "err", err)
		return []common.Address{}, observer_only, consensusQuorumLen, err
	}
	log.Info("master数量", "len", len(masters))
	for r, v := range masters {
		if v == addr {
			num := int(NumMasters)
			if num > len(masters) {
				num = len(masters)
			}
			if batch == 0 {
				return masters, uint32(r), consensusQuorumLen, nil
			} else {
				if r/num == batch {
					log.Info("第几批master", "批次", batch, "rank", r)
					return masters[batch*num:], uint32(r), consensusQuorumLen, nil
				}
				log.Info("第几批master", "批次", batch, "rank", observer_only)
				return masters[batch*num:], observer_only, consensusQuorumLen, nil

			}
		}
	}

	return masters, observer_only, consensusQuorumLen, nil
}

//get 2*dis*cfd blockhash
func (w *evertrustWorker) get2cfdBlockHash(isCommitMaster int64, block *core_types.Block) ([]byte, []byte, error) {
	var blockHashCollect []byte //返回值
	var currentNum int64        //目前的位置
	var finishNum int64         //开始的num

	var addresses []byte
	var count int64

	if isCommitMaster != -1 {
		currentNum = isCommitMaster
		if currentNum-Cnfw.Int64() >= 0 {
			finishNum = currentNum - Cnfw.Int64()
		} else {
			finishNum = 0
		}
	} else {
		currentNum = block.Number().Int64() - 1
		cnfNum := Cnfw.Int64() / 2
		if currentNum-cnfNum >= 0 {
			finishNum = currentNum - cnfNum
		} else {
			finishNum = 0
		}
	}
	log.Info("查询计算master", "currentNum", currentNum, "finishNum", finishNum)
	for ; currentNum > finishNum; currentNum-- {
		var block *core_types.Block
		if isCommitMaster != -1 {
			block = w.blockchain.CommitChain.GetBlockByNum(uint64(currentNum))
		} else {
			block = w.blockchain.GetBlockByNumber(uint64(currentNum))
		}

		if block == nil {
			log.Warn("get2cfdBlockHash methord didnot get commitblock")
			return nil, nil, errors.New("get2cfdBlockHash methord didnot get commitblock")
		}
		header := block.Header()
		if header == nil {
			log.Info("block header is empty")
			return nil, nil, errors.New("block header is nill")
		}

		blockHashCollect = bytes.Join([][]byte{blockHashCollect, block.Header().Hash().Bytes()}, []byte{})

		if count <= Cnfw.Int64() {
			addresses = bytes.Join([][]byte{addresses, block.Header().Coinbase.Bytes()}, []byte{})
		}
		count++
	}

	return blockHashCollect, addresses, nil
}

//创建blockExtra
func (w *evertrustWorker) createBlockExtra(blockExtra types.BlockExtra, cNum int64, rank uint32, extraData []byte) (*types.BlockExtra, error) {
	blockExtra.CNumber = big.NewInt(cNum)
	blockExtra.NodeID = discover.PubkeyID(&w.evertrust1.stack.Server().PrivateKey.PublicKey)
	//当前节点rank
	blockExtra.Rank = rank
	blockExtra.Extra = extraData
	blockExtra.HistoryHeight = quorum.UpdateQuorums.HistoryUpdateHeight //上次更新委员会的高度,用这个高度回滚后可以找到下次更新委员会的时间

	if !evertrust.Perf {
		signFn, signer := w.evertrust1.signFn, w.evertrust1.signer
		//blockExtra进行签名
		data, err := rlp.EncodeToBytes(blockExtra)
		if err != nil {
			log.Error("blockExtra EncodeToBytes error")
			return nil, errors.New("blockExtra EncodeToBytes error")
		}

		hash := crypto.Keccak256Hash(data)
		sig, _ := signFn(accounts.Account{Address: signer}, hash.Bytes())
		blockExtra.Signature = sig
	}

	return &blockExtra, nil
}

func (w *evertrustWorker) createAndMulticastBlockAssertion(task *blockTask) {
	// 1) Create AssertExtra
	log.Info("计算要发的assertion的地址")
	blockPath := make([]common.Hash, 0)
	assertExtra := types.AssertExtra{}
	cfdStart := task.newHeight + 1
	cfdEnd := cfdStart + Cnfw.Uint64() - 1
	log.Info("创建assertion需要发送的normal区块", "要打的assertion", task.CNumber.Uint64()+1, "从", cfdStart, "到", cfdEnd)
	//循环取出所有区间cfd个区块并且转成hash储存到blockPath
	for i := cfdStart; i <= cfdEnd; i++ {
		block := w.blockchain.GetBlockByNumber(i)
		if block == nil {
			log.Error("---------------block is nil num :", "normal高度", i)
			return
		}
		blockPath = append(blockPath, block.Hash())
	}

	//pack evidence into assert extra-----
	log.Debug("pack multiSign")
	packMultiSignEvidence(&assertExtra)

	log.Info("查询assertion的数据", "task.rank", task.rank, "observer_only", observer_only, "task.CNumber.Uint64()", task.CNumber.Uint64())

	currentQuorum, _ := quorum.CommitHeightToConsensusQuorum.Get(task.CNumber.Uint64(), w.evertrust1.db)
	if currentQuorum.Contains(w.evertrust1.signer) {
		//委员会成员才发送path
		log.Info("查询assertion的数据2")
		assertExtra.BlockPath = blockPath
	}

	commitBlockNumber := big.NewInt(task.CNumber.Int64())
	assertExtra.LatestCommitBlockNumber = commitBlockNumber
	//commithash
	assertExtra.ParentCommitHash = w.blockchain.CommitChain.GetBlockByNum(commitBlockNumber.Uint64()).Hash()
	//拼接blockPath+commithash
	var signHash []common.Hash
	signHash = append(signHash, assertExtra.BlockPath...)
	signHash = append(signHash, assertExtra.ParentCommitHash)
	log.Info("要签名的数据", "数据", core_types.RlpHash(signHash))
	//签名Assert 对整个 AssertExtra 进行签名
	if !evertrust.Perf {
		signer, signFn := w.evertrust1.signer, w.evertrust1.signFn
		data, err := rlp.EncodeToBytes(signHash)
		if err != nil {
			log.Info("blockPath EncodeToBytes error")
			return
		}
		hash := crypto.Keccak256Hash(data)
		sig, _ := signFn(accounts.Account{Address: signer}, hash.Bytes())
		assertExtra.Signature = sig
	}
	reader, _, _ := rlp.EncodeToReader(assertExtra)
	msg := p2p.Msg{Size: uint32(reader)}
	log.Info("自己查询assertion大小", "size", msg)
	// modify by liangc
	//多播给masters,让下一个区块的master进行commitBlock确认
	var nodes []discover.NodeID
	for _, address := range task.masters {
		//flag := false
		if address.Hash() == w.evertrust1.signer.Hash() {
			//自己是委员会成员时候发给自己
			w.processBlockAssert(assertExtra)
			continue
		}
		ok, toPubkey := cacheBlock.AddrAndPubkeyMap.AddrAndPubkeyGet(address)
		if !ok {
			continue
		}
		nodes = append(nodes, discover.PubkeyID(toPubkey))
	}
	//多播asserblock给commitblock区块的master
	w.evertrust1.MulticastAssertBlock(assertExtra, nodes) //进行master多播
}

func packMultiSignEvidence(assertExtra *types.AssertExtra) {
	MultiSign.Lock() //lock---
	for _, headers := range MultiSign.BlockMap {
		if len(headers) >= 2 {
			log.Info("pack multi sign normal block header into assert extra!!!!!")
			log.Info("header0", "num", headers[0].Number.String(),
				"coinbase", headers[0].Coinbase.String(), "size", headers[0].Size())
			log.Info("header1", "num", headers[1].Number.String(),
				"coinbase", headers[1].Coinbase.String(), "size", headers[1].Size())
			assertExtra.MultiSignBlockEvidence = append(assertExtra.MultiSignBlockEvidence, headers)
		}
	}

	for _, commitHeaders := range MultiSign.CommitBlockMap {
		if len(commitHeaders) >= 2 {
			log.Info("pack multi sign commit block header into assert extra!!!!!")
			log.Info("header0", "num", commitHeaders[0].Number.String(),
				"coinbase", commitHeaders[0].Coinbase.String(), "size", commitHeaders[0].Size())
			log.Info("header1", "num", commitHeaders[1].Number.String(),
				"coinbase", commitHeaders[1].Coinbase.String(), "size", commitHeaders[1].Size())
			assertExtra.MultiSignCommitBlockEvidence = append(assertExtra.MultiSignCommitBlockEvidence, commitHeaders)
		}
	}

	//del multi sign block from cache
	MultiSign.BlockMap = nil
	MultiSign.BlockMap = make(map[common.Hash][]core_types.Header)

	MultiSign.CommitBlockMap = nil
	MultiSign.CommitBlockMap = make(map[common.Hash][]core_types.Header)
	MultiSign.Unlock() //unlock---
}

func (w *evertrustWorker) createAndBroadcastCommitBlock(task *blockTask) {
	// add by liangc : 出 commit 块要启动 Advertise
	defer p2p.SendAlibp2pAdvertiseEvent(&p2p.AdvertiseEvent{Start: true, Period: 60 * time.Second})
	timeout := time.NewTimer(time.Millisecond * time.Duration(BlockDelay))
	//外面从新存的commitNumber
	nextCommitHeight := task.CNumber.Uint64() + 1
	log.Info("获取assertion的commit高度", "高度", nextCommitHeight)
	var allNewAssertions *utils.SafeSet

	var ok bool
waiting:
	for {
		select {

		case <-timeout.C:
			allNewAssertions, ok = AssertCacheObject.Get(nextCommitHeight, w.evertrust1.db)
			if !ok {
				log.Error("no block assertions received, ignore create and broadcast commit block")
				return
			}
			//取出assertion删除掉本地assertion
			AssertCacheObject.Del(nextCommitHeight, w.evertrust1.db)
			break waiting
		}
	}
	_, commitExtra := types.CommitExtraDecode(w.blockchain.CommitChain.CurrentBlock())
	//获取岛屿信息
	land, version := w.ContractQuery(commitExtra)

	log.Info("done waiting for assertion collection", "高度是", nextCommitHeight, "收集到的assertions数量", allNewAssertions.Len())

	//孤儿
	if allNewAssertions.Len() <= 0 {
		log.Error("received no assertions before timeout")
		return
	}

	consensusQuorum, err := w.getQuorumForHeight()
	if err != nil {
		return
	}

	//create blockExtra & commitExtra
	blockExtra, commitExtra, multiSignNormalByte, multiSignCommitByte, err := w.createCommitExtra(consensusQuorum,
		allNewAssertions, task, nextCommitHeight, land)
	if err != nil {
		return
	}
	commitExtra.Version = version
	commit, _ := commitExtra.Encode()
	//set commitExtra to blockExtra
	extra, err := w.createBlockExtra(blockExtra, task.CNumber.Int64()+1, task.rank, commit)
	if err != nil {
		return
	}

	currentBlockHash := w.blockchain.CommitChain.CurrentBlock().Hash()
	//创建commitBlcok
	commitBlock, err := types.NewCommitblock(extra, currentBlockHash, w.evertrust1.signer, w.evertrust1.signFn)
	if err != nil {
		return
	}

	commitBlock.SetMultiSign(multiSignNormalByte, multiSignCommitByte)

	log.Info("commit打包完成", "commit信息 number", commitBlock.NumberU64(), "hash", commitBlock.Hash().String(), "rank", extra.Rank)

	w.evertrust1.CommitFetcher.Enqueue(fmt.Sprintf("%x", blockExtra.NodeID.Bytes()[:8]), []*core_types.Block{commitBlock})

	return
}

func (w *evertrustWorker) createCommitExtra(consensusQuorum *quorum.NodeAddress, allNewAssertions *utils.SafeSet,
	task *blockTask, nextCommitHeight uint64, land LocalLand) (types.BlockExtra, types.CommitExtra, []byte, []byte, error) {
	//如果是evertrust共识就用委员会总数,否则就是收到assertion的数量
	var total int
	switch Majority {
	case Twothirds:
		log.Info("Twothirds共识")
		total = consensusQuorum.Len()
	case Simple:
		log.Info("Simple共识")
		total = allNewAssertions.Len()
	default:
		log.Info("Simple共识")
		total = allNewAssertions.Len()
	}

	//获取所有共识节点的2/3节点的数量
	needNode := int(math.Ceil(float64(total) * 2 / 3))
	log.Debug("开始needNode", "needNode", needNode)

	currentCommitBlock := w.blockchain.CommitChain.CurrentBlock()
	//取上一个commitExtra
	_, lastCommitExtra := types.CommitExtraDecode(currentCommitBlock)
	log.Debug("lastCommitExtra", "commit高度", task.CNumber, "长度", lastCommitExtra.Quorum)

	if task.CNumber.Uint64()+1 != currentCommitBlock.Number().Uint64()+1 {
		log.Error("block height wrong")
		return types.BlockExtra{}, types.CommitExtra{}, nil, nil, errors.New("区块高度有误")
	}

	if needNode == 0 {
		needNode = 1
	}
	log.Debug("最终needNode", "needNode", needNode)
	//过滤在委员会中的成员,进行path计算和岛屿判断
	validNewAssertionsInConsensusQuorum := allNewAssertions.CopyInConsensusQuorum(consensusQuorum.Hmap)

	var commitExtra types.CommitExtra
	var blockExtra types.BlockExtra
	//用收到的assertion计算共识BlocksPath
	commitExtra = w.setUpCommitBlockPath(validNewAssertionsInConsensusQuorum, needNode)
	if w.evertrust1.config.Majority == Twothirds {
		//判断岛屿并设置岛屿标识 使用全部的assertion
		blockExtra, commitExtra = w.setUpIslandInfo(blockExtra, needNode, allNewAssertions, validNewAssertionsInConsensusQuorum, task, consensusQuorum, commitExtra, lastCommitExtra, land)
	}
	//setUp evidence 这里存放所有的assertion
	commitExtra = w.setUpEvidence(allNewAssertions, commitExtra)
	//收集assertion 的数量
	sum, err := cacheBlock.CommitAssertionSum.GetAssertionSum(currentCommitBlock.Number(), w.evertrust1.db)
	if err != nil {
		log.Error("GetAssertionSum fail", "err", err)
	}
	log.Info("取出的assertion的数量", "高度", currentCommitBlock.Number(), "sum", sum)
	//当前的assertion加上本次收到的有效assertion总和
	commitExtra.AssertionSum = sum.Add(big.NewInt(int64(validNewAssertionsInConsensusQuorum.Len())), sum)
	log.Info("save condensedEvidence", "当前的assertion总数", commitExtra.AssertionSum, "validNewAssertionsInConsensusQuorum.Len()", validNewAssertionsInConsensusQuorum.Len())
	//根据commitBlocksPath的最后一区块hash获取最新区块高度

	var height *big.Int
	//要用commitExtra.AcceptedBlocks如果分叉是用的自己的path
	if len(commitExtra.AcceptedBlocks) > 0 {
		height = big.NewInt(int64(len(commitExtra.AcceptedBlocks)) + w.blockchain.CommitChain.CurrentCommitExtra().NewBlockHeight.Int64())
	} else {
		//path是0 取上一个commitBlock存的高度
		height = w.blockchain.CommitChain.CurrentCommitExtra().NewBlockHeight
	}
	log.Info("commit的newHeight", "commit高度", task.CNumber.Uint64()+1, "newHeight", height.Uint64(), "commitExtra.AcceptedBlocks", len(commitExtra.AcceptedBlocks),
		"assertionSum", commitExtra.AssertionSum)
	commitExtra.NewBlockHeight = height

	//更新活跃的 打快的时候应该不会报错
	nodeDetails, err := w.calculateStatusAndQualification(nextCommitHeight, &commitExtra, w.evertrust1.signer)
	if err != nil {
		return types.BlockExtra{}, types.CommitExtra{}, nil, nil, err
	}

	localPath := w.selfPath(allNewAssertions)
	//计算节点增减

	commitExtra.MinerAdditions, commitExtra.MinerDeletions,
		commitExtra.NodeAdditions, commitExtra.NodeDeletions, nodeDetails = w.calculateMembershipUpdates(nodeDetails, commitExtra, nextCommitHeight, localPath, w.evertrust1.signer)

	if nodeDetails == nil {
		return types.BlockExtra{}, types.CommitExtra{}, nil, nil, errors.New("nodeDetails is nil")
	}

	multiSignNormalByte, multiSignCommitByte := collectMultiSign(allNewAssertions, nodeDetails, nextCommitHeight)

	if nextCommitHeight == 1 && w.evertrust1.config.Hypothecation == true {
		for _, addr := range commitExtra.MinerAdditions {
			nodeDetail := nodeDetails.Get(addr.String())
			if nodeDetail != nil {
				qualification.CommitHeight2NodeDetailSetCache.Lock.Lock()
				nodeDetail.CanBeMaster = qualification.CanBeMaster
				qualification.CommitHeight2NodeDetailSetCache.Lock.Unlock()
				nodeDetails.Add(addr.String(), nodeDetail)
			}
		}
	}

	commitExtra.QualificationHash, err = nodeDetails.DecodeToString()
	if err != nil {
		return types.BlockExtra{}, types.CommitExtra{}, nil, nil, err
	}

	log.Info("委员会状态", "新增委员会成员", len(commitExtra.MinerAdditions), "收到的assertion数量", allNewAssertions.Len())
	return blockExtra, commitExtra, multiSignNormalByte, multiSignCommitByte, nil
}

//搜集assertion中的multiSign
func collectMultiSign(allNewAssertions *utils.SafeSet, nodeDetails *qualification.SafeNodeDetailSet, nextCommitHeight uint64) ([]byte, []byte) {
	log.Debug("collect multiSign")
	existN := make(map[common.Address]struct{})
	existC := make(map[common.Address]struct{})
	var multiSignNormal [][]core_types.Header
	var multiSignCommit [][][]byte //[][]blockExtral
	for _, key := range allNewAssertions.Keys() {
		val := allNewAssertions.Get(key)
		assertInfo := val.(*AssertInfo)
		for _, headers := range assertInfo.AssertExtra.MultiSignBlockEvidence {
			if len(headers) == 2 {
				if _, ok := existN[headers[0].Coinbase]; !ok {
					log.Debug("create commit block multiSign normal", "coinbase", headers[0].Coinbase)

					//进行处理惩罚
					h1 := headers[0]
					miner1, err := getMinerFromHeaderSig(&h1)
					if err != nil {
						log.Error("get miner1", "err", err, "num", h1.Number.String(), "miner", h1.Coinbase.String())
						continue
					}

					h2 := headers[1]
					miner2, err := getMinerFromHeaderSig(&h2)
					if err != nil {
						log.Error("get miner2", "err", err, "num", h1.Number.String(), "miner", h1.Coinbase.String())
						continue
					}

					var blockExtra1 types.BlockExtra
					blockExtra1.Decode(h1.Extra)

					var blockExtra2 types.BlockExtra
					blockExtra2.Decode(h2.Extra)

					log.Info("h1", "num", h1.Number.String(), "miner", miner1.String(), "rank", blockExtra1.Rank, "hash", h1.Hash().String())
					log.Info("h2", "num", h2.Number.String(), "miner", miner2.String(), "rank", blockExtra2.Rank, "hash", h2.Hash().String())
					//是否是双签的块（两个块的块号，打块的地址，rank都一样，但是块hash不一样）
					if (h1.Number.Cmp(h2.Number) == 0 && miner1 == miner2 && blockExtra1.Rank == blockExtra2.Rank) &&
						(h1.Hash() != h2.Hash()) {
						//更改多签节点的活跃度
						multiSignNodeDetail := nodeDetails.Get(miner1.Hex())
						qualification.CleanUpNodeDetailInfo(multiSignNodeDetail, nextCommitHeight, qualification.MultSign+qualification.ShouldStacking).CanBeMaster = qualification.ShouldBePunished
						nodeDetails.Add(multiSignNodeDetail.Address.Hex(), multiSignNodeDetail)
						log.Info("clean up node", "addr", multiSignNodeDetail.Address.String(),
							"cB", multiSignNodeDetail.CanBeMaster,
							"dAt", multiSignNodeDetail.DisqualifiedAt,
							"nAT", multiSignNodeDetail.NumAssertionsTotal)
					}

					//打入commit header中
					multiSignNormal = append(multiSignNormal, headers)
					existN[headers[0].Coinbase] = struct{}{}
				}
			}
		}
		for _, headers := range assertInfo.AssertExtra.MultiSignCommitBlockEvidence {
			if len(headers) == 2 {
				if _, ok := existC[headers[0].Coinbase]; !ok {
					log.Debug("create commit block multiSign commit", "coinbase", headers[0].Coinbase)

					//多签处理惩罚
					h1 := headers[0]
					e1 := h1.Extra
					var blockExtra1 types.BlockExtra
					err := blockExtra1.Decode(e1)
					if err != nil {
						log.Error("decode blockExtra", "err", err)
						continue
					}

					miner1, err := getMinerFromCommitHeaderSig(blockExtra1)
					if err != nil {
						log.Error("get commit miner1", "err", err, "num", blockExtra1.CNumber, "miner", miner1)
						continue
					}

					h2 := headers[1]
					e2 := h2.Extra
					var blockExtra2 types.BlockExtra
					err = blockExtra2.Decode(e2)
					if err != nil {
						log.Error("decode blockExtra2", "err", err)
						continue
					}

					miner2, err := getMinerFromCommitHeaderSig(blockExtra2)
					if err != nil {
						log.Error("get commit miner2", "err", err, "num", blockExtra1, "miner", miner2)
						continue
					}

					log.Info("commit h1", "num", blockExtra1.CNumber, "miner", miner1.String(), "rank", blockExtra1.Rank)
					log.Info("commit h2", "num", blockExtra2.CNumber, "miner", miner2.String(), "rank", blockExtra2.Rank)
					//是否是双签的块（两个块的块号，打块的地址，rank都一样，但是块hash不一样）
					if (blockExtra1.CNumber.Cmp(blockExtra2.CNumber) == 0 && miner1 == miner2 && blockExtra1.Rank == blockExtra2.Rank) &&
						(h1.Hash() != h2.Hash()) {
						//更改多签节点的活跃度
						multiSignCommitNodeDetail := nodeDetails.Get(miner1.Hex())
						qualification.CleanUpNodeDetailInfo(multiSignCommitNodeDetail, nextCommitHeight, qualification.MultSign+qualification.ShouldStacking).CanBeMaster = qualification.ShouldBePunished
						nodeDetails.Add(multiSignCommitNodeDetail.Address.Hex(), multiSignCommitNodeDetail)
						log.Info("clean up node detail info", "addr", multiSignCommitNodeDetail.Address.String(), "canBeMaster", multiSignCommitNodeDetail.CanBeMaster, "disqualifiedAt", multiSignCommitNodeDetail.DisqualifiedAt, "numAssertionsTotal", multiSignCommitNodeDetail.NumAssertionsTotal)
					}

					//打入commit header中
					multiSignCommit = append(multiSignCommit, [][]byte{headers[0].Extra, headers[1].Extra})
					existC[headers[0].Coinbase] = struct{}{}
				}
			}
		}
	}
	multiSignNormalByte, err := rlp.EncodeToBytes(multiSignNormal)
	if err != nil {
		log.Error("rlp encode multiSignNormal", err)
		multiSignNormalByte = nil
	}
	multiSignCommitByte, err := rlp.EncodeToBytes(multiSignCommit)
	if err != nil {
		log.Error("rlp encode multiSignCommit", err)
		multiSignCommitByte = nil
	}

	return multiSignNormalByte, multiSignCommitByte
}

func (w *evertrustWorker) calculateStatusAndQualification(commitHeight uint64, commitExtra *types.CommitExtra,
	miner common.Address) (*qualification.SafeNodeDetailSet, error) {

	//get or create node details set for this commit height
	nodeDetails, ok := qualification.CommitHeight2NodeDetailSetCache.Dup(commitHeight-1, w.evertrust1.db)
	if !ok {
		nodeDetails = qualification.NewNodeSet()
		nodeDetail := &qualification.NodeDetail{Address: miner}
		nodeDetails.Add(miner.Hex(), nodeDetail)
	}

	//NumAssertionsAccepted 信息统计
	nodeDetails = w.updateAssertionsAccepted(commitExtra, nodeDetails, commitHeight) //更新完的101的活跃度集合=====
	// 减少资格
	if commitHeight > qualification.DistantOfCfd {
		if err := w.clearUpActiveNum(commitHeight, nodeDetails); err != nil {
			return nil, err
		}
	}

	// update qualification indices
	for _, value := range nodeDetails.NodeMap {
		//活跃度总量
		value.ActivenessIndex = value.NumAssertionsTotal
		value.ContributionIndex = 80*value.NumBlocksAcceptedTotal + 20*value.NumAssertionsTotal
		value.CapabilitiesIndex = 100 //TODO each node probe and commit node verify
		value.QualificationIndex = 60*value.ActivenessIndex + 20*value.ContributionIndex + 20*value.CapabilitiesIndex
	}
	// persist node statistics details 更新最新的高度

	return nodeDetails, nil
}

func (w *evertrustWorker) updateAssertionsAccepted(commitExtra *types.CommitExtra, nodeDetails *qualification.SafeNodeDetailSet, commitHeight uint64) *qualification.SafeNodeDetailSet {
	if len(commitExtra.Evidences) == 0 {
		return nodeDetails
	}
	newNodeDetails, ok := w.nodeDetailsWithDistanct(qualification.DistantOfCfd, commitHeight-1)
	if !ok {
		log.Error("no data on this height:", "height", commitHeight-1)
		panic("no data on this height:")
	}
	for _, evidence := range commitExtra.Evidences {
		//log.Info("取出的evidence数量", "evidence地址", evidence.Address())
		evidenceValue := nodeDetails.Get(evidence.Address().Hex())
		if evidenceValue == nil {
			evidenceValue = &qualification.NodeDetail{Address: evidence.Address()}
			nodeDetails.Add(evidence.Address().Hex(), evidenceValue)
		}
		evidenceValue.UselessAssertions++
		if w.evertrust1.config.Hypothecation == false || evidenceValue.CanBeMaster == qualification.CanBeMaster {
			evidenceValue.NumAssertionsAccepted++
			evidenceValue.NumAssertionsTotal++

			//判断assert数量够不够  增加资格
			if evidenceValue.NumAssertionsTotal >= qualification.DistantOfCfd {
				//至少证明了我活跃数量是够了 接下来判断我活跃的区间是不是过去的1000个区间
				//一段区间的活跃的差值

				newNodeDetail := newNodeDetails.Get(evidenceValue.Address.Hex())
				if newNodeDetail == nil {
					log.Error("一段区间的活跃的差值 ---没有节点记录", "address", evidenceValue.Address.Hex())
					panic("")
				}

				//区间值要大于3/2
				if newNodeDetail.NumAssertionsTotal >= qualification.DistantOfCfd/3*2 {

					//本高度的100个区间 newNodeDetail.NumAssertionsTotal >= distantOfcdf/3*2
					// && commitHeight >= newNodeDetail.DisqualifiedAt+activedDistant) -- 失去资格但是重新活跃了activedDistant个区间
					if newNodeDetail.PrequalifiedAt == 0 &&
						(newNodeDetail.DisqualifiedAt == 0 || (newNodeDetail.DisqualifiedAt != 0 &&
							commitHeight >= newNodeDetail.DisqualifiedAt+qualification.DistantOfCfd)) {

						evidenceValue.PrequalifiedAt = commitHeight                  //在哪个高度有资格
						evidenceValue.QualifiedAt = commitHeight + 2                 //在哪个高度正式成为委员会
						evidenceValue.PunishedHeight = 0                             //要惩罚的高度
						evidenceValue.DisqualifiedAt = 0                             //在哪个高度失去资格
						evidenceValue.DisqualifiedReason = qualification.EmptyString //失去资格的原因
						log.Info("增加资格的地址", "地址", evidence.Address())
					}
				}
			}
		}
		nodeDetails.Add(evidence.Address().Hex(), evidenceValue)
	}

	return nodeDetails
}

func (w *evertrustWorker) clearUpActiveNum(commitHeight uint64, nodeDetails *qualification.SafeNodeDetailSet) error {
	//清除活跃度不够的节点
	currentHeightNodeDetails, ok := w.nodeDetailsWithDistanct(qualification.DistantOfCfd, commitHeight-1) //100-98的活跃度
	if !ok {
		log.Error("no data on this height:", "height", commitHeight-1)
		return errors.New("no data on this height")
	}
	for _, address := range nodeDetails.Keys() {
		nodeDetail := currentHeightNodeDetails.Get(address)
		if nodeDetail != nil {
			//活跃度小于 distantOfcdf/3*2&&在委员会中&&没有被剔除
			if nodeDetail.NumAssertionsTotal < qualification.DistantOfCfd/3*2 &&
				nodeDetail.QualifiedAt != 0 && nodeDetail.DisqualifiedAt == 0 {
				log.Info("清理的nodeDetail", "高度", commitHeight, "resaon", nodeDetail.DisqualifiedReason)
				nodeDetail = qualification.CleanUpNodeDetailInfo(nodeDetail, commitHeight, qualification.ActivityNotEnough+qualification.ShouldStacking)
				nodeDetails.Add(address, nodeDetail)
			}
		}
	}
	return nil
}

//获取当前高度距离指定距离的NodeDetails集合
func (w *evertrustWorker) nodeDetailsWithDistanct(dist uint64, commitHeight uint64) (*qualification.SafeNodeDetailSet, bool) {

	nodeDetails, ok := qualification.CommitHeight2NodeDetailSetCache.Dup(commitHeight, w.evertrust1.db)
	if !ok {
		log.Info("no NodeDetailSet on height :", "height", commitHeight)
		return nil, false
	}

	if commitHeight < dist {
		return nodeDetails, true
	}

	if commitHeight-dist >= 1 {
		oldNodeDetails, ok := qualification.CommitHeight2NodeDetailSetCache.Dup(commitHeight-dist, w.evertrust1.db)
		if !ok {
			log.Error("no NodeDetailSet on prevheight :", "prevheight", commitHeight-dist)
		}

		for _, addressHex := range nodeDetails.Keys() {
			currentNodeDetail := nodeDetails.Get(addressHex) //100 add->活跃度
			oldNodeDetail := oldNodeDetails.Get(addressHex)  //98  add->活跃度
			if oldNodeDetail == nil || currentNodeDetail == nil {
				continue
			}

			if int(currentNodeDetail.NumAssertionsTotal)-int(oldNodeDetail.NumAssertionsTotal) >= 0 {
				currentNodeDetail.NumAssertionsAccepted -= oldNodeDetail.NumAssertionsAccepted
				currentNodeDetail.NumAssertionsTotal -= oldNodeDetail.NumAssertionsTotal
				currentNodeDetail.NumBlocksAccepted -= oldNodeDetail.NumBlocksAccepted
				currentNodeDetail.NumBlocksAcceptedTotal -= oldNodeDetail.NumBlocksAcceptedTotal
			}
		}
	}
	return nodeDetails, true
}

// called on create and broadcast commit block
func (w *evertrustWorker) calculateMembershipUpdates(nodeDetails *qualification.SafeNodeDetailSet, commitExtra types.CommitExtra, commitHeight uint64, localPath []common.Hash, coinbase common.Address) (minerAdditions []common.Address, minerDeletions []common.Address,
	nodeAdditions []common.Address, nodeDeletions []common.Address, nodeDetailsAft *qualification.SafeNodeDetailSet) {
	/*
		todo 方法计算委员会变更,
		1.根据commitHeight-2 和 commitHeight-1 取出活跃度计算委员会变更
		2.修改nodeDetails 中活跃度(非rank0剔除,对下个区块有影响)
		3.根据nodeDetails 新增nodeDeletions中成员(logFilter,doPunish)
	*/

	if commitHeight <= 1 {
		log.Warn("commit height 1 only has local node as miner addition")
		return []common.Address{w.evertrust1.signer}, nil, nil, nil, nodeDetails
	}

	//log.Info("取前两个高度的共识委员会","height",commitHeight-2,"quorum",prevConsensusQuorum.Keys())
	prevNodeSet, ok := w.nodeDetailsWithDistanct(qualification.DistantOfCfd, commitHeight-2)
	if !ok {
		log.Warn("failed to get node set for commit height:", "height", commitHeight)
		return nil, nil, nil, nil, nodeDetails
	}

	// get current nodes (active, capable and willing-to-contribute)
	currNodeSet, ok := w.nodeDetailsWithDistanct(qualification.DistantOfCfd, commitHeight-1)
	if !ok {
		log.Warn("failed to get node set for commit height:", "height", commitHeight)
		return nil, nil, nil, nil, nodeDetails
	}

	// get current nodes (active, capable and willing-to-contribute)
	//所有节点的活跃度
	currMiners, nodeAdditions, err := w.getNodeAdditions(prevNodeSet, currNodeSet)
	if err != nil {
		return nil, nil, nil, nil, nodeDetails
	}
	log.Info("计算委员会所有有资格的委员会成员", "currMiners", len(currMiners))

	//移除失效的
	currMiners = removeFailureNode(currMiners)
	log.Info("移除失效的委员会所有有资格的委员会成员", "currMiners", len(currMiners))
	prevConsensusQuorum, ok := quorum.CommitHeightToConsensusQuorum.Get(commitHeight-1, w.evertrust1.db)
	if !ok {
		return nil, nil, nil, nil, nodeDetails
	}
	currMiners = w.removeActivityNotEnough(commitHeight, currMiners, prevConsensusQuorum)

	log.Info("移除活跃度不够的的委员会所有有资格的委员会成员", "currMiners", len(currMiners))

	minerAdditions = w.getMinerAdditions(prevConsensusQuorum, currMiners)

	// persist current consensus quorum into database
	currConsensusQuorum := quorum.NewNodeAddress()
	for _, v := range currMiners {
		currConsensusQuorum.Add(v.Address.Hex(), v.Address)
	}
	prevMiners := prevConsensusQuorum.KeysCommonAddress()
	minerDeletions = w.getMinerDeletions(prevMiners, currConsensusQuorum, coinbase)

	//剔除非rank 0 的
	if w.blockchain.Config().IsUIP1(big.NewInt(int64(commitHeight))) {
		//不影响本次区块委员会变更
		log.Info("进入UIP exceptStorageUIP1", "commitHeight", commitHeight, "UIP", w.evertrust1.config.UIP1)
		err := w.exceptStorageUIP1(commitHeight, commitExtra, nodeDetails)
		if err != nil {
			return nil, nil, nil, nil, nodeDetails
		}
	} else {
		//不影响本次区块委员会变更
		nodeDetails, err = w.exceptStorage(commitHeight, commitExtra, nodeDetails, minerDeletions)
		if err != nil {
			return nil, nil, nil, nil, nodeDetails
		}
	}
	if w.evertrust1.config.Hypothecation == true {
		nodeDetails, minerDeletions, err = w.logFilter(minerDeletions, commitHeight, nodeDetails, currConsensusQuorum)
		if err != nil {
			return nil, nil, nil, nil, nodeDetails
		}
		nodeDetails = w.doPunish(commitHeight, nodeDetails)
	}

	//如果是岛屿块,不添加非原委员会成员
	if commitExtra.Island {
		log.Info("当前岛屿链状态需要过滤新增委员会成员", "原委员会成员个数", len(minerAdditions))
		m := make(map[string]int)
		newMinerAdditions := make([]common.Address, 0)
		for _, add := range commitExtra.Quorum {
			m[add]++
		}
		for _, v := range minerAdditions {
			if _, ok := m[v.String()]; ok {
				newMinerAdditions = append(newMinerAdditions, v)
			}
		}
		minerAdditions = newMinerAdditions
		log.Info("当前岛屿链状态需要过滤新增委员会成员", "更新后的委员会成员", len(minerAdditions))
	}

	//排序
	minerAdditions, err = w.minderAdditionLimited(minerAdditions)
	if err != nil {
		return nil, nil, nil, nil, nodeDetails
	}

	log.Info("finished calculating membership update for commit height:", "commitHeight", commitHeight,
		"minerAdditions", len(minerAdditions), "minerDeletions", len(minerDeletions), "nodeAdditions", len(nodeAdditions), "nodeDeletions", len(nodeDeletions))
	return minerAdditions, minerDeletions, nodeAdditions, nodeDeletions, nodeDetails
}

func (w *evertrustWorker) logFilter(minerDeletions []common.Address, commitHeight uint64, nodeDetails *qualification.SafeNodeDetailSet, currConsensusQuorum *quorum.NodeAddress) (*qualification.SafeNodeDetailSet, []common.Address, error) {
	//更新惩罚名单
	if len(minerDeletions) > 0 {
		w.updatePunishedList(minerDeletions, commitHeight, nodeDetails)
	}

	//把log拿出来更新记录
	hypothecationAddr := utils.HypothecationContract
	recaptionAddr := utils.RedamptionContract
	temHeight := commitHeight - 1
	if temHeight <= 0 {
		temHeight = commitHeight
	}

	prevCommitBlock := w.blockchain.CommitChain.GetBlockByNum(temHeight)

	if prevCommitBlock != nil {
		_, prevCommitExtra := types.CommitExtraDecode(prevCommitBlock)
		normalBlock := w.blockchain.GetBlockByNumber(prevCommitExtra.NewBlockHeight.Uint64())

		if normalBlock == nil {
			log.Error("质押获取normalBlock错误")
			return nodeDetails, minerDeletions, errors.New("cannot get normal block")
		}
		if w.blockchain.HasState(normalBlock.Root()) {
			st, err := w.blockchain.StateAt(normalBlock.Root())
			if err != nil {
				log.Error("获取状态出错", "err", err)
			} else {
				cacheData := st.GetCRDState(hypothecationAddr, hypothecationAddr.Hash())

				if len(cacheData) != 0 {
					log.Info("获取状态成功", "数据不为空", len(cacheData))
					var cache vm.CacheMap
					cache.Decode(cacheData)

					for key, _ := range cache.HypothecationMap {
						if _, ok := currConsensusQuorum.Hmap[key]; !ok {
							//log.Info("已经质押但没在共识委员会中")
							ethAddr := common.HexToAddress(key)
							nodeDetail := nodeDetails.Get(key)
							if nodeDetail == nil {
								nodeDetail = &qualification.NodeDetail{Address: ethAddr, CanBeMaster: qualification.CanBeMaster}
							} else if nodeDetail.CanBeMaster == qualification.ShouldBePunished {
								continue
							} else {
								nodeDetail.CanBeMaster = qualification.CanBeMaster
							}
							nodeDetails.Add(key, nodeDetail)
						}
					}
				}

				readData := st.GetCRDState(recaptionAddr, recaptionAddr.Hash())
				if len(readData) != 0 {
					var cache1 vm.CacheMap1
					cache1.Decode(readData)
					for addr, _ := range cache1.RecaptionMap {
						log.Info("看一下退出质押里面有谁", "addr", addr)
						nodeDetail := nodeDetails.Get(addr)
						ethAddr := common.HexToAddress(addr)
						if nodeDetail == nil {
							nodeDetail = &qualification.NodeDetail{Address: ethAddr, CanBeMaster: qualification.CantBeMaster}
						} else {
							nodeDetail.CanBeMaster = qualification.CantBeMaster
						}

						nodeDetails.Add(addr, nodeDetail)
						minerDeletions = append(minerDeletions, ethAddr)
					}
				}
			}
		}
		log.Info("对应的normal块高度", "num", prevCommitExtra.NewBlockHeight.Uint64())
	}
	return nodeDetails, minerDeletions, nil
}

func (w *evertrustWorker) minderAdditionLimited(minerAdditions []common.Address) ([]common.Address, error) {
	currentNum := public.BC.CurrentCommit().NumberU64()
	qur, ok := quorum.CommitHeightToConsensusQuorum.Get(currentNum, w.evertrust1.db)
	if !ok {
		return []common.Address{}, errors.New("cant find quorum")
	}

	num := int(ConsensusQuorumLimt) - qur.Len()

	switch num > 0 {

	case true:
		if len(minerAdditions) > num {
			minerAdditions = minerAdditions[:num]
		}
	default:
		minerAdditions = make([]common.Address, 0)
	}
	return minerAdditions, nil
}

func (w *evertrustWorker) exceptStorageUIP1(commitHeight uint64, commitExtra types.CommitExtra, nodeDetails *qualification.SafeNodeDetailSet) error {
	if commitHeight > 3 && !commitExtra.Island {
		commit := w.blockchain.CommitChain.GetBlockByNum(commitHeight - 1)
		_, preCommitExt := types.CommitExtraDecode(commit)
		//通过blockpath进行本地节点非高rank的剔除
		blockPath := preCommitExt.AcceptedBlocks
		//满足条件后走新逻辑
		for _, hash := range blockPath {
			block := w.blockchain.GetBlockByHash(hash)
			if block == nil {
				return errors.New("w.blockchain.GetBlockByHash error")
			}
			extra := types.BlockExtraDecode(block)
			rank := extra.Rank

			if rank != 0 {
				number := block.NumberU64() - 1
				batch := rank / uint32(NumMasters)
				block = w.blockchain.GetBlockByNumber(number)
				masters, _, _ := w.getMasterOfNextBlock(-1, block, int(batch))
				for i, master := range masters {
					details := nodeDetails.Get(master.String())
					if uint32(i) < rank {
						//非rank0节点增加失效值
						log.Info("UIP1非rank0失效值", "高度是", number+1, "地址", master, "失效值", details.NumBlocksFailedTotal)

						if details.DisqualifiedReason == qualification.EmptyString {
							//如果被剔除,不在进行失效值累计
							details.NumBlocksFailedTotal++
						}
						if details.NumBlocksFailedTotal >= 5 {
							//minerDeletions = append(minerDeletions, master)
							details.NumBlocksFailedTotal = 0 //UIP1 剔除委员会并且非rank0失效值清0
							qualification.CleanUpNodeDetailInfo(details, commitHeight, qualification.ExceptStorage+qualification.ShouldNotStacking)
						}

					} else {
						//只清理出块节点的失效值
						if uint32(i) == rank {
							//如果正常出块,失效值清零
							details.NumBlocksFailedTotal = 0
						}

					}
				}
			}
		}

	}
	return nil
}

func (w *evertrustWorker) exceptStorage(commitHeight uint64, commitExtra types.CommitExtra, nodeDetails *qualification.SafeNodeDetailSet, minerDeletions []common.Address) (*qualification.SafeNodeDetailSet, error) {
	exceptStorage := make([]common.Address, 0)
	//剔除非rank 0 的
	if commitHeight > 3 && !commitExtra.Island {
		commit := w.blockchain.CommitChain.GetBlockByNum(commitHeight - 1)
		_, preCommitExt := types.CommitExtraDecode(commit)
		//通过blockpath进行本地节点非高rank的剔除
		blockPath := preCommitExt.AcceptedBlocks
		for _, hash := range blockPath {
			block := w.blockchain.GetCacheBlock(hash)
			if block == nil {
				block = w.blockchain.GetBlockByHash(hash)
			}
			if block == nil {
				return nodeDetails, errors.New("")
			}
			extra := types.BlockExtraDecode(block)
			rank := extra.Rank
			if rank != 0 {
				number := block.NumberU64() - 1
				batch := rank / uint32(NumMasters)
				block = w.blockchain.GetBlockByNumber(number)
				masters, _, _ := w.getMasterOfNextBlock(-1, block, int(batch))
				for i, master := range masters {
					if uint32(i) < rank && !deleContains(minerDeletions, master) {
						log.Info("没找到缓存非rank0剔除添加", "高度是", number+1, "添加的地址是", master)
						minerDeletions = append(minerDeletions, master)
						exceptStorage = append(exceptStorage, master)
					}
				}
			}
		}
	}

	//非正常存储的记录剔除
	if len(exceptStorage) > 0 {
		for _, addr := range exceptStorage {
			nodeDetail := nodeDetails.Get(addr.Hex())
			if nodeDetail != nil {
				log.Info("清理的nodeDetail--非正常存储的记录剔除", "高度", commitHeight)
				nodeDetail = qualification.CleanUpNodeDetailInfo(nodeDetail, commitHeight, qualification.ExceptStorage+qualification.ShouldNotStacking)
				nodeDetails.Add(addr.Hex(), nodeDetail)
			}
		}
	}
	return nodeDetails, nil
}

func deleContains(addresses []common.Address, address common.Address) bool {
	for _, addr := range addresses {
		if addr == address {
			return true
		}
	}
	return false
}

func (w *evertrustWorker) getNodeAdditions(prevNodeSet, currNodeSet *qualification.SafeNodeDetailSet) (qualification.ByQualificationIndex, []common.Address, error) {

	currNodes := make(qualification.ByQualificationIndex, 0, currNodeSet.Len())

	//对应高度中活跃度差值中所有地址的活跃度
	for _, v := range currNodeSet.NodeMap {
		if v == nil {
			continue
		}
		currNodes = append(currNodes, v)
	}
	// for each in new node quorum, find additions from previous node quorum
	nodeAdditions := make([]common.Address, 0)
	for _, v := range currNodes {
		n := prevNodeSet.Get(v.Address.Hex())
		if n == nil {
			nodeAdditions = append(nodeAdditions, v.Address)
		}
	}

	if len(nodeAdditions) == 0 {
		nodeAdditions = nil
	}
	return currNodes, nodeAdditions, nil
}

//移除失效的
func removeFailureNode(currMiners qualification.ByQualificationIndex) qualification.ByQualificationIndex {
	tempCurrNodes := make(qualification.ByQualificationIndex, 0)
	for _, nodeDetail := range currMiners {
		//DisqualifiedAt 什么时候失效的
		//DisqualifiedReason 失效的原因
		//log.Info("currMiners中的地址", "地址", nodeDetail.Address, "活跃度", nodeDetail.NumAssertionsTotal)
		if nodeDetail.DisqualifiedAt == 0 && nodeDetail.DisqualifiedReason == qualification.EmptyString {
			//有资格的成员
			tempCurrNodes = append(tempCurrNodes, nodeDetail)
		}
	}
	//把要剔除的节点过滤
	if len(tempCurrNodes) != 0 {
		currMiners = tempCurrNodes
	}
	return currMiners
}

//满足条件的成员
func (w *evertrustWorker) removeActivityNotEnough(commitHeight uint64, currMiners qualification.ByQualificationIndex, prevConsensusQuorum *quorum.NodeAddress) qualification.ByQualificationIndex {
	//// remove ones that must be deferred qualification
	tempArray := make(qualification.ByQualificationIndex, 0)
	for _, nodeDetail := range currMiners {

		switch w.evertrust1.config.Hypothecation {

		case true:
			if nodeDetail.QualifiedAt <= commitHeight && nodeDetail.QualifiedAt != 0 && nodeDetail.CanBeMaster == 1 {
				tempArray = append(tempArray, nodeDetail)
			} else {
				if len(prevConsensusQuorum.Keys()) == 1 && prevConsensusQuorum.Keys()[0] == nodeDetail.Address.String() {
					//当共识节点俩列表里面只有自己的时候并不移除
					tempArray = append(tempArray, nodeDetail)
				}
			}
		default:
			//QualifiedAt 什么时候成为委员会
			if nodeDetail.QualifiedAt <= commitHeight && nodeDetail.QualifiedAt != 0 {
				tempArray = append(tempArray, nodeDetail)
			} else {
				if len(prevConsensusQuorum.Keys()) == 1 && prevConsensusQuorum.Keys()[0] == nodeDetail.Address.String() {
					//当共识节点俩列表里面只有自己的时候并不移除
					tempArray = append(tempArray, nodeDetail)
				}
			}
		}
	}
	return tempArray
}

//func (w *evertrustWorker) pickUpLegalNodeIntoConsensQuorum(commitHeight uint64, currMiners qualification.ByQualificationIndex, prevConsensusQuorum *quorum.NodeAddress, prevNodeSet *qualification.SafeNodeDetailSet) (qualification.ByQualificationIndex, error) {
//	// TODO pick the highest 5% of previous consensus quorum
//	// get previous consensus quorum
//	if commitHeight > 1 {
//		prevNodes := make(qualification.ByQualificationIndex, 0)
//		for _, addressHex := range prevConsensusQuorum.Keys() {
//			prevNode := prevNodeSet.Get(addressHex)
//			if prevNode == nil {
//				log.Warn("no this address nodeDetain on height:", "height", commitHeight-2)
//				continue
//			}
//			prevNodes = append(prevNodes, prevNode)
//		}
//
//		if len(prevNodes) != 1 {
//			//make shure sorted by qu
//			if !sort.IsSorted(prevNodes) {
//				sort.Sort(prevNodes)
//			}
//		}
//
//		//从currMiners当中挑选出再上一共识委员会的活跃纪录加进来
//		for _, nodeDet := range currMiners {
//			for _, prevNodeDet := range prevNodes {
//				if nodeDet.Address.String() == prevNodeDet.Address.String() {
//					if !contains(currMiners, nodeDet) {
//						currMiners = append(currMiners, nodeDet)
//					}
//				}
//			}
//		}
//	}
//	return currMiners, nil
//}

func (w *evertrustWorker) getMinerAdditions(prevConsensusQuorum *quorum.NodeAddress, currMiners qualification.ByQualificationIndex) []common.Address {
	// for each in new miner quorum, find additions from previous miner quorum
	var minerAdditions common.SortAddress
	for _, v := range currMiners {
		n := prevConsensusQuorum.Get(v.Address.Hex())

		if evertrust.Consortium || !w.evertrust1.config.Hypothecation {
			if n == [20]byte{} {
				minerAdditions = append(minerAdditions, v.Address)
			}
		} else {
			if n == [20]byte{} && v.CanBeMaster == qualification.CanBeMaster {
				minerAdditions = append(minerAdditions, v.Address)
			}
		}
	}
	sort.Sort(minerAdditions)
	return minerAdditions
}

func (w *evertrustWorker) getMinerDeletions(prevMiners []common.Address, currConsensusQuorum *quorum.NodeAddress, coinbase common.Address) []common.Address {
	minerDeletions := make([]common.Address, 0)
	for _, v := range prevMiners {
		n := currConsensusQuorum.Get(v.Hex())
		if n == [20]byte{} {
			minerDeletions = append(minerDeletions, v)
		}
	}

	currentCommitHeight := w.blockchain.CommitChain.CurrentBlock().NumberU64()
	if len(minerDeletions) == 0 {
		minerDeletions = nil
	}

	currentQuorum, ok := quorum.CommitHeightToConsensusQuorum.Get(currentCommitHeight, w.evertrust1.db)
	if !ok {
		return minerDeletions
	}
	currentQuorumCopy := currentQuorum.Copy()
	for _, del := range minerDeletions {
		currentQuorumCopy.Del(del.String())
	}
	if currentQuorumCopy.Len() == 0 {
		newMinerDeletions := make([]common.Address, 0)
		for _, add := range minerDeletions {
			if add != coinbase {
				newMinerDeletions = append(newMinerDeletions, add)
			}
		}
		return newMinerDeletions
	}
	return minerDeletions
}

//set up blockpath
func (w *evertrustWorker) setUpCommitBlockPath(validNewAssertions *utils.SafeSet, needNode int) types.CommitExtra {
	var commitExtra types.CommitExtra
	commitBlocksPath := blockPath(validNewAssertions, needNode)
	pathLen := len(commitBlocksPath)
	log.Info("commitBlocksPath信息", "commitBlocksPath长度", pathLen, "validNewAssertions长度", validNewAssertions.Len(), "收到的Assertions信息", validNewAssertions.Keys())
	switch {
	case int64(pathLen) == Cnfw.Int64():
		//计算出完整的AcceptedBlocks
		commitExtra.Reset = false
		commitExtra.AcceptedBlocks = commitBlocksPath //标准区块
	default:
		//计算的path不是完整的cfd
		commitExtra.Reset = true
		commitExtra.AcceptedBlocks = commitBlocksPath
	}
	return commitExtra
}

//commit收到的全部的assertion,和裂脑前的委员会比较
func (w *evertrustWorker) cmpAssertionsAndIslandQuorum(consensusQuorum *quorum.NodeAddress, validNewAssertions *utils.SafeSet, islandQuorum []string) bool {
	if len(islandQuorum) == 0 {
		return true
	}
	sum := 0
	for _, add := range islandQuorum {
		if _, ok := consensusQuorum.Hmap[add]; ok {
			sum++
		}
	}
	changeToLandNum := int(math.Ceil(float64(len(islandQuorum)) * 2 / 3))

	log.Info("cmpAssertionsAndIslandQuorum信息", "changeToLandNum", changeToLandNum, "sum", sum)
	if sum >= changeToLandNum {
		//如果收到的assertion到达了列脑前的3/2,就回复大陆状态
		return true
	}
	return false
}

//set up island info
func (w *evertrustWorker) setUpIslandInfo(blockExtra types.BlockExtra, needNode int, validNewAssertions *utils.SafeSet, validNewAssertionsInConsensusQuorum *utils.SafeSet, task *blockTask,
	consensusQuorum *quorum.NodeAddress, commitExtra types.CommitExtra, lastCommitExtra types.CommitExtra, land LocalLand) (types.BlockExtra, types.CommitExtra) {
	currentNum := task.CNumber.Uint64()
	log.Info("打commit的一些信息", "高度", currentNum+1, "共识委员会数量", int(consensusQuorum.Len()))
	//1.收到的assertion < needNode  2.分叉前委员会 >= 委员会

	log.Info("validNewAssertionsInConsensusQuorum", "validNewAssertionsInConsensusQuorum", validNewAssertionsInConsensusQuorum.Len(), "needNode", needNode)
	islandState := land.IslandState
	cNum := land.IslandCNum
	islandQuorum := land.IslandQuorum
	if validNewAssertionsInConsensusQuorum.Len() < needNode || !w.cmpAssertionsAndIslandQuorum(consensusQuorum, validNewAssertions, islandQuorum) {
		log.Info("分叉了", "高度", currentNum+1, "needNode", needNode, "当前Quorum", consensusQuorum.Len())

		if (!lastCommitExtra.Island && !islandState) || (islandState && cNum == 0) {
			//第一次
			log.Debug("打commit第一次分叉", "分叉前cnum", currentNum, "querum", consensusQuorum.Keys(), "rank", task.rank)
			commitExtra.Island = true
			blockExtra.IsLandID = w.evertrust1.signer.String()
			commitExtra.CNum = task.CNumber.Uint64()
			commitExtra.Quorum = consensusQuorum.Keys()
		} else {
			//以后
			blockExtra.IsLandID = land.IslandIDState
			commitExtra.Island = land.IslandState
			commitExtra.Quorum = land.IslandQuorum
			commitExtra.CNum = land.IslandCNum

			log.Debug("打commit以后", "岛屿id", blockExtra.IsLandID, "岛屿状态", commitExtra.Island,
				"cNum", commitExtra.CNum)
		}
		//如果分叉 就用自己的path
		commitBlocksPath := w.selfPath(validNewAssertions)
		log.Info("分叉后使用自己的path", "path", commitBlocksPath)
		commitExtra.AcceptedBlocks = commitBlocksPath
		commitExtra.Reset = false
	}
	return blockExtra, commitExtra
}

//set up evidence
func (w *evertrustWorker) setUpEvidence(allNewAssertions *utils.SafeSet, commitExtra types.CommitExtra) types.CommitExtra {
	//保存condensedEvidence信息
	var commitBlocksPath []common.Hash
	commitBlocksPath = commitExtra.AcceptedBlocks
	for _, key := range allNewAssertions.Keys() {
		val := allNewAssertions.Get(key)
		assertInfo := val.(*AssertInfo)
		condensedEvidence := types.CondensedEvidence{}
		condensedEvidence.SetPubkey(assertInfo.Pubkey)
		condensedEvidence.Signature = assertInfo.AssertExtra.Signature

		switch {
		case len(commitBlocksPath) == len(assertInfo.AssertExtra.BlockPath):
			condensedEvidence.ExtraKind = types.EVIDENCE_ADD_EXTRA
		case len(commitBlocksPath) < len(assertInfo.AssertExtra.BlockPath):
			condensedEvidence.ExtraKind = types.EVIDENCE_DEL_EXTRA
		case len(assertInfo.AssertExtra.BlockPath) == 0:
			//不在委员会中 可以不发送path
			condensedEvidence.ExtraKind = types.EVIDENCE_EMP_EXTRA
		}

		// 不是空 可以进入
		if condensedEvidence.ExtraKind != types.EVIDENCE_EMP_EXTRA {
			for i, blockHash := range assertInfo.AssertExtra.BlockPath {
				//sBlockHash 是选出来3/2标准的
				if i < len(commitBlocksPath) {
					sBlockHash := commitBlocksPath[i]
					if sBlockHash != blockHash {
						//得到跟标准blockPath不同的区块hash下标,并且把从这个区块开始后面所有的区块都保存起来
						//把每个节点BlockPath比共识的BlockPath多余的部分保存在condensedEvidence.ExtraBlocks中
						condensedEvidence.ExtraBlocks = assertInfo.AssertExtra.BlockPath[i:]
						break
					}
				} else {
					condensedEvidence.ExtraBlocks = assertInfo.AssertExtra.BlockPath[i:]
					break
				}
			}
		}

		//set up multi sign evidence
		condensedEvidence.ParentCommitHash = assertInfo.AssertExtra.ParentCommitHash
		//condensedEvidence保存在commitExtra.Evidences中
		commitExtra.Evidences = append(commitExtra.Evidences, condensedEvidence)
	}

	return commitExtra
}

func (w *evertrustWorker) getQuorumForHeight() (*quorum.NodeAddress, error) {
	commitBlockHeight := w.blockchain.CommitChain.CurrentBlock().NumberU64()
	if commitBlockHeight == 0 {
		commitBlockHeight = 1
	}
	//获取共识节点
	log.Info("打包commit的时候取委员会的高度是", "高度", commitBlockHeight)
	consensusQuorum, _ := quorum.CommitHeightToConsensusQuorum.Get(commitBlockHeight, w.evertrust1.db)
	if consensusQuorum == nil {
		log.Error("no consensus quorum, failed creating commit block")
		return nil, errors.New("no consensus quorum, failed creating commit block")
	}
	return consensusQuorum, nil
}

func (w *evertrustWorker) selfPath(allNewAssertions *utils.SafeSet) []common.Hash {
	for _, add := range allNewAssertions.KeysOrdered() {
		if add == w.evertrust1.signer.String() {
			value := allNewAssertions.Get(add)
			assertInfo := value.(*AssertInfo)
			return assertInfo.AssertExtra.BlockPath
		}
	}
	return nil
}

func blockPath(assertions *utils.SafeSet, nodesNeeded int) []common.Hash {
	// 每行 block path 放入matrix中，根据Addr进行排序
	matrix := list.New()
	for _, key := range assertions.KeysOrdered() {
		value := assertions.Get(key)
		assertInfo := value.(*AssertInfo)
		blockpath := assertInfo.AssertExtra.BlockPath
		if blockpath != nil && len(blockpath) > 0 {
			matrix.PushBack(blockpath)
		}
	}
	result := make([]common.Hash, 0)
	for i := 0; int64(i) < Cnfw.Int64(); i++ { // the block sequence in the interval
		counters := make(map[string]int, 0)

		// blockpath里第i列，对块hash进行投票，
		for row := matrix.Front(); row != nil; row = row.Next() {

			blockpath := row.Value.([]common.Hash)

			for j := 0; j < len(blockpath); j++ {
				if j == i {
					counters[blockpath[j].Hex()] += 1
					break
				}
			}
		}

		if len(counters) == 0 {
			break
		}

		var acceptedBlock string
		vote := 0

		// 某列的最大投票数
		for key, val := range counters {
			if val > vote {
				vote = val          //出现次数
				acceptedBlock = key //区块hash
			}
		}

		// 投票达到2/3多数，放入result中
		if vote >= nodesNeeded {

			result = append(result, common.HexToHash(acceptedBlock))

			//remove failed assertion paths
		loop:
			for row := matrix.Front(); row != nil; row = row.Next() {
				blockpath := row.Value.([]common.Hash)
				// 对于长度不够的，删除row
				if i >= len(blockpath) {
					row0 := row
					row = row.Next()
					if row == nil {
						break
					}
					matrix.Remove(row0)
					continue
				}

				// 如果某row的第i列不是acceptedBlock，就删除该row
				for j := 0; j < len(blockpath); j++ {
					if j == i {
						if strings.Compare(blockpath[j].Hex(), acceptedBlock) != 0 {
							row0 := row
							row = row.Next()
							if row == nil {
								break loop
							}
							matrix.Remove(row0)
							continue
						}
					}
				}
			}
		} else {
			log.Warn("出现测次数不大于3/2退出", "BlockPath长度", len(result))
			break
		}
	}
	return result
}

func (w *evertrustWorker) createAndBroadcastNormalBlock(task *blockTask) {

	server := w.evertrust1.stack.Server()
	nodeId := discover.PubkeyID(&server.PrivateKey.PublicKey)
	land, _ := LocalLandSetMap.LandMapGet(w.evertrust1.blockchain.CommitChain.CurrentBlock().NumberU64(), w.evertrust1.db)
	blockMiningReq := &types.BlockMiningReq{
		Kind:     types.NORNAML_BLOCK,
		Rank:     task.rank,
		Number:   task.CNumber.Uint64(), //当前块normal高度 借用了cNum字段
		NodeID:   nodeId,
		CNumber:  w.blockchain.CommitChain.CurrentBlock().Number(),
		IsLandID: land.IslandIDState, //岛屿ID 空是大陆
		Empty:    task.empty,
	}
	log.Info("当前区块的岛屿id", "blockMiningReq", blockMiningReq.IsLandID, "w.Evertrust.Running", atomic.LoadInt32(w.evertrust1.Running),
		"下一个normal高度", blockMiningReq.Number+1)

	if atomic.LoadInt32(w.evertrust1.Running) == 1 || task.CNumber.Int64() <= 1 { //打开挖矿
		w.evertrust1.MinerCh <- blockMiningReq
	}
}

//验证签名
func verifySignBlock(block *core_types.Block) bool {
	if evertrust.Perf {
		log.Trace("perf mode no verify normal block header")
		return true
	}

	header := block.Header()
	hash := header.HashNoSignature()

	address, _, err := evertrust.SigToAddress(hash.Bytes(), header.Signature)
	if err != nil {
		log.Error("verifySignBlock SigToAddress error", "err", err)
		return false
	}
	if address.Hex() != block.Coinbase().Hex() {
		log.Error("address incorrect", "addr", address, "coinBase", block.Coinbase())
		return false
	}
	return true
}

//从块头的签名中获得签名者（矿工地址）
func getMinerFromHeaderSig(header *core_types.Header) (common.Address, error) {
	if evertrust.Perf {
		log.Trace("perf mode no verify normal block header")
		return common.Address{}, errors.New("perf mode")
	}
	log.Info("get miner from header signature")

	addresses, _, err := evertrust.SigToAddress(header.HashNoSignature().Bytes(), header.Signature)
	if err != nil {
		log.Error("verifySignBlock SigToAddress error", "err", err)
		return common.Address{}, err
	}

	return addresses, nil
}

//verify rank
func (w *evertrustWorker) verifyBlockRank(block *core_types.Block, needVerifyedAddress common.Address, needVerifyedRank uint32, isCommit int64, batch int) bool {
	var currentBlock *core_types.Block
	var currentBlockNum uint64
	if isCommit == -1 {
		//计算 normal commit不需要normal高度
		currentBlockNum = block.NumberU64() - 1 //用上一个区间的normal验证rank
		currentBlock = w.blockchain.GetBlockByNumber(currentBlockNum)
		if currentBlock == nil {
			log.Info("verifyBlockRank没有取到currentBlock", "currentBlockNum", currentBlockNum)
			return false
		}
		log.Info("取到的normal高度", "当前高度", currentBlock.NumberU64())
	}

	master, _, err := w.getMasterOfNextBlock(isCommit, currentBlock, batch)
	if err != nil || master == nil {
		log.Info("verifyBlockRank_getMasterOfNextBlock错误", "master", master, "err", err)
		return false
	}

	for index, address := range master {
		if address == needVerifyedAddress && needVerifyedRank == uint32(index) {
			return true
		}
		log.Info("verifyBlockRank计算", "address", address, "Rank", index)
	}
	return false
}

//需要等待第一个commit block 处理完
func (w *evertrustWorker) firstCommit() {
	firstCommitCh := make(chan int, 1)
	for {
		if w.blockchain.CommitChain.CurrentBlock().NumberU64() >= 1 {
			firstCommitCh <- 0
		}
		select {
		case <-firstCommitCh:
			return
		case <-time.After(1 * time.Second):
			log.Error("no receive event")
			break
		}
	}
}

//验证rank
func (w *evertrustWorker) verifyBlock(block *core_types.Block, blockExtra types.BlockExtra, isCommit int64, sync bool) (isVerified bool) {
	isVerified = true
	if block.NumberU64() > 1 && sync { //同步的
		needVerifiedBlockAddress := block.Coinbase()
		needVerifiedRank := blockExtra.Rank
		batch := 0 //根据Rank计算master批次
		if needVerifiedRank >= uint32(NumMasters) {
			batch = int(needVerifiedRank / uint32(NumMasters))
			log.Debug("收到commitMaster批次", "批次", batch)
		}
		isVerified = w.verifyBlockRank(block, needVerifiedBlockAddress, needVerifiedRank, isCommit, batch)
		if !isVerified {
			log.Error("verifyBlockRank fail", "height", block.NumberU64(), "hash", block.Hash(), "add", block.Coinbase())
			return
		}
		log.Info("开始进行验证签名", "高度", block.NumberU64())
		// signature verification (此处签的是 block.Header,用的是seal中的sighash)
		isVerified = verifySignBlock(block)
		if !isVerified {
			log.Error("verifySignBlock fail", "height", block.NumberU64(), "hash", block.Hash(), "add", block.Coinbase())
			return
		}
	}
	return
}

func (w *evertrustWorker) processNormalBlock(block *core_types.Block, sync bool) error {
	defer func() {
		NormalDeRepetition.Del(block.NumberU64()) //删除normal缓存
	}()

	w.firstCommit()
	if block.NumberU64() != w.blockchain.CurrentBlock().NumberU64()+1 {
		log.Error("无效的Normal高度", "normal高度", block.NumberU64(), "当前高度", w.blockchain.CurrentBlock().NumberU64())
		return errors.New("无效的Normal高度")
	}

	blockExtra := types.BlockExtraDecode(block)

	log.Info("normalBlock processing", "height", block.NumberU64(), "hash", block.Hash().Hex(), "rank", blockExtra.Rank, "sync", sync)

	if !w.verifyBlock(block, blockExtra, -1, sync) {
		log.Error("normal sync verifyBlock fail")
		return errors.New("normal sync verifyBlock fail")
	}

	blocks := []*core_types.Block{block} //保存区块链需要这个参数
	log.Info("开始进行blockchain.InsertChain", "高度", block.NumberU64())
	_, err := w.blockchain.InsertChain(blocks) //区块上链
	if err != nil {
		log.Error("processNormalBlock--InsertChain error", "err", err.Error())
		return err
	}
	log.Info("normalBlock保存完毕", "num", block.NumberU64(), "rank", blockExtra.Rank, "hash", block.Hash().String())
	return nil
}

func (w *evertrustWorker) prepareNextBlock(currentBlock *core_types.Block, batch int) {
	if currentBlock.NumberU64() != w.blockchain.CurrentBlock().NumberU64() {
		log.Debug("无效的normal高度", "要处理的normal高度", currentBlock.NumberU64(), "当前高度", w.blockchain.CurrentBlock().NumberU64())
		return
	}
	//计算Normal的Rank
	_, rank, consensusQuorumLen, err := w.masterRank(currentBlock, w.evertrust1.signer, -1, batch)
	if err != nil {
		log.Error("get next block masterRank error", "error", err)
		return
	}
	log.Info("normal的rank", "next normal height", currentBlock.NumberU64()+1, "next rank", rank)
	// create & broadcast normal block when it's my turn
	if rank != observer_only { //rank大于0 说明是master
		ExamineBlock.RWLock.Lock()                            //add lock---
		delete(ExamineBlock.masterBatch, currentBlock.Hash()) //清除批次
		ExamineBlock.RWLock.Unlock()                          //unlock---
		w.createAndBoradcastNormalBlockWithTask(currentBlock.Number().Int64(), rank, currentBlock, false, batch)
	} else {
		//是ob也要打块去触发toProcess
		w.createAndBoradcastNormalBlockWithTask(currentBlock.Number().Int64(), uint32(consensusQuorumLen+int(NumMasters)-1), currentBlock, true, batch)
	}
}

func (w *evertrustWorker) ProcessCommitLogic(block *core_types.Block, batch int, march bool) (pick bool) {
	commitExtra := w.blockchain.CommitChain.CurrentCommitExtra()
	// create & multicast block assertion if on cfd boundary
	currBlockNum := commitExtra.NewBlockHeight.Uint64()
	diff := int64(block.Number().Uint64()) - int64(currBlockNum+Cnfw.Uint64())
	log.Info("diff", "normalHeight", block.Number().Uint64(), "boundary", currBlockNum+Cnfw.Uint64(), "diff", diff)
	//
	if diff == 0 || (diff >= Cnfw.Int64() && diff%Cnfw.Int64() == 0) || march { // Time for block assertion
		// task.CNumber is the current commit block height
		number := w.blockchain.CommitChain.CurrentBlock().Number()
		log.Info("当前commit高度是", "number", number, "batch", batch)
		// create block assertion and multicast it to all m masters of the next commit block
		masters, rank, consensusQuorumLen, err := w.masterRank(block, w.evertrust1.signer, number.Int64(), batch)
		if err != nil {
			log.Error("masterRank is error", "err", err)
		}

		task := &blockTask{CNumber: number, masters: masters, rank: rank, block: block, newHeight: currBlockNum}
		log.Info("commitRank", "commit高度", number.Uint64()+1, "rank", rank)

		w.createAndMulticastBlockAssertion(task)
		if rank != observer_only {
			// i am a master (with rank m-1 or better) or
			// just a consensus node eager to assume mastership
			w.createAndBroadcastCommitBlock(task)
			log.Info("commit边界 ----------->>>>>>>--------------", "normalHeight", block.Number().Uint64(), "Cfd", currBlockNum+Cnfw.Uint64())
		} else {
			log.Info("i am observer, done after createAndMulticastBlockAssertion.")
			w.emptyCommitBlock(task, number.Int64(), consensusQuorumLen, batch)
		}
		return false
	} else {
		log.Info("normal边界 ----------->>>>>>>--------------", "normalHeight", block.Number().Uint64(), "Cfd", currBlockNum+Cnfw.Uint64())
		return true
	}
}

func (w *evertrustWorker) emptyCommitBlock(task *blockTask, isCommit int64, consensusQuorumLen int, batch int) {
	//模拟asserted的时间
	if batch != 0 {
		return
	}
	timeout := time.NewTimer(time.Millisecond * time.Duration(BlockDelay))

	select {
	case <-timeout.C:
		//模拟BlockExtra
		var blockExtra types.BlockExtra
		blockExtra.Empty = true
		blockExtra.NodeID = discover.PubkeyID(&w.evertrust1.stack.Server().PrivateKey.PublicKey)

		blockExtra.Rank = uint32(consensusQuorumLen + int(NumMasters) - 1) //取委员会的最大值,如果委员会有一个,那这个无效的就是Rank1

		blockExtra.CNumber = big.NewInt(task.CNumber.Int64() + 1)

		currentBlockHash := w.blockchain.CommitChain.CurrentBlock().Hash()

		commitBlock, err := types.NewCommitblock(&blockExtra, currentBlockHash, w.evertrust1.signer, w.evertrust1.signFn)
		if err != nil {
			return
		}

		w.evertrust1.OnCommitBlock(commitBlock)
	}
}

func (w *evertrustWorker) commitLoop() {
	for {
		select {
		case block := <-w.commitCh:
			log.Info("检查通道长度", "len", len(w.commitCh))
			if atomic.LoadInt32(w.evertrust1.Syncing) == 0 {
				pick := w.ProcessCommitLogic(block, 0, false)
				if pick {
					w.prepareNextBlock(block, 0)
				}
				log.Info("commitLoop结束", "normal高度", block.NumberU64())
			}
		case block := <-w.evertrust1.ReorgChainCh:
			log.Info("ReorgChain后继续打块", "normal高度", block.NumberU64())
			w.prepareNextBlock(block, 0)
		case block := <-w.syncJoinCH:
			//判断是否没有收到其他节点发来的块,只能自己打快
			if block.NumberU64() < w.blockchain.CurrentBlock().NumberU64() || w.blockchain.CurrentBlock().NumberU64() == 0 {
				log.Warn("无效的高度")
				break
			}
			//修改岛屿状态
			w.SetLandState()
			go w.selfWork() //自己打快
		case examineBlock := <-w.examineBlockCh:
			//没有收到区块,启动下一批master打快
			currentNormalNum := w.blockchain.CurrentBlock().NumberU64()
			currentCommitNum := w.blockchain.CommitChain.CurrentBlock().NumberU64()

			if currentCommitNum == 0 && currentNormalNum == 0 {
				currentNormalBlock := w.blockchain.CurrentBlock()
				ExamineBlock.RWLock.Lock() //add lock---
				ExamineBlock.masterBatch[currentNormalBlock.Hash()] = 0
				ExamineBlock.RWLock.Unlock() //unlock---
			} else {
				ExamineBlock.RWLock.RLock()                                  //add rlock---
				batch := examineBlock.masterBatch[examineBlock.block.Hash()] //批次
				ExamineBlock.RWLock.RUnlock()                                //RUnlock---
				pick := w.ProcessCommitLogic(examineBlock.block, batch, false)
				if pick {
					w.prepareNextBlock(examineBlock.block, batch)
				}
			}
		}
	}
}

func (w *evertrustWorker) VerifyCommitBlock(block *core_types.Block, land LocalLand, sync bool) error {
	if evertrust.Perf {
		log.Trace("perf mode don't verify commit block")
		return nil
	}

	blockExtra, commitExtra := types.CommitExtraDecode(block)
	newCommitHeight := block.NumberU64()

	if !w.verifyBlock(block, blockExtra, int64(newCommitHeight-1), sync) {
		log.Error("commit sync verifyBlock fail")
		return errors.New("commit sync verifyBlock fail")
	}

	// 对收到的commitBlock.blockExtra进行的验签
	err := verifySignBlockExtra(blockExtra, block.Coinbase())
	if err != nil {
		log.Error("verifySignCommitBlockExtra error", "err", err)
		return err
	}

	log.Info("verify commit block", "height", newCommitHeight)
	err = w.verifyCommitEvidence(newCommitHeight, commitExtra, land, sync)
	if err != nil {
		log.Error("verifyCommitEvidence error", "err", err)
		return err
	}

	return nil
}

func (w *evertrustWorker) ProcessCommitBlock(block *core_types.Block, sync bool) error {
	log.Info("ProcessCommitBlock lock")
	if !sync {
		w.CommitRw.Lock()
	}
	defer func() {
		CommitDeRepetition.Del(block.NumberU64())           //commit删除缓存
		AssociatedCommitDeRepetition.Del(block.NumberU64()) //commit删除缓存
		if !sync {
			log.Info("ProcessCommitBlock unlock")
			w.CommitRw.Unlock() //和同步删除数据互斥
		}
	}()
	newCommitHeight := block.NumberU64()
	currentNum := w.blockchain.CommitChain.CurrentBlock().NumberU64()
	switch {
	case block.NumberU64() > currentNum+1:
		log.Debug("commit高度无效,什么都不做", "num", block.NumberU64(), "current", currentNum+1)
		return errors.New("commit高度无效,什么都不做")
	case block.NumberU64() < currentNum+1:
		log.Debug("commit高度太小")
		return CommitHeightToLow
	default:
	}
	//获取岛屿信息
	blockExtra, commitExtra := types.CommitExtraDecode(block)
	land, version := w.ContractQuery(commitExtra)
	if commitExtra.Version != version {
		log.Error("commit版本号不一致", "commitExtra.Version", commitExtra.Version, "version", version)
		return errors.New("commit版本号不一致")
	}

	log.Info("commitBlock processing", "height", newCommitHeight, "hash", block.Hash().Hex(), "Rank", blockExtra.Rank, "打快地址", block.Coinbase(), "sync", sync)
	currentCommitBlock := w.blockchain.CommitChain.CurrentBlock()

	// 对收到的commitBlock.blockExtra进行的验签
	err := w.VerifyCommitBlock(block, land, sync)
	if err != nil {
		return fmt.Errorf("verify commit block:%v", err)
	}

	log.Debug("BlockPath verify succeed")

	err = w.blockchain.InsertCommitBlock(block)
	if err != nil {
		log.Error("commit保存错误", "err", err.Error())
		return err
	}
	//计算活跃度
	nodeDetails, err := w.calculateStatusAndQualification(newCommitHeight, &commitExtra, block.Coinbase())
	if err != nil {
		log.Error("calculateStatusAndQualification fail rollBackCommit", "height", block.NumberU64(), "err", err)
		w.RollBackCommit(block)
	}

	//处理多签
	log.Debug("handle multiSign")
	err = handleMultiSign(block, nodeDetails, newCommitHeight)
	if err != nil {
		log.Error("handle multiSign", "err", err)
	}

	log.Info("查看数据", "高度是", newCommitHeight)

	//更新本地活跃度
	if nodeDetails, err = w.verifyMiner(nodeDetails, block.NumberU64(), commitExtra, block.Coinbase()); err != nil {
		log.Error("verifyMiner fail rollBackCommit", "height", block.NumberU64(), "err", err)
		w.RollBackCommit(block)
		return err
	}

	if block.NumberU64() == 1 && w.evertrust1.config.Hypothecation == true {
		for _, addr := range commitExtra.MinerAdditions {
			nodeDetail := nodeDetails.Get(addr.String())
			if nodeDetail != nil {
				qualification.CommitHeight2NodeDetailSetCache.Lock.Lock()
				nodeDetail.CanBeMaster = qualification.CanBeMaster
				qualification.CommitHeight2NodeDetailSetCache.Lock.Unlock()
				nodeDetails.Add(addr.String(), nodeDetail)
			}
		}
	}

	qualifi, err := nodeDetails.DecodeToString()
	if err != nil {
		log.Error("nodeDetails DecodeToString fail", "err", err)
		w.RollBackCommit(block)
		return err
	}

	for address, value := range nodeDetails.NodeMap {
		log.Info("查看一下活跃度信息", "地址", address, "活跃度", value.CanBeMaster, "value.NumAssertionsTotal", value.NumAssertionsTotal, "value.QualifiedAt", value.QualifiedAt, "value.NumBlocksAccepted", value.NumBlocksAccepted, "UselessAssertions", value.UselessAssertions, "reason", value.DisqualifiedReason)
	}

	log.Info("活跃度的比较", "本地", qualifi, "commit块中", commitExtra.QualificationHash)
	if qualifi != "" && newCommitHeight > 1 && qualifi != commitExtra.QualificationHash {
		log.Error("verifyQualification fail")
		w.RollBackCommit(block)
		return errors.New("verifyQualification fail")
	}

	log.Info("保存的nodeDetail高度是", "height", newCommitHeight)
	qualification.CommitHeight2NodeDetailSetCache.Set(newCommitHeight, nodeDetails, w.evertrust1.db)

	log.Info("查看数据deletion1", "长度", len(commitExtra.MinerDeletions))
	if Majority == Twothirds {
		//判断是否是分叉
		w.forkCommit(blockExtra, commitExtra, block, currentCommitBlock, land)
	}
	log.Info("查看数据deletion2", "长度", len(commitExtra.MinerDeletions))

	//跟新assertion数量
	cacheBlock.CommitAssertionSum.SetAssertionSum(commitExtra.AssertionSum, block.Number(), w.evertrust1.db)

	err = w.upDateQuorum(block, newCommitHeight, commitExtra, sync)
	if err != nil {
		log.Error("upDateQuorum fail RollBackCommit", "height", block.NumberU64(), "err", err)
		w.RollBackCommit(block)
		return err
	}

	log.Debug("BlockPath长度", "AcceptedBlocks", len(commitExtra.AcceptedBlocks))

	//保存assertion的累计总数
	w.evertrust1.CommitFetcher.InsertCh <- struct{}{}

	//更新下一次的委员会更新
	if !UpdateQuorumsHeight(block, w.evertrust1.db) {
		w.RollBackCommit(block)
		return errors.New("UpdateQuorumsHeight fail")
	}
	log.Info("保存CommitBlock完成", "number", block.NumberU64(), "hash", block.Hash().String())

	if newCommitHeight != 0 {
		//清除活跃度缓存
		qualification.CommitHeight2NodeDetailSetCache.CleanUpNodeDetail(newCommitHeight - 100)
		//清除委员会缓存
		quorum.CommitHeightToConsensusQuorum.CleanUpConsensusQuorum(newCommitHeight - 100)
		//清除岛屿信息缓存
		LocalLandSetMap.LandMapClean(newCommitHeight - 100)
	}

	//prevent not to send assertion, so that not del multiSign
	MultiSign.DelMultiSign()

	if !sync {
		//非同步情况下,保存完区块,准备perconnect
		w.preConnectCh <- int64(block.NumberU64())
		w.examineCh <- block
		//通知继续打块 用newHeight触发打下一个normal,避免重复打块
		nBlock := w.blockchain.GetBlockByNumber(commitExtra.NewBlockHeight.Uint64())
		if block.NumberU64() > 1 && nBlock != nil {
			w.commitCh <- nBlock
		}

		//send commit block to iaas
		w.sendToIaas(block)

		//send trust tx after n commit block
		err = w.commitSendTx(block)
		if err != nil {
			return err
		}
	}

	return nil
}

func handleMultiSign(block *core_types.Block, nodeDetails *qualification.SafeNodeDetailSet, commitHeight uint64) error {
	header := block.Header()
	multiSignNormalBytes := header.MultiSignNormal
	multiSignCommitBytes := header.MultiSignCommit

	if len(multiSignNormalBytes) == 0 && len(multiSignCommitBytes) == 0 {
		return nil
	}

	var multiSignNormal [][]core_types.Header
	err := rlp.DecodeBytes(multiSignNormalBytes, &multiSignNormal)
	if err != nil {
		log.Error("rlp decode multiSignNormalBytes", "err", err)
	}

	for _, headers := range multiSignNormal {
		if len(headers) >= 2 {
			h1 := headers[0]
			miner1, err := getMinerFromHeaderSig(&h1)
			if err != nil {
				log.Error("get miner1", "err", err, "num", h1.Number.String(), "miner", h1.Coinbase.String())
				continue
			}

			h2 := headers[1]
			miner2, err := getMinerFromHeaderSig(&h2)
			if err != nil {
				log.Error("get miner2", "err", err, "num", h1.Number.String(), "miner", h1.Coinbase.String())
				continue
			}

			var blockExtra1 types.BlockExtra
			blockExtra1.Decode(h1.Extra)

			var blockExtra2 types.BlockExtra
			blockExtra2.Decode(h2.Extra)

			log.Info("h1", "num", h1.Number.String(), "miner", miner1.String(), "rank", blockExtra1.Rank, "hash", h1.Hash().String())
			log.Info("h2", "num", h2.Number.String(), "miner", miner2.String(), "rank", blockExtra2.Rank, "hash", h2.Hash().String())
			//是否是双签的块（两个块的块号，打块的地址，rank都一样，但是块hash不一样）
			if (h1.Number.Cmp(h2.Number) == 0 && miner1 == miner2 && blockExtra1.Rank == blockExtra2.Rank) &&
				(h1.Hash() != h2.Hash()) {
				//更改多签节点的活跃度
				multiSignNodeDetail := nodeDetails.Get(miner1.Hex())
				qualification.CleanUpNodeDetailInfo(multiSignNodeDetail, commitHeight, qualification.MultSign+qualification.ShouldStacking).CanBeMaster = qualification.ShouldBePunished
				nodeDetails.Add(multiSignNodeDetail.Address.Hex(), multiSignNodeDetail)
				log.Info("clean up node", "addr", multiSignNodeDetail.Address.String(),
					"cB", multiSignNodeDetail.CanBeMaster,
					"dAt", multiSignNodeDetail.DisqualifiedAt,
					"nAT", multiSignNodeDetail.NumAssertionsTotal)
			}
		}
	}

	var multiSignCommit [][][]byte
	err = rlp.DecodeBytes(multiSignCommitBytes, &multiSignCommit)
	if err != nil {
		log.Error("decode multiSignCommitBytes", "err", err)
	}
	for _, extrals := range multiSignCommit {
		if len(extrals) >= 2 {
			e1 := extrals[0]
			var blockExtra1 types.BlockExtra
			err = blockExtra1.Decode(e1)
			if err != nil {
				log.Error("decode blockExtra", "err", err)
				continue
			}

			miner1, err := getMinerFromCommitHeaderSig(blockExtra1)
			if err != nil {
				log.Error("get commit miner1", "err", err, "num", blockExtra1.CNumber, "miner", miner1)
				continue
			}

			e2 := extrals[1]
			var blockExtra2 types.BlockExtra
			err = blockExtra2.Decode(e2)
			if err != nil {
				log.Error("decode blockExtra2", "err", err)
				continue
			}

			miner2, err := getMinerFromCommitHeaderSig(blockExtra2)
			if err != nil {
				log.Error("get commit miner2", "err", err, "num", blockExtra1, "miner", miner2)
				continue
			}

			log.Info("commit h1", "num", blockExtra1.CNumber, "miner", miner1.String(), "rank", blockExtra1.Rank)
			log.Info("commit h2", "num", blockExtra2.CNumber, "miner", miner2.String(), "rank", blockExtra2.Rank)
			//是否是双签的块（两个块的块号，打块的地址，rank都一样，但是块hash不一样）
			if blockExtra1.CNumber.Cmp(blockExtra2.CNumber) == 0 && miner1 == miner2 && blockExtra1.Rank == blockExtra2.Rank {
				//更改多签节点的活跃度
				multiSignCommitNodeDetail := nodeDetails.Get(miner1.Hex())
				qualification.CleanUpNodeDetailInfo(multiSignCommitNodeDetail, commitHeight, qualification.MultSign+qualification.ShouldStacking).CanBeMaster = qualification.ShouldBePunished
				nodeDetails.Add(multiSignCommitNodeDetail.Address.Hex(), multiSignCommitNodeDetail)
				log.Info("clean up node detail info", "addr", multiSignCommitNodeDetail.Address.String(), "canBeMaster", multiSignCommitNodeDetail.CanBeMaster, "disqualifiedAt", multiSignCommitNodeDetail.DisqualifiedAt, "numAssertionsTotal", multiSignCommitNodeDetail.NumAssertionsTotal)
			}
		}
	}
	return nil
}

func (w *evertrustWorker) updatePunishedList(minerDeletions []common.Address, commitHeight uint64, nodeDetails *qualification.SafeNodeDetailSet) {
	//将要惩罚的人放入名单当中
	for _, addr := range minerDeletions {
		nodeDetail := nodeDetails.Get(addr.Hex())
		if nodeDetail != nil {
			punishList := nodeDetail.PunishedHeight
			if punishList == 0 {
				nodeDetail := nodeDetails.Get(addr.String())
				log.Info("updatePunishedList--", "原因", nodeDetail.DisqualifiedReason)
				nodeDetail.PunishedHeight = commitHeight
			} else {
				continue
			}
		}
	}
}

func (w *evertrustWorker) doPunish(commitHeight uint64, nodeDetails *qualification.SafeNodeDetailSet) *qualification.SafeNodeDetailSet {
	for _, nodeDet := range nodeDetails.NodeMap {
		if nodeDet.PunishedHeight != 0 && nodeDet.PunishedHeight == commitHeight {
			//符合惩罚要求
			log.Info("需要被惩罚的地址是", "address", nodeDet.Address, "惩罚高度", nodeDet.PunishedHeight)
			if nodeDet.DisqualifiedReason == qualification.ExceptStorage+qualification.ShouldNotStacking {
				continue
			}
			nodeDet.CanBeMaster = qualification.ShouldBePunished
		}
	}

	return nodeDetails
}

func (w *evertrustWorker) updateCanBeMasterFlag(height uint64, address string, canBeMaster uint64) {
	nodeDetails, ok := qualification.CommitHeight2NodeDetailSetCache.Get(height, w.evertrust1.db)
	if !ok {
		log.Error("这个高度下没有活跃度记录")
	}
	nodeDetail := nodeDetails.Get(address)
	if nodeDetail == nil {
		nodeDetail = &qualification.NodeDetail{Address: common.HexToAddress(address), CanBeMaster: canBeMaster}
	} else {
		nodeDetail.CanBeMaster = canBeMaster
	}

	if canBeMaster == 0 {
		log.Info("updateCanBeMasterFlag--清理的nodeDetail", "高度", height, "reason", nodeDetail.DisqualifiedReason)
		nodeDetail = qualification.CleanUpNodeDetailInfo(nodeDetail, height, qualification.ExitOnHisOwn+qualification.ShouldStacking)
	}

	nodeDetails.Add(address, nodeDetail)

	log.Info("updateCanBeMasterFlag---保存nodeDetail", "高度", height)
	qualification.CommitHeight2NodeDetailSetCache.Set(height, nodeDetails, w.evertrust1.db)

	if canBeMaster == 0 {
		log.Info("共识委员会清理了", "清理的高度是", height)
		quorumMap, _ := quorum.CommitHeightToConsensusQuorum.Get(height, w.evertrust1.db)
		quorumMap.Del(address)
		quorum.CommitHeightToConsensusQuorum.Set(height, quorumMap, w.evertrust1.db)
	}
}

func (w *evertrustWorker) RollBackCommit(commitBlock *core_types.Block) {
	CommitDeRepetition.Del(commitBlock.NumberU64())           //commit删除缓存
	AssociatedCommitDeRepetition.Del(commitBlock.NumberU64()) //commit删除缓存
	core.DeleteCommitBlock(w.evertrust1.db, commitBlock.Hash(), commitBlock.NumberU64(), *w.blockchain.CommitChain)
	CommitBlockQueued.DelToProcessCommitBlockQueueMap(commitBlock.NumberU64())     //删除toProcessCommit缓存
	quorum.CommitHeightToConsensusQuorum.Del(commitBlock.NumberU64(), w.evertrust1.db) //清除委员会
	qualification.CommitHeight2NodeDetailSetCache.Del(commitBlock.NumberU64(), w.evertrust1.db)
	parentCommit := w.blockchain.CommitChain.GetBlockByNum(commitBlock.NumberU64() - 1)
	core.SetCurrentCommitBlock(w.blockchain.CommitChain, parentCommit)
	MultiSign.DelMultiSign()                                                         //清除多签
	LocalLandSetMap.LandMapDel(commitBlock.NumberU64(), w.evertrust1.db)                 //清除本区块的岛屿信息
	cacheBlock.CommitAssertionSum.DelAssertionSum(commitBlock.Number(), w.evertrust1.db) //清除assertion信息
}

func (w *evertrustWorker) verifyMiner(nodeDetails *qualification.SafeNodeDetailSet, commitBlockNum uint64, commitExtra types.CommitExtra, coinbase common.Address) (*qualification.SafeNodeDetailSet, error) {
	var localCommitExtra types.CommitExtra

	path := commitExtra.AcceptedBlocks
	//本地计算新增委员会成员
	localCommitExtra.MinerAdditions, localCommitExtra.MinerDeletions,
		localCommitExtra.NodeAdditions, localCommitExtra.NodeDeletions, nodeDetails = w.calculateMembershipUpdates(nodeDetails, commitExtra, commitBlockNum, path, coinbase)
	//岛屿情况不验证additions和Deletions
	if nodeDetails == nil && commitBlockNum > 1 {
		return nil, errors.New("verifyMiner验证失败")
	}
	if !commitExtra.Island && commitBlockNum > 1 {
		//拼接addition和deletion然后比较
		var localMiner common.SortAddress
		var commitMiner common.SortAddress
		localMiner = append(localMiner, localCommitExtra.MinerAdditions...)
		localMiner = append(localMiner, localCommitExtra.MinerDeletions...)
		commitMiner = append(commitMiner, commitExtra.MinerAdditions...)
		commitMiner = append(commitMiner, commitExtra.MinerDeletions...)
		sort.Sort(localMiner)
		sort.Sort(commitMiner)
		if len(localCommitExtra.MinerAdditions) != len(commitExtra.MinerAdditions) {
			return nodeDetails, errors.New("MinerAddition length unequal")
		}
		commitByte, err := rlp.EncodeToBytes(commitMiner)
		if err != nil {
			return nodeDetails, errors.New("rlp.EncodeToBytes fail")
		}
		commitHash := crypto.Keccak256(commitByte)
		localByte, err := rlp.EncodeToBytes(localMiner)
		if err != nil {
			return nodeDetails, errors.New("rlp.EncodeToBytes fail")
		}
		localHash := crypto.Keccak256(localByte)

		if hex.EncodeToString(commitHash) != hex.EncodeToString(localHash) {
			//不相同 出问题
			log.Error("verifyMiner unlike")
			return nodeDetails, errors.New("verifyMiner unlike")
		}
	}
	return nodeDetails, nil
}

func (w *evertrustWorker) verifyCommitEvidence(newCommitHeight uint64, commitExtra types.CommitExtra, land LocalLand, sync bool) error {
	if newCommitHeight > 1 {
		currentQuorum, ok := quorum.CommitHeightToConsensusQuorum.Get(newCommitHeight-1, w.evertrust1.db)
		if !ok && !sync {
			return errors.New("no quorum existed on commit block height")
		}
		log.Info("verifyCommitEvidence取出委员会成员", "高度", newCommitHeight-1, "len", currentQuorum.Len())
		needNodes := 0
		if !sync {
			//模拟删除委员会成员
			testCommitQuorum := currentQuorum.Copy()
			for _, del := range commitExtra.MinerDeletions {
				testCommitQuorum.Del(del.String())
			}

			//增加一个commit块中assertion数量的判断,收到的assertion数量要大于委员会中2/3的数量
			needNodes = int(math.Ceil(float64(currentQuorum.Len()) * 2 / 3))

			if needNodes == 0 {
				needNodes = 1
			}
		}
		log.Info("验证BlockPath", "needNodes", needNodes, "commitExtra.Evidences长度", len(commitExtra.Evidences))
		assertions := utils.NewSafeSet()
		commitQuorumNum := 0 //纪录commit中参与共识的节点数量,节点数量要大于本地委员会的2/3
		acceptedBlocksLen := len(commitExtra.AcceptedBlocks)
		acceptedBlocks := commitExtra.AcceptedBlocks
		for _, condensedEvidence := range commitExtra.Evidences {
			total := make([]common.Hash, 0)
			ExtraBlocksLen := len(condensedEvidence.ExtraBlocks)
			switch {
			case condensedEvidence.ExtraKind == types.EVIDENCE_ADD_EXTRA && ExtraBlocksLen != 0:
				//恢复每个节点的path
				//total = append(acceptedBlocks[:acceptedBlocksLen-ExtraBlocksLen],condensedEvidence.ExtraBlocks...)
				total = append(total, acceptedBlocks[:acceptedBlocksLen-ExtraBlocksLen]...)
				total = append(total, condensedEvidence.ExtraBlocks...)
				//log.Debug("ADD出现了path不一致的问题", "恢复的path", total)
			case condensedEvidence.ExtraKind == types.EVIDENCE_DEL_EXTRA:
				//多余的区块Hash+标准的BlockPath
				total = append(total, acceptedBlocks...)
				total = append(total, condensedEvidence.ExtraBlocks...)
				//log.Debug("DEL出现了path不一致的问题", "恢复的path", total)
			case ExtraBlocksLen == 0 && condensedEvidence.ExtraKind != types.EVIDENCE_EMP_EXTRA:
				//path完全一致
				total = append(total, acceptedBlocks...)
			//log.Debug("没有出现path不一致的问题", "恢复的path", total)
			default:
				//log.Info("非委员会成员,不需要添加", "add", condensedEvidence.Address())
			}
			var assertExtra types.AssertExtra
			assertExtra.BlockPath = total
			total = append(total, condensedEvidence.ParentCommitHash)
			//验证每一个节点的签名
			add := condensedEvidence.Address()
			if !evertrust.Perf {
				var err error
				add, _, err = VerifySignAssertBlock(total, condensedEvidence.Signature)
				if err != nil {
					return errors.New("commit VerifySignAssertBlock sing error")
				}
			} else {
				log.Trace("no verify block path sign in assert block")
			}
			//验证assertion的父hash
			if !sync && condensedEvidence.ParentCommitHash != w.blockchain.CommitChain.CurrentBlock().Hash() {
				log.Error("commit ParentCommitHash error", "condensedEvidence.ParentCommitHash", condensedEvidence.ParentCommitHash,
					"w.blockchain.CommitChain.CurrentBlock().Hash()", w.blockchain.CommitChain.CurrentBlock().Hash(), "add", condensedEvidence.Address())

				return errors.New("commit ParentCommitHash error")
			}

			cacheBlock.AddrAndPubkeyMap.AddrAndPubkeySet(add, condensedEvidence.Pubkey())

			if currentQuorum.Contains(add) {
				commitQuorumNum++
			}

			assertions.Add(add.String(), &AssertInfo{AssertExtra: &assertExtra})

		}
		localSum, err := cacheBlock.CommitAssertionSum.GetAssertionSum(big.NewInt(int64(newCommitHeight)-1), w.evertrust1.db)
		if err != nil {
			return errors.New("GetAssertionSum fail")
		}
		log.Info("check assertion的数量", "commit高度", newCommitHeight, "assertion总数", commitExtra.AssertionSum, "localSum", localSum, "符合要求的委员会成员", commitQuorumNum)
		if commitExtra.AssertionSum.Cmp(localSum.Add(localSum, big.NewInt(int64(commitQuorumNum)))) != 0 {
			log.Error("commitExtra.AssertionSum verify fail", "AssertionSum", commitExtra.AssertionSum, "localSum", localSum)
			return errors.New("commitExtra.AssertionSum verify fail")
		}

		if Majority == Twothirds && !sync {

			switch {
			case needNodes > commitQuorumNum && commitExtra.Island:
				//岛屿,标识也是岛屿 正常

			case needNodes > commitQuorumNum && !commitExtra.Island:
				//岛屿,标识是大陆 不正常 退出
				log.Error("这个commit无效,标识大陆,不正确", "needNodes", needNodes, "commitQuorumNum", commitQuorumNum, "岛屿标识", commitExtra.Island)
				return errors.New("commit中的节点数量小于本地委员会的数量,这个commit无效")

			case needNodes <= commitQuorumNum && commitExtra.Island:
				//大陆,标识是岛屿 不正常 退出
				if w.cmpAssertionsAndIslandQuorum(currentQuorum, assertions, land.IslandQuorum) && needNodes != 1 {
					log.Error("这个commit无效,标识岛屿,不正确!!!!!!", "needNodes", needNodes, "commitQuorumNum", commitQuorumNum, "岛屿标识", commitExtra.Island)
					//return errors.New("commit中的节点数量小于本地委员会的数量,这个commit无效")
				}

			case needNodes <= commitQuorumNum && !commitExtra.Island:
				//大陆,标识是大陆 正常

			}

		}

		if !commitExtra.Island && !sync {

			assertionsQuorum := assertions.CopyInConsensusQuorum(currentQuorum.Hmap)
			//选择在委员会中的assertion
			//如果是大陆,验证path,岛屿不用验证
			blockPath := blockPath(assertionsQuorum, needNodes)
			log.Info("BlockPathLen", "len(blockPath)", len(blockPath), "len(commitExtra.AcceptedBlocks)", len(commitExtra.AcceptedBlocks), "assertionsQuorum长度", assertionsQuorum.Len())
			if len(blockPath) != len(commitExtra.AcceptedBlocks) {
				return errors.New("blockPath Verify len error")
			}
			//对比blockPath和commitExtra.AcceptedBlocks是否相等
			for index, nblockHahs := range blockPath {
				if nblockHahs != commitExtra.AcceptedBlocks[index] {
					return errors.New("blockPath Verify AcceptedBlocks error")
				}
			}
		}
	}
	return nil
}

func (w *evertrustWorker) upDateQuorum(block *core_types.Block, newCommitHeight uint64, commitExtra types.CommitExtra, sync bool) error {
	var preSectionHeight uint64
	//取没存之前的commit的newheight
	if w.blockchain.CommitChain.CurrentBlock().NumberU64() != 0 {
		preSectionHeight = w.blockchain.CommitChain.CurrentCommitExtra().NewBlockHeight.Uint64()
	}
	if !UpdateConsensusQuorum(w, &commitExtra, block) {
		log.Error("UpdateConsensusQuorum fail RollBackCommit", "height", block.NumberU64())
		return errors.New("UpdateConsensusQuorum fail RollBackCommit")
	}

	err := core.SetCurrentCommitBlock(w.blockchain.CommitChain, block)
	if err != nil {
		log.Error("SetCurrentCommitBlock错误", "err", err)
		return err
	}
	core.UpdateHeightMap(commitExtra.NewBlockHeight.Uint64(), block.NumberU64(), w.blockchain.CommitChain)

	//避免无限rollback
	log.Info("回滚信息", "当前链上Normal高度", w.blockchain.CurrentBlock().NumberU64(), "commitNewHeight+CFD", commitExtra.NewBlockHeight.Uint64()+Cnfw.Uint64())
	//if !sync && (w.blockchain.CurrentBlock().NumberU64() < commitExtra.NewBlockHeight.Uint64()+Cnfw.Uint64() ||
	//	(!sync && block.Coinbase().String() == w.Evertrust.signer.String())) {
	if !sync {
		forkingFlag, rollbackHeight, newHeight, err := w.blockchain.ReorgChain(commitExtra.AcceptedBlocks, commitExtra.Reset, preSectionHeight, w.evertrust1.Syncing)
		if forkingFlag {
			for i := rollbackHeight + 1; i < newHeight; i++ {
				NormalBlockQueued.DelToProcessNormalBlockQueueMap(i) //删除toProcessNormal缓存
			}
		}
		if err != nil {
			log.Error("commit回滚Normal失败", "commit高度", block.NumberU64())
			return err
		}
	}

	return nil
}

//存储黑名单
func (w *evertrustWorker) sendToIaas(block *core_types.Block) {
	//send commit block to iaas
	iaasServer := evertrust.Config.String("iaas")
	log.Trace("send commit block to iaas", "iaas", iaasServer)
	if iaasServer != "" && block.Coinbase() == w.evertrust1.signer {
		ks := w.evertrust1.AccountManager.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
		privK := ks.GetUnlocked(w.evertrust1.signer).PrivateKey
		go iaasconn.SendToIaas(block, privK)
	}
}

//send trust tx after n commit block
func (w *evertrustWorker) commitSendTx(block *core_types.Block) error {
	iaasServer := evertrust.Config.String("iaas")
	if iaasServer == "" {
		return nil
	}

	sub := new(big.Int).Sub(block.Number(), big.NewInt(evertrust.TrustTxCommitBlockLimit))
	if sub.Cmp(big.NewInt(0)) == +1 && block.Coinbase() == w.evertrust1.signer {
		//信任链信息
		land, _ := LocalLandSetMap.LandMapGet(block.NumberU64(), w.evertrust1.db)

		id := land.IslandIDState
		status := land.IslandState
		if status && id != w.evertrust1.signer.String() {
			return nil
		}
		go w.sendTxData(sub)
	}
	return nil
}

func (w *evertrustWorker) forkCommit(blockExtra types.BlockExtra, commitExtra types.CommitExtra, commitBlock *core_types.Block,
	lastCommitBlock *core_types.Block, land LocalLand) {
	//判断保存的块是岛屿,改变自己的状态
	if commitExtra.Island == true {
		log.Error("保存的是岛屿块", "高度", commitBlock.NumberU64())
		//判断是不是第一次变岛屿
		lastBlockNum := lastCommitBlock.NumberU64()
		db := w.evertrust1.db
		_, lastCommitExtra := types.CommitExtraDecode(lastCommitBlock)
		state := land.IslandState
		cNum := land.IslandCNum
		if (!lastCommitExtra.Island && !state) || (state && cNum == 0) {
			//取上一个commit高度
			log.Info("第一次分叉", "高度", commitBlock.NumberU64(), "last高度", lastCommitBlock.NumberU64())
			consensusQuorum, ok := quorum.CommitHeightToConsensusQuorum.Get(lastBlockNum, w.evertrust1.db)
			//第一次保存数据库
			quorum := make([]string, 0)
			if ok {
				quorum = consensusQuorum.Keys()
			}
			log.Info("第一次保存数据库", "consensusQuorum.Keys()", consensusQuorum.Keys())
			land := NewLocalLand()
			land.LandSet(blockExtra.IsLandID, true, lastBlockNum, quorum)
			LocalLandSetMap.LandMapSet(commitBlock.NumberU64(), land, db)
		} else {
			//不是第一次,取出当前的岛屿信息更新
			log.Info("还在分叉", "高度", commitBlock.NumberU64())
			land, _ := LocalLandSetMap.LandMapGet(lastBlockNum, db)

			land.IslandIDState = blockExtra.IsLandID
			LocalLandSetMap.LandMapSet(commitBlock.NumberU64(), land, db)
		}
	} else {
		//保存的大陆块就把岛屿数据清空
		log.Info("保存的是大陆块", "高度", commitBlock.NumberU64())
		//IslandStore(w.Evertrust, "", false, 0, []string{}, 0, 0)
	}
}

func VerifySignAssertBlock(BlockPath []common.Hash, sig []byte) (common.Address, *ecdsa.PublicKey, error) {
	data, err := rlp.EncodeToBytes(BlockPath)
	if err != nil {
		return common.Address{}, nil, err
	}

	hash := crypto.Keccak256Hash(data)

	return evertrust.SigToAddress(hash.Bytes(), sig)
}

func verifySignBlockExtra(blockExtra types.BlockExtra, coinbase common.Address) error {
	if evertrust.Perf {
		log.Trace("perf mode no verify blockExtra sign")
		return nil
	}

	sig := make([]byte, len(blockExtra.Signature))
	copy(sig, blockExtra.Signature)
	blockExtra.Signature = nil

	data, err := rlp.EncodeToBytes(blockExtra)
	if err != nil {
		log.Error("rlp error", "err", err.Error())
		return err
	}
	hash := crypto.Keccak256Hash(data)

	addr, _, err := evertrust.SigToAddress(hash.Bytes(), sig)
	if err != nil {
		return err
	}

	if addr != coinbase {
		return errors.New("processBlockAssert Don't agree")
	}

	return nil
}

func getMinerFromCommitHeaderSig(blockExtra types.BlockExtra) (common.Address, error) {
	log.Info("get miner from commit header signature")
	sig := make([]byte, len(blockExtra.Signature))
	copy(sig, blockExtra.Signature)
	blockExtra.Signature = nil

	data, err := rlp.EncodeToBytes(blockExtra)
	if err != nil {
		log.Error("rlp error", "err", err.Error())
		return common.Address{}, err
	}
	hash := crypto.Keccak256Hash(data)

	addr, _, err := evertrust.SigToAddress(hash.Bytes(), sig)
	if err != nil {
		return common.Address{}, err
	}

	return addr, err
}

func (w *evertrustWorker) processBlockAssert(assert types.AssertExtra) error {

	currentCommit := w.blockchain.CurrentCommit()

	if currentCommit.Hash() != assert.ParentCommitHash {
		log.Error("assertion ParentCommitHash 不合法", "当前commitHash", currentCommit.Hash(), "assertExtra.ParentCommitHash", assert.ParentCommitHash)
		return errors.New("assertion Hash不合法")
	}

	//验证assertion签名
	var signHash []common.Hash
	var address common.Address
	var err error
	var pubKey *ecdsa.PublicKey
	signHash = append(signHash, assert.BlockPath...)
	signHash = append(signHash, assert.ParentCommitHash)
	if !evertrust.Perf {
		sig := make([]byte, len(assert.Signature))
		copy(sig, assert.Signature)
		address, pubKey, err = VerifySignAssertBlock(signHash, sig)
		if err != nil {
			log.Error("VerifySignAssertBlock error")
			return err
		}
	} else {
		log.Trace("perf mode no verify block path in assert block")
	}
	SynAssertionLock.Lock()
	log.Info("assertion查询数据", "对应commit高度", assert.LatestCommitBlockNumber, "add", address)
	//清除前一个assertion
	nextCommitNumber := currentCommit.NumberU64() + 1
	if nextCommitNumber != 0 {
		AssertCacheObject.ClearUpAssertMap(nextCommitNumber - 100)
	}

	assertions, ok := AssertCacheObject.Get(nextCommitNumber, w.evertrust1.db)
	if !ok {
		assertions = utils.NewSafeSet()
		AssertCacheObject.Set(nextCommitNumber, assertions, w.evertrust1.db)
	}
	//统计收到的assertion
	assertions.Add(address.Hex(),
		&AssertInfo{Address: address, Pubkey: pubKey, AssertExtra: &assert})
	SynAssertionLock.Unlock()
	return nil
}

func (w *evertrustWorker) sendTxData(commitNum *big.Int) {
	log.Info("start send trust tx")
	//send trust tx
	chainID := conf.ChainId.String()

	//get points & blockfree url from iaas
	var targetHosts, targetHostsSide1, targetHostsSide2, destChainId []string

	ks := w.evertrust1.AccountManager.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	privK := ks.GetUnlocked(w.evertrust1.signer).PrivateKey
	destChainId = tcUpdate.TrustHosts.ReadAllChainID()
	pointsMap := make(map[string]string) //key = id  val=points
	for index, destChainId := range destChainId {
		//获取信任链和冗余链的points,如果没有tcupdate,不会有目标的chainID
		points := evertrust.Getpoints(privK, chainID, destChainId, evertrust.TrustTxpointsType)
		pointsMap[destChainId] = points
		if points != "" {
			switch index {
			case 0:
				targetHosts = []string{fmt.Sprintf(evertrust.ProxyRPC, destChainId)}
			case 1:
				targetHostsSide1 = []string{fmt.Sprintf(evertrust.ProxyRPC, destChainId)}
			default:
				targetHostsSide2 = []string{fmt.Sprintf(evertrust.ProxyRPC, destChainId)}
			}
		}
	}

	if len(targetHosts) == 0 {
		//获取points失败,并且没有tcupdate 会是空
		log.Info("no proxy", "points", pointsMap)
		targetHosts, targetHostsSide1, targetHostsSide2 = tcUpdate.GetTrustHosts()
	}

	log.Info("get trust hosts", "hosts", targetHosts)
	if len(targetHosts) == 0 {
		log.Info("host list is zero, go to get hosts from iaas")
		targetHosts, targetHostsSide1, targetHostsSide1 = evertrust.GetTrustNodeFromIaas(chainID, "", "")
		destChainId = tcUpdate.TrustHosts.ReadAllChainID()

	}
	if len(targetHosts) == 0 {
		log.Warn("trust nodes empty from Iaas")
		return
	}
	if targetHosts[0] == "300" {
		log.Info("no under layer trust chain")
		return
	}

	log.Debug("trust nodes hosts", "list", targetHosts, "len", len(targetHosts), "destChainId", destChainId)
	for index, id := range destChainId {
		switch index {
		case 0:
			log.Info("targetHosts", "targetHosts", targetHosts, "id", id)
			w.sendTrustTx(commitNum, targetHosts, chainID, id, pointsMap[id])
		case 1:
			log.Info("targetHostsSide1", "targetHostsSide1", targetHosts, "id", id)
			w.sendTrustTx(commitNum, targetHostsSide1, chainID, id, pointsMap[id])
		default:
			log.Info("targetHostsSide2", "targetHostsSide2", targetHosts, "id", id)
			w.sendTrustTx(commitNum, targetHostsSide2, chainID, id, pointsMap[id])

		}
	}
}

func (w *evertrustWorker) sendTrustTx(commitNum *big.Int, hosts []string, chainID, destChainId, points string) {
	maxNum := evertrust.GetMaxNumFromTrustChain(hosts, chainID, destChainId, points)
	var commitNums []*big.Int
	if maxNum == nil {
		//commitNum < 100 then send from 1th commitNum
		if commitNum.Cmp(big.NewInt(100)) <= 0 {
			log.Info("get max num from trustChain nil, commitNum < 100", "commitNum", commitNum)
			numLimit := 0 // prevent transaction oversized data
			for i := big.NewInt(1); i.Cmp(commitNum) <= 0; i.Add(i, big.NewInt(1)) {
				if numLimit >= 10 {
					break
				}
				c := new(big.Int).Set(i)
				commitNums = append(commitNums, c)
				numLimit++
			}
		} else {
			log.Error("get max num from trustChain nil")
			//不发送？如果下层信任链切换了，到了新的链上仍然是nil
			//所以此处必须要发，合约里面去判断是否是第一次存储，如果是就直接存储。如果不是且发生了跳块，就不做任何处理。
			//如果发生了回滚，就把原来num对应的hash给覆盖，然后把maxNum给更新成当前的commit block num
			//数据结构：maxNum: key=chainId + "-trustTransactionHeight" value=commitNo
			//当前commit block的hash： key=chainId:blockNum(当前commit block num) value=commitBlockHash
			commitNums = append(commitNums, commitNum)
		}
	} else {
		log.Info("get max num from trustChain", "maxNum", maxNum.Int64(), "commitNum", commitNum.Int64())
		sub := new(big.Int).Sub(commitNum, maxNum)

		if sub.Cmp(big.NewInt(0)) == +1 {
			numLimit := 0 // prevent transaction oversized data
			for i := maxNum.Add(maxNum, big.NewInt(1)); i.Cmp(commitNum) <= 0; i.Add(i, big.NewInt(1)) {
				if numLimit >= 10 {
					break
				}
				c := new(big.Int).Set(i) // copy
				commitNums = append(commitNums, c)
				numLimit++
			}
		} else {
			commitNums = append(commitNums, commitNum)
		}
	}
	_, preChainID := tcUpdate.TrustHosts.ReadChainID()
	w.sendTx(hosts, chainID, commitNums, points, destChainId, preChainID)
}

func (w *evertrustWorker) sendTx(hosts []string, chainID string, commitNums []*big.Int, points string,
	curTrustChainID, preTrustChainID string) {
	ccName := "baap-trusttree"
	version := "v1.0"
	fcn := ""
	var datas []vm.TrustTxData
	for _, commitNum := range commitNums {
		commitB := w.blockchain.CommitChain.GetBlockByNum(commitNum.Uint64())
		if commitB == nil {
			log.Error("get block by num nil")
			return
		}
		log.Info("send trust tx start", "sendCommit", commitB.NumberU64())

		blockNum := commitB.NumberU64()
		txData := vm.TrustTxData{
			PreTrustChainID:     preTrustChainID,
			CurTrustChainID:     curTrustChainID,
			CommitBlockNo:       blockNum,
			CommitBlockHash:     commitB.Hash(),
			PrevCommitBlockHash: w.blockchain.CommitChain.GetBlockByNum(blockNum - 1).Hash(),
			NodeAddress:         commitB.Coinbase().String(),
		}
		datas = append(datas, txData)
	}

	info := vm.TrustTxInfo{
		Datas:   datas,
		ChainId: chainID,
	}
	paramsByt, err := rlp.EncodeToBytes(info)
	if err != nil {
		log.Error("rlp encode datas", "err", err)
		return
	}

	from := w.evertrust1.signer
	account := accounts.Account{Address: from}
	wallet, err := w.evertrust1.AccountManager.Find(account)
	if err != nil {
		log.Error("account manager error", "err", err)
		return
	}

	log.Debug("Evertrust signer", "from", from)

	//shuffle hosts
	retryN := 0
	gasPrice := big.NewInt(4000000000000)
retry:
	evertrust.Shuffle(hosts)
	for i, dstHost := range hosts {
		log.Info("try trust tx", "i", i, "host", dstHost, "链id", curTrustChainID)
		//if i > 4 {
		//	log.Error("try five times fail", "i", i)
		//	break
		//}
		//curTrustChainID, _ := tcUpdate.TrustHosts.ReadChainID()
		if err := SendTrustTx(curTrustChainID, account, wallet, dstHost, ccName, version, fcn, paramsByt, points, gasPrice); err != nil {
			//if errStr == "replacement transaction underpriced" {
			//	time.Sleep(frequency.ReqIntervalLimit + 1 * time.Second)
			//	continue
			//}
			log.Error("send trust tx", "err", err)
			if retryN < 4 {
				log.Info("send trust tx fail, get new hosts")
				trustHosts, _, _ := evertrust.GetTrustNodeFromIaas(chainID, curTrustChainID, points)
				if len(trustHosts) == 0 {
					log.Error("trust nodes empty from Iaas")
					return
				}
				hosts = trustHosts
				log.Info("after fail, get new host", "host", hosts)

				errStr := err.Error()
				if strings.HasPrefix(errStr, "known transaction") || errStr == "replacement transaction underpriced" {
					gasPriceInt := gasPrice.Int64()
					gasPrice = big.NewInt(gasPriceInt + gasPriceInt/10)
				}

				retryN++
				//ReqIntervalLimit之后重试，不应该立马重试，频率过高有可能会被加入到信任交易的黑名单中
				time.Sleep(frequency.ReqIntervalLimit + 1*time.Second)
				goto retry
			}
		}
		break
	}
}

func SendTrustTx(curTrustChainID string, account accounts.Account, wallet accounts.Wallet, host, ccName,
	version, fcn string, params []byte, points string, gasPrice *big.Int) error {
	log.Info("send trust tx to " + host)
	proxy := evertrust.Config.String("blockFreeCloud")
	cli, err := client.Connect(host, proxy, points)
	if err != nil {
		log.Error("!!!!connect error", "err", err)
		return err
	}

	owner := ""
	to := evertrust.Keccak256ToAddress(owner + ":" + ccName + ":" + version)
	ctx, cancel := context.WithTimeout(context.Background(), 1000*time.Millisecond)
	defer cancel()
	nonce, err := cli.EthClient.NonceAt(ctx, account.Address, nil)
	if err != nil {
		log.Error("!!!!!nonce error", "err", err, "from", account.Address)
		return err
	}
	log.Info("!!!!!!nonce", "nonce", nonce)
	amount := big.NewInt(0)
	gasLimit := uint64(evertrust.TrustTxGasLimit)

	tx := core_types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, params)

	// Look up the wallet containing the requested signer
	cID, ok := big.NewInt(0).SetString(curTrustChainID, 10)
	if !ok {
		log.Error("string to big int fail")
		cID = nil
	}
	signedTx, err := wallet.SignTx(account, tx, cID)
	log.Info("查询chainID", "cID", cID, "host", host, "account", account.Address.String(),
		"tx", signedTx.Hash())

	txHash, err := cli.SendRawTransaction(ctx, signedTx)
	if err != nil {
		log.Error("!!!!!!send raw transaction error", "err", err)
		return err
	}

	log.Info("#####sucess send raw transaction txHash", "hash", txHash.String(), "size", signedTx.Size()) // string() 显示完整hash
	return nil
}

func (w *evertrustWorker) Signer() common.Address {
	return w.evertrust1.signer
}
func (w *evertrustWorker) Evertrust() *Evertrust {
	return w.evertrust1
}
func (w *evertrustWorker) ContractQuery(commitExtra types.CommitExtra) (LocalLand, uint64) {
	commitNum := w.blockchain.CommitChain.CurrentBlock().NumberU64()

	if commitNum <= 1 {
		//第一次同步不需要去数据库中取数据
		return LocalLand{}, commitExtra.Version
	}
	land, ok := LocalLandSetMap.LandMapGet(commitNum, w.evertrust1.db)
	if !ok {
		//没找到证明是大陆
		return LocalLand{}, commitExtra.Version
	}
	contract := utils.QuorumResetContract //恢复大陆合约
	state, _ := w.blockchain.State()
	restoreLandByte := state.GetCRDState(contract, contract.Hash())
	var RestoreLandParams vm.RestoreLandParam
	if len(restoreLandByte) != 0 {
		rlp.DecodeBytes(restoreLandByte, &RestoreLandParams)
	}
	log.Info("ContractQuery查询", "RestoreLandParams", RestoreLandParams, "数据长度", len(restoreLandByte))
	//取出岛屿信息,然后修改,非指针,CreateCommit时候全都用这个岛屿信息
	//ProcessCommit使用完成后,进行岛屿信息更新

	if RestoreLandParams.RestoreHeight == commitNum {
		//到达需要恢复大陆的高度
		return LocalLand{}, RestoreLandParams.Version
	}
	//如果是正常岛屿,返回正常岛屿信息
	return land, commitExtra.Version

}
