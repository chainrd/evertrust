// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package eth

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cc14514/go-alibp2p"
	"github.com/deckarep/golang-set"
	"math"
	"math/big"
	"CRD-chain/cacheBlock"
	"CRD-chain/core/vm"
	"CRD-chain/crypto"
	"CRD-chain/quorum"
	"CRD-chain/evertrust/utils"
	"sync"
	"sync/atomic"
	"time"

	"CRD-chain/common"
	"CRD-chain/consensus"
	"CRD-chain/consensus/misc"
	"CRD-chain/core"
	"CRD-chain/core/types"
	"CRD-chain/eth/downloader"
	"CRD-chain/eth/fetcher"
	"CRD-chain/ethdb"
	"CRD-chain/event"
	"CRD-chain/log"
	"CRD-chain/p2p"
	"CRD-chain/p2p/discover"
	"CRD-chain/params"
	"CRD-chain/rlp"
	"CRD-chain/evertrust/engine"
	evertrust_types "CRD-chain/evertrust/types"
)

const (
	softResponseLimit = 2 * 1024 * 1024 // Target maximum size of returned blocks, headers or node data.
	commitLimit       = 8 * 1024 * 1024 // commit大小限制
	estHeaderRlpSize  = 500             // Approximate size of an RLP encoded block header

	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096
)

var (
	daoChallengeTimeout = 15 * time.Second // Time allowance for a node to reply to the DAO handshake challenge
)

//var commitMapCache sync.Map
// errIncompatibleConfig is returned if the requested protocols and configs are
// not compatible (low protocol version restrictions and high requirements).
var errIncompatibleConfig = errors.New("incompatible configuration")

func errResp(code errCode, format string, v ...interface{}) error {
	return fmt.Errorf("%v - %v", code, fmt.Sprintf(format, v...))
}

type ProtocolManager struct {
	networkID uint64

	fastSync  uint32 // Flag whether fast sync is enabled (gets disabled if we already have blocks)
	acceptTxs uint32 // Flag whether we're considered synchronised (enables transaction processing)

	txpool      txPool
	blockchain  *core.BlockChain
	chainconfig *params.ChainConfig
	maxPeers    int

	downloader    *downloader.Downloader
	fetcher       *fetcher.Fetcher
	commitFetcher *fetcher.CbFetcher
	peers         *peerSet
	hiwayPeers    func() map[common.Address]*p2p.Peer
	SubProtocols  []p2p.Protocol

	eventMux       *event.TypeMux
	txsCh          chan core.NewTxsEvent
	txsSub         event.Subscription
	minedBlockSub  *event.TypeMuxSubscription
	commitBlockSub *event.TypeMuxSubscription
	assertBlockSub *event.TypeMuxSubscription

	//BlockChainNodeCh chan *quorum.BlockchainNode
	consensusEngine consensus.Engine
	// channels for fetcher, syncer, txsyncLoop
	newPeerCh   chan *peer
	txsyncCh    chan *txsync
	quitSync    chan struct{}
	noMorePeers chan struct{}
	addTxCh     chan []*types.Transaction

	// wait group is used for graceful shutdowns during downloading
	// and processing
	wg                 sync.WaitGroup
	infection          *infection     //CRD
	etherbase          common.Address //CRD
	chaindb            ethdb.Database //CRD
	missHash           []*common.Hash //CRD
	AssertionNewFeed   event.Feed     //CRD
	CommitBroadcast    chan *types.Block
	NormalBroadcast    chan *types.Block
	AssertionBroadcast chan evertrust_types.NewAssertBlockEvent
}

// NewProtocolManager returns a new Ethereum sub protocol manager. The Ethereum sub protocol manages peers capable
// with the Ethereum network.
func NewProtocolManager(config *params.ChainConfig, mode downloader.SyncMode, networkID uint64, mux *event.TypeMux, txpool txPool, engineImpl consensus.Engine, blockchain *core.BlockChain, chaindb ethdb.Database, etherbase common.Address) (*ProtocolManager, error) {
	// Create the protocol manager with the base fields
	manager := &ProtocolManager{
		networkID:          networkID,
		eventMux:           mux,
		txpool:             txpool,
		blockchain:         blockchain,
		chainconfig:        config,
		peers:              newPeerSet(),
		newPeerCh:          make(chan *peer),
		noMorePeers:        make(chan struct{}),
		txsyncCh:           make(chan *txsync),
		quitSync:           make(chan struct{}),
		addTxCh:            make(chan []*types.Transaction, 100000),
		consensusEngine:    engineImpl,
		etherbase:          etherbase,
		chaindb:            chaindb,
		missHash:           make([]*common.Hash, 0),
		CommitBroadcast:    engineImpl.(*engine.Evertrust).CommitBroadcast,
		NormalBroadcast:    engineImpl.(*engine.Evertrust).NormalBroadcast,
		AssertionBroadcast: engineImpl.(*engine.Evertrust).AssertionBroadcast,
		//BlockChainNodeCh: make(chan *quorum.BlockchainNode, 1),
		//AssertionNewPeer: make(chan *peer),
	}
	// Figure out whether to allow fast sync or not
	if mode == downloader.FastSync && blockchain.CurrentBlock().NumberU64() > 0 {
		log.Warn("Blockchain not empty, fast sync disabled")
		mode = downloader.FullSync
	}
	if mode == downloader.FastSync {
		manager.fastSync = uint32(1)
		//examineSync.ExamineBlockWork = 1
	}
	// Initiate a sub-protocol for every implemented version we can handle
	manager.SubProtocols = make([]p2p.Protocol, 0, len(ProtocolVersions))
	for i, version := range ProtocolVersions {
		// Skip protocol version if incompatible with the mode of operation
		if mode == downloader.FastSync && version < eth63 {
			continue
		}
		// Compatible; initialise the sub-protocol
		version := version // Closure for the run
		manager.SubProtocols = append(manager.SubProtocols, p2p.Protocol{
			Name:    ProtocolName,
			Version: version,
			Length:  ProtocolLengths[i],
			Run: func(p *p2p.Peer, rw p2p.MsgReadWriter) error {
				peer := manager.newPeer(int(version), p, rw)
				select {
				case manager.newPeerCh <- peer:
					manager.wg.Add(1)
					defer manager.wg.Done()
					return manager.handle(peer)
				case <-manager.quitSync:
					return p2p.DiscQuitting
				}
			},
			NodeInfo: func() interface{} {
				return manager.NodeInfo()
			},
			PeerInfo: func(id discover.NodeID) interface{} {
				if p := manager.peers.Peer(fmt.Sprintf("%x", id[:8])); p != nil {
					return p.Info()
				}
				return nil
			},
		})
	}
	if len(manager.SubProtocols) == 0 {
		return nil, errIncompatibleConfig
	}
	evertrust, _ := engineImpl.(*engine.Evertrust)
	// Construct the different synchronisation mechanisms
	manager.downloader = downloader.New(mode, chaindb, manager.eventMux, blockchain, nil, manager.removePeer)
	manager.downloader.Worker = evertrust.Worker()
	manager.downloader.Commitchain = blockchain.CommitChain
	validator := func(header *types.Header) error {
		return engineImpl.VerifyHeader(blockchain, header, true)
	}
	heighter := func() uint64 {
		return blockchain.CurrentBlock().NumberU64()
	}
	commitHeighter := func() uint64 {
		return blockchain.CommitChain.CurrentBlock().NumberU64()
	}
	normalNewHeight := func() uint64 {
		return blockchain.CurrentBlock().NumberU64()
	}

	inserter := func(blocks types.Blocks) (int, error) {
		//If fast sync is running, deny importing weird blocks
		if atomic.LoadUint32(&manager.fastSync) == 1 {
			if len(manager.peers.peers) == 0 || blocks[0].Number().Uint64() <= 1 {
				atomic.StoreUint32(&manager.fastSync, 0)
			} else {
				log.Warn("Discarded bad propagated block", "number", blocks[0].Number(), "hash", blocks[0].Hash())
				return 0, nil
			}

		}
		atomic.StoreUint32(&manager.acceptTxs, 1) // Mark initial sync done on any fetcher import

		if evertrust, ok := manager.consensusEngine.(*engine.Evertrust); ok {
			evertrust.OnNormalBlock(blocks[0])
			return 0, nil
		} else {
			return manager.blockchain.InsertChain(blocks)
		}
	}
	commitInserter := func(commitBlocks types.Blocks) (int, error) {
		if evertrust, ok := engineImpl.(*engine.Evertrust); ok {
			for index, block := range commitBlocks {
				err := evertrust.OnCommitBlock(block)
				if err != nil {
					log.Error("process commit block", "error", err)
					return index, err
				}
			}
		}
		return 0, nil
	}
	manager.fetcher = fetcher.New(blockchain.GetBlockByHash, validator, manager.BroadcastBlock, heighter, inserter, manager.removePeer, &manager.downloader.Synchronis)
	manager.commitFetcher = fetcher.NewCBFetcher(blockchain.CommitChain.GetBlockByHash, validator, commitHeighter, commitInserter, manager.removePeer, normalNewHeight, &manager.downloader.Synchronis)

	manager.infection = newInfection(manager)
	manager.downloader.CbFetcher = manager.commitFetcher
	return manager, nil
}

func (pm *ProtocolManager) removePeer(id string) {
	// Short circuit if the peer was already removed
	peer := pm.peers.Peer(id)
	if peer == nil {
		return
	}
	log.Debug("Removing CRD peer", "peer", id)

	// Unregister the peer from the downloader and Ethereum peer set
	pm.downloader.UnregisterPeer(id)
	if err := pm.peers.Unregister(id); err != nil {
		log.Error("Peer removal failed", "peer", id, "err", err)
	}

	// Hard disconnect at the networking layer
	if peer != nil {
		peer.Peer.Disconnect(p2p.DiscUselessPeer)
	}
	peer.knownTxs = mapset.NewSet()

}

func (pm *ProtocolManager) Start(maxPeers int) {
	pm.maxPeers = maxPeers

	// broadcast transactions
	pm.txsCh = make(chan core.NewTxsEvent, txChanSize)
	pm.txsSub = pm.txpool.SubscribeNewTxsEvent(pm.txsCh)
	go pm.txBroadcastLoop()

	// broadcast mined blocks
	pm.minedBlockSub = pm.eventMux.Subscribe(core.NewMinedBlockEvent{})
	pm.commitBlockSub = pm.eventMux.Subscribe(evertrust_types.NewCommitBlockEvent{})
	pm.assertBlockSub = pm.eventMux.Subscribe(evertrust_types.NewAssertBlockEvent{})
	//pm.consensusEngine.(*engine.evertrust).BlockChainNodeFeed.Subscribe(pm.BlockChainNodeCh) //订阅
	go pm.minedBroadcastLoop()
	go pm.commitBroadcastLoop()
	go pm.assertMulticastLoop()
	//go pm.peerLoop()
	//go pm.blockChainNodeLoop()
	go pm.broadcastAddTx()

	// start sync handlers
	go pm.infection.start()
	go pm.syncer()
	go pm.txsyncLoop()
}

func (pm *ProtocolManager) Stop() {
	log.Info("Stopping Ethereum protocol")

	pm.txsSub.Unsubscribe() // quits txBroadcastLoop
	//pm.minedBlockSub.Unsubscribe() // quits blockBroadcastLoop

	// Quit the sync loop.
	// After this send has completed, no new peers will be accepted.
	pm.noMorePeers <- struct{}{}

	// Quit fetcher, txsyncLoop.
	close(pm.quitSync)

	// Disconnect existing sessions.
	// This also closes the gate for any new registrations on the peer set.
	// sessions which are already established but not added to pm.peers yet
	// will exit when they try to register.
	pm.peers.Close()

	// Wait for all peer handler goroutines and the loops to come down.
	pm.wg.Wait()
	pm.infection.stop()

	log.Info("Ethereum protocol stopped")
}

func (pm *ProtocolManager) newPeer(pv int, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	return newPeer(pv, p, newMeteredMsgWriter(rw))
}

//CRD
//func (pm *ProtocolManager) SyncIsland(cNum int, blockExtra evertrust_types.BlockExtra, commitExtraIsland bool) {
//
//	log.Info("SyncIsland开始删除commit")
//	if atomic.LoadInt32(&pm.downloader.AssociatedSynchronising) == 1 {
//		log.Warn("SyncIsland或者SyncNormalDeleteCommit半生commit正在同步")
//		return
//	}
//
//	currentCommitNum := pm.blockchain.CommitChain.CurrentBlock().NumberU64()
//
//	//如果分叉前的高度比当前高度大,就不删了
//	if uint64(cNum)-1 > currentCommitNum {
//		return
//	}
//	//从分叉前前一个开始删除,删除到当前current
//	for i := uint64(cNum) - 1; i <= currentCommitNum; i++ {
//		block := pm.blockchain.CommitChain.GetBlockByNum(i)
//		log.Info("要删除的高度", "分叉前的高度", cNum, "当前要删的高度", i, "要删除到哪里", currentCommitNum)
//		//先删除 在同步
//		if block == nil {
//			continue
//		}
//		//先删除 在同步
//		engine.CommitDeRepetition.Del(block.NumberU64())           //commit删除缓存
//		engine.AssociatedCommitDeRepetition.Del(block.NumberU64()) //commit删除缓存
//		core.DeleteCommitBlock(pm.chaindb, block.Hash(), block.NumberU64(), *pm.blockchain.CommitChain)
//		engine.CommitBlockQueued.DelToProcessCommitBlockQueueMap(i) //删除toProcessCommit缓存
//		quorum.CommitHeightToConsensusQuorum.Del(block.NumberU64(), pm.chaindb)
//	}
//	//如果当前的commit高度已经比裂脑前的高度小,就用当前高度
//	//取删除前的面的一个当成当前current
//	localCnum := uint64(cNum) - 2
//	if localCnum > currentCommitNum {
//		localCnum = currentCommitNum
//	}
//	if localCnum == 0 {
//		localCnum = 1
//	}
//	log.Info("commit回滚高度", "cNum", cNum, "当前commit高度", localCnum)
//	localCommit := pm.blockchain.CommitChain.GetBlockByNum(localCnum)
//	core.SetCurrentCommitBlock(pm.blockchain.CommitChain, localCommit)
//
//	log.Info("selfCommit", "selfCommit高度", localCommit.NumberU64())
//	_, commitExtra := evertrust_types.CommitExtraDecode(localCommit)
//	rollbackHeight := commitExtra.NewBlockHeight.Uint64()
//	currentBlockNumber := pm.blockchain.CommitChain.CurrentBlock().NumberU64()
//	log.Info("currentCommit高度", "commit高度", currentBlockNumber)
//	//处理Normal
//	currentBlockNormalNum := pm.blockchain.CurrentBlock().NumberU64()
//	pm.blockchain.SetHead(rollbackHeight)
//	log.Info("normal回滚高度", "normal高度", rollbackHeight)
//	for i := rollbackHeight + 1; i <= currentBlockNormalNum; i++ {
//		pm.blockchain.CommitChain.DeleteHeightMap(i)
//		engine.NormalBlockQueued.DelToProcessNormalBlockQueueMap(i) //删除toProcessNormal
//	}
//
//	evertrustEng := pm.consensusEngine.(*engine.evertrust)
//
//	if evertrustEng.Config().Majority == engine.Twothirds {
//		//同步完成后存对方的岛屿ID,改变自己岛屿状态
//		//evertrustEng := pm.consensusEngine.(*engine.evertrust)
//		evertrustEng.SetIslandIDState(blockExtra.IsLandID)
//		evertrustEng.SetIslandState(commitExtraIsland)
//	}
//
//	atomic.StoreInt32(&downloader.IslandDel, 1) //normal同步就不要删除啦
//
//	//pm.downloader.AssociatedCH <- true
//}

//检查节点是否在委员会中,如果在可以清除节点,如果不在,保留节点,有可能是新加入的节点
//func (pm *ProtocolManager) ExamineConsensusQuorum(peer string) bool {
//	commitHeight := pm.blockchain.CommitChain.CurrentBlock().NumberU64() - 1
//	consensusQuorum, ok := quorum.CommitHeightToConsensusQuorum.Get(uint64(commitHeight)-1, pm.chaindb)
//	if !ok {
//		return true //委员会获取失败 不能删
//	}
//	address := examineSync.IDAndBlockAddress.GetAddIDAndAddress(peer)
//	BlockNode, b := quorum.BlockChainNodeSets.Get(address, pm.chaindb)
//	if !b {
//		return true //BlockChainNode获取失败 不能删
//	}
//	for _, address := range consensusQuorum.Hmap {
//		if BlockNode.Address == address {
//			return false //可以删
//		}
//
//	}
//	return true //不在委员会中
//}

//删除超出列表的peer
//func (pm *ProtocolManager) spillRemovePeer(num int) {
//	delNum := 0
//	nodeIds := make([]string, 0)
//	pm.peers.lock.RLock()
//	for nodeId := range pm.peers.peers {
//		nodeIds = append(nodeIds, nodeId)
//	}
//	pm.peers.lock.RUnlock()
//	for _, nodeId := range nodeIds {
//		if examineSync.PeerExamineSync.ExaminePeer(nodeId) { //是否是正同步中的区块
//			continue
//		}
//		if pm.ExamineConsensusQuorum(nodeId) { //检查要删除的节点是否在委员会中,防止删除新加入的节点
//			continue
//		}
//		pm.removePeer(nodeId)
//		delNum++
//		if delNum == num {
//			break
//		}
//
//	}
//}

//func (pm *ProtocolManager) peerLoop() {
//	for {
//		rand.Seed(time.Now().UnixNano())
//		time.Sleep(time.Duration(int(engine.BlockDelay)*(100+rand.Intn(10))) * time.Millisecond)
//		if pm.peers.Len() >= pm.maxPeers+1 {
//			//return p2p.DiscTooManyPeers
//			log.Info("peer超出范围需要删除")
//			pm.spillRemovePeer(pm.peers.Len() - pm.maxPeers)
//		}
//		pm.peerNumCheck()
//	}
//}

//func (pm *ProtocolManager) peerNumCheck() {
//	currentCommitNum := pm.blockchain.CommitChain.CurrentBlock().NumberU64()
//	consensusQuorum, ok := quorum.CommitHeightToConsensusQuorum.Get(currentCommitNum, pm.chaindb)
//	if !ok {
//		return
//	}
//	peerNum := pm.peers.Len() + 1
//
//	address := pm.etherbase
//	evertrust := pm.consensusEngine.(*engine.evertrust)
//	server := evertrust.Server()
//	if peerNum < pm.maxPeers && peerNum < consensusQuorum.Len() && peerNum < int(engine.NumMasters) {
//		log.Info("peer数量为0,开始链接StaticNodes")
//		for _, add := range consensusQuorum.Hmap {
//			if address == add {
//				//跳过自己
//				log.Info("pm是自己不加入")
//				continue
//			}
//			node := examineSync.AllNodeLists.FindNode(add)
//			if node != nil {
//				//去除已经链接上的
//				log.Info("找到的地址", "地址", add.String())
//				if ok := pm.peers.Peer(node.ID.String()[:16]); ok == nil {
//					log.Info("不在列表进行链接")
//					go server.AddPeer(node)
//					//examineSync.DiscoverEnode.AddDiscoverEnode(node.ID.String(),node)
//					break
//				}
//
//			}
//
//		}
//
//	}
//	if pm.peers.Len() == 0 && len(server.StaticNodes) != 0 {
//		for _, node := range server.StaticNodes {
//			go server.AddPeer(node)
//		}
//	}
//
//}

// handle is the callback invoked to manage the life cycle of an eth peer. When
// this function terminates, the peer is disconnected.
func (pm *ProtocolManager) handle(p *peer) error {
	// Ignore maxPeers if this is a trusted peer
	//if pm.peers.Len() >= pm.maxPeers && !p.Peer.Info().Network.Trusted {
	//	//return p2p.DiscTooManyPeers
	//	log.Info("peer超出范围需要删除")
	//	pm.spillRemovePeer()
	//}
	p.Log().Debug("CRD peer connected", "name", p.Name())

	// Execute the Ethereum handshake
	var (
		genesis = pm.blockchain.Genesis()
		head    = pm.blockchain.CurrentHeader()
		hash    = head.Hash()
		number  = head.Number.Uint64()
		td      = pm.blockchain.GetTd(hash, number)
		flags   = p.Peer.Flags() // add by liangc
	)

	if err := p.Handshake(pm.networkID, td, hash, genesis.Hash(), pm.blockchain.CommitChain.CurrentBlock().NumberU64(), flags); err != nil {
		p.Log().Debug("CRD handshake failed", "err", err)
		p2p.SendAddpeerHandshakeEvent(&p2p.AddpeerHandshakeEvent{p.ID().Bytes(), err}) // add by liangc
		return err
	}
	p2p.SendAddpeerHandshakeEvent(&p2p.AddpeerHandshakeEvent{p.ID().Bytes(), nil}) // add by liangc
	if rw, ok := p.rw.(*meteredMsgReadWriter); ok {
		rw.Init(p.version)
	}

	// Register the peer locally
	if err := pm.peers.Register(p); err != nil {
		p.Log().Error("CRD peer registration failed", "err", err)
		return err
	}
	defer pm.removePeer(p.id)

	// Register the peer in the downloader. If the downloader considers it banned, we disconnect
	if err := pm.downloader.RegisterPeer(p.id, p.version, p, p.Peer); err != nil {
		return err
	}
	pm.AssertionNewFeed.Send(p)

	// Propagate existing transactions. new transactions appearing
	// after this will be sent via broadcasts.(CRD:maybe affect block broadcast)
	//pm.syncTransactions(p)

	// If we're DAO hard-fork aware, validate any remote peer with regard to the hard-fork
	if daoBlock := pm.chainconfig.DAOForkBlock; daoBlock != nil {
		// Request the peer's DAO fork header for extra-data validation
		if err := p.RequestHeadersByNumber(daoBlock.Uint64(), 1, 0, false); err != nil {
			return err
		}
		// Start a timer to disconnect if the peer doesn't reply in time
		p.forkDrop = time.AfterFunc(daoChallengeTimeout, func() {
			p.Log().Debug("Timed out DAO fork-check, dropping")
			pm.removePeer(p.id)
		})
		// Make sure it's cleaned up if the peer dies off
		defer func() {
			if p.forkDrop != nil {
				p.forkDrop.Stop()
				p.forkDrop = nil
			}
		}()
	}
	// main loop. handle incoming messages.
	for {
		if err := pm.handleMsg(p); err != nil {
			p.Log().Debug("CRD message handling failed", "err", err)
			return err
		}

	}
}

type mcounter struct {
	counter map[string]map[uint64]msglog
	lock    sync.RWMutex
}
type msglog struct {
	Code  uint64
	Total uint64
	Ts    int64
}

var (
	_counter = &mcounter{
		counter: make(map[string]map[uint64]msglog),
	}
	_s = 0
)

func (m *mcounter) String() string {
	buf, err := json.Marshal(m.counter)
	if err != nil {
		log.Error("mcounter-err", "err", err)
		return err.Error()
	} else {
		log.Info("mcounter", "counter", string(buf))
	}
	return string(buf)
}

//var commitIslandSync int32
func MsgCounter(p *peer, msg p2p.Msg) {
	_counter.lock.Lock()
	defer _counter.lock.Unlock()
	id := ""
	if p.Mrw == nil {
		id = p.ID().String()
	} else {
		id = p.id
	}
	logmap, ok := _counter.counter[id]
	if !ok {
		logmap = make(map[uint64]msglog)
	}

	logobj, ok := logmap[msg.Code]
	if !ok {
		logobj = msglog{
			Code:  msg.Code,
			Total: 1,
			Ts:    time.Now().Unix(),
		}
	} else {
		logobj.Total = logobj.Total + 1
		logobj.Ts = time.Now().Unix()
	}
	logmap[msg.Code] = logobj
	_counter.counter[id] = logmap
	if _s%1000 == 0 {
		log.Warn("msg_counter", "total", _s, "log", _counter.String())
	}
	_s += 1
}

// handleMsg is invoked whenever an inbound message is received from a remote
// peer. The remote connection is torn down upon returning any error.
func (pm *ProtocolManager) handleMsg(p *peer) error {
	// Read the next message from the remote peer, and ensure it's fully consumed
	//t := time.Now()
	msg, err := p.rw.ReadMsg()
	defer func() {
		//log.Info("handleMsg","msg",msg.Code,"size",msg.Size,"timeused",time.Since(t))
	}()
	if err != nil {
		return err
	}

	if msg.Size > p2p.ProtocolMaxMsgSize {
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, p2p.ProtocolMaxMsgSize)
	}
	defer msg.Discard()

	//todo check freq

	//if err == nil {
	//	go MsgCounter(p, msg)
	//}
	// Handle the message depending on its contents
	switch {
	case msg.Code == 14515, msg.Code == 0xA1:
		// add by liangc : 测试 highway 通道
		var data = new(types.Header)
		err := msg.Decode(data)
		fmt.Println("-> cc14515 ->", err, msg.Code, msg.Size, data.Number, data.Hash().Hex(), data.Extra)
	case msg.Code == 14514, msg.Code == 0xA0:
		// add by liangc : 测试 highway 通道
		var data = new(types.Header)
		err := msg.Decode(data)
		fmt.Println("-> cc14514 ->", err, msg.Code, msg.Size, data.Number, data.Hash().Hex(), data.Extra)
		code := big.NewInt(int64(msg.Code + 1))
		data.Number = code
		data.Root = common.BytesToHash(code.Bytes())
		if from, ok := pm.hiwayPeers()[data.Coinbase]; ok {
			err := p2p.Send(from.Mrw, code.Uint64(), data)
			fmt.Println("<- cc14515 <-", err, from.ID())
		} else {
			c := len(data.Extra)
			xb, yb := data.Extra[:c/2], data.Extra[c/2:]
			pk := &ecdsa.PublicKey{X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb), Curve: crypto.S256()}
			id, _ := alibp2p.ECDSAPubEncode(pk)
			err = p2p.Send(pk, code.Uint64(), data)
			fmt.Println("<- cc14515 <-", err, id)
		}
	case msg.Code == StatusMsg:
		// Status messages should never arrive after the handshake
		return errResp(ErrExtraStatusMsg, "uncontrolled status message")

		// Block header query, collect the requested headers and reply
	case msg.Code == GetBlockHeadersMsg:
		// Decode the complex header query
		var query getBlockHeadersData
		if err := msg.Decode(&query); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		hashMode := query.Origin.Hash != (common.Hash{})
		maxNonCanonical := uint64(100)

		// Gather headers until the fetch or network limits is reached
		var (
			bytes   common.StorageSize
			headers []*types.Header
			//commitblocks []*types.Block
			unknown bool
		)
		for !unknown && len(headers) < int(query.Amount) && bytes < softResponseLimit && len(headers) < downloader.MaxHeaderFetch {
			// Retrieve the next header satisfying the query
			var origin *types.Header
			if hashMode {
				normalBlock := cacheBlock.CacheBlocks.GetBlock(query.Origin.Hash)
				if normalBlock == nil {
					origin = pm.blockchain.GetHeaderByHash(query.Origin.Hash)
					if origin != nil {
						query.Origin.Number = origin.Number.Uint64()
					} else {
						origin = pm.blockchain.GetHeader(query.Origin.Hash, query.Origin.Number)
					}
				} else {
					origin = normalBlock.Header()
				}

			} else {
				origin = pm.blockchain.GetHeaderByNumber(query.Origin.Number)
			}
			if origin == nil {
				break
			}

			headers = append(headers, origin)
			bytes += estHeaderRlpSize

			// Advance to the next header of the query
			switch {
			case hashMode && query.Reverse:
				// Hash based traversal towards the genesis block
				ancestor := query.Skip + 1
				if ancestor == 0 {
					unknown = true
				} else {
					query.Origin.Hash, query.Origin.Number = pm.blockchain.GetAncestor(query.Origin.Hash, query.Origin.Number, ancestor, &maxNonCanonical)
					unknown = query.Origin.Hash == common.Hash{}
				}
			case hashMode && !query.Reverse:
				// Hash based traversal towards the leaf block
				var (
					current = origin.Number.Uint64()
					next    = current + query.Skip + 1
				)
				if next <= current {
					infos, _ := json.MarshalIndent(p.Peer.Info(), "", "  ")
					p.Log().Warn("GetBlockHeaders skip overflow attack", "current", current, "skip", query.Skip, "next", next, "attacker", infos)
					unknown = true
				} else {
					if header := pm.blockchain.GetHeaderByNumber(next); header != nil {
						nextHash := header.Hash()
						expOldHash, _ := pm.blockchain.GetAncestor(nextHash, next, query.Skip+1, &maxNonCanonical)
						if expOldHash == query.Origin.Hash {
							query.Origin.Hash, query.Origin.Number = nextHash, next
						} else {
							unknown = true
						}
					} else {
						unknown = true
					}
				}
			case query.Reverse:
				// Number based traversal towards the genesis block
				if query.Origin.Number >= query.Skip+1 {
					query.Origin.Number -= query.Skip + 1
				} else {
					unknown = true
				}

			case !query.Reverse:
				// Number based traversal towards the leaf block
				query.Origin.Number += query.Skip + 1
			}
		}
		//if len(commitblocks) > 0 {
		//
		//	err := p.SendAssociatedCommitBlocks(commitblocks)
		//	if err != nil {
		//		log.Error("err", err.Error())
		//	}
		//}

		//log.Info("发送的headers是","peer-id",p.id,"headers长度",len(headers))
		return p.SendBlockHeaders(headers)

	case msg.Code == GetCommitBlocksByNumMsg:
		var query getBlockHeadersData
		if err := msg.Decode(&query); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		// Gather headers until the fetch or network limits is reached
		var (
			bytes   common.StorageSize
			headers []*types.Block
		)
		for len(headers) < int(query.Amount) && bytes < commitLimit && len(headers) < downloader.MaxHeaderFetch {
			// Retrieve the next header satisfying the query
			var origin *types.Block

			origin = pm.blockchain.CommitChain.GetBlockByNum(query.Origin.Number)

			if origin == nil {
				break
			}

			headers = append(headers, origin)
			bytes += origin.Size()

			// Advance to the next header of the query
			switch {
			case !query.Reverse:
				// Number based traversal towards the leaf block
				query.Origin.Number += query.Skip + 1
			}
		}
		p.SendCommitSyncBlocks(headers)

		return nil

	case msg.Code == GetCommitBlocksMsg:
		// Decode the complex header query
		//log.Info("GetCommitBlocksMsg", "name", p.Name(), "id", p.id)
		var query getBlockHeadersData
		if err := msg.Decode(&query); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}

		// Gather headers until the fetch or network limits is reached
		var (
			bytes   common.StorageSize
			headers []*types.Block
		)
		for len(headers) < int(query.Amount) && bytes < commitLimit && len(headers) < downloader.MaxHeaderFetch {
			// Retrieve the next header satisfying the query
			var origin *types.Block
			origin = cacheBlock.CacheBlocks.GetBlock(query.Origin.Hash)
			if origin == nil {
				origin = pm.blockchain.CommitChain.GetBlockByHash(query.Origin.Hash)
				if origin == nil {
					origin = pm.blockchain.CommitChain.GetBlockByNum(query.Origin.Number)
				}
				if origin == nil {
					log.Error("没有找到对应的commitHash", "hash", query.Origin.Hash)
					break
				}
			}

			headers = append(headers, origin)
			bytes += origin.Size()

			// Advance to the next header of the query
			switch {
			case !query.Reverse:
				// Number based traversal towards the leaf block
				query.Origin.Number += query.Skip + 1
			}
		}
		return p.SendCommitBlocks(headers)
	case msg.Code == GetLatestCommitBlockMsg:
		block := pm.blockchain.CommitChain.CurrentBlock()
		var blocks []*types.Block
		blocks = append(blocks, block)
		p.SendCommitSyncBlocks(blocks)

	case msg.Code == GetLatestNormalBlockMsg:
		block := pm.blockchain.CurrentBlock()
		var headers []*types.Header
		headers = append(headers, block.Header())
		return p.SendBlockHeaders(headers)

	case msg.Code == BlockHeadersMsg:
		// A batch of headers arrived to one of our previous requests
		var headers []*types.Header
		if err := msg.Decode(&headers); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		log.Info("收到了header的数量", "数量", len(headers))
		// If no headers were received, but we're expending a DAO fork check, maybe it's that
		if len(headers) == 0 && p.forkDrop != nil {
			// Possibly an empty reply to the fork header checks, sanity check TDs
			verifyDAO := true

			// If we already have a DAO header, we can check the peer's TD against it. If
			// the peer's ahead of this, it too must have a reply to the DAO check
			if daoHeader := pm.blockchain.GetHeaderByNumber(pm.chainconfig.DAOForkBlock.Uint64()); daoHeader != nil {
				if _, td := p.Head(); td.Cmp(pm.blockchain.GetTd(daoHeader.Hash(), daoHeader.Number.Uint64())) >= 0 {
					verifyDAO = false
				}
			}
			// If we're seemingly on the same chain, disable the drop timer
			if verifyDAO {
				p.Log().Debug("Seems to be on the same side of the DAO fork")
				p.forkDrop.Stop()
				p.forkDrop = nil
				return nil
			}
		}
		// Filter out any explicitly requested headers, deliver the rest to the downloader
		filter := len(headers) == 1
		if filter {
			// If it's a potential DAO fork check, validate against the rules
			if p.forkDrop != nil && pm.chainconfig.DAOForkBlock.Cmp(headers[0].Number) == 0 {
				// Disable the fork drop timer
				p.forkDrop.Stop()
				p.forkDrop = nil

				// Validate the header and either drop the peer or continue
				if err := misc.VerifyDAOHeaderExtraData(pm.chainconfig, headers[0]); err != nil {
					p.Log().Debug("Verified to be on the other side of the DAO fork, dropping")
					return err
				}
				p.Log().Debug("Verified to be on the same side of the DAO fork")
				return nil
			}
			// Irrelevant of the fork checks, send the header to the fetcher just in case
			headers = pm.fetcher.FilterHeaders(p.id, headers, time.Now())
		}
		for _, head := range headers {
			log.Info("收到的head", "head", head.Hash(), "高度", head.Number.Uint64())
		}

		if len(headers) > 0 || !filter {
			err := pm.downloader.DeliverHeaders(p.id, headers)
			if err != nil {
				log.Debug("Failed to deliver headers", "err", err)
			}
		}

	case msg.Code == GetBlockBodiesMsg:
		// Decode the retrieval message

		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather blocks until the fetch or network limits is reached
		var (
			hash   common.Hash
			bytes  int
			bodies []rlp.RawValue
		)
		//log.Info("收到获取bodies请求", "peerID", p.id, "name", p.Name())
		for bytes < softResponseLimit && len(bodies) < downloader.MaxBlockFetch {
			// Retrieve the hash of the next block
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested block body, stopping if enough was found
			block := cacheBlock.CacheBlocks.GetBlock(hash)

			// add by liangc : ewasm 重新封包 >>>>
			if block == nil {
				block = pm.blockchain.GetBlockByHash(hash)
				if block == nil {
					log.Error("CRD 获取rlpBodie失败 1")
					break
				}
			}
			block, err := repackBlockTxdata(block)
			if err != nil {
				log.Error("严重错误,应该panic,不接受这种错误repackBlockTxdata(block)", "err", err)
				return nil
			}
			data, err := rlp.EncodeToBytes(block.Body())
			if err != nil {
				log.Error("CRD 获取rlpBodie失败 2", "err", err)
				return nil
			}
			bodies = append(bodies, data)
			bytes += len(data)
			// add by liangc : ewasm 重新封包 <<<<

			// modify by liangc
			//if block == nil {
			//	if data := pm.blockchain.GetBodyRLP(hash); len(data) != 0 {
			//		bodies = append(bodies, data)
			//		bytes += len(data)
			//	}
			//} else {
			//	//CRD 获取rlpBodie
			//	data, err := rlp.EncodeToBytes(block.Body())
			//	if err != nil {
			//		log.Error("CRD 获取rlpBodie失败", "err", err)
			//		return nil
			//	}
			//	bodies = append(bodies, data)
			//	bytes += len(data)
			//}
		}
		//log.Info("发回bodies长度", "长度", len(bodies), "peer", p.id, "name", p.Name())
		return p.SendBlockBodiesRLP(bodies)

	case msg.Code == GetBlockBodyMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather blocks until the fetch or network limits is reached
		var (
			hash   common.Hash
			bytes  int
			bodies []rlp.RawValue
		)
		log.Info("收到获取body请求", "peerID", p.id, "name", p.Name())
		for bytes < softResponseLimit && len(bodies) < downloader.MaxBlockFetch {
			// Retrieve the hash of the next block
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested block body, stopping if enough was found
			block := cacheBlock.CacheBlocks.GetBlock(hash)

			// add by liangc : ewasm 重新封包 >>>>
			if block == nil {
				block = pm.blockchain.GetBlockByHash(hash)
				if block == nil {
					log.Error("CRD 获取rlpBodie失败 1")
					break
				}
			}
			block, err := repackBlockTxdata(block)
			if err != nil {
				log.Error("严重错误,应该panic,不接受这种错误repackBlockTxdata(block)", "err", err)
				return nil
			}
			data, err := rlp.EncodeToBytes(block.Body())
			if err != nil {
				log.Error("CRD 获取rlpBodie失败 2", "err", err)
				return nil
			}
			bodies = append(bodies, data)
			bytes += len(data)

		}
		log.Info("发回body长度", "长度", len(bodies), "peer", p.id, "name", p.Name())
		return p.SendBlockBodyRLP(bodies)

	case msg.Code == BlockBodiesMsg:
		// A batch of block bodies arrived to one of our previous requests
		log.Info("receive Bodies", "peerID", p.id, "name", p.Name())
		var request blockBodiesData
		if err := msg.Decode(&request); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Deliver them all to the downloader for queuing
		transactions := make([][]*types.Transaction, len(request))
		uncles := make([][]*types.Header, len(request))

		for i, body := range request {
			// add by liangc : 解包 ewasm tx data
			for j, tx := range body.Transactions {
				ntx, err := unpackTxdata(tx)
				if err != nil {
					log.Error("RecvTxError", "err", err)
					return errResp(ErrDecode, "transaction %d is error ewasm finalcode", i)
				}
				body.Transactions[j] = ntx
			}
			transactions[i] = body.Transactions
			uncles[i] = body.Uncles
		}
		// Filter out any explicitly requested bodies, deliver the rest to the downloader
		filter := len(transactions) > 0 || len(uncles) > 0
		if filter {
			transactions, uncles = pm.fetcher.FilterBodies(p.id, transactions, uncles, time.Now())
		}
		if len(transactions) > 0 || len(uncles) > 0 || !filter {
			err := pm.downloader.DeliverBodies(p.id, transactions, uncles)
			if err != nil {
				log.Debug("Failed to deliver bodies", "err", err)
			}
		}

	case msg.Code == BlockBodyMsg:
		// A batch of block bodies arrived to one of our previous requests
		log.Info("receive Body", "peerID", p.id, "name", p.Name())
		var request blockBodiesData
		if err := msg.Decode(&request); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Deliver them all to the downloader for queuing
		transactions := make([][]*types.Transaction, len(request))
		uncles := make([][]*types.Header, len(request))

		for i, body := range request {
			// add by liangc : 解包 ewasm tx data
			for j, tx := range body.Transactions {
				ntx, err := unpackTxdata(tx)
				if err != nil {
					log.Error("RecvTxError", "err", err)
					return errResp(ErrDecode, "transaction %d is error ewasm finalcode", i)
				}
				body.Transactions[j] = ntx
			}
			transactions[i] = body.Transactions
			uncles[i] = body.Uncles
		}
		// Filter out any explicitly requested bodies, deliver the rest to the downloader
		filter := len(transactions) > 0 || len(uncles) > 0
		if filter {
			transactions, uncles = pm.fetcher.FilterBodies(p.id, transactions, uncles, time.Now())
		}
		if len(transactions) > 0 || len(uncles) > 0 || !filter {
			err := pm.downloader.DeliverBodies(p.id, transactions, uncles)
			if err != nil {
				log.Debug("Failed to deliver bodies", "err", err)
			}
		}
	case p.version >= eth63 && msg.Code == GetNodeDataMsg:
		// Decode the retrieval message
		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather state data until the fetch or network limits is reached
		var (
			hash  common.Hash
			bytes int
			data  [][]byte
		)
		for bytes < softResponseLimit && len(data) < downloader.MaxStateFetch {
			// Retrieve the hash of the next state entry
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested state entry, stopping if enough was found
			if entry, err := pm.blockchain.TrieNode(hash); err == nil {
				data = append(data, entry)
				bytes += len(entry)
			}
		}
		return p.SendNodeData(data)

	case p.version >= eth63 && msg.Code == NodeDataMsg:
		// A batch of node state data arrived to one of our previous requests
		var data [][]byte
		if err := msg.Decode(&data); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		// Deliver all to the downloader
		if err := pm.downloader.DeliverNodeData(p.id, data); err != nil {
			log.Debug("Failed to deliver node state data", "err", err)
		}

	case p.version >= eth63 && msg.Code == GetReceiptsMsg:
		// Decode the retrieval message
		log.Info("收到receipt请求", "id", p.id, "name", p.Name())

		msgStream := rlp.NewStream(msg.Payload, uint64(msg.Size))
		if _, err := msgStream.List(); err != nil {
			return err
		}
		// Gather state data until the fetch or network limits is reached
		var (
			hash     common.Hash
			bytes    int
			receipts []rlp.RawValue
		)
		for bytes < softResponseLimit && len(receipts) < downloader.MaxReceiptFetch {
			// Retrieve the hash of the next block
			if err := msgStream.Decode(&hash); err == rlp.EOL {
				break
			} else if err != nil {
				return errResp(ErrDecode, "msg %v: %v", msg, err)
			}
			// Retrieve the requested block's receipts, skipping if unknown to us
			results := pm.blockchain.GetReceiptsByHash(hash)
			if results == nil {
				if header := pm.blockchain.GetHeaderByHash(hash); header == nil || header.ReceiptHash != types.EmptyRootHash {
					continue
				}
			}
			// If known, encode and queue for response packet
			if encoded, err := rlp.EncodeToBytes(results); err != nil {
				log.Error("Failed to encode receipt", "err", err)
			} else {
				receipts = append(receipts, encoded)
				bytes += len(encoded)
			}
		}
		return p.SendReceiptsRLP(receipts)

	case p.version >= eth63 && msg.Code == ReceiptsMsg:
		// A batch of receipts arrived to one of our previous requests
		var receipts [][]*types.Receipt
		if err := msg.Decode(&receipts); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		log.Info("收到receipt的回复", "id", p.id, "name", p.Name())
		// Deliver all to the downloader
		if err := pm.downloader.DeliverReceipts(p.id, receipts); err != nil {
			log.Debug("Failed to deliver receipts", "err", err)
		}

	case msg.Code == NewBlockHashesMsg:
		var announces newBlockHashesData
		if err := msg.Decode(&announces); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		// Mark the hashes as present at the remote node
		for _, block := range announces {
			p.MarkBlock(block.Hash)
		}
		// Schedule all the unknown hashes for retrieval
		unknown := make(newBlockHashesData, 0, len(announces))
		for _, block := range announces {
			if !pm.blockchain.HasBlock(block.Hash, block.Number) {
				unknown = append(unknown, block)
			}
		}
		//evertrustEng := pm.consensusEngine.(*engine.evertrust)
		//if engine.Majority == engine.Twothirds {
		//	if evertrustEng.GetIslandState() {
		//		return nil
		//	}
		//}

		cuurentNum := pm.blockchain.CurrentBlock().NumberU64()
		for _, block := range unknown {
			if cacheBlock.CacheBlocks.GetBlock(block.Hash) == nil &&
				!cacheBlock.CacheBlocks.CheckBlockHash(block.Hash) &&
				atomic.LoadInt32(&pm.downloader.Synchronis) == 0 {
				if block.Number > cuurentNum {
					//log.Info("收到BlockHash进行远程取块", "hash", block.Hash, "height", block.Number, "current", cuurentNum)
					cacheBlock.CacheBlocks.AddBlockHash(block.Hash) //纪录获取的hash
					pm.fetcher.Notify(p.id, block.Hash, block.Number, time.Now(), p.RequestOneHeader, p.RequestBody)
				}
			}
		}

	case msg.Code == NewBlockMsg:
		if atomic.LoadInt32(&pm.downloader.Synchronis) == 1 {
			//如果正在同步,不进行区块的解析
			return nil
		}
		// Retrieve and decode the propagated block
		var request newBlockData
		if err := msg.Decode(&request); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		log.Debug("====BlockNormal====>>", "msg", msg, "size", msg.Size)

		if request.Block.NumberU64() < pm.blockchain.CurrentBlock().NumberU64() {
			p.MarkBlock(request.Block.Hash())
			log.Error("收到的区块低于当前高度", "本地高度", pm.blockchain.CurrentBlock().NumberU64(), "收到的高度", request.Block.NumberU64(), "收到的hash", request.Block.Hash())
			return nil
		}

		// add by liangc : 判断块是否包含 ewasm 封包，如果有则需要解包 >>>>
		block := request.Block
		txs := block.Transactions()
		for i, tx := range txs {
			rtx, err := unpackTxdata(tx)
			if err != nil {
				return errResp(ErrDecode, "NewBlock ewasm code error : %v", err)
			}
			txs[i] = rtx
		}
		request.Block, err = block.CloneAndResetTxs(txs, false)
		if err != nil {
			return errResp(ErrDecode, "NewBlock CloneAndResetTxs error : %v", err)
		}
		// add by liangc : 判断块是否包含 ewasm 封包，如果有则需要解包 <<<<

		//去重1 查询是否已经保存
		localBlockData := pm.blockchain.SearchingBlock(request.Block.Hash(), request.Block.NumberU64())
		if localBlockData != nil {
			return nil
		}
		//去重2 查询是否已经接收过
		//log.Info("开始去重","高度",request.Block.NumberU64(),"hash",request.Block.Hash())
		if !engine.NormalDeRepetition.Add(request.Block.NumberU64(), request.Block.Hash()) {
			return nil
		}
		//去重3 查询GetBlock
		if cacheBlock.CacheBlocks.GetBlock(request.Block.Hash()) != nil {
			return nil
		}

		request.Block.ReceivedAt = msg.ReceivedAt
		request.Block.ReceivedFrom = p
		blockExtra := evertrust_types.BlockExtraDecode(request.Block)

		if engine.Majority == engine.Twothirds {
			land, _ := engine.LocalLandSetMap.LandMapGet(pm.blockchain.CommitChain.CurrentBlock().NumberU64(), pm.chaindb)
			localIsLandID := land.IslandIDState
			var oneOfMasters bool
			//判断岛屿Id是否一样,如果不一样 直接丢掉
			currentCommitNum := pm.blockchain.CommitChain.CurrentBlock().NumberU64()
			if blockExtra.IsLandID != "" && blockExtra.IsLandID != localIsLandID && currentCommitNum >= 1 {
				consensusQuorum, ok := quorum.CommitHeightToConsensusQuorum.Get(currentCommitNum, pm.chaindb)
				if !ok {
					log.Error("NewBlockMsg quorum.CommitHeightToConsensusQuorum 获取失败")
					return nil
				}
				for _, address := range consensusQuorum.Keys() {
					if request.Block.Coinbase().String() == address {
						oneOfMasters = true
						break
					}
					quorumLen := consensusQuorum.Len()
					if !oneOfMasters || quorumLen != 1 {
						//本地大陆,收到岛屿,判断父hash是否和本地currenthash相同,如果相同,直接接收
						if request.Block.ParentHash() != pm.blockchain.CurrentBlock().Hash() {
							log.Error("收到无效的岛屿块,直接丢掉", "高度", request.Block.NumberU64(), "父hash", request.Block.ParentHash())
							return nil
						}
					}
				}
			}
		}

		// Mark the peer as owning the block and schedule it for import
		log.Info("receive Normal block", "Num", request.Block.NumberU64(), "Rank", blockExtra.Rank, "Hash", request.Block.Hash(), "size", request.Block.Size())
		p.MarkBlock(request.Block.Hash())
		pm.fetcher.Enqueue(p.id, request.Block)
		//cache block for
		pm.blockchain.CacheBlock(request.Block)

		// Assuming the block is importable by the peer, but possibly not yet done so,
		// calculate the head hash and TD that the peer truly must have.
		var (
			trueHead = request.Block.ParentHash()
			trueTD   = new(big.Int).Sub(request.TD, request.Block.Difficulty())
			trueNum  = request.CommitNum
		)
		// Update the peers total difficulty if better than the previous
		if _, td := p.Head(); trueTD.Cmp(td) > 0 {
			p.SetHead(trueHead, trueTD, trueNum)

			currentBlock := pm.blockchain.CurrentBlock()
			getTd := pm.blockchain.GetTd(currentBlock.Hash(), currentBlock.NumberU64())
			if getTd == nil {
				getTd = big.NewInt(0)
			}
		}

	case msg.Code == TxMsg:
		if atomic.LoadInt32(&pm.downloader.Synchronis) != 0 {
			return nil
		}
		// Transactions arrived, make sure we have a valid and fresh chain to handle them
		if atomic.LoadUint32(&pm.acceptTxs) == 0 {
			break
		}
		// Transactions can be processed, parse all of them and deliver to the pool
		var txs []*types.Transaction
		if err := msg.Decode(&txs); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		for i, tx := range txs {
			//log.Info("receive tx Msg", "tx hash", tx.Hash())
			// Validate and mark the remote transaction
			if tx == nil {
				return errResp(ErrDecode, "transaction %d is nil", i)
			}
			// add by liangc : 解包 ewasm tx data
			ntx, err := unpackTxdata(tx)
			if err != nil {
				log.Error("RecvTxError", "err", err)
				return errResp(ErrDecode, "transaction %d is error ewasm finalcode", i)
			}
			txs[i] = ntx
			p.MarkTransaction(ntx.Hash())
		}

		//go pm.txpool.AddRemotes(txs)
		//pm.addTxCh<-txs
		select {
		case pm.addTxCh <- txs:
		default:
			log.Info("add tx channel is full!!!!", "len", len(pm.addTxCh))
		}

		//CRD: call evertrust consensus engine
	case msg.Code == BlockAssertMsg:
		var assert evertrust_types.AssertExtra
		err := msg.Decode(&assert)
		log.Info("查询assertion的大小", "size", msg.Size)

		if err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		if evertrust, ok := pm.consensusEngine.(*engine.Evertrust); ok {

			err := evertrust.OnAssertBlock(assert, p.Name())
			if err != nil {
				return err
			}
		}

		//CRD 接收commitHash
	case msg.Code == NewCommitBlockHashesMsg:
		var announces newCommitBlockHashesData
		if err := msg.Decode(&announces); err != nil {
			return errResp(ErrDecode, "%v: %v", msg, err)
		}
		// Schedule all the unknown hashes for retrieval
		unknown := make(newCommitBlockHashesData, 0, len(announces))
		for _, block := range announces {
			if !pm.blockchain.CommitChain.HasBlock(block.Hash, block.Number) {
				unknown = append(unknown, block)
			}
		}
		currentNum := pm.blockchain.CommitChain.CurrentBlock().NumberU64()
		for _, block := range unknown {
			if cacheBlock.CacheBlocks.GetBlock(block.Hash) == nil && !cacheBlock.CacheBlocks.CheckBlockHash(block.Hash) {
				if block.Number > currentNum && atomic.LoadInt32(&pm.downloader.Synchronis) == 0 {
					log.Info("收到CommitBlockHash进行远程取块", "hash", block.Hash, "height", block.Number, "current", currentNum)
					cacheBlock.CacheBlocks.AddBlockHash(block.Hash) //纪录获取的hash
					pm.commitFetcher.Notify(p.id, block.Hash, block.Number, time.Now(), p.RequestCommitsByHash)
				}
			}
		}

	case msg.Code == BlockCommitMsg:
		log.Debug("====BlockCommitMsg====>>", "msg", msg, "sync", atomic.LoadInt32(&pm.downloader.Synchronis))
		if atomic.LoadInt32(&pm.downloader.Synchronis) == 1 {
			//如果正在同步,不进行区块的解析
			return nil
		}
		// add by liangc : 收到 commitMsg 时启动 Advertise
		p2p.SendAlibp2pAdvertiseEvent(&p2p.AdvertiseEvent{Start: true, Period: 60 * time.Second})

		var commitBlock types.Block
		if err := msg.Decode(&commitBlock); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		if !pm.verifyRepeatCommitBlock(commitBlock) {
			return nil
		}
		blockExtra, _ := evertrust_types.CommitExtraDecode(&commitBlock)
		log.Debug("receive broadcast commit block ", "num:", commitBlock.NumberU64(), "hash", commitBlock.Hash().Hex(), "rank", blockExtra.Rank, "收到的islandID", blockExtra.IsLandID)
		commitBlock.ReceivedAt = msg.ReceivedAt
		commitBlock.ReceivedFrom = p

		if engine.Majority == engine.Twothirds {
			err := pm.verifyCommitBlockIsland(commitBlock, p)
			if err != nil {
				log.Error("broadcast verifyCommitBlockIsland is error", "err", err)
				return nil
			}
		} else {
			pm.commitFetcher.Enqueue(p.id, []*types.Block{&commitBlock})
			currentBlock := pm.blockchain.CommitChain.CurrentBlock()
			//_, commitExtraDecode := evertrust_types.CommitExtraDecode(currentBlock)
			if commitBlock.NumberU64() > currentBlock.NumberU64()+2 {
				if atomic.LoadInt32(&pm.downloader.Synchronis) == 0 {
					log.Info("broadcastCommit 半路发现有差距,进行commit同步", "currentNum", currentBlock.NumberU64()+1, "receiveCommitNum", commitBlock.NumberU64())
					_, commitExtra := evertrust_types.CommitExtraDecode(currentBlock)
					go pm.synchroniseCommit(p, false, &commitBlock, downloader.CommitAssertionSum{commitExtra.AssertionSum, commitBlock.Number()})
				}
			}
		}

	case msg.Code == CommitSyncBlocksMsg: //commit最新高度
		var commitBlocks []*types.Block
		if err := msg.Decode(&commitBlocks); err != nil {
			log.Error("decode err", "err", err.Error())
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		pm.downloader.DeliverCommits(p.id, commitBlocks)

	case msg.Code == CommitBlocksMsg:
		log.Debug("---CommitBlocksMsg--->", "msg", msg, "sync", atomic.LoadInt32(&pm.downloader.Synchronis))
		if atomic.LoadInt32(&pm.downloader.Synchronis) == 1 {
			//如果正在同步,不进行区块的解析
			return nil
		}

		// add by liangc : 收到 commitMsg 时启动 Advertise
		p2p.SendAlibp2pAdvertiseEvent(&p2p.AdvertiseEvent{Start: true, Period: 60 * time.Second})

		var commitBlocks []*types.Block
		if err := msg.Decode(&commitBlocks); err != nil {
			log.Error("decode err", "err", err.Error())
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		if len(commitBlocks) > 0 {
			log.Info("receive sync commitblocks msg", "firstNum", commitBlocks[0].NumberU64(), "hash", commitBlocks[0].Hash().Hex())
			for _, block := range commitBlocks {
				block.ReceivedAt = msg.ReceivedAt
				block.ReceivedFrom = p
				if !pm.verifyRepeatCommitBlock(*block) {
					log.Info("CommitBlocksMsg重复接收")
					return nil
				}
				if engine.Majority == engine.Twothirds {
					err := pm.verifyCommitBlockIsland(*block, p)
					if err != nil {
						log.Error("HashCommit verifyCommitBlockIsland is error", "err", err)
						return nil
					}
				} else {
					pm.commitFetcher.Enqueue(p.id, []*types.Block{block})
					currentBlock := pm.blockchain.CommitChain.CurrentBlock()
					//_, commitExtraDecode := evertrust_types.CommitExtraDecode(currentBlock)
					//log.Info("当前岛屿状态", "存储的是否是岛屿", localIslandState, "当前高度", currentBlock.NumberU64(), "当前的commit状态", commitExtraDecode.Island)
					if block.NumberU64() > currentBlock.NumberU64()+2 {
						if atomic.LoadInt32(&pm.downloader.Synchronis) == 0 {
							log.Info("HashCommit 半路发现有差距,进行commit同步", "currentNum", currentBlock.NumberU64()+1, "receiveCommitNum", block.NumberU64())
							_, commitExtra := evertrust_types.CommitExtraDecode(block)
							go pm.synchroniseCommit(p, false, block, downloader.CommitAssertionSum{commitExtra.AssertionSum, block.Number()})
							break
						}
					}
				}
			}
		}

	case msg.Code == AssociatedCommitBlocksMsg:
		var commitBlocks []*types.Block
		if err := msg.Decode(&commitBlocks); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		if len(commitBlocks) > 0 {
			for _, block := range commitBlocks {
				log.Info("commitBlocks", "commit高度", block.NumberU64(), "hash", block.Hash())
				block.ReceivedAt = msg.ReceivedAt
				block.ReceivedFrom = p
			}
			pm.downloader.ProcessCommitChAssociated <- commitBlocks
			log.Info("半生传输完毕", "commitBlocks长度", len(commitBlocks))
		}

	case msg.Code == GetBlocksByHashMsg:
		var request CachedBlocksRequest
		var response cachedBlocksResponse
		if err := msg.Decode(&request); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		log.Info("receive cached blocks from remote request", "requestId", request.RequestId)
		hashes := request.Hashes
		for _, hash := range hashes {
			block := pm.blockchain.GetCacheBlock(*hash)
			if block != nil {
				log.Info("找到的block进行回传", "block", block.Hash().Hex(), "高度", block.NumberU64())
				// add by liangc : 这个包既然存储在本地了，那么重新封包一定是成功的
				block, _ = repackBlockTxdata(block)
				response.Blocks = append(response.Blocks, block)
			} else {
				// 不全就直接返回
				log.Info("not find block", "block", hash.Hex(), "reqId", request.RequestId, "peer", p.id)
				return nil
			}
		}
		response.RequestId = request.RequestId
		err := p.SendCachedBlocksByHash(response)
		if err != nil {
			log.Error("rlp err", "err", err.Error())
		}
	case msg.Code == BlocksByHashMsg:
		var response cachedBlocksResponse
		if err := msg.Decode(&response); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		log.Info("receive cached blocks from remote response", "requestId", response.RequestId)
		//cache blocks
		log.Info("BlocksByHashMsg传来的normal块", "response", len(response.Blocks))
		for i, block := range response.Blocks {
			log.Info("BlocksByHashMsg传来的normal块是", "高度", block.NumberU64(), "hash", block.Hash().Hex())
			// add by liangc : 解包 ewasm >>>>
			txs := block.Transactions()
			for j, tx := range txs {
				ntx, err := unpackTxdata(tx)
				if err != nil {
					// 除非作恶，否则这里一定会成功
					return errResp(ErrDecode, "BlocksByHashMsg unpackTxdata error : %v", err)
				}
				txs[j] = ntx
			}
			block, err = block.CloneAndResetTxs(txs, false)
			if err != nil {
				// 除非作恶，否则这里一定会成功
				return errResp(ErrDecode, "BlocksByHashMsg CloneAndResetTxs error : %v", err)
			}
			response.Blocks[i] = block
			// add by liangc : 解包 ewasm <<<<
		}

		//notify infection
		pm.infection.responseCh <- response

	case msg.Code == syncBlockPathMsg:
		var path []common.Hash
		//var blocks []*types.Block
		var headers []*types.Header
		if err := msg.Decode(&path); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}

		//根据path中的hash获取block
		for _, hash := range path {
			block := cacheBlock.CacheBlocks.GetBlock(hash)
			if block == nil {
				block = pm.blockchain.GetBlockByHash(hash)
				if block == nil {
					log.Error("syncBlockPathMsg没有找到对应的区块", "hash", hash)
					p.SendBlockHeaders(headers)
					//如果有一个块是空,直接返回空,再找其他节点进行同步
					return nil
				}
			}
			headers = append(headers, block.Header())
		}
		p.SendBlockHeaders(headers)

	case msg.Code == BlockSyncInPathMsg:
		var blocks []*types.Block
		if err := msg.Decode(&blocks); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		log.Info("根据path拿到的block", "block", blocks)
		pm.downloader.SyncInBlockPathCh <- blocks

	case msg.Code == ReceiptsIsland:
		//取出带有restoreLand交易的区块
		var restoreLandParam vm.RestoreLandParam
		var blocks []*types.Block
		stateDB, _ := pm.blockchain.State()
		byte := stateDB.GetCRDState(utils.QuorumResetContract, utils.QuorumResetContract.Hash())
		json.Unmarshal(byte, &restoreLandParam)
		for _, height := range restoreLandParam.TxBlockNum {

			block := pm.blockchain.GetBlockByNumber(height)
			blocks = append(blocks, block)
		}
		p.SendIslandBlock(blocks)
	case msg.Code == SendIslandLand:
		var blocks []*types.Block
		if err := msg.Decode(&blocks); err != nil {
			return errResp(ErrDecode, "msg %v: %v", msg, err)
		}
		log.Info("待验证的restoreIslnadBlock", len(blocks))
		pm.downloader.IslandCH <- blocks

	default:
		return errResp(ErrInvalidMsgCode, "%v", msg.Code)
	}
	return nil
}

func (pm *ProtocolManager) verifyRepeatCommitBlock(block types.Block) bool {
	self := pm.blockchain.CommitChain.SearchingBlock(block.Hash(), block.NumberU64())
	if self != nil {
		return false
	}
	//去重2 查询是否已经接收过
	if !engine.CommitDeRepetition.Add(block.NumberU64(), block.Hash()) {
		return false
	}
	//去重3 查询ca
	if cacheBlock.CacheBlocks.GetBlock(block.Hash()) != nil {
		return false
	}
	return true
}

func (pm *ProtocolManager) verifyCommitBlockIsland(commitBlock types.Block, p *peer) error {
	blockExtra, commitExtra := evertrust_types.CommitExtraDecode(&commitBlock) //收到的commitExtra
	commitExtraIsland := commitExtra.Island                                 //接收的commit是否是岛屿
	currentNum := pm.blockchain.CommitChain.CurrentBlock().Number()
	//evertrustEng := pm.consensusEngine.(*engine.evertrust)
	//localIslandID, localIslandState, _, _, _, _ := engine.IslandLoad(evertrustEng)
	var localIslandID string
	var localIslandState bool
	land, _ := engine.LocalLandSetMap.LandMapGet(currentNum.Uint64(), pm.chaindb)
	localIslandID = land.IslandIDState
	localIslandState = land.IslandState
	localAssertionSum, err := cacheBlock.CommitAssertionSum.GetAssertionSum(currentNum, pm.chaindb)
	if err != nil {
		log.Warn("verifyCommitBlockIsland GetAssertionSum", "err", err)
		localAssertionSum = big.NewInt(0)
	}
	log.Info("开始验证commitBlock", "高度", commitBlock.NumberU64())
	p.MarkCommitBlock(commitBlock.Hash())
	pm.commitFetcher.Enqueue(p.id, []*types.Block{&commitBlock})
	currentBlock := pm.blockchain.CommitChain.CurrentBlock()

	//判断本地是大陆还是岛屿
	switch localIslandState {

	case true:
		//本地岛屿 不能重复接收commit块
		if commitExtraIsland {
			//收到的是岛屿块跟自己不是同岛进行合并
			log.Info("收到的岛屿ID", "收到岛屿ID", blockExtra.IsLandID, "本地岛屿ID", localIslandID)
			if localIslandID != blockExtra.IsLandID {
				switch {
				case localAssertionSum.Cmp(commitExtra.AssertionSum) >= 0:
					//本地收到的assertion多,直接扔掉,如果等于证明比自己收到的assertion少
					log.Error("收到的commit块assertion比本地少直接丢弃", "本地assertion", localAssertionSum, "远端的assertion", commitExtra.AssertionSum)
					return nil
				case localAssertionSum.Cmp(commitExtra.AssertionSum) < 0:
					//本地岛屿 不用验证收到的commit
					if commitBlock.ParentHash().Hex() != currentBlock.Hash().Hex() {
						//找不到父hash 进行同步,
						go pm.synchroniseCommit(p, false, nil, downloader.CommitAssertionSum{commitExtra.AssertionSum, commitBlock.Number()})
					}
					log.Info("岛屿和岛屿找到了父块,可以直接进入存块流程")
				}

			} else {
				//如果是同一岛屿,正常往下进行
				log.Info("收到的岛屿ID与自己相同", "岛屿ID", blockExtra.IsLandID)

			}
		} else {
			//收到的是大陆块是 合并
			log.Info("本地是岛屿,收到了大陆块,需要去同步大陆块", "收到的commit高度", commitBlock.NumberU64(), "父hash", commitBlock.ParentHash())
			prentCommitBlock := pm.blockchain.CommitChain.SearchingBlock(commitBlock.ParentHash(), commitBlock.NumberU64()-1)
			//如果找到父块,并且等于当前hash,证明没有裂脑正常往下进行
			if prentCommitBlock != nil && prentCommitBlock.Hash() == pm.blockchain.CommitChain.CurrentBlock().Hash() {
				log.Info("找到commit父块,继续进行,不回滚")
				//atomic.StoreInt32(&commitIslandSync, 0)
			} else {
				go pm.synchroniseCommit(p, false, &commitBlock, downloader.CommitAssertionSum{commitExtra.AssertionSum, commitBlock.Number()})
				//atomic.StoreInt32(&commitIslandSync, 0)
				return nil
			}
		}

	case false:
		//本地大陆
		if commitExtraIsland {
			//查看下父hash是否能找到,如果能找到,就收下,并且比自己高度高
			if block := pm.blockchain.CommitChain.GetBlock(commitBlock.ParentHash(), commitBlock.NumberU64()-1); block == nil {
				log.Error("commit本地是大陆,收到了岛屿块,直接丢掉", "收到的commit高度", commitBlock.NumberU64(), "本地高度", currentNum.Uint64())
				return nil
			}
			if commitBlock.NumberU64() < pm.blockchain.CommitChain.CurrentBlock().NumberU64() {
				log.Error("commit本地是大陆,收到了比自己小的岛屿块,直接丢掉", "收到的commit高度", commitBlock.NumberU64())
				return nil
			}
		}
	}
	//收到的是大陆块 正常保存
	log.Info("本地岛屿状态", "本地存储的是否是岛屿", localIslandState, "本地高度", currentBlock.NumberU64())
	//if commitBlock.NumberU64() > currentBlock.NumberU64()+2 {  //去掉高度限制
	if commitBlock.ParentHash().Hex() != currentBlock.Hash().Hex() {
		sum, err := cacheBlock.CommitAssertionSum.GetAssertionSum(currentBlock.Number(), pm.chaindb)
		if err != nil || sum == nil {
			log.Warn("GetAssertionSum fail", "err", err)
			sum = big.NewInt(0)
		}
		//如果收到相同高度,不同rank的区块,本地存的是大陆块, 不需要触发同步
		if !localIslandState && currentBlock.NumberU64() == commitBlock.NumberU64() {
			return nil
		}
		//没有进行同步,并且过来的assertion比自己本地高
		if atomic.LoadInt32(&pm.downloader.Synchronis) == 0 && commitExtra.AssertionSum.Cmp(sum) == 1 {
			log.Info("半路发现有差距,进行commit同步", "currentNum", currentBlock.NumberU64()+1, "receiveCommitNum", commitBlock.NumberU64(), "commitExtra.AssertionSum", commitExtra.AssertionSum, "sum", sum)
			go pm.synchroniseCommit(p, false, &commitBlock, downloader.CommitAssertionSum{commitExtra.AssertionSum, commitBlock.Number()})

		}
	}

	//}
	return nil
}

// BroadcastBlock will either propagate a block to a subset of it's peers, or
// will only announce it's availability (depending what's requested).
func (pm *ProtocolManager) BroadcastBlock(block *types.Block, propagate bool) {
	hash := block.Hash()
	peers := pm.peers.PeersWithoutBlock(hash)

	if len(peers) == 0 {
		return
	}

	// If propagation is requested, send to a subset of the peer
	if propagate {
		// Calculate the TD of the block (it's not imported yet, so block.Td is not valid)
		var td *big.Int
		if parent := pm.blockchain.GetBlock(block.ParentHash(), block.NumberU64()-1); parent != nil {
			parentTd := pm.blockchain.GetTd(block.ParentHash(), block.NumberU64()-1)
			if parentTd == nil {
				log.Error("parentTd nil", "hash", block.ParentHash().String(), "num", block.NumberU64()-1)
				return
			}
			td = new(big.Int).Add(block.Difficulty(), parentTd)
		} else {
			log.Error("Propagating dangling block", "number", block.Number(), "hash", hash)
			return
		}
		// Send the block to a subset of our peers
		var transfer []*peer
		if len(peers) >= 4 {
			transfer = peers[:int(math.Sqrt(float64(len(peers))))]
		} else {
			// CRD 发送所有节点
			transfer = peers
		}
		//log.Debug("ProtocolManager.BroadcastBlock >>", "peers", len(peers), "transfer", len(transfer))
		for _, peer := range transfer {
			peer.AsyncSendNewBlock(block, td, pm.blockchain.CommitChain.CurrentBlock().NumberU64())
		}
		return
	} else {
		// Otherwise if the block is indeed in out own chain, announce it
		//if pm.blockchain.HasBlock(hash, block.NumberU64()) {
		for _, peer := range peers {
			//log.Info("广播区块hash", "peer", peer, "block", block.NumberU64())
			peer.AsyncSendNewBlockHash(block)
		}
	}
}

// BroadcastCommit will propagate a "commit" block to all of it's peers
func (pm *ProtocolManager) BroadcastCommit(commitBlock *types.Block) {
	if atomic.LoadInt32(&pm.downloader.Synchronis) == 1 {
		log.Debug("正在同步,不进行commit广播")
		return
	}
	hash := commitBlock.Hash()
	peers := pm.peers.PeersWithoutCommitBlock(hash)

	if len(peers) == 0 {
		return
	}
	var transfer []*peer
	if len(peers) >= 4 {
		transfer = peers[:int(math.Sqrt(float64(len(peers))))]
	} else {
		// CRD 发送所有节点
		transfer = peers
	}
	for _, peer := range transfer {
		p2p.Send(peer.rw, BlockCommitMsg, commitBlock)
	}
	peers = pm.peers.PeersWithoutCommitBlock(hash)
	log.Info("发送commitHahs", "peer数量", len(peers))
	for _, peer := range peers {
		peer.MarkCommitBlock(hash)
		peer.SendNewCommitBlockHashes([]common.Hash{hash}, []uint64{commitBlock.NumberU64()})
	}
	log.Info("发送commitHahs发送完成", "高度", commitBlock.NumberU64())
}

// MulticastAssert will multicast a block assertion to a list of peers
func (pm *ProtocolManager) MulticastAssert(assert evertrust_types.AssertExtra, nodes []discover.NodeID, assertionEvent event.Subscription) {
	log.Info("multicast assert start", "node长度", len(nodes))
	for _, node := range nodes {
		to, _ := node.Pubkey()
		taddr := crypto.PubkeyToAddress(*to)
		err := p2p.Send(to, BlockAssertMsg, assert)
		now := time.Now().Unix()
		log.Debug("XXXXX MulticastAssert ======>>>===>>>===>>",
			"ts", now,
			"taddr", taddr.Hex(),
			"assert-hash", types.RlpHash(assert),
			"err", err)
	}
}

// BroadcastTxs will propagate a batch of transactions to all peers which are not known to
// already have the given transaction.
func (pm *ProtocolManager) BroadcastTxs(txs types.Transactions) {
	var txset = make(map[*peer]types.Transactions)

	// Broadcast transactions to a batch of peers not knowing about it
	for _, tx := range txs {
		//查询peer列表
		peers := pm.peers.PeersWithoutTx(tx.Hash())
		var transfer []*peer
		switch {
		case len(peers) <= 4:
			// peer列表小于等于4 全部广播
			transfer = peers
		default:
			var filter []*peer
			//查询当前高度委员会,peer列表大于4 过滤委员会
			consensusQuorum, _ := quorum.CommitHeightToConsensusQuorum.Get(pm.blockchain.CommitChain.CurrentBlock().NumberU64(), pm.chaindb)
			for _, peer := range peers {
				add := cacheBlock.AddrAndPubkeyMap.PeerIDAddrMapGet(peer.id)
				if consensusAdd := consensusQuorum.Get(add.String()); consensusAdd != quorum.EmptyAddress {
					transfer = append(transfer, peer)
				} else {
					filter = append(filter, peer)
				}
			}

			switch {
			case len(transfer) < 4:
				//过滤后小于4  补齐4个后广播
				for i := 0; len(transfer) <= 4; i++ {
					transfer = append(transfer, filter[i])
				}
			case len(transfer) > 16:
				//过滤后大于16 按照平方根发送发
				transfer = transfer[:int(math.Sqrt(float64(len(transfer))))]

			default:
				//过滤后大于4 小于16  按4个随机广播
				transfer = transfer[:4]

			}

		}

		for _, peer := range transfer {
			txset[peer] = append(txset[peer], tx)
		}
			log.Info("Broadcast transaction", "nonce", tx.Nonce(),"hash", tx.Hash(), "recipients", transfer)

	}

	//for _, tx := range txs {
	//	peers := pm.peers.PeersWithoutTx(tx.Hash())
	//	var transfer []*peer
	//	if utils.IsBaapChainIaas(tx.To()) {
	//		transfer = peers
	//	}else {
	//		peersLen := len(peers)
	//		if peersLen >= 64 { // len >= 64
	//			transfer = peers[:int(math.Sqrt(float64(len(peers))))]
	//		}else {
	//			if peersLen <= 8 { // len <= 8
	//				transfer = peers
	//			}else { // 8 < len < 64
	//				transfer = peers[:8]
	//			}
	//		}
	//	}
	//
	//	for _, peer := range transfer {
	//		txset[peer] = append(txset[peer], tx)
	//	}
	//	log.Info("Broadcast transaction", "nonce", tx.Nonce(),"hash", tx.Hash(), "recipients", transfer)
	//}
	// FIXME include this again: peers = peers[:int(math.Sqrt(float64(len(peers))))]
	for peer, txs := range txset {
		peer.AsyncSendTransactions(txs)
	}
}

// Mined broadcast loop
func (pm *ProtocolManager) minedBroadcastLoop() {
	// automatically stops if unsubscribe
	//for obj := range pm.minedBlockSub.Chan() {
	//	if ev, ok := obj.Data.(core.NewMinedBlockEvent); ok {
	//		pm.BroadcastBlock(ev.Block, true)  // First propagate block to peers
	//		pm.BroadcastBlock(ev.Block, false) // Only then announce to the rest
	//	}
	//}

	for {
		select {
		case block := <-pm.NormalBroadcast:

			pm.BroadcastBlock(block, true)  // First propagate block to peers
			pm.BroadcastBlock(block, false) // Only then announce to the rest
		}
	}

}

// Commit broadcast loop
func (pm *ProtocolManager) commitBroadcastLoop() {
	// automatically stops if unsubscribe
	for {
		select {
		case block := <-pm.CommitBroadcast:
			log.Info("开始广播commitBlock")
			pm.BroadcastCommit(block)
		}
	}

}

// Assert multicast loop
func (pm *ProtocolManager) assertMulticastLoop() {
	// automatically stops if unsubscribe
	//for obj := range pm.assertBlockSub.Chan() {
	//	if ev, ok := obj.Data.(evertrust_types.NewAssertBlockEvent); ok {
	//		go pm.MulticastAssert(ev.Block, ev.Nodes, nil)
	//	}
	//}
	for {
		select {
		case assert := <-pm.AssertionBroadcast:
			log.Info("开始广播commitBlock")
			go pm.MulticastAssert(assert.Assert, assert.Nodes, nil)
		}
	}
}

func (pm *ProtocolManager) txBroadcastLoop() {
	for {
		select {
		case event := <-pm.txsCh:
			//log.Debug("broadcast txs", "len of ch", len(pm.txsCh))
			pm.BroadcastTxs(event.Txs)
			// Err() channel will be closed when unsubscribing.
		case <-pm.txsSub.Err():
			return
		}
	}
}

// NodeInfo represents a short summary of the Ethereum sub-protocol metadata
// known about the host peer.
type NodeInfo struct {
	Network    uint64              `json:"network"`    // Ethereum network ID (1=Frontier, 2=Morden, Ropsten=3, Rinkeby=4)
	Difficulty *big.Int            `json:"difficulty"` // Total difficulty o the host's blockchain
	Genesis    common.Hash         `json:"genesis"`    // SHA3 hash of the host's genesis block
	Config     *params.ChainConfig `json:"config"`     // Chain configuration for the fork rules
	Head       common.Hash         `json:"head"`       // SHA3 hash of the host's best owned block
}

// NodeInfo retrieves some protocol metadata about the running host node.
func (pm *ProtocolManager) NodeInfo() *NodeInfo {
	currentBlock := pm.blockchain.CurrentBlock()
	return &NodeInfo{
		Network:    pm.networkID,
		Difficulty: pm.blockchain.GetTd(currentBlock.Hash(), currentBlock.NumberU64()),
		Genesis:    pm.blockchain.Genesis().Hash(),
		Config:     pm.blockchain.Config(),
		Head:       currentBlock.Hash(),
	}
}

func (pm *ProtocolManager) broadcastAddTx() *NodeInfo {
	for {
		select {
		case txs := <-pm.addTxCh:
			//log.Trace("来交易了","通道长度",len(pm.addTxCh))
			pm.txpool.AddRemotes(txs)
		}
	}
}

func (pm *ProtocolManager) SubscribeAssertionNewFeed(ch chan<- *peer) event.Subscription {
	return pm.AssertionNewFeed.Subscribe(ch)
}

func unpackTxdata(tx *types.Transaction) (*types.Transaction, error) {
	ewasmtool := utils.EwasmToolImpl
	if tx.To() == nil && ewasmtool.IsWASM(tx.Data()) {
		finalcode := tx.Data()
		code, final, err := ewasmtool.SplitTxdata(finalcode)
		if err != nil {
			log.Error("RecvTxError", "err", err)
			return nil, err
		}
		codekey := utils.EwasmToolImpl.GenCodekey(code)
		finalkey := crypto.Keccak256(final)
		utils.EwasmToolImpl.PutCode(finalkey, final)
		utils.EwasmToolImpl.PutCode(codekey, finalkey)
		// 还原
		ntx, err := tx.CloneAndResetPayload(code)
		log.Debug("unpackTxdata->",
			"err", err,
			"txhash", ntx.Hash(),
			"codekey", hex.EncodeToString(codekey),
			"code", len(ntx.Data()),
			"final", len(final),
			"finalcode", len(finalcode))
		return ntx, err
	}
	return tx, nil
}
