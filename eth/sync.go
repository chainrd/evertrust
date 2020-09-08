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
	"math/rand"
	"CRD-chain/p2p"
	"sync/atomic"
	"time"

	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/eth/downloader"
	"CRD-chain/log"
	"CRD-chain/p2p/discover"
)

const (
	forceSyncCycle      = 10 * time.Second // Time interval to force syncs, even if few peers are available
	minDesiredPeerCount = 5                // Amount of peers desired to start syncing

	// This is the target size for the packs of transactions sent by txsyncLoop.
	// A pack can get larger than this if a single transactions exceeds this size.
	txsyncPackSize = 100 * 1024
)

type txsync struct {
	p   *peer
	txs []*types.Transaction
}

// syncTransactions starts sending all currently pending transactions to the given peer.
func (pm *ProtocolManager) syncTransactions(p *peer) {
	var txs types.Transactions
	pending, _ := pm.txpool.Pending()
	for _, batch := range pending {
		txs = append(txs, batch...)
	}
	if len(txs) == 0 {
		return
	}
	select {
	case pm.txsyncCh <- &txsync{p, txs}:
	case <-pm.quitSync:
	}
}

// txsyncLoop takes care of the initial transaction sync for each new
// connection. When a new peer appears, we relay all currently pending
// transactions. In order to minimise egress bandwidth usage, we send
// the transactions in small packs to one peer at a time.
func (pm *ProtocolManager) txsyncLoop() {
	var (
		pending = make(map[discover.NodeID]*txsync)
		sending = false               // whether a send is active
		pack    = new(txsync)         // the pack that is being sent
		done    = make(chan error, 1) // result of the send
	)

	// send starts a sending a pack of transactions from the sync.
	send := func(s *txsync) {
		// Fill pack with transactions up to the target size.
		size := common.StorageSize(0)
		pack.p = s.p
		pack.txs = pack.txs[:0]
		for i := 0; i < len(s.txs) && size < txsyncPackSize; i++ {
			if s.txs[i] == nil {
				continue
			}
			pack.txs = append(pack.txs, s.txs[i])
			size += s.txs[i].Size()
		}
		// Remove the transactions that will be sent.
		s.txs = s.txs[:copy(s.txs, s.txs[len(pack.txs):])]
		if len(s.txs) == 0 {
			delete(pending, s.p.ID())
		}
		// Send the pack in the background.
		s.p.Log().Trace("Sending batch of transactions", "count", len(pack.txs), "bytes", size)
		sending = true
		go func() { done <- pack.p.SendTransactions(pack.txs) }()
	}

	// pick chooses the next pending sync.
	pick := func() *txsync {
		if len(pending) == 0 {
			return nil
		}
		n := rand.Intn(len(pending)) + 1
		for _, s := range pending {
			if n--; n == 0 {
				return s
			}
		}
		return nil
	}

	for {
		select {
		case s := <-pm.txsyncCh:
			pending[s.p.ID()] = s
			if !sending {
				send(s)
			}
		case err := <-done:
			sending = false
			// Stop tracking peers that cause send failures.
			if err != nil {
				pack.p.Log().Debug("Transaction send failed", "err", err)
				delete(pending, pack.p.ID())
			}
			// Schedule the next send.
			if s := pick(); s != nil {
				send(s)
			}
		case <-pm.quitSync:
			return
		}
	}
}

// syncer is responsible for periodically synchronising with the network, both
// downloading hashes and blocks as well as handling the announcement handler.
func (pm *ProtocolManager) syncer() {
	// Start and ensure cleanup of sync mechanisms
	pm.fetcher.Start()
	pm.commitFetcher.Start()
	defer pm.fetcher.Stop()
	defer pm.commitFetcher.Stop()
	defer pm.downloader.Terminate()

	// Wait for different events to fire synchronisation operations
	forceSync := time.NewTicker(forceSyncCycle)
	defer forceSync.Stop()

	for {
		select {
		case <-pm.newPeerCh:
			// Make sure we have peers to select from, then sync
			//if pm.peers.Len() < minDesiredPeerCount {
			//	break
			//}
			//if pm.blockchain.CurrentBlock().NumberU64() <= 1 && pm.downloader.Synchronis == 0 {
			//	time.Sleep(100 * time.Millisecond) //等待peer节点注册,然后进行同步
			//	log.Info("新节点注册")
			//
			//	firstMiner := pm.blockchain.GetBlockByNumber(0).Extra()
			//	if pm.downloader.Worker.Signer().Hash() == common.BytesToAddress(firstMiner).Hash() {
			//		break
			//	}
			//	go pm.synchroniseCommit(pm.peers.SyncPeer(), false, nil, downloader.CommitAssertionSum{nil, big.NewInt(0)})
			//}

		case <-forceSync.C:
			//// Force a sync even if not enough peers are present
			//if !engine.IslandState.Load().(bool) && atomic.LoadUint32(&pm.fastSync) == 0&&pm.blockchain.CurrentBlock().NumberU64()>1 {
			//	log.Info("时间到了,开始同步")
			//	go pm.synchroniseCommit(pm.peers.SyncPeer(), true,nil)
			//}

		case <-pm.noMorePeers:
			return
		}
	}
}

// synchronise tries to sync up our local block chain with a remote peer.
func (pm *ProtocolManager) synchronise(peer *peer) {
	// Short circuit if no peers are available
	if peer == nil {
		log.Error("sync return : peer is nil ")
		return
	}
	// Make sure the peer's TD is higher than our own
	//currentBlock := pm.blockchain.CurrentBlock()
	////td := pm.blockchain.GetTd(currentBlock.Hash(), currentBlock.NumberU64())
	//
	pHead, pTd := peer.Head()
	//localCommitNum := pm.blockchain.CommitChain.CurrentBlock().NumberU64()
	//localNormalNum := currentBlock.NumberU64()
	//cNum:=atomic.LoadUint64(&peer.CommitNum)
	//log.Debug("节点信息", "peerCommit高度",cNum , "本地commit高度", localCommitNum,
	//	"peerNormal高度", normalNum, "本地Normal高度", localNormalNum)
	//
	//if normalNum != 0 && cNum <= localCommitNum && normalNum <= localNormalNum {
	//	log.Debug("sync return :peer join in or force sync", "peer的commit高度", cNum, "自己的commit高度", localCommitNum)
	//	return
	//}

	//时间到了的同步方式
	//if normalNum == 0 && peer.CommitNum <= localCommitNum + 1 {
	//	log.Debug("sync return :peer join in or force sync", "peer的commit高度", peer.CommitNum, "自己的commit高度", localCommitNum)
	//	return
	//}

	//if pTd.Cmp(td) <= 0 {
	//	log.Debug("sync return : ptd<=td ,peer join in or force sync")
	//	return
	//}
	// Otherwise try to sync with the downloader
	mode := downloader.FullSync
	//if atomic.LoadUint32(&pm.fastSync) == 1 {
	//	// Fast sync was explicitly requested, and explicitly granted
	//	mode = downloader.FastSync
	//} else if currentBlock.NumberU64() == 0 && pm.blockchain.CurrentFastBlock().NumberU64() > 0 {
	//	// The database seems empty as the current block is the genesis. Yet the fast
	//	// block is ahead, so fast sync was enabled for this node at a certain point.
	//	// The only scenario where this can happen is if the user manually (or via a
	//	// bad block) rolled back a fast sync node below the sync point. In this case
	//	// however it's safe to reenable fast sync.
	//	atomic.StoreUint32(&pm.fastSync, 1)
	//	mode = downloader.FastSync
	//}

	//if mode == downloader.FastSync {
	//	// Make sure the peer's total difficulty we are synchronizing is higher.
	//	if pm.blockchain.GetTdByHash(pm.blockchain.CurrentFastBlock().Hash()).Cmp(pTd) >= 0 {
	//		return
	//	}
	//}

	// Run the sync cycle, and disable fast sync if we've went past the pivot block
	if err := pm.downloader.Synchronise(peer.id, pHead, pTd, mode); err != nil {
		log.Error("sync return : ", "err", err.Error())
		return
	}
	if atomic.LoadUint32(&pm.fastSync) == 1 {
		log.Info("Fast sync complete, auto disabling")
		atomic.StoreUint32(&pm.fastSync, 0)
	}
	atomic.StoreUint32(&pm.acceptTxs, 1) // Mark initial sync done
	if head := pm.blockchain.CurrentBlock(); head.NumberU64() > 0 {
		// We've completed a sync cycle, notify all peers of new state. This path is
		// essential in star-topology networks where a gateway node needs to notify
		// all its out-of-date peers of the availability of a new block. This failure
		// scenario will most often crop up in private and hackathon networks with
		// degenerate connectivity, but it should be healthy for the mainnet too to
		// more reliably update peers or the local TD state.
		go pm.BroadcastBlock(head, false)
	}
}

func (pm *ProtocolManager) synchroniseCommit(peer *peer, timeSync bool, latest *types.Block, assertionSum downloader.CommitAssertionSum) {

	if !atomic.CompareAndSwapInt32(&pm.downloader.Synchronis, 0, 1) {
		log.Error("commit sync return : ", "err", downloader.ErrCommitBusy)
		pm.downloader.Mux.Post(downloader.FailedEvent{downloader.ErrCommitBusy})
		return
	}
	defer func() {
		log.Info("同步结束")
		atomic.StoreInt32(&pm.downloader.Synchronis, 0) //commit同步完成标志
	}()
	// add by liangc : 同步时通知 Advertise 停止
	p2p.SendAlibp2pAdvertiseEvent(&p2p.AdvertiseEvent{Start: false})

	if pm.blockchain.CurrentBlock().NumberU64() == 0 {
		log.Info("等待BAAP链接")
		time.Sleep(10 * time.Second)
	}

	if peer == nil {
		log.Error("commit sync return : peer is nil")
		return
	}
	if peer.CommitNum <= 1 {
		log.Warn("对点节点无数据")
		return
	}
	//latest 验证要同步的节点是不是本地委员会中的成员
	if pm.blockchain.CurrentBlock().NumberU64() != 0 && latest != nil {
		if !pm.downloader.VerifyQualification(latest) {
			log.Error("同步区块作者不在委员会中")
			return
		}
	}

	//时间到了的同步方式
	if timeSync {
		localCommitNum := pm.blockchain.CommitChain.CurrentBlock().NumberU64()
		cNum := atomic.LoadUint64(&peer.CommitNum)
		if cNum <= localCommitNum+1 {
			log.Debug("sync return :peer join in or force sync", "peer的commit高度", cNum, "自己的commit高度", localCommitNum)
			return
		}
	}

	pm.downloader.Mux.Post(downloader.StartEvent{})
	err := pm.downloader.SynchroniseCommit(peer.id, 0, assertionSum)
	switch err {
	case nil:
		log.Info("开始同步剩余的normal")
		pm.synchronise(peer)
		pm.downloader.Mux.Post(downloader.DoneEvent{})
		pm.downloader.CbFetcher.Synced <- struct{}{} //通知同步完毕
		return
	//case downloader.ErrCommitBusy:
	//	log.Error("commit sync return : ", "err", err.Error())
	//	pm.downloader.Mux.Post(downloader.FailedEvent{err})
	//	return

	default:
		//如果返回其他错误,改变同步状态
		//atomic.StoreInt32(&pm.downloader.Synchronis, 0) //commit同步完成标志
		log.Error("commit sync return : ", "err", err.Error())
		pm.downloader.Mux.Post(downloader.FailedEvent{err})
		return
	}

}
