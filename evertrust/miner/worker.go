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
package miner

import (
	"fmt"
	"math/big"
	"CRD-chain/current"
	"CRD-chain/examineSync"
	"CRD-chain/CRDcc"
	"CRD-chain/evertrust"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deckarep/golang-set"
	"CRD-chain/common"
	"CRD-chain/consensus"
	"CRD-chain/core"
	"CRD-chain/core/state"
	"CRD-chain/core/types"
	"CRD-chain/core/vm"
	"CRD-chain/event"
	"CRD-chain/log"
	"CRD-chain/params"
	"CRD-chain/rlp"
	evertrust_engine "CRD-chain/evertrust/engine"
	evertrust_types "CRD-chain/evertrust/types"
)

var evertrustEngine *evertrust_engine.Evertrust

const (
	// resultQueueSize is the size of channel listening to sealing result.
	resultQueueSize = 10

	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096

	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10

	// chainSideChanSize is the size of channel listening to ChainSideEvent.
	chainSideChanSize = 10

	// resubmitAdjustChanSize is the size of resubmitting interval adjustment channel.
	resubmitAdjustChanSize = 10

	// miningLogAtDepth is the number of confirmations before logging successful mining.
	miningLogAtDepth = 5

	// minRecommitInterval is the minimal time interval to recreate the mining block with
	// any newly arrived transactions.
	minRecommitInterval = 1 * time.Second

	// maxRecommitInterval is the maximum time interval to recreate the mining block with
	// any newly arrived transactions.
	maxRecommitInterval = 15 * time.Second

	// intervalAdjustRatio is the impact a single interval adjustment has on sealing work
	// resubmitting interval.
	intervalAdjustRatio = 0.1

	// intervalAdjustBias is applied during the new resubmit interval calculation in favor of
	// increasing upper limit or decreasing lower limit so that the limit can be reachable.
	intervalAdjustBias = 200 * 1000.0 * 1000.0
)

// environment is the worker's current environment and holds all of the current state information.
type environment struct {
	signer types.Signer

	state *state.StateDB // apply state changes here
	// state array for concurrent executing
	stArray   []*state.MStateDB
	txmap     map[common.Hash]*types.Transaction
	wg        sync.WaitGroup
	ancestors mapset.Set    // ancestor set (used for checking uncle parent validity)
	family    mapset.Set    // family set (used for checking uncle invalidity)
	uncles    mapset.Set    // uncle set
	tcount    int           // tx count in cycle
	gasPool   *core.GasPool // available gas used to pack transactions

	header   *types.Header
	txs      []*types.Transaction
	receipts []*types.Receipt
}

// task contains all information for consensus engine sealing and result submitting.
type task struct {
	receipts   []*types.Receipt
	state      *state.StateDB
	block      *types.Block
	createdAt  time.Time
	BlockExtra *evertrust_types.BlockExtra
	timeStart  time.Time
}

const (
	commitInterruptNone int32 = iota
	commitInterruptNewHead
	commitInterruptResubmit
)

// newWorkReq represents a request for new sealing work submitting with relative interrupt notifier.
type newWorkReq struct {
	interrupt *int32
	noempty   bool
}

// intervalAdjust represents a resubmitting interval adjustment.
type intervalAdjust struct {
	ratio float64
	inc   bool
}

// evertrustWorker is the main object which takes care of submitting new work to consensus engine
// and gathering the sealing result.
type evertrustWorker struct {
	config *params.ChainConfig
	engine consensus.Engine
	eth    Backend
	chain  *core.BlockChain

	// Subscriptions
	mux          *event.TypeMux
	txsCh        chan core.NewTxsEvent
	txsSub       event.Subscription
	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription

	// Channels
	newWorkCh chan *evertrust_types.BlockMiningReq
	taskCh    chan *task
	resultCh  chan *task
	startCh   chan struct{}
	exitCh    chan struct{}
	//cancelCh           chan struct{}
	resubmitIntervalCh chan time.Duration
	resubmitAdjustCh   chan *intervalAdjust

	current        *environment                 // An environment for current running cycle.
	possibleUncles map[common.Hash]*types.Block // A set of side blocks as the possible uncle blocks.
	unconfirmed    *unconfirmedBlocks           // A set of locally mined blocks pending canonicalness confirmations.

	mu       sync.RWMutex // The lock used to protect the coinbase and extra fields
	coinbase common.Address
	extra    []byte

	snapshotMu    sync.RWMutex // The lock used to protect the block snapshot and state snapshot
	snapshotBlock *types.Block
	snapshotState *state.StateDB

	// atomic status counters
	running int32 // The indicator whether the consensus engine is running or not.
	newTxs  int32 // New arrival transaction count since last sealing work submitting.
	// Test hooks
	newTaskHook  func(*task)                        // Method to call upon receiving a new sealing task.
	skipSealHook func(*task) bool                   // Method to decide whether skipping the sealing.
	fullTaskHook func()                             // Method to call before pushing the full sealing task.
	resubmitHook func(time.Duration, time.Duration) // Method to call upon updating resubmitting interval.
}

func newevertrustWorker(config *params.ChainConfig, engine consensus.Engine, eth Backend, mux *event.TypeMux, recommit time.Duration) *evertrustWorker {
	evertrustWorker := &evertrustWorker{
		config:         config,
		engine:         engine,
		eth:            eth,
		mux:            mux,
		chain:          eth.BlockChain(),
		possibleUncles: make(map[common.Hash]*types.Block),
		unconfirmed:    newUnconfirmedBlocks(eth.BlockChain(), miningLogAtDepth),
		txsCh:          make(chan core.NewTxsEvent, txChanSize),
		chainHeadCh:    make(chan core.ChainHeadEvent, chainHeadChanSize),
		newWorkCh:      make(chan *evertrust_types.BlockMiningReq, 10000),
		taskCh:         make(chan *task),
		resultCh:       make(chan *task, resultQueueSize),
		exitCh:         make(chan struct{}),
		startCh:        make(chan struct{}, 1),
		//cancelCh:           make(chan struct{}, 1),
		resubmitIntervalCh: make(chan time.Duration),
		resubmitAdjustCh:   make(chan *intervalAdjust, resubmitAdjustChanSize),
	}

	var ok bool
	evertrustEngine, ok = engine.(*evertrust_engine.Evertrust)
	if !ok {
		panic("miner/worker & engine mismatch")
	}
	evertrustEngine.Running = &evertrustWorker.running
	evertrustEngine.SetMinerChannel(evertrustWorker.newWorkCh)
	evertrustEngine.SetEventMux(mux)
	//core.GasPoolMax = eth.Genesis().GasLimit //todo gasliimit from genesis but genesis is nil

	// Subscribe NewTxsEvent for tx pool
	//evertrustWorker.txsSub = eth.TxPool().SubscribeNewTxsEvent(evertrustWorker.txsCh)
	// Subscribe events for blockchain
	//evertrustWorker.chainHeadSub = eth.BlockChain().SubscribeChainHeadEvent(evertrustWorker.chainHeadCh)

	go evertrustWorker.mainLoop()
	go evertrustWorker.resultLoop()
	go evertrustWorker.taskLoop()
	// Submit first work to initialize pending state.
	//<-evertrustWorker.startCh

	return evertrustWorker
}

// setEtherbase sets the etherbase used to initialize the block coinbase field.
func (w *evertrustWorker) setEtherbase(addr common.Address) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.coinbase = addr
	current.CRDCoinBase = addr
}

// setExtra sets the content used to initialize the block extra field.
func (w *evertrustWorker) setExtra(extra []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.extra = extra
}

// setRecommitInterval updates the interval for miner sealing work recommitting.
func (w *evertrustWorker) setRecommitInterval(interval time.Duration) {
	w.resubmitIntervalCh <- interval
}

// pending returns the pending state and corresponding block.
func (w *evertrustWorker) pending() (*types.Block, *state.StateDB) {
	// return a snapshot to avoid contention on currentMu mutex
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	if w.snapshotState == nil {
		return nil, nil
	}
	return w.snapshotBlock, w.snapshotState.Copy()
}

// pendingBlock returns pending block.
func (w *evertrustWorker) pendingBlock() *types.Block {
	// return a snapshot to avoid contention on currentMu mutex
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	return w.snapshotBlock
}

// start sets the running status as 1 and triggers new work submitting.
func (w *evertrustWorker) start() {
	atomic.StoreInt32(&w.running, 1)
	log.Info("start miner")
	w.startCh <- struct{}{}
}

// stop sets the running status as 0.
func (w *evertrustWorker) stop() {
	atomic.StoreInt32(&w.running, 0)
}

// isRunning returns an indicator whether evertrustWorker is running or not.
func (w *evertrustWorker) isRunning() bool {
	return atomic.LoadInt32(&w.running) == 1
}

// close terminates all background threads maintained by the evertrustWorker and cleans up buffered channels.
// Note the evertrustWorker does not support being closed multiple times.
func (w *evertrustWorker) close() {
	close(w.exitCh)
	// Clean up buffered channels
	for empty := false; !empty; {
		select {
		case <-w.resultCh:
		default:
			empty = true
		}
	}
}

// mainLoop is a standalone goroutine to regenerate the sealing task based on the received event.
func (w *evertrustWorker) mainLoop() {
	//defer w.txsSub.Unsubscribe()
	//defer w.chainHeadSub.Unsubscribe()
	<-w.startCh
	log.Info("entering mainloop")

	for {
		select {
		case req := <-w.newWorkCh:
			timeMain := time.Now()
			log.Info("received new work")
			//如果正在执行同步,不进行打快
			if w.eth.Synchronising() == 1 {
				break
			}
			w.commitNewWork(req, timeMain)

		case <-w.exitCh:
			log.Error("exit mainloop")
			return

		}
	}
}

// seal pushes a sealing task to consensus engine and submits the result.
func (w *evertrustWorker) seal(t *task, stop <-chan struct{}) {
	var (
		err error
		res *task
	)

	if w.skipSealHook != nil && w.skipSealHook(t) {
		return
	}

	if t.block, err = w.engine.Seal(w.chain, t.block, stop); t.block != nil {
		log.Info("Successfully sealed new block", "number", t.block.Number(), "hash", t.block.Hash(),
			"elapsed", common.PrettyDuration(time.Since(t.createdAt)))
		res = t
		if t.block.NumberU64() != w.chain.CurrentBlock().NumberU64()+1 {
			log.Debug("无效的块")
			return
		}
	} else {
		if err != nil {
			log.Warn("Block sealing failed", "err", err)
		}
		res = nil
	}
	res.timeStart = t.timeStart
	select {
	case w.resultCh <- res:
	case <-w.exitCh:
		log.Info("seal recv'd exit signal")
	}
}

// taskLoop is a standalone goroutine to fetch sealing task from the generator and
// push them to consensus engine.
func (w *evertrustWorker) taskLoop() {
	var (
		stopCh chan struct{}
		prev   common.Hash
	)

	// interrupt aborts the in-flight sealing task.
	interrupt := func() {
		if stopCh != nil {
			close(stopCh)
			stopCh = nil
		}
	}
	for {
		select {
		case task := <-w.taskCh:
			if w.newTaskHook != nil {
				w.newTaskHook(task)
			}

			// Reject duplicate sealing work due to resubmitting.
			if task.block.HashNoNonce() == prev {
				continue
			}
			interrupt()
			stopCh = make(chan struct{})
			prev = task.block.HashNoNonce()

			go w.seal(task, stopCh)
		case <-w.exitCh:
			interrupt()
			return
		}
	}
}

// resultLoop is a standalone goroutine to handle sealing result submitting
// and flush relative data to the database.
func (w *evertrustWorker) resultLoop() {
	for {

		select {
		case result := <-w.resultCh:
			if result.block.NumberU64() != w.chain.CurrentBlock().NumberU64()+1 {
				log.Debug("无效的块", "高度", result.block.NumberU64(), "hash", result.block.Hash())
				break
			}
			log.Info("resultLoop----", "number", result.block.NumberU64(), "hash", result.block.Hash())
			timeStart := time.Since(result.timeStart).Seconds() * 1000
			timeEnd := float64(time.Duration(evertrust_engine.BlockDelay + 300))
			log.Info("time", "time", timeStart, "timeEnd", timeEnd)

			if timeStart > timeEnd {
				log.Error("打快超时", "高度", result.block.Number(), "timeStart", timeStart, "timeEnd", timeEnd)
				//需要回滚交易
			}
			//
			if timeStart < timeEnd {
				time.Sleep(time.Duration(timeEnd-timeStart) * time.Millisecond)
			}

			log.Info("OnNormalBlock----", "number", result.block.NumberU64(), "hash", result.block.Hash())

			blockExtra := evertrust_types.BlockExtraDecode(result.block)
			evertrustEngine.Fetcher.Enqueue(fmt.Sprintf("%x", blockExtra.NodeID.Bytes()[:8]), result.block)

		case <-w.exitCh:
			log.Info("exit resultloop")
			return
		}
		log.Info("another result loop")
	}
}

// makeCurrent creates a new environment for the current cycle.
func (w *evertrustWorker) makeCurrent(parent *types.Block, header *types.Header) error {
	state, err := w.chain.StateAt(parent.Root())
	if err != nil {
		return err
	}
	// TODO
	// tx bucket
	// tx journal
	// state should support getStateLock
	env := &environment{
		signer:    types.NewEIP155Signer(w.config.ChainID),
		state:     state,
		txmap:     make(map[common.Hash]*types.Transaction),
		ancestors: mapset.NewSet(),
		family:    mapset.NewSet(),
		uncles:    mapset.NewSet(),
		header:    header,
		gasPool:   new(core.GasPool).AddGas(header.GasLimit),
	}
	if w.config.Sm2Crypto {
		env.signer = types.NewSm2Signer(w.config.ChainID)
	}
	//// when 08 is processed ancestors contain 07 (quick block)
	//for _, ancestor := range w.chain.GetBlocksFromHash(parent.Hash(), 7) {
	//	for _, uncle := range ancestor.Uncles() {
	//		env.family.Add(uncle.Hash())
	//	}
	//	env.family.Add(ancestor.Hash())
	//	env.ancestors.Add(ancestor.Hash())
	//}

	// Keep track of transactions which return errors so they can be removed
	env.tcount = 0
	w.current = env
	return nil
}

func (w *evertrustWorker) initCurrentMStateDB(num int) error {
	mstdb, err := state.NewMStateDB(w.current.state, num)
	if err != nil {
		return err
	}

	w.current.stArray = mstdb
	return nil
}

// updateSnapshot updates pending snapshot block and state.
// Note this function assumes the current variable is thread safe.
func (w *evertrustWorker) updateSnapshot() {
	w.snapshotMu.Lock()
	defer w.snapshotMu.Unlock()

	var uncles []*types.Header
	w.current.uncles.Each(func(item interface{}) bool {
		hash, ok := item.(common.Hash)
		if !ok {
			return false
		}
		uncle, exist := w.possibleUncles[hash]
		if !exist {
			return false
		}
		uncles = append(uncles, uncle.Header())
		return false
	})

	w.snapshotBlock = types.NewBlock(
		w.current.header,
		w.current.txs,
		uncles,
		w.current.receipts,
	)

	w.snapshotState = w.current.state.Copy()
}

func (w *evertrustWorker) commitTransaction(tx *types.Transaction, coinbase common.Address, rmap map[common.Hash]*types.Receipt, idx int) ([]*types.Log, error) {
	snap := w.current.stArray[idx].Snapshot()
	var err error
	defer func() {
		// recover from deadlock panic
		e := recover()
		if e == state.ErrMStateDBDeadLock {
			log.Info("recover deadlock", "error", e)
			err = state.ErrMStateDBDeadLock
			w.current.stArray[idx].RevertToSnapshot(snap)
			w.current.stArray[idx].UnLockAccounts(false)
			//unlocks
		} else if e != nil {

			log.Info("recover other panic", "err", e)
			// throw out other panics
			panic(err)
		}
	}()
	// modify by liangc for wasm
	receipt, _, err := core.ApplyTransaction(w.config, w.chain, &coinbase, w.current.gasPool, w.current.stArray[idx], w.current.header, tx, &w.current.header.GasUsed, w.chain.GetVmConfig())
	if err != nil {
		w.current.stArray[idx].RevertToSnapshot(snap)
		w.current.stArray[idx].UnLockAccounts(false)
		return nil, err
	}
	w.current.stArray[idx].UnLockAccounts(true)
	rmap[tx.Hash()] = receipt
	return receipt.Logs, err
}

func (w *evertrustWorker) commitTransactions(txs *types.TransactionsByPriceAndNonce,
	coinbase common.Address, tstart time.Time, rmap map[common.Hash]*types.Receipt, idx int) bool {
	defer w.current.wg.Done()
	// Short circuit if current is nil
	if w.current == nil {
		return true
	}

	var coalescedLogs []*types.Log
	txsStartTime := time.Now()
	i := 0
	tcount := 0
	for {
		//如果正在进行同步,或者正在存normal块不执行交易
		if atomic.LoadUint32(&examineSync.ExamineInsertBlock) == 1 || w.eth.Synchronising() == 1 {
			log.Info("区块正在insert,不执行交易")
			break
		}
		// In the following three cases, we will interrupt the execution of the transaction.
		// (1) new head block event arrival, the interrupt signal is 1
		// (2) worker start or restart, the interrupt signal is 1
		// (3) worker recreate the mining block with any newly arrived transactions, the interrupt signal is 2.
		// For the first two cases, the semi-finished work will be discarded.
		// For the third case, the semi-finished work will be submitted to the consensus engine.

		// If we don't have enough gas for any further transactions then we're done
		//if w.current.gasPool.Gas() < params.TxGas {
		//	log.Error("Not enough gas for further transactions", "have", w.current.gasPool, "want", params.TxGas)
		//	break
		//}
		// Retrieve the next transaction and abort if all done
		tx := txs.Peek()
		if tx == nil {
			break
		}
		i++
		// Error may be ignored here. The error has already been checked
		// during transaction acceptance is the transaction pool.
		//
		// We use the eip155 signer regardless of the current hf.
		from, _ := types.Sender(w.current.signer, tx)
		// Check whether the tx is replay protected. If we're not in the EIP155 hf
		// phase, start ignoring the sender until we do.
		if tx.Protected() && !w.config.IsEIP155(w.current.header.Number) {
			log.Warn("Ignoring reply protected transaction", "hash", tx.Hash(), "eip155", w.config.EIP155Block)

			txs.Pop()
			continue
		}
		// Start executing the transaction
		w.current.stArray[idx].Prepare(tx.Hash(), common.Hash{}, tcount)

		//txStartTime := time.Now()
		logs, err := w.commitTransaction(tx, coinbase, rmap, idx)
		switch err {
		case core.ErrGasLimitReached:
			// Pop the current out-of-gas transaction without shifting in the next from the account
			log.Error("Gas limit exceeded for current block", "sender", from)
			txs.Pop()

		case core.ErrNonceTooLow:
			// New head notification data race between the transaction pool and miner, shift
			log.Error("Skipping transaction with low nonce", "sender", from, "nonce", tx.Nonce())
			txs.Shift()

		case core.ErrNonceTooHigh:
			// Reorg notification data race between the transaction pool and miner, skip account =
			log.Error("Skipping account with hight nonce", "sender", from, "nonce", tx.Nonce())
			txs.Pop()

		case vm.ErrChainCodeContract:
			log.Error("cc call error")
			txs.Pop()

		case state.ErrMStateDBDeadLock:
			log.Error("Deadlock occurred", "sender", from, "to", tx.To())
			txs.Pop()

		case CRDcc.ErrChainCodeTimeOut:
			log.Error("cc call time out")
			txs.Pop()

		case vm.ErrCliRpcTimeOut:
			log.Error("cli rpc timeout")
			txs.Pop()

		case nil:
			// Everything ok, collect the logs and shift in the next transaction from the same account
			//log.Info("everything ok, shift the next transaction", "sender", from, "nonce", tx.Nonce())
			coalescedLogs = append(coalescedLogs, logs...)
			tcount++
			txs.Shift()

		default:
			// Strange error, discard the transaction and get the next in line (note, the
			// nonce-too-high clause will prevent us from executing in vain).
			log.Error("Transaction failed, account skipped", "hash", tx.Hash(), "err", err)
			txs.Shift()
		}
		//log.Info("single tx elapsed", "collapse", time.Since(txStartTime))
		if evertrust_engine.BlockDelay <= int32(time.Since(tstart).Seconds()*1000) {
			log.Info("交易超时", "交易时间", time.Since(tstart))
			break

		}
	}
	log.Info("################# all txs elapsed", "time", time.Since(txsStartTime), "all txs num", i, "success txs num", tcount)

	if !w.isRunning() && len(coalescedLogs) > 0 {
		// We don't push the pendingLogsEvent while we are mining. The reason is that
		// when we are mining, the worker will regenerate a mining block every 3 seconds.
		// In order to avoid pushing the repeated pendingLog, we disable the pending log pushing.

		// make a copy, the state caches the logs and these logs get "upgraded" from pending to mined
		// logs by filling in the block hash when the block was mined by the local miner. This can
		// cause a race condition if a log was "upgraded" before the PendingLogsEvent is processed.
		cpy := make([]*types.Log, len(coalescedLogs))
		for i, l := range coalescedLogs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		go w.mux.Post(core.PendingLogsEvent{Logs: cpy}) //todo 有什么用处
	}
	// Notify resubmit loop to decrease resubmitting interval if current interval is larger
	// than the user-specified one.

	return false
}

// commitNewWork generates several new sealing tasks based on the parent block.
func (w *evertrustWorker) commitNewWork(work *evertrust_types.BlockMiningReq, timeMain time.Time) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	tstart := timeMain
	parent := w.chain.GetBlockByNumber(work.Number)
	if parent == nil && work.Number != 0 {
		log.Error("commitNewWork 获取parent块为空")
	}
	//parent := w.chain.CurrentBlock()

	tstamp := tstart.Unix()
	var extraByte []byte
	var err error
	var extra evertrust_types.BlockExtra
	if work != nil {
		////set header extra with work

		switch work.Kind {

		case evertrust_types.NORNAML_BLOCK:
			extra = evertrust_types.BlockExtra{NodeID: work.NodeID, Rank: work.Rank, CNumber: work.CNumber, IsLandID: work.IsLandID, Empty: work.Empty}

		default:
			log.Info("incorrect block type:", "type", work.Kind)
		}

		extraByte, err = rlp.EncodeToBytes(extra)
		if err != nil {
			log.Info("extra encode error", "err", err.Error())
		}
	}

	rewardAddr := evertrust.Config.String("rewardAddress")
	var rwdAddr common.Address
	if common.IsHexAddress(rewardAddr) {
		switch {
		case rewardAddr != "" || len(rewardAddr) != 0:
			rwdAddr = common.HexToAddress(rewardAddr)
		default:
			rwdAddr = w.coinbase
		}
	} else {
		log.Warn("rewardAddress is not a address,by setting coinbase default")
		rwdAddr = w.coinbase
	}

	num := parent.Number()
	header := &types.Header{
		ParentHash:    parent.Hash(),
		Number:        num.Add(num, common.Big1),
		RewardAddress: rwdAddr,
		GasLimit:      core.CalcGasLimit(parent),
		Extra:         extraByte,
		Time:          big.NewInt(tstamp),
		Difficulty:    big.NewInt(1024),
		//BlockExtra: types.BlockExtra{Rank:work.Rank},
	}
	log.Info("block GasLimit", "GasLimit", header.GasLimit)
	// Only set the coinbase if our consensus engine is running (avoid spurious block rewards)
	if w.isRunning() {
		if w.coinbase == (common.Address{}) {
			log.Error("Refusing to mine without etherbase")
			return
		}
		header.Coinbase = w.coinbase
	}
	if err := w.engine.Prepare(w.chain, header); err != nil {
		log.Error("Failed to prepare header for mining", "err", err)
		return
	}
	// Could potentially happen if starting to mine in an odd state.
	err = w.makeCurrent(parent, header)
	if err != nil {
		log.Error("Failed to create mining context", "err", err)
		return
	}
	txPool := w.eth.TxPool()
	// Fill the block with all available pending transactions.
	if parent.NumberU64()%1024 == 0 {
		//检查pending中过期交易
		txPool.CheckPending()
	}
	log.Info("work.Empty", "work.Empty", work.Empty, "IsLandID", extra.IsLandID)
	//不是master不执行交易
	if !work.Empty {
		//读pending超时处理
		var pending map[common.Address]types.Transactions
		completed := make(chan uint8)
		go func() {
			pending, err = txPool.Pending()
			completed <- 1
		}()

		select {
		case <-completed:
		case <-time.After(time.Duration(evertrust_engine.BlockDelay) * time.Millisecond):
			//读取pending超时
			log.Warn("read txpool pending timeout")
			pending = nil
		}
		if err != nil {
			log.Error("Failed to fetch pending transactions", "err", err)
			return
		}

		remoteTxs := pending
		log.Info("commitNewWork----2", "pending数量", len(remoteTxs))
		if len(remoteTxs) > 0 {
			buckets := w.fillTxsToBuckets(remoteTxs)
			log.Info("multi-statedb", "buckets number:", len(buckets))
			err = w.initCurrentMStateDB(len(buckets))
			if err != nil {
				return
			}

			receiptArray := make([]map[common.Hash]*types.Receipt, len(buckets), len(buckets))
			for idx, bkt := range buckets {
				receiptArray[idx] = make(map[common.Hash]*types.Receipt)
				txs := types.NewTransactionsByPriceAndNonce(w.current.signer, bkt)
				w.current.wg.Add(1)
				go w.commitTransactions(txs, w.coinbase, tstart, receiptArray[idx], idx)
			}

			w.current.wg.Wait()
			eTxs := w.current.stArray[0].GetTxs()
			w.current.tcount = len(eTxs)
			w.current.txs = make([]*types.Transaction, 0, w.current.tcount)
			w.current.receipts = make([]*types.Receipt, 0, w.current.tcount)
			for _, tx := range eTxs {
				w.current.txs = append(w.current.txs, w.current.txmap[tx])
				for _, ra := range receiptArray {
					if r, ok := ra[tx]; ok {
						w.current.receipts = append(w.current.receipts, r)
						break
					}
				}
			}
			log.Info("all txs", "tcount:", w.current.tcount, "len(txs)", len(w.current.txs), "len(receipts):", len(w.current.receipts))
		}
	}

	w.commit(w.fullTaskHook, true, tstart, &extra)
}

func (w *evertrustWorker) fillTxsToBuckets(txs map[common.Address]types.Transactions) []map[common.Address]types.Transactions {
	// sort txs according to from and to
	var bkts []map[common.Address]types.Transactions
	var bktFilter []map[common.Address]struct{}

	for _addr, _txs := range txs {
		var exist bool
		var idx int
		filter := make(map[common.Address]struct{})
		filter[_addr] = struct{}{}
		for _, _tx := range _txs {
			w.current.txmap[_tx.Hash()] = _tx
			if _tx.To() == nil {
				continue
			}
			filter[*_tx.To()] = struct{}{}

			if exist {
				continue
			}

			for _idx, _bf := range bktFilter {
				if _, ok := _bf[*_tx.To()]; ok {
					idx = _idx
					exist = true
					break
				}
				if _, ok := _bf[_addr]; ok {
					idx = _idx
					exist = true
					break
				}
			}
		}
		if exist {
			// find the bucket and put it in
			bkts[idx][_addr] = _txs
			for _key, _ := range filter {
				bktFilter[idx][_key] = struct{}{}
			}

		} else {
			// don't find the bucket, create a new one
			tmp := make(map[common.Address]types.Transactions)
			tmp[_addr] = _txs
			bkts = append(bkts, tmp)
			bktFilter = append(bktFilter, filter)
		}
	}
	return bkts
}

// commit runs any post-transaction state modifications, assembles the final block
// and commits new work if consensus engine is running.
func (w *evertrustWorker) commit(interval func(), update bool, start time.Time, blockExtra *evertrust_types.BlockExtra) error {
	// Deep copy receipts here to avoid interaction between different tasks.
	receipts := make([]*types.Receipt, len(w.current.receipts))
	for i, l := range w.current.receipts {
		receipts[i] = new(types.Receipt)
		*receipts[i] = *l
	}
	s := w.current.state.Copy()
	block, err := w.engine.Finalize(w.chain, w.current.header, s, w.current.txs, nil, w.current.receipts)
	if err != nil {
		log.Error("Finalize错误", "err", err)
		return err
	}

	if w.isRunning() {
		if interval != nil {
			interval()
		}
		select {
		case w.taskCh <- &task{receipts: receipts, state: s, block: block, createdAt: time.Now(), BlockExtra: blockExtra, timeStart: start}:
			w.unconfirmed.Shift(block.NumberU64() - 1)

			feesWei := new(big.Int)
			for i, tx := range block.Transactions() {
				feesWei.Add(feesWei, new(big.Int).Mul(new(big.Int).SetUint64(receipts[i].GasUsed), tx.GasPrice()))
			}
			feesEth := new(big.Float).Quo(new(big.Float).SetInt(feesWei), new(big.Float).SetInt(big.NewInt(params.Ether)))

			log.Info("Commit new mining work", "number", block.Number(), "txs", w.current.tcount,
				"gas", block.GasUsed(), "fees", feesEth, "elapsed", common.PrettyDuration(time.Since(start)))

		case <-w.exitCh:
			log.Info("Worker has exited")
		}
	} else {
		log.Error("miner启动失败")
	}
	if update {
		w.updateSnapshot()
	}
	return nil
}
