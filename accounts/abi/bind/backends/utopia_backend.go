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
 * @Time   : 2019-08-09 14:25
 * @Author : liangc
 *************************************************************************/

package backends

import (
	"context"
	"math/big"
	"CRD-chain"
	"CRD-chain/accounts/abi/bind"
	"CRD-chain/common"
	"CRD-chain/common/math"
	"CRD-chain/core"
	"CRD-chain/core/state"
	"CRD-chain/core/types"
	"CRD-chain/core/vm"
	"CRD-chain/eth/filters"
	"CRD-chain/event"
	"CRD-chain/params"
	"CRD-chain/rpc"
	"CRD-chain/evertrust/miner"
	"sync"
)

const defaultGasPrice = 18000000000

// 在进程内部调用合约时使用, abigen 合约调用接口
type evertrustContractBackend struct {
	mu     *sync.Mutex
	config *params.ChainConfig
	ub     evertrustBackend
	events *filters.EventSystem
}

type evertrustBackend interface {
	Miner() *miner.Miner
	BlockChain() *core.BlockChain
	TxPool() *core.TxPool
	FiltersBackend() filters.Backend
}

func NewevertrustContractBackend(ub evertrustBackend, config *params.ChainConfig) bind.ContractBackend {
	return &evertrustContractBackend{
		mu:     new(sync.Mutex),
		config: config,
		ub:     ub,
		events: filters.NewEventSystem(ub.FiltersBackend().EventMux(), ub.FiltersBackend(), false),
	}
}

func (b *evertrustContractBackend) CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if blockNumber != nil && blockNumber.Cmp(b.ub.BlockChain().CurrentBlock().Number()) != 0 {
		return nil, errBlockNumberUnsupported
	}
	statedb, _ := b.ub.BlockChain().State()
	return statedb.GetCode(contract), nil
}

func (b *evertrustContractBackend) CallContract(ctx context.Context, call ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if blockNumber != nil && blockNumber.Cmp(b.ub.BlockChain().CurrentBlock().Number()) != 0 {
		return nil, errBlockNumberUnsupported
	}
	state, err := b.ub.BlockChain().State()
	if err != nil {
		return nil, err
	}
	rval, _, _, err := b.callContract(ctx, call, b.ub.BlockChain().CurrentBlock(), state)
	return rval, err
}

func (b *evertrustContractBackend) PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, state := b.ub.Miner().Pending()
	code := state.GetCode(account)
	return code, nil
}

func (b *evertrustContractBackend) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, state := b.ub.Miner().Pending()
	return state.GetNonce(account), nil
}

func (b *evertrustContractBackend) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	return big.NewInt(defaultGasPrice), nil
}

func (b *evertrustContractBackend) EstimateGas(ctx context.Context, call ethereum.CallMsg) (gas uint64, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Determine the lowest and highest possible gas limits to binary search in between
	var (
		lo        uint64 = params.TxGas - 1
		hi        uint64
		cap       uint64
		pblock    = b.ub.Miner().PendingBlock()
		_, pstate = b.ub.Miner().Pending()
	)
	if call.Gas >= params.TxGas {
		hi = call.Gas
	} else {
		hi = pblock.GasLimit()
	}
	cap = hi

	// Create a helper to check if a gas allowance results in an executable transaction
	executable := func(gas uint64) bool {
		call.Gas = gas
		snapshot := pstate.Snapshot()
		_, _, failed, err := b.callContract(ctx, call, pblock, pstate)
		pstate.RevertToSnapshot(snapshot)
		if err != nil || failed {
			return false
		}
		return true
	}
	// Execute the binary search and hone in on an executable gas limit
	for lo+1 < hi {
		mid := (hi + lo) / 2
		if !executable(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	// Reject the transaction as invalid if it still fails at the highest allowance
	if hi == cap {
		if !executable(hi) {
			return 0, errGasEstimationFailed
		}
	}
	return hi, nil
}

func (b *evertrustContractBackend) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ub.TxPool().AddLocal(tx)
}

func (b *evertrustContractBackend) FilterLogs(ctx context.Context, crit ethereum.FilterQuery) ([]types.Log, error) {
	var filterBackend = b.ub.FiltersBackend()
	var filter *filters.Filter

	if crit.BlockHash != nil {
		// Block filter requested, construct a single-shot filter
		filter = filters.NewBlockFilter(filterBackend, *crit.BlockHash, crit.Addresses, crit.Topics)
	} else {
		// Convert the RPC block numbers into internal representations
		begin := rpc.LatestBlockNumber.Int64()
		if crit.FromBlock != nil {
			begin = crit.FromBlock.Int64()
		}
		end := rpc.LatestBlockNumber.Int64()
		if crit.ToBlock != nil {
			end = crit.ToBlock.Int64()
		}
		// Construct the range filter
		filter = filters.NewRangeFilter(filterBackend, begin, end, crit.Addresses, crit.Topics)
	}
	// Run the filter and return all the logs
	logs, err := filter.Logs(ctx)
	if err != nil {
		return nil, err
	}
	ret := make([]types.Log, 0)
	if logs == nil {
		return ret, nil
	}
	for _, l := range logs {
		ret = append(ret[:], *l)
	}
	return ret, nil
}

func (b *evertrustContractBackend) SubscribeFilterLogs(ctx context.Context, query ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error) {
	sink := make(chan []*types.Log)
	sub, err := b.events.SubscribeLogs(query, sink)
	if err != nil {
		return nil, err
	}
	// Since we're getting logs in batches, we need to flatten them into a plain stream
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case logs := <-sink:
				for _, log := range logs {
					select {
					case ch <- *log:
					case err := <-sub.Err():
						return err
					case <-quit:
						return nil
					}
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

func (b *evertrustContractBackend) callContract(ctx context.Context, call ethereum.CallMsg, block *types.Block, statedb *state.StateDB) ([]byte, uint64, bool, error) {
	// Ensure message is initialized properly.
	if call.GasPrice == nil {
		call.GasPrice = big.NewInt(defaultGasPrice)
	}
	if call.Gas == 0 {
		call.Gas = 50000000
	}
	if call.Value == nil {
		call.Value = new(big.Int)
	}
	// Set infinite balance to the fake caller account.
	from := statedb.GetOrNewStateObject(call.From)
	from.SetBalance(math.MaxBig256)
	// Execute the call.
	msg := callmsg{call}

	evmContext := core.NewEVMContext(msg, block.Header(), b.ub.BlockChain(), nil)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(evmContext, statedb, b.config, vm.Config{})
	gaspool := new(core.GasPool).AddGas(math.MaxUint64)
	return core.NewStateTransition(vmenv, msg, gaspool).TransitionDb(make(map[string][]byte))
}
