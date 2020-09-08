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

package core

import (
	"bytes"
	"fmt"
	"math/big"
	"CRD-chain/contracts/erc20points"
	"CRD-chain/log"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/evertrust/utils"
	"strings"
	"sync/atomic"

	"CRD-chain/common"
	"CRD-chain/consensus"
	"CRD-chain/consensus/misc"
	"CRD-chain/core/state"
	"CRD-chain/core/types"
	"CRD-chain/core/vm"
	"CRD-chain/crypto"
	"CRD-chain/params"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, uint64, error) {
	var (
		receipts types.Receipts
		usedGas  = new(uint64)
		header   = block.Header()
		allLogs  []*types.Log
		gp       = new(GasPool).AddGas(block.GasLimit()).AddGas(block.GasLimit())
	)
	// Mutate the the block and state according to any hard-fork specs
	if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
		misc.ApplyDAOHardFork(statedb)
	}
	// Iterate over and process the individual transactions
	//t:=time.Now()
	for i, tx := range block.Transactions() {
		statedb.Prepare(tx.Hash(), block.Hash(), i)
		//coinbase := block.Coinbase()
		receipt, _, err := ApplyTransaction(p.config, p.bc, nil, gp, statedb, header, tx, usedGas, cfg)
		if err != nil {
			return receipts, allLogs, *usedGas, err
		}
		receipts = append(receipts, receipt)
		allLogs = append(allLogs, receipt.Logs...)
	}
	if gp.Gas() < block.GasLimit() {
		return receipts, allLogs, *usedGas, ErrGasLimitReached
	}
	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, header, statedb, block.Transactions(), nil, receipts)
	return receipts, allLogs, *usedGas, nil
}

// ApplyTransaction attempts to apply a transaction to the given state database
// and uses the input parameters for its environment. It returns the receipt
// for the transaction, gas used and an error if the transaction failed,
// indicating the block was invalid.
func ApplyTransaction(config *params.ChainConfig, bc ChainContext, author *common.Address, gp *GasPool, statedb state.IStateDB, header *types.Header, tx *types.Transaction, usedGas *uint64, cfg vm.Config) (*types.Receipt, uint64, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config, header.Number))
	if err != nil {
		return nil, 0, err
	}
	// Create a new context to be used in the EVM environment
	context := NewEVMContext(msg, header, bc, author)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	// add by liangc : 如果执行的不是 wasm 合约则不创建 wasm 合约解释器 >>>>
	var vmenv = vm.NewEVM(context, statedb, config, cfg)
	// add by liangc : 如果执行的不是 wasm 合约则不创建 wasm 合约解释器 <<<<

	// Apply the transaction to the current state (included in the env)

	extra := make(map[string][]byte)
	extra[conf.BaapTxid] = tx.Hash().Bytes()
	extra[conf.BaapEngineID] = conf.ChainId.Bytes()
	if tx.To() != nil && *tx.To() == utils.CRDSafeContract {
		if config.Sm2Crypto {
			signer := types.NewSm2Signer(conf.ChainId)
			pubkey, err := signer.SenderPubkey(tx)
			if err != nil {
				log.Error("sender public key", "err", err)
				return nil, 0, err
			}
			extra[conf.BaapSpbk] = pubkey
		} else {
			signer := types.NewEIP155Signer(conf.ChainId)
			pubkey, err := signer.SenderPubkey(tx)
			if err != nil {
				log.Error("sender public key", "err", err)
				return nil, 0, err
			}
			extra[conf.BaapSpbk] = crypto.CompressPubkey(pubkey)
		}


	}

	//log.Info("ApplyMessage state_processor Begin", "tx hash", tx.Hash().Hex(), "to", tx.To())//note to maybe == nil
	_, gas, failed, err := ApplyMessage(vmenv, msg, gp, extra)
	//log.Info("ApplyMessage state_processor end", "tx hash", tx.Hash().Hex(), "to", tx.To(), "usedGas", gas)
	if err != nil {
		log.Error("ApplyMessageError", "err", err)
		return nil, 0, err
	}
	// Update the state with pending changes
	var (
		root         []byte
		contractAddr common.Address
	)

	if msg.To() == nil {
		contractAddr = crypto.CreateAddress(vmenv.Context.Origin, tx.Nonce())
	}

	// add by linagc : 如果 to==nil 就是创建合约，此时判断是否为 erc20 合约
	if err == nil && !failed && len(tx.Data()) > 4 {
		args := vm.TTAArgs{State: statedb}
		if tx.To() == nil && utils.ERC20Trait.IsERC20(tx.Data()) {
			// 如果是 erc20 的部署，则直接将合约地址注册到 tokenexange 中
			if erc20points.Template.VerifyCode(statedb.GetCode(contractAddr)) == nil {
				vm.PointsExange.Erc20Trigger(vm.TTA_CREATE, args.AppendAddr(contractAddr))
			}
		} else if tx.To() != nil {
			args = args.AppendAddr(*tx.To())
			if to, amount, err := utils.ERC20Trait.IsTransfer(tx.Data()); err == nil {
				if verifyTransferLog(statedb, tx.Hash(), msg.From(), to, amount) {
					vm.PointsExange.Erc20Trigger(vm.TTA_TRANSFER, args.AppendFrom(msg.From()).AppendTo(to).AppendAmount(amount))
				}
			} else if from, to, amount, err := utils.ERC20Trait.IsTransferFrom(tx.Data()); err == nil {
				if verifyTransferLog(statedb, tx.Hash(), from, to, amount) {
					vm.PointsExange.Erc20Trigger(vm.TTA_TRANSFERFROM, args.AppendFrom(from).AppendTo(to).AppendAmount(amount))
				}
			}
		}
	}

	// don't record root multi-goroutine(MStateDB) execution
	statedb.Finalise(true)

	//*usedGas += gas
	atomic.AddUint64(usedGas, gas)

	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing wether the root touch-delete accounts.
	receipt := types.NewReceipt(root, failed, *usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = gas
	// if the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = contractAddr
	}
	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})

	return receipt, gas, err
}

// event Transfer(address indexed from, address indexed to, uint value);
func verifyTransferLog(statedb state.IStateDB, txHash common.Hash, from, to common.Address, amount *big.Int) bool {
	var (
		// Transfer func sign : 0xddf252ad
		fs   = "0xddf252ad"
		logs = statedb.GetLogs(txHash)
		// 1 : 事件签名验证
		v1 = func(log *types.Log) bool {
			return strings.Index(log.Topics[0].Hex(), fs) == 0
		}
		// 2 : from/to 验证
		v2 = func(log *types.Log) bool {
			var f, t bool
			if len(log.Topics) > 1 {
				for _, topic := range log.Topics[1:] {
					if bytes.Equal(from.Hash().Bytes(), topic.Bytes()) {
						f = true
					}
					if bytes.Equal(to.Hash().Bytes(), topic.Bytes()) {
						t = true
					}
				}
			}
			if len(log.Data) > 32 {
				if bytes.Contains(log.Data, from.Hash().Bytes()) {
					f = true
				}
				if bytes.Contains(log.Data, to.Hash().Bytes()) {
					t = true
				}
			}
			return f && t
		}
		// 3 : 金额验证
		v3 = func(log *types.Log) bool {
			var (
				a bool
				h = common.BytesToHash(amount.Bytes())
			)
			if len(log.Topics) > 1 {
				for _, topic := range log.Topics[1:] {
					if bytes.Equal(h.Bytes(), topic.Bytes()) {
						a = true
					}
				}
			}
			if len(log.Data) >= 32 {
				if bytes.Contains(log.Data, h.Bytes()) {
					a = true
				}
			}
			return a
		}
	)
	fmt.Println("verifyTransferLog start.")
	for _, log := range logs {
		fmt.Println("1 : 事件签名验证")
		if v1(log) {
			fmt.Println("2 : from/to 验证")
			if v2(log) {
				fmt.Println("3 : 金额验证")
				if v3(log) {
					fmt.Println("verifyTransferLog success.")
					return true
				}
			}
		}
	}
	fmt.Println("from", from.Hash())
	fmt.Println("to", from.Hash())
	fmt.Println("amount", common.BytesToHash(amount.Bytes()).Bytes())
	for i, lg := range logs {
		fmt.Println(i, "log", lg.Topics, lg.Data)
	}
	fmt.Println("verifyTransferLog fail.")
	return false
}
