// Copyright 2014 The go-ethereum Authors
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
	"errors"
	"math"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/core/vm"
	"CRD-chain/log"
	"CRD-chain/params"
	"CRD-chain/CRDcc"
	"CRD-chain/CRDcc/util"
	"CRD-chain/evertrust"
	"CRD-chain/evertrust/utils"
)

var (
	errInsufficientBalanceForGas = errors.New("insufficient balance to pay for gas")
)

/*
The State Transitioning Model

A state transition is a change made when a transaction is applied to the current world state
The state transitioning model does all the necessary work to work out a valid new state root.

1) Nonce handling
2) Pre pay gas
3) Create a new state object if the recipient is \0*32
4) Value transfer
== If contract creation ==
  4a) Attempt to run transaction data
  4b) If valid, use result as code for the new state object
== end ==
5) Run Script section
6) Derive new state root
*/
type StateTransition struct {
	gp         *GasPool
	msg        Message
	gas        uint64
	gasPrice   *big.Int
	initialGas uint64
	value      *big.Int
	data       []byte
	state      vm.StateDB
	evm        *vm.EVM
}

// Message represents a message sent to a contract.
type Message interface {
	From() common.Address
	//FromFrontier() (common.Address, error)
	To() *common.Address

	GasPrice() *big.Int
	Gas() uint64
	Value() *big.Int

	Nonce() uint64
	CheckNonce() bool
	Data() []byte
}

var evertrustExtraFlag = util.EthHash([]byte("evertrust"))

// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
func IntrinsicGas(data []byte, contractCreation, homestead bool, to *common.Address) (uint64, error) {
	if utils.IsFreeGas() {
		return 0, nil
	}

	// Set the starting gas for the raw transaction
	var gas uint64
	if contractCreation && homestead {
		gas = params.TxGasContractCreation
	} else {
		gas = params.TxGas
	}
	// Bump the required gas by the amount of transactional data
	if len(data) > 0 {
		// Zero and non-zero bytes are priced differently
		var nz uint64
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		// Make sure we don't exceed uint64 for all data combinations
		if (math.MaxUint64-gas)/params.TxDataNonZeroGas < nz {
			return 0, vm.ErrOutOfGas
		}
		gas += nz * params.TxDataNonZeroGas

		z := uint64(len(data)) - nz
		if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
			return 0, vm.ErrOutOfGas
		}
		gas += z * params.TxDataZeroGas
	}
	return gas, nil
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(evm *vm.EVM, msg Message, gp *GasPool) *StateTransition {
	return &StateTransition{
		gp:       gp,
		evm:      evm,
		msg:      msg,
		gasPrice: msg.GasPrice(),
		value:    msg.Value(),
		data:     msg.Data(),
		state:    evm.StateDB,
	}
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.

func ApplyMessage(evm *vm.EVM, msg Message, gp *GasPool, extra map[string][]byte) ([]byte, uint64, bool, error) {
	return NewStateTransition(evm, msg, gp).TransitionDb(extra)
}

// to returns the recipient of the message.
func (st *StateTransition) to() common.Address {
	if st.msg == nil || st.msg.To() == nil /* contract creation */ {
		return common.Address{}
	}
	return *st.msg.To()
}

func (st *StateTransition) useGas(amount uint64) error {
	if st.gas < amount {
		return vm.ErrOutOfGas
	}
	st.gas -= amount

	return nil
}

func (st *StateTransition) buyGas() error {
	mgval := new(big.Int).Mul(new(big.Int).SetUint64(st.msg.Gas()), st.gasPrice)
	to := st.to()
	if st.state.GetBalance(st.msg.From()).Cmp(mgval) < 0 && !utils.IsFreeGas() && !utils.IsFreeTx(&to) {
		return errInsufficientBalanceForGas
	}
	if err := st.gp.SubGas(st.msg.Gas()); err != nil {
		return err
	}
	st.gas += st.msg.Gas()

	st.initialGas = st.msg.Gas()
	if !utils.IsFreeGas() && !utils.IsFreeTx(&to) {
		st.state.SubBalance(st.msg.From(), mgval)
	}

	return nil
}

func (st *StateTransition) preCheck() error {
	// Make sure this transaction's nonce is correct.
	if st.msg.CheckNonce() {
		nonce := st.state.GetNonce(st.msg.From())
		if nonce < st.msg.Nonce() {
			return ErrNonceTooHigh
		} else if nonce > st.msg.Nonce() {
			return ErrNonceTooLow
		}
	}
	return st.buyGas()
}

// TransitionDb will transition the state by applying the current message and
// returning the result including the the used gas. It returns an error if it
// failed. An error indicates a consensus issue.
func (st *StateTransition) TransitionDb(extra map[string][]byte) (ret []byte, usedGas uint64, failed bool, err error) {
	//log.Info("开始执行TrasitionDb", "txid", "0x"+hex.EncodeToString(extra[conf.BaapTxid]), "from", st.msg.From(), "nonce", st.msg.Nonce())
	if err = st.preCheck(); err != nil {
		return
	}
	msg := st.msg
	sender := vm.AccountRef(msg.From())
	homestead := st.evm.ChainConfig().IsHomestead(st.evm.BlockNumber)
	contractCreation := msg.To() == nil

	//parse data
	var meta utils.Meta
	st.data, meta, err = evertrust.ParseData(st.data)
	if err != nil {
		log.Error("parse data", "err", err)
		return nil, 0, false, err
	}



	// Pay intrinsic gas
	gas, err := IntrinsicGas(st.data, contractCreation, homestead, msg.To())
	if err != nil {
		log.Error("Intrinsic Gas", "err", err)
		return nil, 0, false, err
	}

	//add log
	//txid := hexutil.Encode(extra[conf.BaapTxid][:])[2:]
	//log.Info(fmt.Sprintf("%s -- pay gas %d(%d, %d)", txid, gas, st.initialGas, st.gas))

	if err = st.useGas(gas); err != nil {
		log.Error("useGas", "err", err)
		return nil, 0, false, err
	}

	//log.Info(fmt.Sprintf("%s -- remain gas %d", txid, st.gas))
	var (
		evm = st.evm
		// vm errors do not effect consensus and are therefor
		// not assigned to err, except for insufficient balance
		// error.
		vmerr error
	)



	if contractCreation {
		//log.Info("contract create", "sender", sender.Address(), "value", st.value)
		var (
			contractAddr common.Address
			final        = st.data
		)
		// add by liangc : ewasm 合约部署时，如果携带了 meta 则需把 meta 信息再拼回去，还原 tx.data
		/*if vm.EwasmFuncs.IsWASM(final) && meta != nil && err == nil {
			final, err = evertrust.AssemblePayload(final, meta)
			if err != nil {
				log.Error("AssemblePayload-error", "err", err)
				return nil, 0, false, err
			}
		}*/
		ret, contractAddr, st.gas, vmerr = evm.Create(sender, final, st.gas, st.value)
		//store solidity contract addr
		if vmerr == nil {
			err = vm.StoreContractAddr(evm, contractAddr, meta, sender.Address().Hex(), 1)
			if err != nil {
				log.Error("store solidity contract addr", "err", err)
			}
		}
	} else {
		// Increment the nonce for the next transaction
		st.state.SetNonce(msg.From(), st.state.GetNonce(sender.Address())+1)
		ret, st.gas, vmerr = evm.Call(sender, st.to(), st.data, st.gas, st.value, extra)
	}
	if vmerr != nil {
		log.Error("VM returned with error", "err", vmerr)
		// The only possible consensus-error would be if there wasn't
		// sufficient balance to make the transfer happen. The first
		// balance transfer may never fail.
		if vmerr == vm.ErrInsufficientBalance || vmerr == CRDcc.ErrChainCodeTimeOut || vmerr == vm.ErrCliRpcTimeOut {
			return nil, 0, false, vmerr
		}
		//return nil, 0, false, vmerr
	}
	st.refundGas()
	if !utils.IsFreeGas() && !utils.IsFreeTx(msg.To()) {
		//查看是否有reward地址
		rewardAddr := st.evm.Header.RewardAddress
		//if common.IsHexAddress(rewardAddr) {
		//	rwdAddr := common.HexToAddress(rewardAddr)
		//	log.Info("交易给的奖励地址","add",rwdAddr)
		st.state.AddBalance(rewardAddr, new(big.Int).Mul(new(big.Int).SetUint64(st.gasUsed()), st.gasPrice))
		//} else {
		//	log.Info("交易给的奖励地址","add",st.evm.Coinbase)
		//
		//	st.state.AddBalance(st.evm.Coinbase, new(big.Int).Mul(new(big.Int).SetUint64(st.gasUsed()), st.gasPrice))
		//}
	}
	return ret, st.gasUsed(), vmerr != nil, err
}

func (st *StateTransition) refundGas() {
	// Apply refund counter, capped to half of the used gas.
	refund := st.gasUsed() / 2
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}
	st.gas += refund

	// Return ETH for remaining gas, exchanged at the original rate.
	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.gasPrice)
	if !utils.IsFreeGas() && !utils.IsFreeTx(st.msg.To()) {
		st.state.AddBalance(st.msg.From(), remaining)
	}

	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	st.gp.AddGas(st.gas)
}

// gasUsed returns the amount of gas used up by the state transition.
func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gas
}