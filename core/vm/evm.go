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

package vm

import (
	"fmt"
	"math/big"
	"CRD-chain/common/hexutil"
	"CRD-chain/core/types"
	"CRD-chain/log"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/CRDcc/protos"
	"CRD-chain/evertrust/utils"
	"sync/atomic"
	"time"

	"github.com/golang/protobuf/proto"

	"CRD-chain/CRDcc"

	"CRD-chain/common"
	"CRD-chain/crypto"
	"CRD-chain/params"
)

// emptyCodeHash is used by create to ensure deployment is disallowed to already
// deployed contract addresses (relevant after the account abstraction).
var emptyCodeHash = crypto.Keccak256Hash(nil)

type (
	// CanTransferFunc is the signature of a transfer guard function
	CanTransferFunc func(StateDB, common.Address, *big.Int, common.Address) bool
	// TransferFunc is the signature of a transfer function
	TransferFunc func(StateDB, common.Address, common.Address, *big.Int)
	// GetHashFunc returns the nth block hash in the blockchain
	// and is used by the BLOCKHASH EVM op code.
	GetHashFunc func(uint64) common.Hash
	// add by liangc for wasm
	codeAndHash struct {
		code []byte
		hash common.Hash
	}
)

// add by liangc for wasm
func (c *codeAndHash) Hash() common.Hash {
	if c.hash == (common.Hash{}) {
		c.hash = crypto.Keccak256Hash(c.code)
	}
	return c.hash
}

// run runs the given contract and takes care of running precompiles with a fallback to the byte code interpreter.
func run(evm *EVM, contract *Contract, input []byte, extra map[string][]byte) ([]byte, error) {
	return runReadonly(evm, contract, input, extra, false)
}

// add by liangc for wasm
func runReadonly(evm *EVM, contract *Contract, input []byte, extra map[string][]byte, readonly bool) ([]byte, error) {
	if contract.CodeAddr != nil {
		//log.Info("run contract", "contract addr", contract.CodeAddr.Hex())
		precompiles := PrecompiledContractsHomestead
		if evm.ChainConfig().IsByzantium(evm.BlockNumber) {
			precompiles = PrecompiledContractsByzantium
		}

		codeAddr := contract.CodeAddr
		if p := precompiles[*codeAddr]; p != nil {
			return RunPrecompiledContract(evm, p, input, contract, extra)
		}

		if CRDcc.CanExec(*codeAddr) {
			return RunPrecompiledContract(evm, precompiles[utils.BaapDeployContract], input, contract, extra)
		} else {
			//cc run
			RunCCWhenExec(contract, extra)
		}

	}
	for _, interpreter := range evm.interpreters {
		if interpreter.CanRun(contract.Code) {
			if evm.interpreter != interpreter {
				// Ensure that the interpreter pointer is set back
				// to its current value upon return.
				defer func(i Interpreter) {
					evm.interpreter = i
				}(evm.interpreter)
				evm.interpreter = interpreter
			}
			// add by liangc : wasm deploy 时跳过 verifyStatus
			if _, ok := extra["DEPLOY"]; !ok && EwasmFuncs.IsWASM(contract.Code) {
				if err := EwasmFuncs.VerifyStatus(evm.BlockNumber, contract.Code); err != nil {
					log.Error("EWASM VerifyStatus error", "err", err)
					return nil, err
				}
			}
			return interpreter.Run(contract, input, readonly)

		}
	}
	return nil, ErrNoCompatibleInterpreter
}

func RunCCWhenExec(contract *Contract, extra map[string][]byte) (err error) {
	ccBuf := contract.Code
	if len(ccBuf) == 0 {
		//log.Error("get cc buf", "err", ErrNoChainCodeContract)
		return ErrNoChainCodeContract
	}
	var deploy protos.Deployment
	err = proto.Unmarshal(ccBuf, &deploy)
	if err != nil {
		//log.Error("ccBuf unmarshal error", "err", err)
		return
	}

	//让cc启动
	stateFunc := func(fcn string, key string, value []byte) []byte {
		//note: do nothing
		return nil
	}

	extra[conf.BaapDst] = utils.CCBaapDeploy.Bytes()

	ptx := &protos.Transaction{
		Type:    types.Transaction_deploy, //1invoke 2deploy
		Payload: ccBuf,
	}
	ccDeployInput, err := proto.Marshal(ptx)
	if err != nil {
		fmt.Printf("!!!!!!!!proto marshal error:%v \n", err)
		return
	}

	log.Trace("cc not running, then run cc!!!!", "addr", contract.CodeAddr)
	err = CRDcc.Apply(deploy.Payload, extra, ccDeployInput, stateFunc)
	if err != nil {
		log.Error("cc apply error", "err", err)
		return
	}

	return
}

// Context provides the EVM with auxiliary information. Once provided
// it shouldn't be modified.
type Context struct {
	// CanTransfer returns whether the account contains
	// sufficient ether to transfer the value
	CanTransfer CanTransferFunc
	// Transfer transfers ether from one account to the other
	Transfer TransferFunc
	// GetHash returns the hash corresponding to n
	GetHash GetHashFunc

	// Message information
	Origin   common.Address // Provides information for ORIGIN
	GasPrice *big.Int       // Provides information for GASPRICE

	// Block information
	Coinbase    common.Address // Provides information for COINBASE
	GasLimit    uint64         // Provides information for GASLIMIT
	Header      *types.Header  // Provides information for BlockHeader
	BlockNumber *big.Int       // Provides information for NUMBER
	Time        *big.Int       // Provides information for TIME
	Difficulty  *big.Int       // Provides information for DIFFICULTY
}

// EVM is the Ethereum Virtual Machine base object and provides
// the necessary tools to run a contract on the given state with
// the provided context. It should be noted that any error
// generated through any of the calls should be considered a
// revert-state-and-consume-all-gas operation, no checks on
// specific errors should ever be performed. The interpreter makes
// sure that any errors generated are to be considered faulty code.
//
// The EVM should never be reused and is not thread safe.
type EVM struct {
	// Context provides auxiliary blockchain related information
	Context
	// StateDB gives access to the underlying state
	StateDB StateDB
	// Depth is the current call stack
	depth int

	// chainConfig contains information about the current chain
	chainConfig *params.ChainConfig
	// chain rules contains the chain rules for the current epoch
	chainRules params.Rules
	// virtual machine configuration options used to initialise the
	// evm.
	vmConfig Config
	// global (to this context) ethereum virtual machine
	// used throughout the execution of the tx.
	interpreters []Interpreter
	interpreter  Interpreter
	// abort is used to abort the EVM calling operations
	// NOTE: must be set atomically
	abort int32
	// callGasTemp holds the gas available for the current call. This is needed because the
	// available gas is calculated in gasCall* according to the 63/64 rule and later
	// applied in opCall*.
	callGasTemp uint64
}

// NewEVM returns a new EVM. The returned EVM is not thread safe and should
// only ever be used *once*.
func NewEVM(ctx Context, statedb StateDB, chainConfig *params.ChainConfig, vmConfig Config) *EVM {
	evm := &EVM{
		Context:     ctx,
		StateDB:     statedb,
		vmConfig:    vmConfig,
		chainConfig: chainConfig,
		chainRules:  chainConfig.Rules(ctx.BlockNumber),
		//interpreters: make([]Interpreter, 1),
		// add by liangc for wasm
		interpreters: make([]Interpreter, 0, 1),
	}
	//evm.interpreters[0] = NewEVMInterpreter(evm, vmConfig)
	//evm.interpreter = evm.interpreters[0]

	// add by liangc for wasm >>>>
	if chainConfig.IsEWASM(ctx.BlockNumber) {
		evm.interpreters = append(evm.interpreters, NewEWASMInterpreter(evm))
	}
	evm.interpreters = append(evm.interpreters, NewEVMInterpreter(evm, vmConfig))
	evm.interpreter = evm.interpreters[len(evm.interpreters)-1]
	// add by liangc for wasm <<<<

	return evm
}

// Cancel cancels any running EVM operation. This may be called concurrently and
// it's safe to be called multiple times.
func (evm *EVM) Cancel() {
	atomic.StoreInt32(&evm.abort, 1)
}

// Interpreter returns the current interpreter
func (evm *EVM) Interpreter() Interpreter {
	return evm.interpreter
}

// Call executes the contract associated with the addr with the given input as
// parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.

func (evm *EVM) Call(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int,
	extra map[string][]byte) (ret []byte, leftOverGas uint64, err error) {
	txid := hexutil.Encode(extra[conf.BaapTxid][:])[2:]

	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		log.Error("evm error 1")
		return nil, gas, nil
	}

	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		log.Error("evm error 2")
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	if !evm.Context.CanTransfer(evm.StateDB, caller.Address(), value, addr) {
		log.Error("evm error 3")
		return nil, gas, ErrInsufficientBalance
	}

	var (
		to       = AccountRef(addr)
		snapshot = evm.StateDB.Snapshot()
	)
	if !evm.StateDB.Exist(addr) {
		precompiles := PrecompiledContractsHomestead
		if evm.ChainConfig().IsByzantium(evm.BlockNumber) {
			precompiles = PrecompiledContractsByzantium
		}

		if !CRDcc.CanExec(addr) && precompiles[addr] == nil && evm.ChainConfig().IsEIP158(evm.BlockNumber) && value.Sign() == 0 && !utils.IsFreeGas() && !utils.IsFreeTx(&addr) {
			log.Info("Calling a non existing account", "to addr", addr.String())
			// Calling a non existing account, don't do anything, but ping the tracer
			if evm.vmConfig.Debug && evm.depth == 0 {
				evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, gas, value)
				evm.vmConfig.Tracer.CaptureEnd(ret, 0, 0, nil)
			}
			return nil, gas, ErrChainCodeContract
		}
		evm.StateDB.CreateAccount(addr)
		//for user custom contract to put state
		if evm.ChainConfig().IsEIP158(evm.BlockNumber) {
			evm.StateDB.SetNonce(addr, 1)
		}
	}
	evm.Transfer(evm.StateDB, caller.Address(), to.Address(), value)

	// Initialise a new contract and set the code that is to be used by the EVM.
	// The contract is a scoped environment for this execution context only.
	contract := NewContract(caller, to, value, gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	// Capture the tracer start/end events in debug mode
	if evm.vmConfig.Debug && evm.depth == 0 {
		start := time.Now()

		evm.vmConfig.Tracer.CaptureStart(caller.Address(), addr, false, input, gas, value)

		defer func() { // Lazy evaluation of the parameters
			evm.vmConfig.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
		}()
	}

	//log.Info("evm run s contract", "txid", txid, "gas", contract.Gas)
	ret, err = run(evm, contract, input, extra)
	//log.Info(fmt.Sprintf("evm run e contract --- %s(%d)", txid, contract.Gas))

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if err != nil {
		log.Error("run contract","err", err, "txid", txid)
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted && !utils.IsFreeGas() && !utils.IsFreeTx(&addr) {
			log.Error("evm error will reverted")
			contract.UseGas(contract.Gas)
		}
	}

	return ret, contract.Gas, err
}

// CallCode executes the contract associated with the addr with the given input
// as parameters. It also handles any necessary value transfer required and takes
// the necessary steps to create accounts and reverses the state in case of an
// execution error or failed value transfer.
//
// CallCode differs from Call in the sense that it executes the given address'
// code with the caller as context.
func (evm *EVM) CallCode(caller ContractRef, addr common.Address, input []byte, gas uint64, value *big.Int) (ret []byte, leftOverGas uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}

	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Fail if we're trying to transfer more than the available balance
	if !evm.CanTransfer(evm.StateDB, caller.Address(), value, addr) {
		return nil, gas, ErrInsufficientBalance
	}

	var (
		snapshot = evm.StateDB.Snapshot()
		to       = AccountRef(caller.Address())
	)
	// initialise a new contract and set the code that is to be used by the
	// EVM. The contract is a scoped environment for this execution context
	// only.
	contract := NewContract(caller, to, value, gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	ret, err = run(evm, contract, input, make(map[string][]byte))
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, contract.Gas, err
}

// DelegateCall executes the contract associated with the addr with the given input
// as parameters. It reverses the state in case of an execution error.
//
// DelegateCall differs from CallCode in the sense that it executes the given address'
// code with the caller as context and the caller is set to the caller of the caller.
func (evm *EVM) DelegateCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}

	var (
		snapshot = evm.StateDB.Snapshot()
		to       = AccountRef(caller.Address())
	)

	// Initialise a new contract and make initialise the delegate values
	contract := NewContract(caller, to, nil, gas).AsDelegate()
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	ret, err = run(evm, contract, input, make(map[string][]byte))
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, contract.Gas, err
}

// StaticCall executes the contract associated with the addr with the given input
// as parameters while disallowing any modifications to the state during the call.
// Opcodes that attempt to perform such modifications will result in exceptions
// instead of performing the modifications.
func (evm *EVM) StaticCall(caller ContractRef, addr common.Address, input []byte, gas uint64) (ret []byte, leftOverGas uint64, err error) {
	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, gas, nil
	}
	// Fail if we're trying to execute above the call depth limit
	if evm.depth > int(params.CallCreateDepth) {
		return nil, gas, ErrDepth
	}
	// Make sure the readonly is only set if we aren't in readonly yet
	// this makes also sure that the readonly flag isn't removed for
	// child calls.
	if !evm.interpreter.IsReadOnly() {
		evm.interpreter.SetReadOnly(true)
		defer func() { evm.interpreter.SetReadOnly(false) }()
	}

	var (
		to       = AccountRef(addr)
		snapshot = evm.StateDB.Snapshot()
	)
	// Initialise a new contract and set the code that is to be used by the
	// EVM. The contract is a scoped environment for this execution context
	// only.
	contract := NewContract(caller, to, new(big.Int), gas)
	contract.SetCallCode(&addr, evm.StateDB.GetCodeHash(addr), evm.StateDB.GetCode(addr))

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in Homestead this also counts for code storage gas errors.
	ret, err = runReadonly(evm, contract, input, make(map[string][]byte), true)
	if err != nil {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	return ret, contract.Gas, err
}

// create creates a new contract using code as deployment code.
func (evm *EVM) create(caller ContractRef, codeAndHash *codeAndHash, gas uint64, value *big.Int, address common.Address) ([]byte, common.Address, uint64, error) {
	// Depth check execution. Fail if we're trying to execute above the
	// limit.
	if evm.depth > int(params.CallCreateDepth) {
		return nil, common.Address{}, gas, ErrDepth
	}
	if !evm.CanTransfer(evm.StateDB, caller.Address(), value, address) {
		return nil, common.Address{}, gas, ErrInsufficientBalance
	}

	var (
		snapshot int
		code     = codeAndHash.code
		nonce    = evm.StateDB.GetNonce(caller.Address())
		// Ensure there's no existing contract already at the designated address
		contractHash = evm.StateDB.GetCodeHash(address)
		// add by liangc : 如果在 txpool 中预处理过，这个 key 会拿到处理结果
		//txcodek = common.BytesToHash(crypto.Keccak256(code))
	)

	evm.StateDB.SetNonce(caller.Address(), nonce+1)
	if evm.StateDB.GetNonce(address) != 0 || (contractHash != (common.Hash{}) && contractHash != emptyCodeHash) {
		return nil, common.Address{}, 0, ErrContractAddressCollision
	}

	// Create a new account on the state
	snapshot = evm.StateDB.Snapshot()
	evm.StateDB.CreateAccount(address)
	if evm.ChainConfig().IsEIP158(evm.BlockNumber) {
		evm.StateDB.SetNonce(address, 1)
	}
	evm.Transfer(evm.StateDB, caller.Address(), address, value)

	// initialise a new contract and set the code that is to be used by the
	// EVM. The contract is a scoped environment for this execution context
	// only.
	contract := NewContract(caller, AccountRef(address), value, gas)
	//contract.SetCallCode(&address, crypto.Keccak256Hash(code), code)

	// add by liangc : 如果预处理拿到了结果，则跳过执行过程，直接返回结果 >>>>
	/*
		if p := utils.Precreate.Det(txcodek); p != nil && !p.Failed && (p.BlockNumber == evm.BlockNumber.Uint64() || p.Logs == nil || len(p.Logs) == 0) {
			// 如果出错的话，要不要执行状态插入呢？
			//if p.Err == nil {
			// 如果构造函数里使用了 event 那么就会产生 log 数据
			for _, _log := range p.Logs {
				// 此处手写比 rlp 和其他方案效率高
				_l := &types.Log{_log.Address, _log.Topics, _log.Data, _log.BlockNumber, _log.TxHash, _log.TxIndex, _log.BlockHash, _log.Index, _log.Removed}
				evm.StateDB.AddLog(_l)
			}
			// evm 和 wasm 合约都会产生 state 数据
			for addr, stateMap := range p.State {
				for k, v := range stateMap {
					evm.StateDB.SetState(addr, k, v)
				}
			}
			// 目前只有 wasm 合约部署时可能会产生 stateCRD 数据
			for addr, stateMap := range p.StateCRDMap {
				for k, v := range stateMap {
					evm.StateDB.SetCRDState(addr, k, v)
				}
			}
			log.Info("<< PRECREATE_SUCCESS >>", "contractAddress", address.Hex(), "refundGas", p.Gas, "failed", p.Failed, "err", p.Err)
			evm.StateDB.SetCode(address, p.Ret)
			return p.Ret, address, p.Gas, p.Err
			//}
	}*/

	// add by liangc : 如果预处理拿到了结果，则跳过执行过程，直接返回结果 <<<<
	// fmt.Println("<< CREATE_CONTRACT >>", "blocknumber", evm.BlockNumber.Uint64(), "contractAddress", address.Hex(), "gas", gas)

	// add by liangc for wasm >>>>
	//for _, interpreter := range evm.interpreters {
	//	if interpreter.CanRun(codeAndHash.code) {
	//		var err error
	//		codeAndHash.code, err = interpreter.PreContractCreation(codeAndHash.code, contract)
	//		if err != nil {
	//			return nil, address, gas, nil
	//		}
	//	}
	//}

	// 检查 wasm
	if EwasmFuncs.IsWASM(codeAndHash.code) {
		// code 一定可以找到对应的 finalcode ，否则就是一个错误的数据
		_, err := EwasmFuncs.ValidateCode(codeAndHash.code)
		if err != nil {
			// 教研不通过，有两种可能，一种是 code ，可以通过 codekey 得到 final
			// 另一种是 错误的 final ，所以先去获取，然后再教研 final
			//codekey := crypto.Keccak256(codeAndHash.code)
			codekey := EwasmFuncs.GenCodekey(codeAndHash.code)
			final, ok := EwasmFuncs.GetCode(codekey)
			if ok && len(final) == 32 {
				final, ok = EwasmFuncs.GetCode(final)
			}
			if !ok {
				log.Error("EwasmFuncs.ValidateCode-error", "err", err)
				return nil, address, gas, err
			}
			_, err := EwasmFuncs.ValidateCode(final)
			if err != nil {
				log.Error("EwasmFuncs.ValidateFinal-error", "err", err)
				return nil, address, gas, err
			}
			codeAndHash.code = final
		}
	}

	contract.SetCodeOptionalHash(&address, codeAndHash)

	// add by liangc for wasm <<<<

	if evm.vmConfig.NoRecursion && evm.depth > 0 {
		return nil, address, gas, nil
	}

	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureStart(caller.Address(), address, true, code, gas, value)
	}

	start := time.Now()

	ret, err := run(evm, contract, nil, map[string][]byte{"DEPLOY": []byte{1}})

	maxCodeSizeExceeded := evm.ChainConfig().IsEIP158(evm.BlockNumber) && len(ret) > params.MaxCodeSize

	//log.Info("create_contract", "maxCodeSizeExceeded", maxCodeSizeExceeded, "ret", len(ret), "err", err)
	if err == nil && !maxCodeSizeExceeded {
		createDataGas := uint64(len(ret)) * params.CreateDataGas
		//log.Info("create_contract", "gas", createDataGas)
		if contract.UseGas(createDataGas) {
			if EwasmFuncs.IsWASM(codeAndHash.code) {
				// 因为 ewasm 合约已经被 sentinel 提前处理过了，所以这里直接把验证通过的 code 插入 state 即可
				evm.StateDB.SetCode(address, codeAndHash.code)
			} else {
				evm.StateDB.SetCode(address, ret)
			}
		} else {
			err = ErrCodeStoreOutOfGas
			log.Error("create_contract_error", "err", err, "gas", contract.Gas, "createDataGas", createDataGas)
		}
	}

	// When an error was returned by the EVM or when setting the creation code
	// above we revert to the snapshot and consume any gas remaining. Additionally
	// when we're in homestead this also counts for code storage gas errors.
	if maxCodeSizeExceeded || (err != nil && (evm.ChainConfig().IsHomestead(evm.BlockNumber) || err != ErrCodeStoreOutOfGas)) {
		evm.StateDB.RevertToSnapshot(snapshot)
		if err != errExecutionReverted {
			contract.UseGas(contract.Gas)
		}
	}
	// Assign err if contract code size exceeds the max while the err is still empty.
	if maxCodeSizeExceeded && err == nil {
		err = errMaxCodeSizeExceeded
	}
	if evm.vmConfig.Debug && evm.depth == 0 {
		evm.vmConfig.Tracer.CaptureEnd(ret, gas-contract.Gas, time.Since(start), err)
	}
	return ret, address, contract.Gas, err
}

// Create creates a new contract using code as deployment code.
func (evm *EVM) Create(caller ContractRef, code []byte, gas uint64, value *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	contractAddr = crypto.CreateAddress(caller.Address(), evm.StateDB.GetNonce(caller.Address()))
	return evm.create(caller, &codeAndHash{code: code}, gas, value, contractAddr)
}

// Create2 creates a new contract using code as deployment code.
//
// The different between Create2 with Create is Create2 uses sha3(0xff ++ msg.sender ++ salt ++ sha3(init_code))[12:]
// instead of the usual sender-and-nonce-hash as the address where the contract is initialized at.
func (evm *EVM) Create2(caller ContractRef, code []byte, gas uint64, endowment *big.Int, salt *big.Int) (ret []byte, contractAddr common.Address, leftOverGas uint64, err error) {
	codeAndHash := &codeAndHash{code: code}
	contractAddr = crypto.CreateAddress2(caller.Address(), common.BigToHash(salt), codeAndHash.Hash().Bytes())
	return evm.create(caller, codeAndHash, gas, endowment, contractAddr)
}

// ChainConfig returns the environment's chain configuration
func (evm *EVM) ChainConfig() *params.ChainConfig { return evm.chainConfig }

// CanRun checks the binary for a WASM header and accepts the binary blob
// if it matches.

// add by liangc >>>>>>>>>>>>>>
func IsWASM(file []byte) bool {
	return EwasmFuncs.IsWASM(file)
}

// add by liangc <<<<<<<<<<<<<<
