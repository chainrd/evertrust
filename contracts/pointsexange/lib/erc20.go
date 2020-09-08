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
 * @Time   : 2019-08-08 13:13
 * @Author : liangc
 *************************************************************************/
package pointsexangelib

import (
	"math/big"
	"CRD-chain/accounts/abi"
	"CRD-chain/accounts/abi/bind"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"strings"
)

// EIP20InterfaceABI is the input ABI used to generate the binding from.
const EIP20InterfaceABI = `
[
  {
    "constant": true,
    "inputs": [],
    "name": "name",
    "outputs": [
      {
        "name": "",
        "type": "string"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "_spender",
        "type": "address"
      },
      {
        "name": "_value",
        "type": "uint256"
      }
    ],
    "name": "approve",
    "outputs": [
      {
        "name": "success",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "totalSupply",
    "outputs": [
      {
        "name": "",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "_from",
        "type": "address"
      },
      {
        "name": "_to",
        "type": "address"
      },
      {
        "name": "_value",
        "type": "uint256"
      }
    ],
    "name": "transferFrom",
    "outputs": [
      {
        "name": "success",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "decimals",
    "outputs": [
      {
        "name": "",
        "type": "uint8"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "_owner",
        "type": "address"
      }
    ],
    "name": "balanceOf",
    "outputs": [
      {
        "name": "balance",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "symbol",
    "outputs": [
      {
        "name": "",
        "type": "string"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "_to",
        "type": "address"
      },
      {
        "name": "_value",
        "type": "uint256"
      }
    ],
    "name": "transfer",
    "outputs": [
      {
        "name": "success",
        "type": "bool"
      }
    ],
    "payable": false,
    "stateMutability": "nonpayable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "_owner",
        "type": "address"
      },
      {
        "name": "_spender",
        "type": "address"
      }
    ],
    "name": "allowance",
    "outputs": [
      {
        "name": "remaining",
        "type": "uint256"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  }
]
`

// EIP20Interface is an auto generated Go binding around an Ethereum contract.
type EIP20Interface struct {
	EIP20InterfaceCaller     // Read-only binding to the contract
	EIP20InterfaceTransactor // Write-only binding to the contract
	EIP20InterfaceFilterer   // Log filterer for contract events
}

// EIP20InterfaceCaller is an auto generated read-only Go binding around an Ethereum contract.
type EIP20InterfaceCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// EIP20InterfaceTransactor is an auto generated write-only Go binding around an Ethereum contract.
type EIP20InterfaceTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// EIP20InterfaceFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type EIP20InterfaceFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// EIP20InterfaceSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type EIP20InterfaceSession struct {
	Contract     *EIP20Interface   // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// EIP20InterfaceCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type EIP20InterfaceCallerSession struct {
	Contract *EIP20InterfaceCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts         // Call options to use throughout this session
}

// EIP20InterfaceTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type EIP20InterfaceTransactorSession struct {
	Contract     *EIP20InterfaceTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts         // Transaction auth options to use throughout this session
}

// EIP20InterfaceRaw is an auto generated low-level Go binding around an Ethereum contract.
type EIP20InterfaceRaw struct {
	Contract *EIP20Interface // Generic contract binding to access the raw methods on
}

// EIP20InterfaceCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type EIP20InterfaceCallerRaw struct {
	Contract *EIP20InterfaceCaller // Generic read-only contract binding to access the raw methods on
}

// EIP20InterfaceTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type EIP20InterfaceTransactorRaw struct {
	Contract *EIP20InterfaceTransactor // Generic write-only contract binding to access the raw methods on
}

// NewEIP20Interface creates a new instance of EIP20Interface, bound to a specific deployed contract.
func NewEIP20Interface(address common.Address, backend bind.ContractBackend) (*EIP20Interface, error) {
	contract, err := bindEIP20Interface(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &EIP20Interface{EIP20InterfaceCaller: EIP20InterfaceCaller{contract: contract}, EIP20InterfaceTransactor: EIP20InterfaceTransactor{contract: contract}, EIP20InterfaceFilterer: EIP20InterfaceFilterer{contract: contract}}, nil
}

// NewEIP20InterfaceCaller creates a new read-only instance of EIP20Interface, bound to a specific deployed contract.
func NewEIP20InterfaceCaller(address common.Address, caller bind.ContractCaller) (*EIP20InterfaceCaller, error) {
	contract, err := bindEIP20Interface(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &EIP20InterfaceCaller{contract: contract}, nil
}

// NewEIP20InterfaceTransactor creates a new write-only instance of EIP20Interface, bound to a specific deployed contract.
func NewEIP20InterfaceTransactor(address common.Address, transactor bind.ContractTransactor) (*EIP20InterfaceTransactor, error) {
	contract, err := bindEIP20Interface(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &EIP20InterfaceTransactor{contract: contract}, nil
}

// NewEIP20InterfaceFilterer creates a new log filterer instance of EIP20Interface, bound to a specific deployed contract.
func NewEIP20InterfaceFilterer(address common.Address, filterer bind.ContractFilterer) (*EIP20InterfaceFilterer, error) {
	contract, err := bindEIP20Interface(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &EIP20InterfaceFilterer{contract: contract}, nil
}

// bindEIP20Interface binds a generic wrapper to an already deployed contract.
func bindEIP20Interface(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(EIP20InterfaceABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_EIP20Interface *EIP20InterfaceRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _EIP20Interface.Contract.EIP20InterfaceCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_EIP20Interface *EIP20InterfaceRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _EIP20Interface.Contract.EIP20InterfaceTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_EIP20Interface *EIP20InterfaceRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _EIP20Interface.Contract.EIP20InterfaceTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_EIP20Interface *EIP20InterfaceCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _EIP20Interface.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_EIP20Interface *EIP20InterfaceTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _EIP20Interface.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_EIP20Interface *EIP20InterfaceTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _EIP20Interface.Contract.contract.Transact(opts, method, params...)
}

// Allowance is a free data retrieval call binding the contract method 0xdd62ed3e.
//
// Solidity: function allowance(_owner address, _spender address) constant returns(remaining uint256)
func (_EIP20Interface *EIP20InterfaceCaller) Allowance(opts *bind.CallOpts, _owner common.Address, _spender common.Address) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _EIP20Interface.contract.Call(opts, out, "allowance", _owner, _spender)
	return *ret0, err
}

// Allowance is a free data retrieval call binding the contract method 0xdd62ed3e.
//
// Solidity: function allowance(_owner address, _spender address) constant returns(remaining uint256)
func (_EIP20Interface *EIP20InterfaceSession) Allowance(_owner common.Address, _spender common.Address) (*big.Int, error) {
	return _EIP20Interface.Contract.Allowance(&_EIP20Interface.CallOpts, _owner, _spender)
}

// Allowance is a free data retrieval call binding the contract method 0xdd62ed3e.
//
// Solidity: function allowance(_owner address, _spender address) constant returns(remaining uint256)
func (_EIP20Interface *EIP20InterfaceCallerSession) Allowance(_owner common.Address, _spender common.Address) (*big.Int, error) {
	return _EIP20Interface.Contract.Allowance(&_EIP20Interface.CallOpts, _owner, _spender)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(_owner address) constant returns(balance uint256)
func (_EIP20Interface *EIP20InterfaceCaller) BalanceOf(opts *bind.CallOpts, _owner common.Address) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _EIP20Interface.contract.Call(opts, out, "balanceOf", _owner)
	return *ret0, err
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(_owner address) constant returns(balance uint256)
func (_EIP20Interface *EIP20InterfaceSession) BalanceOf(_owner common.Address) (*big.Int, error) {
	return _EIP20Interface.Contract.BalanceOf(&_EIP20Interface.CallOpts, _owner)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(_owner address) constant returns(balance uint256)
func (_EIP20Interface *EIP20InterfaceCallerSession) BalanceOf(_owner common.Address) (*big.Int, error) {
	return _EIP20Interface.Contract.BalanceOf(&_EIP20Interface.CallOpts, _owner)
}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() constant returns(uint8)
func (_EIP20Interface *EIP20InterfaceCaller) Decimals(opts *bind.CallOpts) (uint8, error) {
	var (
		ret0 = new(uint8)
	)
	out := ret0
	err := _EIP20Interface.contract.Call(opts, out, "decimals")
	return *ret0, err
}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() constant returns(uint8)
func (_EIP20Interface *EIP20InterfaceSession) Decimals() (uint8, error) {
	return _EIP20Interface.Contract.Decimals(&_EIP20Interface.CallOpts)
}

// Decimals is a free data retrieval call binding the contract method 0x313ce567.
//
// Solidity: function decimals() constant returns(uint8)
func (_EIP20Interface *EIP20InterfaceCallerSession) Decimals() (uint8, error) {
	return _EIP20Interface.Contract.Decimals(&_EIP20Interface.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() constant returns(string)
func (_EIP20Interface *EIP20InterfaceCaller) Name(opts *bind.CallOpts) (string, error) {
	var (
		ret0 = new(string)
	)
	out := ret0
	err := _EIP20Interface.contract.Call(opts, out, "name")
	return *ret0, err
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() constant returns(string)
func (_EIP20Interface *EIP20InterfaceSession) Name() (string, error) {
	return _EIP20Interface.Contract.Name(&_EIP20Interface.CallOpts)
}

// Name is a free data retrieval call binding the contract method 0x06fdde03.
//
// Solidity: function name() constant returns(string)
func (_EIP20Interface *EIP20InterfaceCallerSession) Name() (string, error) {
	return _EIP20Interface.Contract.Name(&_EIP20Interface.CallOpts)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() constant returns(string)
func (_EIP20Interface *EIP20InterfaceCaller) Symbol(opts *bind.CallOpts) (string, error) {
	var (
		ret0 = new(string)
	)
	out := ret0
	err := _EIP20Interface.contract.Call(opts, out, "symbol")
	return *ret0, err
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() constant returns(string)
func (_EIP20Interface *EIP20InterfaceSession) Symbol() (string, error) {
	return _EIP20Interface.Contract.Symbol(&_EIP20Interface.CallOpts)
}

// Symbol is a free data retrieval call binding the contract method 0x95d89b41.
//
// Solidity: function symbol() constant returns(string)
func (_EIP20Interface *EIP20InterfaceCallerSession) Symbol() (string, error) {
	return _EIP20Interface.Contract.Symbol(&_EIP20Interface.CallOpts)
}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() constant returns(uint256)
func (_EIP20Interface *EIP20InterfaceCaller) TotalSupply(opts *bind.CallOpts) (*big.Int, error) {
	var (
		ret0 = new(*big.Int)
	)
	out := ret0
	err := _EIP20Interface.contract.Call(opts, out, "totalSupply")
	return *ret0, err
}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() constant returns(uint256)
func (_EIP20Interface *EIP20InterfaceSession) TotalSupply() (*big.Int, error) {
	return _EIP20Interface.Contract.TotalSupply(&_EIP20Interface.CallOpts)
}

// TotalSupply is a free data retrieval call binding the contract method 0x18160ddd.
//
// Solidity: function totalSupply() constant returns(uint256)
func (_EIP20Interface *EIP20InterfaceCallerSession) TotalSupply() (*big.Int, error) {
	return _EIP20Interface.Contract.TotalSupply(&_EIP20Interface.CallOpts)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(_spender address, _value uint256) returns(success bool)
func (_EIP20Interface *EIP20InterfaceTransactor) Approve(opts *bind.TransactOpts, _spender common.Address, _value *big.Int) (*types.Transaction, error) {
	return _EIP20Interface.contract.Transact(opts, "approve", _spender, _value)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(_spender address, _value uint256) returns(success bool)
func (_EIP20Interface *EIP20InterfaceSession) Approve(_spender common.Address, _value *big.Int) (*types.Transaction, error) {
	return _EIP20Interface.Contract.Approve(&_EIP20Interface.TransactOpts, _spender, _value)
}

// Approve is a paid mutator transaction binding the contract method 0x095ea7b3.
//
// Solidity: function approve(_spender address, _value uint256) returns(success bool)
func (_EIP20Interface *EIP20InterfaceTransactorSession) Approve(_spender common.Address, _value *big.Int) (*types.Transaction, error) {
	return _EIP20Interface.Contract.Approve(&_EIP20Interface.TransactOpts, _spender, _value)
}

// Transfer is a paid mutator transaction binding the contract method 0xa9059cbb.
//
// Solidity: function transfer(_to address, _value uint256) returns(success bool)
func (_EIP20Interface *EIP20InterfaceTransactor) Transfer(opts *bind.TransactOpts, _to common.Address, _value *big.Int) (*types.Transaction, error) {
	return _EIP20Interface.contract.Transact(opts, "transfer", _to, _value)
}

// Transfer is a paid mutator transaction binding the contract method 0xa9059cbb.
//
// Solidity: function transfer(_to address, _value uint256) returns(success bool)
func (_EIP20Interface *EIP20InterfaceSession) Transfer(_to common.Address, _value *big.Int) (*types.Transaction, error) {
	return _EIP20Interface.Contract.Transfer(&_EIP20Interface.TransactOpts, _to, _value)
}

// Transfer is a paid mutator transaction binding the contract method 0xa9059cbb.
//
// Solidity: function transfer(_to address, _value uint256) returns(success bool)
func (_EIP20Interface *EIP20InterfaceTransactorSession) Transfer(_to common.Address, _value *big.Int) (*types.Transaction, error) {
	return _EIP20Interface.Contract.Transfer(&_EIP20Interface.TransactOpts, _to, _value)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(_from address, _to address, _value uint256) returns(success bool)
func (_EIP20Interface *EIP20InterfaceTransactor) TransferFrom(opts *bind.TransactOpts, _from common.Address, _to common.Address, _value *big.Int) (*types.Transaction, error) {
	return _EIP20Interface.contract.Transact(opts, "transferFrom", _from, _to, _value)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(_from address, _to address, _value uint256) returns(success bool)
func (_EIP20Interface *EIP20InterfaceSession) TransferFrom(_from common.Address, _to common.Address, _value *big.Int) (*types.Transaction, error) {
	return _EIP20Interface.Contract.TransferFrom(&_EIP20Interface.TransactOpts, _from, _to, _value)
}

// TransferFrom is a paid mutator transaction binding the contract method 0x23b872dd.
//
// Solidity: function transferFrom(_from address, _to address, _value uint256) returns(success bool)
func (_EIP20Interface *EIP20InterfaceTransactorSession) TransferFrom(_from common.Address, _to common.Address, _value *big.Int) (*types.Transaction, error) {
	return _EIP20Interface.Contract.TransferFrom(&_EIP20Interface.TransactOpts, _from, _to, _value)
}
