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
 * @Time   : 2019-08-20 10:39
 * @Author : liangc
 *************************************************************************/

package pointsexangelib

import (
	"math/big"
	"CRD-chain/accounts/abi"
	"CRD-chain/accounts/abi/bind"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/event"
	"strings"
)

// ExangeABI is the input ABI used to generate the binding from.
const ExangeABI = `
[
  {
    "constant": true,
    "inputs": [
      {
        "name": "addrs",
        "type": "address[]"
      },
      {
        "name": "pageNum",
        "type": "uint256"
      }
    ],
    "name": "ownerOrder",
    "outputs": [
      {
        "name": "",
        "type": "uint256[]"
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
        "name": "id",
        "type": "uint256"
      }
    ],
    "name": "orderinfo",
    "outputs": [
      {
        "name": "orderType",
        "type": "string"
      },
      {
        "name": "region",
        "type": "address"
      },
      {
        "name": "target",
        "type": "address"
      },
      {
        "name": "regionAmount",
        "type": "uint256"
      },
      {
        "name": "targetAmount",
        "type": "uint256"
      },
      {
        "name": "regionComplete",
        "type": "uint256"
      },
      {
        "name": "targetComplete",
        "type": "uint256"
      },
      {
        "name": "regionDecimals",
        "type": "uint8"
      },
      {
        "name": "targetDecimals",
        "type": "uint8"
      },
      {
        "name": "isFinal",
        "type": "bool"
      },
      {
        "name": "owner",
        "type": "address"
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
        "name": "id",
        "type": "uint256"
      }
    ],
    "name": "cancel",
    "outputs": [],
    "payable": true,
    "stateMutability": "payable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "orderType",
        "type": "string"
      },
      {
        "name": "region",
        "type": "address"
      },
      {
        "name": "target",
        "type": "address"
      }
    ],
    "name": "orderlist",
    "outputs": [
      {
        "name": "",
        "type": "uint256[]"
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
        "name": "region",
        "type": "address"
      },
      {
        "name": "amount",
        "type": "uint256"
      }
    ],
    "name": "withdrawal",
    "outputs": [],
    "payable": true,
    "stateMutability": "payable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "region",
        "type": "address"
      }
    ],
    "name": "balanceOf",
    "outputs": [
      {
        "name": "name",
        "type": "string"
      },
      {
        "name": "symbol",
        "type": "string"
      },
      {
        "name": "balance",
        "type": "uint256"
      },
      {
        "name": "decimals",
        "type": "uint8"
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
        "name": "region",
        "type": "address"
      },
      {
        "name": "target",
        "type": "address"
      },
      {
        "name": "regionAmount",
        "type": "uint256"
      },
      {
        "name": "targetAmount",
        "type": "uint256"
      }
    ],
    "name": "bid",
    "outputs": [],
    "payable": true,
    "stateMutability": "payable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "pointsList",
    "outputs": [
      {
        "name": "",
        "type": "address[]"
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
        "name": "region",
        "type": "address"
      },
      {
        "name": "target",
        "type": "address"
      },
      {
        "name": "regionAmount",
        "type": "uint256"
      },
      {
        "name": "targetAmount",
        "type": "uint256"
      }
    ],
    "name": "ask",
    "outputs": [],
    "payable": true,
    "stateMutability": "payable",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "",
        "type": "address"
      }
    ],
    "name": "pointsInfo",
    "outputs": [
      {
        "name": "name",
        "type": "string"
      },
      {
        "name": "symbol",
        "type": "string"
      },
      {
        "name": "totalSupply",
        "type": "uint256"
      },
      {
        "name": "decimals",
        "type": "uint8"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "orderid",
        "type": "uint256"
      },
      {
        "indexed": true,
        "name": "owner",
        "type": "address"
      },
      {
        "indexed": false,
        "name": "region",
        "type": "address"
      },
      {
        "indexed": false,
        "name": "rc",
        "type": "int8"
      },
      {
        "indexed": false,
        "name": "regionAmount",
        "type": "uint256"
      },
      {
        "indexed": false,
        "name": "target",
        "type": "address"
      },
      {
        "indexed": false,
        "name": "tc",
        "type": "int8"
      },
      {
        "indexed": false,
        "name": "targetAmount",
        "type": "uint256"
      }
    ],
    "name": "Combination",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "owner",
        "type": "address"
      },
      {
        "indexed": true,
        "name": "orderid",
        "type": "uint256"
      }
    ],
    "name": "Bid",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "owner",
        "type": "address"
      },
      {
        "indexed": true,
        "name": "orderid",
        "type": "uint256"
      }
    ],
    "name": "Ask",
    "type": "event"
  }
]
`

// Exange is an auto generated Go binding around an Ethereum contract.
type Exange struct {
	ExangeCaller     // Read-only binding to the contract
	ExangeTransactor // Write-only binding to the contract
	ExangeFilterer   // Log filterer for contract events
}

// ExangeCaller is an auto generated read-only Go binding around an Ethereum contract.
type ExangeCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ExangeTransactor is an auto generated write-only Go binding around an Ethereum contract.
type ExangeTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ExangeFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type ExangeFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// ExangeSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type ExangeSession struct {
	Contract     *Exange           // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ExangeCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type ExangeCallerSession struct {
	Contract *ExangeCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts // Call options to use throughout this session
}

// ExangeTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type ExangeTransactorSession struct {
	Contract     *ExangeTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// ExangeRaw is an auto generated low-level Go binding around an Ethereum contract.
type ExangeRaw struct {
	Contract *Exange // Generic contract binding to access the raw methods on
}

// ExangeCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type ExangeCallerRaw struct {
	Contract *ExangeCaller // Generic read-only contract binding to access the raw methods on
}

// ExangeTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type ExangeTransactorRaw struct {
	Contract *ExangeTransactor // Generic write-only contract binding to access the raw methods on
}

// NewExange creates a new instance of Exange, bound to a specific deployed contract.
func NewExange(address common.Address, backend bind.ContractBackend) (*Exange, error) {
	contract, err := bindExange(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Exange{ExangeCaller: ExangeCaller{contract: contract}, ExangeTransactor: ExangeTransactor{contract: contract}, ExangeFilterer: ExangeFilterer{contract: contract}}, nil
}

// NewExangeCaller creates a new read-only instance of Exange, bound to a specific deployed contract.
func NewExangeCaller(address common.Address, caller bind.ContractCaller) (*ExangeCaller, error) {
	contract, err := bindExange(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &ExangeCaller{contract: contract}, nil
}

// NewExangeTransactor creates a new write-only instance of Exange, bound to a specific deployed contract.
func NewExangeTransactor(address common.Address, transactor bind.ContractTransactor) (*ExangeTransactor, error) {
	contract, err := bindExange(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &ExangeTransactor{contract: contract}, nil
}

// NewExangeFilterer creates a new log filterer instance of Exange, bound to a specific deployed contract.
func NewExangeFilterer(address common.Address, filterer bind.ContractFilterer) (*ExangeFilterer, error) {
	contract, err := bindExange(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &ExangeFilterer{contract: contract}, nil
}

// bindExange binds a generic wrapper to an already deployed contract.
func bindExange(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(ExangeABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Exange *ExangeRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Exange.Contract.ExangeCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Exange *ExangeRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Exange.Contract.ExangeTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Exange *ExangeRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Exange.Contract.ExangeTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Exange *ExangeCallerRaw) Call(opts *bind.CallOpts, result interface{}, method string, params ...interface{}) error {
	return _Exange.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Exange *ExangeTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Exange.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Exange *ExangeTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Exange.Contract.contract.Transact(opts, method, params...)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(region address) constant returns(name string, symbol string, balance uint256, decimals uint8)
func (_Exange *ExangeCaller) BalanceOf(opts *bind.CallOpts, region common.Address) (struct {
	Name     string
	Symbol   string
	Balance  *big.Int
	Decimals uint8
}, error) {
	ret := new(struct {
		Name     string
		Symbol   string
		Balance  *big.Int
		Decimals uint8
	})
	out := ret
	err := _Exange.contract.Call(opts, out, "balanceOf", region)
	return *ret, err
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(region address) constant returns(name string, symbol string, balance uint256, decimals uint8)
func (_Exange *ExangeSession) BalanceOf(region common.Address) (struct {
	Name     string
	Symbol   string
	Balance  *big.Int
	Decimals uint8
}, error) {
	return _Exange.Contract.BalanceOf(&_Exange.CallOpts, region)
}

// BalanceOf is a free data retrieval call binding the contract method 0x70a08231.
//
// Solidity: function balanceOf(region address) constant returns(name string, symbol string, balance uint256, decimals uint8)
func (_Exange *ExangeCallerSession) BalanceOf(region common.Address) (struct {
	Name     string
	Symbol   string
	Balance  *big.Int
	Decimals uint8
}, error) {
	return _Exange.Contract.BalanceOf(&_Exange.CallOpts, region)
}

// Orderinfo is a free data retrieval call binding the contract method 0x047f62c9.
//
// Solidity: function orderinfo(id uint256) constant returns(orderType string, region address, target address, regionAmount uint256, targetAmount uint256, regionComplete uint256, targetComplete uint256, regionDecimals uint8, targetDecimals uint8, isFinal bool, owner address)
func (_Exange *ExangeCaller) Orderinfo(opts *bind.CallOpts, id *big.Int) (struct {
	OrderType      string
	Region         common.Address
	Target         common.Address
	RegionAmount   *big.Int
	TargetAmount   *big.Int
	RegionComplete *big.Int
	TargetComplete *big.Int
	RegionDecimals uint8
	TargetDecimals uint8
	IsFinal        bool
	Owner          common.Address
}, error) {
	ret := new(struct {
		OrderType      string
		Region         common.Address
		Target         common.Address
		RegionAmount   *big.Int
		TargetAmount   *big.Int
		RegionComplete *big.Int
		TargetComplete *big.Int
		RegionDecimals uint8
		TargetDecimals uint8
		IsFinal        bool
		Owner          common.Address
	})
	out := ret
	err := _Exange.contract.Call(opts, out, "orderinfo", id)
	return *ret, err
}

// Orderinfo is a free data retrieval call binding the contract method 0x047f62c9.
//
// Solidity: function orderinfo(id uint256) constant returns(orderType string, region address, target address, regionAmount uint256, targetAmount uint256, regionComplete uint256, targetComplete uint256, regionDecimals uint8, targetDecimals uint8, isFinal bool, owner address)
func (_Exange *ExangeSession) Orderinfo(id *big.Int) (struct {
	OrderType      string
	Region         common.Address
	Target         common.Address
	RegionAmount   *big.Int
	TargetAmount   *big.Int
	RegionComplete *big.Int
	TargetComplete *big.Int
	RegionDecimals uint8
	TargetDecimals uint8
	IsFinal        bool
	Owner          common.Address
}, error) {
	return _Exange.Contract.Orderinfo(&_Exange.CallOpts, id)
}

// Orderinfo is a free data retrieval call binding the contract method 0x047f62c9.
//
// Solidity: function orderinfo(id uint256) constant returns(orderType string, region address, target address, regionAmount uint256, targetAmount uint256, regionComplete uint256, targetComplete uint256, regionDecimals uint8, targetDecimals uint8, isFinal bool, owner address)
func (_Exange *ExangeCallerSession) Orderinfo(id *big.Int) (struct {
	OrderType      string
	Region         common.Address
	Target         common.Address
	RegionAmount   *big.Int
	TargetAmount   *big.Int
	RegionComplete *big.Int
	TargetComplete *big.Int
	RegionDecimals uint8
	TargetDecimals uint8
	IsFinal        bool
	Owner          common.Address
}, error) {
	return _Exange.Contract.Orderinfo(&_Exange.CallOpts, id)
}

// Orderlist is a free data retrieval call binding the contract method 0x584d60e5.
//
// Solidity: function orderlist(orderType string, region address, target address) constant returns(uint256[])
func (_Exange *ExangeCaller) Orderlist(opts *bind.CallOpts, orderType string, region common.Address, target common.Address) ([]*big.Int, error) {
	var (
		ret0 = new([]*big.Int)
	)
	out := ret0
	err := _Exange.contract.Call(opts, out, "orderlist", orderType, region, target)
	return *ret0, err
}

// Orderlist is a free data retrieval call binding the contract method 0x584d60e5.
//
// Solidity: function orderlist(orderType string, region address, target address) constant returns(uint256[])
func (_Exange *ExangeSession) Orderlist(orderType string, region common.Address, target common.Address) ([]*big.Int, error) {
	return _Exange.Contract.Orderlist(&_Exange.CallOpts, orderType, region, target)
}

// Orderlist is a free data retrieval call binding the contract method 0x584d60e5.
//
// Solidity: function orderlist(orderType string, region address, target address) constant returns(uint256[])
func (_Exange *ExangeCallerSession) Orderlist(orderType string, region common.Address, target common.Address) ([]*big.Int, error) {
	return _Exange.Contract.Orderlist(&_Exange.CallOpts, orderType, region, target)
}

// OwnerOrder is a free data retrieval call binding the contract method 0x036e3d2f.
//
// Solidity: function ownerOrder(addrs address[], pageNum uint256) constant returns(uint256[])
func (_Exange *ExangeCaller) OwnerOrder(opts *bind.CallOpts, addrs []common.Address, pageNum *big.Int) ([]*big.Int, error) {
	var (
		ret0 = new([]*big.Int)
	)
	out := ret0
	err := _Exange.contract.Call(opts, out, "ownerOrder", addrs, pageNum)
	return *ret0, err
}

// OwnerOrder is a free data retrieval call binding the contract method 0x036e3d2f.
//
// Solidity: function ownerOrder(addrs address[], pageNum uint256) constant returns(uint256[])
func (_Exange *ExangeSession) OwnerOrder(addrs []common.Address, pageNum *big.Int) ([]*big.Int, error) {
	return _Exange.Contract.OwnerOrder(&_Exange.CallOpts, addrs, pageNum)
}

// OwnerOrder is a free data retrieval call binding the contract method 0x036e3d2f.
//
// Solidity: function ownerOrder(addrs address[], pageNum uint256) constant returns(uint256[])
func (_Exange *ExangeCallerSession) OwnerOrder(addrs []common.Address, pageNum *big.Int) ([]*big.Int, error) {
	return _Exange.Contract.OwnerOrder(&_Exange.CallOpts, addrs, pageNum)
}

// pointsInfo is a free data retrieval call binding the contract method 0xf5dab711.
//
// Solidity: function pointsInfo( address) constant returns(name string, symbol string, totalSupply uint256, decimals uint8)
func (_Exange *ExangeCaller) pointsInfo(opts *bind.CallOpts, arg0 common.Address) (struct {
	Name        string
	Symbol      string
	TotalSupply *big.Int
	Decimals    uint8
}, error) {
	ret := new(struct {
		Name        string
		Symbol      string
		TotalSupply *big.Int
		Decimals    uint8
	})
	out := ret
	err := _Exange.contract.Call(opts, out, "pointsInfo", arg0)
	return *ret, err
}

// pointsInfo is a free data retrieval call binding the contract method 0xf5dab711.
//
// Solidity: function pointsInfo( address) constant returns(name string, symbol string, totalSupply uint256, decimals uint8)
func (_Exange *ExangeSession) pointsInfo(arg0 common.Address) (struct {
	Name        string
	Symbol      string
	TotalSupply *big.Int
	Decimals    uint8
}, error) {
	return _Exange.Contract.pointsInfo(&_Exange.CallOpts, arg0)
}

// pointsInfo is a free data retrieval call binding the contract method 0xf5dab711.
//
// Solidity: function pointsInfo( address) constant returns(name string, symbol string, totalSupply uint256, decimals uint8)
func (_Exange *ExangeCallerSession) pointsInfo(arg0 common.Address) (struct {
	Name        string
	Symbol      string
	TotalSupply *big.Int
	Decimals    uint8
}, error) {
	return _Exange.Contract.pointsInfo(&_Exange.CallOpts, arg0)
}

// pointsList is a free data retrieval call binding the contract method 0x9e2c58ca.
//
// Solidity: function pointsList() constant returns(address[])
func (_Exange *ExangeCaller) pointsList(opts *bind.CallOpts) ([]common.Address, error) {
	var (
		ret0 = new([]common.Address)
	)
	out := ret0
	err := _Exange.contract.Call(opts, out, "pointsList")
	return *ret0, err
}

// pointsList is a free data retrieval call binding the contract method 0x9e2c58ca.
//
// Solidity: function pointsList() constant returns(address[])
func (_Exange *ExangeSession) pointsList() ([]common.Address, error) {
	return _Exange.Contract.pointsList(&_Exange.CallOpts)
}

// pointsList is a free data retrieval call binding the contract method 0x9e2c58ca.
//
// Solidity: function pointsList() constant returns(address[])
func (_Exange *ExangeCallerSession) pointsList() ([]common.Address, error) {
	return _Exange.Contract.pointsList(&_Exange.CallOpts)
}

// Ask is a paid mutator transaction binding the contract method 0xbeb54773.
//
// Solidity: function ask(region address, target address, regionAmount uint256, targetAmount uint256) returns()
func (_Exange *ExangeTransactor) Ask(opts *bind.TransactOpts, region common.Address, target common.Address, regionAmount *big.Int, targetAmount *big.Int) (*types.Transaction, error) {
	return _Exange.contract.Transact(opts, "ask", region, target, regionAmount, targetAmount)
}

// Ask is a paid mutator transaction binding the contract method 0xbeb54773.
//
// Solidity: function ask(region address, target address, regionAmount uint256, targetAmount uint256) returns()
func (_Exange *ExangeSession) Ask(region common.Address, target common.Address, regionAmount *big.Int, targetAmount *big.Int) (*types.Transaction, error) {
	return _Exange.Contract.Ask(&_Exange.TransactOpts, region, target, regionAmount, targetAmount)
}

// Ask is a paid mutator transaction binding the contract method 0xbeb54773.
//
// Solidity: function ask(region address, target address, regionAmount uint256, targetAmount uint256) returns()
func (_Exange *ExangeTransactorSession) Ask(region common.Address, target common.Address, regionAmount *big.Int, targetAmount *big.Int) (*types.Transaction, error) {
	return _Exange.Contract.Ask(&_Exange.TransactOpts, region, target, regionAmount, targetAmount)
}

// Bid is a paid mutator transaction binding the contract method 0x75700d46.
//
// Solidity: function bid(region address, target address, regionAmount uint256, targetAmount uint256) returns()
func (_Exange *ExangeTransactor) Bid(opts *bind.TransactOpts, region common.Address, target common.Address, regionAmount *big.Int, targetAmount *big.Int) (*types.Transaction, error) {
	return _Exange.contract.Transact(opts, "bid", region, target, regionAmount, targetAmount)
}

// Bid is a paid mutator transaction binding the contract method 0x75700d46.
//
// Solidity: function bid(region address, target address, regionAmount uint256, targetAmount uint256) returns()
func (_Exange *ExangeSession) Bid(region common.Address, target common.Address, regionAmount *big.Int, targetAmount *big.Int) (*types.Transaction, error) {
	return _Exange.Contract.Bid(&_Exange.TransactOpts, region, target, regionAmount, targetAmount)
}

// Bid is a paid mutator transaction binding the contract method 0x75700d46.
//
// Solidity: function bid(region address, target address, regionAmount uint256, targetAmount uint256) returns()
func (_Exange *ExangeTransactorSession) Bid(region common.Address, target common.Address, regionAmount *big.Int, targetAmount *big.Int) (*types.Transaction, error) {
	return _Exange.Contract.Bid(&_Exange.TransactOpts, region, target, regionAmount, targetAmount)
}

// Cancel is a paid mutator transaction binding the contract method 0x40e58ee5.
//
// Solidity: function cancel(id uint256) returns()
func (_Exange *ExangeTransactor) Cancel(opts *bind.TransactOpts, id *big.Int) (*types.Transaction, error) {
	return _Exange.contract.Transact(opts, "cancel", id)
}

// Cancel is a paid mutator transaction binding the contract method 0x40e58ee5.
//
// Solidity: function cancel(id uint256) returns()
func (_Exange *ExangeSession) Cancel(id *big.Int) (*types.Transaction, error) {
	return _Exange.Contract.Cancel(&_Exange.TransactOpts, id)
}

// Cancel is a paid mutator transaction binding the contract method 0x40e58ee5.
//
// Solidity: function cancel(id uint256) returns()
func (_Exange *ExangeTransactorSession) Cancel(id *big.Int) (*types.Transaction, error) {
	return _Exange.Contract.Cancel(&_Exange.TransactOpts, id)
}

// Withdrawal is a paid mutator transaction binding the contract method 0x5a6b26ba.
//
// Solidity: function withdrawal(region address, amount uint256) returns()
func (_Exange *ExangeTransactor) Withdrawal(opts *bind.TransactOpts, region common.Address, amount *big.Int) (*types.Transaction, error) {
	return _Exange.contract.Transact(opts, "withdrawal", region, amount)
}

// Withdrawal is a paid mutator transaction binding the contract method 0x5a6b26ba.
//
// Solidity: function withdrawal(region address, amount uint256) returns()
func (_Exange *ExangeSession) Withdrawal(region common.Address, amount *big.Int) (*types.Transaction, error) {
	return _Exange.Contract.Withdrawal(&_Exange.TransactOpts, region, amount)
}

// Withdrawal is a paid mutator transaction binding the contract method 0x5a6b26ba.
//
// Solidity: function withdrawal(region address, amount uint256) returns()
func (_Exange *ExangeTransactorSession) Withdrawal(region common.Address, amount *big.Int) (*types.Transaction, error) {
	return _Exange.Contract.Withdrawal(&_Exange.TransactOpts, region, amount)
}

// ExangeAskIterator is returned from FilterAsk and is used to iterate over the raw logs and unpacked data for Ask events raised by the Exange contract.
type ExangeAskIterator struct {
	Event *ExangeAsk // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log     // Log channel receiving the found contract events
	sub  event.Subscription // Subscription for errors, completion and termination
	done bool               // Whether the subscription completed delivering logs
	fail error              // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ExangeAskIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ExangeAsk)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ExangeAsk)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ExangeAskIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ExangeAskIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ExangeAsk represents a Ask event raised by the Exange contract.
type ExangeAsk struct {
	Owner   common.Address
	Orderid *big.Int
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterAsk is a free log retrieval operation binding the contract event 0x32eb218d63024a6bd54a3e6467c1545c355c44c2e1c17940b1a0ed1555ffeffe.
//
// Solidity: e Ask(owner indexed address, orderid indexed uint256)
func (_Exange *ExangeFilterer) FilterAsk(opts *bind.FilterOpts, owner []common.Address, orderid []*big.Int) (*ExangeAskIterator, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var orderidRule []interface{}
	for _, orderidItem := range orderid {
		orderidRule = append(orderidRule, orderidItem)
	}

	logs, sub, err := _Exange.contract.FilterLogs(opts, "Ask", ownerRule, orderidRule)
	if err != nil {
		return nil, err
	}
	return &ExangeAskIterator{contract: _Exange.contract, event: "Ask", logs: logs, sub: sub}, nil
}

// WatchAsk is a free log subscription operation binding the contract event 0x32eb218d63024a6bd54a3e6467c1545c355c44c2e1c17940b1a0ed1555ffeffe.
//
// Solidity: e Ask(owner indexed address, orderid indexed uint256)
func (_Exange *ExangeFilterer) WatchAsk(opts *bind.WatchOpts, sink chan<- *ExangeAsk, owner []common.Address, orderid []*big.Int) (event.Subscription, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var orderidRule []interface{}
	for _, orderidItem := range orderid {
		orderidRule = append(orderidRule, orderidItem)
	}

	logs, sub, err := _Exange.contract.WatchLogs(opts, "Ask", ownerRule, orderidRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ExangeAsk)
				if err := _Exange.contract.UnpackLog(event, "Ask", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ExangeBidIterator is returned from FilterBid and is used to iterate over the raw logs and unpacked data for Bid events raised by the Exange contract.
type ExangeBidIterator struct {
	Event *ExangeBid // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log     // Log channel receiving the found contract events
	sub  event.Subscription // Subscription for errors, completion and termination
	done bool               // Whether the subscription completed delivering logs
	fail error              // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ExangeBidIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ExangeBid)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ExangeBid)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ExangeBidIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ExangeBidIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ExangeBid represents a Bid event raised by the Exange contract.
type ExangeBid struct {
	Owner   common.Address
	Orderid *big.Int
	Raw     types.Log // Blockchain specific contextual infos
}

// FilterBid is a free log retrieval operation binding the contract event 0xe684a55f31b79eca403df938249029212a5925ec6be8012e099b45bc1019e5d2.
//
// Solidity: e Bid(owner indexed address, orderid indexed uint256)
func (_Exange *ExangeFilterer) FilterBid(opts *bind.FilterOpts, owner []common.Address, orderid []*big.Int) (*ExangeBidIterator, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var orderidRule []interface{}
	for _, orderidItem := range orderid {
		orderidRule = append(orderidRule, orderidItem)
	}

	logs, sub, err := _Exange.contract.FilterLogs(opts, "Bid", ownerRule, orderidRule)
	if err != nil {
		return nil, err
	}
	return &ExangeBidIterator{contract: _Exange.contract, event: "Bid", logs: logs, sub: sub}, nil
}

// WatchBid is a free log subscription operation binding the contract event 0xe684a55f31b79eca403df938249029212a5925ec6be8012e099b45bc1019e5d2.
//
// Solidity: e Bid(owner indexed address, orderid indexed uint256)
func (_Exange *ExangeFilterer) WatchBid(opts *bind.WatchOpts, sink chan<- *ExangeBid, owner []common.Address, orderid []*big.Int) (event.Subscription, error) {

	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}
	var orderidRule []interface{}
	for _, orderidItem := range orderid {
		orderidRule = append(orderidRule, orderidItem)
	}

	logs, sub, err := _Exange.contract.WatchLogs(opts, "Bid", ownerRule, orderidRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ExangeBid)
				if err := _Exange.contract.UnpackLog(event, "Bid", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}

// ExangeCombinationIterator is returned from FilterCombination and is used to iterate over the raw logs and unpacked data for Combination events raised by the Exange contract.
type ExangeCombinationIterator struct {
	Event *ExangeCombination // Event containing the contract specifics and raw log

	contract *bind.BoundContract // Generic contract to use for unpacking event data
	event    string              // Event name to use for unpacking event data

	logs chan types.Log     // Log channel receiving the found contract events
	sub  event.Subscription // Subscription for errors, completion and termination
	done bool               // Whether the subscription completed delivering logs
	fail error              // Occurred error to stop iteration
}

// Next advances the iterator to the subsequent event, returning whether there
// are any more events found. In case of a retrieval or parsing error, false is
// returned and Error() can be queried for the exact failure.
func (it *ExangeCombinationIterator) Next() bool {
	// If the iterator failed, stop iterating
	if it.fail != nil {
		return false
	}
	// If the iterator completed, deliver directly whatever's available
	if it.done {
		select {
		case log := <-it.logs:
			it.Event = new(ExangeCombination)
			if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
				it.fail = err
				return false
			}
			it.Event.Raw = log
			return true

		default:
			return false
		}
	}
	// Iterator still in progress, wait for either a data or an error event
	select {
	case log := <-it.logs:
		it.Event = new(ExangeCombination)
		if err := it.contract.UnpackLog(it.Event, it.event, log); err != nil {
			it.fail = err
			return false
		}
		it.Event.Raw = log
		return true

	case err := <-it.sub.Err():
		it.done = true
		it.fail = err
		return it.Next()
	}
}

// Error returns any retrieval or parsing error occurred during filtering.
func (it *ExangeCombinationIterator) Error() error {
	return it.fail
}

// Close terminates the iteration process, releasing any pending underlying
// resources.
func (it *ExangeCombinationIterator) Close() error {
	it.sub.Unsubscribe()
	return nil
}

// ExangeCombination represents a Combination event raised by the Exange contract.
type ExangeCombination struct {
	Orderid      *big.Int
	Owner        common.Address
	Region       common.Address
	Rc           int8
	RegionAmount *big.Int
	Target       common.Address
	Tc           int8
	TargetAmount *big.Int
	Raw          types.Log // Blockchain specific contextual infos
}

// FilterCombination is a free log retrieval operation binding the contract event 0xd025af3c283935511f884c83da0d18eb1895cfb7aca5659b459d93ada7d2969e.
//
// Solidity: e Combination(orderid indexed uint256, owner indexed address, region address, rc int8, regionAmount uint256, target address, tc int8, targetAmount uint256)
func (_Exange *ExangeFilterer) FilterCombination(opts *bind.FilterOpts, orderid []*big.Int, owner []common.Address) (*ExangeCombinationIterator, error) {

	var orderidRule []interface{}
	for _, orderidItem := range orderid {
		orderidRule = append(orderidRule, orderidItem)
	}
	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}

	logs, sub, err := _Exange.contract.FilterLogs(opts, "Combination", orderidRule, ownerRule)
	if err != nil {
		return nil, err
	}
	return &ExangeCombinationIterator{contract: _Exange.contract, event: "Combination", logs: logs, sub: sub}, nil
}

// WatchCombination is a free log subscription operation binding the contract event 0xd025af3c283935511f884c83da0d18eb1895cfb7aca5659b459d93ada7d2969e.
//
// Solidity: e Combination(orderid indexed uint256, owner indexed address, region address, rc int8, regionAmount uint256, target address, tc int8, targetAmount uint256)
func (_Exange *ExangeFilterer) WatchCombination(opts *bind.WatchOpts, sink chan<- *ExangeCombination, orderid []*big.Int, owner []common.Address) (event.Subscription, error) {

	var orderidRule []interface{}
	for _, orderidItem := range orderid {
		orderidRule = append(orderidRule, orderidItem)
	}
	var ownerRule []interface{}
	for _, ownerItem := range owner {
		ownerRule = append(ownerRule, ownerItem)
	}

	logs, sub, err := _Exange.contract.WatchLogs(opts, "Combination", orderidRule, ownerRule)
	if err != nil {
		return nil, err
	}
	return event.NewSubscription(func(quit <-chan struct{}) error {
		defer sub.Unsubscribe()
		for {
			select {
			case log := <-logs:
				// New log arrived, parse the event and forward to the user
				event := new(ExangeCombination)
				if err := _Exange.contract.UnpackLog(event, "Combination", log); err != nil {
					return err
				}
				event.Raw = log

				select {
				case sink <- event:
				case err := <-sub.Err():
					return err
				case <-quit:
					return nil
				}
			case err := <-sub.Err():
				return err
			case <-quit:
				return nil
			}
		}
	}), nil
}
