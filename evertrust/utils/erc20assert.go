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
 * @Time   : 2019-08-06 15:30
 * @Author : liangc
 *************************************************************************/
package utils

import (
	"bytes"
	"errors"
	"math/big"
	"CRD-chain/accounts/abi"
	"CRD-chain/common"
	"CRD-chain/params"
	"strings"
)

// https://eips.ethereum.org/EIPS/eip-20
/* ------------- trait dict ---------------
name()
symbol()
decimals()
totalSupply()
balanceOf(address)
transfer(address,uint256)
approve(address,uint256)
transferFrom(address,address,uint256)
allowance(address,address)
*/
var ERC20Trait = newErc20trait()

type erc20trait struct {
	funcdict map[string][]byte
	erc20abi abi.ABI
}

func newErc20trait() *erc20trait {
	abiJson, err := abi.JSON(strings.NewReader(params.EIP20InterfaceABI))
	if err != nil {
		panic(err)
	}
	return &erc20trait{map[string][]byte{
		"name()":                                {6, 253, 222, 3},
		"symbol()":                              {149, 216, 155, 65},
		"decimals()":                            {49, 60, 229, 103},
		"totalSupply()":                         {24, 22, 13, 221},
		"balanceOf(address)":                    {112, 160, 130, 49},
		"allowance(address,address)":            {221, 98, 237, 62},
		"transfer(address,uint256)":             {169, 5, 156, 187},
		"approve(address,uint256)":              {9, 94, 167, 179},
		"transferFrom(address,address,uint256)": {35, 184, 114, 221}}, abiJson}
}

// 用来拦截 erc20 转账请求生成 pointsexange 账本数据 >>>>>>>>>>>>>>>>>>>>>>

func (self *erc20trait) IsTransfer(input []byte) (to common.Address, amount *big.Int, err error) {
	method, err := self.erc20abi.MethodById(input[:4])
	if err == nil && bytes.Equal(self.funcdict["transfer(address,uint256)"], input[:4]) {
		data := input[4:]
		err = self.erc20abi.UnpackInput(&[]interface{}{&to, &amount}, method.Name, data)
	} else {
		err = errors.New("error_method_sig")
	}
	if to != params.PointsExagenAddress {
		err = errors.New("normal_skip")
	}
	return
}

func (self *erc20trait) IsTransferFrom(input []byte) (from common.Address, to common.Address, amount *big.Int, err error) {
	method, err := self.erc20abi.MethodById(input[:4])
	if err == nil && bytes.Equal(self.funcdict["transferFrom(address,address,uint256)"], input[:4]) {
		data := input[4:]
		err = self.erc20abi.UnpackInput(&[]interface{}{&from, &to, &amount}, method.Name, data)
	}
	if to != params.PointsExagenAddress {
		err = errors.New("normal_skip")
	}
	return
}

// 用来拦截 erc20 转账请求生成 pointsexange 账本数据 <<<<<<<<<<<<<<<<<<<<<<

// 判断传入 code 是否符合 erc20 标准
// https://eips.ethereum.org/EIPS/eip-20
func (self *erc20trait) IsERC20(code []byte) bool {
	if code == nil || len(code) < 5 {
		return false
	}
	for _, sigb := range self.funcdict {
		if !bytes.Contains(code, sigb[:]) {
			//fmt.Println("create contract", "erc20", false, "not_found_sig=", sigs)
			return false
		}
	}
	return true
}

// 公司名称的方法签名，记录名称，例如：Tether USD
func (self *erc20trait) SigOfName() []byte { return self.funcdict["name()"] }

// points 名称的方法签名，记录points名，例如：USDT
func (self *erc20trait) SigOfSymbol() []byte { return self.funcdict["symbol()"] }
