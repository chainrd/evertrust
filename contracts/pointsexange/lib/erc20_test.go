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
	"context"
	"fmt"
	"CRD-chain/accounts/abi"
	"CRD-chain/accounts/abi/bind"
	"CRD-chain/common"
	"CRD-chain/ethclient"
	"CRD-chain/rpc"
	"strings"
	"testing"
)

func TestCall(t *testing.T) {
	ctx := context.Background()
	t.Log("Call")
	endpoint := "http://localhost:8545"
	erc20addr := common.HexToAddress("0xbc9dcf4e5ccc03ffc49f5b1c9ddaa45cc7bb4bf8")

	client, err := rpc.Dial(endpoint)
	ethClient := ethclient.NewClient(client)
	erc20, err := NewEIP20InterfaceCaller(erc20addr, ethClient)
	t.Log(err)
	opts := &bind.CallOpts{
		Context: ctx,
	}

	name, err := erc20.Name(opts)
	symbol, err := erc20.Symbol(opts)
	totalSupply, err := erc20.TotalSupply(opts)
	decimals, err := erc20.Decimals(opts)
	t.Log(err, name)
	t.Log(err, symbol)
	t.Log(err, totalSupply)
	t.Log(err, decimals)
}

func TestABI(t *testing.T) {
	fmt.Println(EIP20InterfaceABI)
	a, _ := abi.JSON(strings.NewReader(EIP20InterfaceABI))
	m, _ := a.Methods["transfer"]
	m.Inputs.Pack("")
}
