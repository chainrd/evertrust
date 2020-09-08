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
	"context"
	"fmt"
	"CRD-chain/accounts/abi/bind"
	"CRD-chain/common"
	"CRD-chain/ethclient"
	"CRD-chain/rpc"
	"testing"
)

func TestpointsList(t *testing.T) {
	ctx := context.Background()
	endpoint := "http://localhost:8545"
	exangeAddr := common.HexToAddress("0x123")

	client, err := rpc.Dial(endpoint)
	t.Log(err)
	ethClient := ethclient.NewClient(client)
	exange, err := NewExange(exangeAddr, ethClient)
	t.Log(err)
	opts := &bind.CallOpts{
		Context: ctx,
	}
	pointslist, err := exange.pointsList(opts)
	for i, points := range pointslist {
		ti, err := exange.pointsInfo(opts, points)
		t.Log(i, err, points.Hex(), ti)
	}
}

func TestABIS(t *testing.T) {
	fmt.Println(ExangeABI)
}
