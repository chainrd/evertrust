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
 * @Time   : 2020/3/13 10:03 上午
 * @Author : liangc
 *************************************************************************/

package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"gopkg.in/urfave/cli.v1"
	"io/ioutil"
	"math/big"
	"os"
	"CRD-chain/accounts/keystore"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/crypto"
	"CRD-chain/ethclient"
	"time"
)

var (
	_ipc, _prvhex          string
	_count, _chainid, _avg int
	_jpp, _jpf             string
	base, _                = new(big.Int).SetString("1000000000000000000", 10)
	app                    *cli.App

	gas      = big.NewInt(50000)
	price, _ = new(big.Int).SetString("18000000000", 10)

	hexToPrv = func(h string) *ecdsa.PrivateKey {
		b, _ := hex.DecodeString(h)
		p, _ := crypto.ToECDSA(b)
		return p
	}
	prvToAddr = func(prv *ecdsa.PrivateKey) common.Address {
		return crypto.PubkeyToAddress(prv.PublicKey)
	}
	getAddr = func(prvHex string) (*ecdsa.PrivateKey, common.Address) {
		var prv = hexToPrv(prvHex)
		var addr = prvToAddr(prv)
		return prv, addr
	}
)

func init() {
	app = cli.NewApp()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "ipc,i",
			Usage:       "ipc path",
			Destination: &_ipc,
		},
		cli.StringFlag{
			Name:        "prvhex,p",
			Usage:       "private key hex",
			Destination: &_prvhex,
		},
		cli.IntFlag{
			Name:        "count,c",
			Usage:       "total tx",
			Destination: &_count,
		},
		cli.IntFlag{
			Name:        "avg,a",
			Usage:       "pre second avg",
			Value:       200,
			Destination: &_avg,
		},
		cli.IntFlag{
			Name:        "chainid",
			Usage:       "chain id",
			Value:       739,
			Destination: &_chainid,
		},
	}
	app.Action = maketx
	app.Commands = []cli.Command{
		{
			Name:   "unlock",
			Usage:  "解锁并输出一个私钥",
			Action: unlock,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "f",
					Usage:       "json private key file path",
					Destination: &_jpf,
				},
				cli.StringFlag{
					Name:        "p",
					Usage:       "json private key passwd",
					Destination: &_jpp,
				},
			},
		},
	}
}

func unlock(_ *cli.Context) error {
	jd, err := ioutil.ReadFile(_jpf)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	k, err := keystore.DecryptKey(jd, _jpp)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	pb := crypto.FromECDSA(k.PrivateKey)
	ph := hex.EncodeToString(pb)
	fmt.Println("Privatekey Hex :", ph)
	return nil
}

func maketx(_ *cli.Context) error {
	v := new(big.Int).Mul(big.NewInt(1), base)
	ctx := context.Background()
	prv, addr := getAddr(_prvhex)
	client, err := ethclient.Dial(_ipc)
	if err != nil {
		panic(err)
	}
	nonce, err := client.PendingNonceAt(ctx, addr)
	if err != nil {
		panic(err)
	}
	__to := nonce
	_to := fmt.Sprintf("0x%d", __to)
	fmt.Println("from =", addr.Hex(), " , to =", common.HexToAddress(_to).Hex(), " , total =", _count)
	for i := nonce; i < nonce+uint64(_count); i++ {
		tx := types.NewTransaction(i, common.HexToAddress(_to), v, gas.Uint64(), price, nil)
		signer := types.NewEIP155Signer(big.NewInt(int64(_chainid)))
		tx, err = types.SignTx(tx, signer, prv)
		if err != nil {
			panic(err)
		}
		err = client.SendTransaction(ctx, tx)
		if err != nil {
			panic(err)
		}
		if i%400 == 0 {
			__to = __to + 1
			_to = fmt.Sprintf("0x%d", __to)
			fmt.Println("target =", _count, " , current =", i-nonce, "to = ", common.HexToAddress(_to).Hex())
			<-time.After(1 * time.Second)
		}
	}
	fmt.Println("over.", _count)
	return nil
}

func main() {
	app.Run(os.Args)
}
