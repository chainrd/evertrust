/*************************************************************************
 * Copyright (C) 2016-2019 CRD Technologies, Inc. All Rights Reserved.
 *
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
 *************************************************************************/
package vm

import (
	"encoding/json"
	"errors"
	"math/big"
	"CRD-chain/common"
	public "CRD-chain/core/publicBC"
	"CRD-chain/log"
	"CRD-chain/params"
	"CRD-chain/CRDcc/conf"
)

type Increase struct {
}

func (c *Increase) RequiredGas(input []byte) uint64 {
	return uint64(len(input)/192) * params.Bn256PairingPerPointGas
}

func (c *Increase) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	if len(extra[conf.TxEstimateGas]) > 0 {
		return nil, nil
	}

	//判断是否设置了减半
	if ctx.Evm.chainConfig.Evertrust.AllowIncrease == (common.Address{}) {
		return nil, errors.New("not support increase")
	}
	from := ctx.Contract.Caller()
	genAddress := common.BytesToAddress(public.BC.GetBlockByNumber(0).Extra())
	log.Info("查看from和genAddress", "from", )
	//判断是否是第一个出块地址
	if from.String() != genAddress.String() {
		return nil, errors.New("is not genesis from")
	}
	var val int64
	//要增发多少金额
	json.Unmarshal(input, &val)

	ctx.Evm.StateDB.AddBalance(common.HexToAddress("123456789"), new(big.Int).Mul(big.NewInt(val), big.NewInt(1e18)))
	return nil, nil
}
