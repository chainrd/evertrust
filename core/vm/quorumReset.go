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
	"fmt"
	"CRD-chain/common"
	"CRD-chain/core/publicBC"
	"CRD-chain/log"
	"CRD-chain/params"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/CRDcc/util"
	"CRD-chain/rlp"
	"CRD-chain/evertrust/types"
	"CRD-chain/evertrust/utils"
)

const (
	restoreLandHeight = 10 //要经过多少岛屿块后才能 1000
	restoreWaitHeight = 10 //在哪个高度进行恢复 10
	restoreKey        = "restoreKey"
)

type QuorumReset struct {
}

func (r *QuorumReset) RequiredGas(input []byte) uint64 {
	return uint64(len(input)/192) * params.Bn256PairingPerPointGas
}

func (r *QuorumReset) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	if len(extra[conf.TxEstimateGas]) > 0 {
		return nil, nil
	}

	//投票
	if !statisticSign(ctx, input) {
		//票数不够,等待票数足够,在往下进行
		return nil, nil
	}

	stateDB := ctx.Evm.StateDB

	//判断分叉时间是否足够,使用当前Normal对应的Commit高度,获取commit
	cNum := types.BlockExtraDecode(public.BC.CurrentBlock()).CNumber.Uint64()
	currentCommit := public.BC.GetCommitBlock(cNum)
	_, commitExtra := types.CommitExtraDecode(currentCommit)
	//判断当前commit是不是岛屿块
	if !commitExtra.Island {
		log.Error("QuorumReset fail commit is mainland")
		return nil, errors.New("QuorumReset fail commit is mainland")
	}
	rh := ctx.Evm.chainConfig.Evertrust.QuorumResetAfterHeight
	if rh == 0 {
		//如果不配置默认1000
		rh = 1000
	}
	//commitExtra.CNum是分叉前的commit高度
	islandCNum := commitExtra.CNum + rh
	commitNum := currentCommit.NumberU64()
	if commitNum < islandCNum {
		log.Error("QuorumReset Height No enough", "commitNum", commitNum, "islandCNum", islandCNum)
		return nil, errors.New("QuorumReset Height No enough")
	}
	//设置重置委员会高度
	var RestoreLandParams = RestoreLandParam{TxBlockNum: make([]uint64, 0)}
	date := stateDB.GetCRDState(utils.QuorumResetContract, utils.QuorumResetContract.Hash())
	if len(date) != 0 {
		//如果有数据解码数据
		rlp.DecodeBytes(date, &RestoreLandParams)
	}
	RestoreLandParams.RestoreHeight = commitNum + restoreWaitHeight
	//设置本地参数回滚根据
	RestoreLandParams.TxBlockNum = append(RestoreLandParams.TxBlockNum, public.BC.CurrentBlock().NumberU64())
	RestoreLandParams.Version++
	bytes, err := rlp.EncodeToBytes(RestoreLandParams)
	if err != nil {
		return nil, errors.New("rlp.EncodeToBytes RestoreLandParams err")
	}
	//存入状态数据库
	stateDB.SetCRDState(utils.QuorumResetContract, utils.QuorumResetContract.Hash(), bytes)
	log.Info("QuorumReset succeed", "Restore", RestoreLandParams)
	//合约成功后增加合约账户nonce
	stateDB.SetNonce(ctx.Contract.Address(), stateDB.GetNonce(ctx.Contract.Address())+1)
	return nil, nil
}

type RestoreLandParam struct {
	RestoreHeight uint64   //重置委员会的commit高度
	TxBlockNum    []uint64 //每次更新都 在哪个normal执行的交易
	Version       uint64   //大陆版本
}

func statisticSign(ctx *PrecompiledContractContext, input []byte) bool {
	//确定投票轮数
	var voteNum uint64
	json.Unmarshal(input, &voteNum)
	stateDB := ctx.Evm.StateDB
	contractAddr := ctx.Contract.Address() //合约账户
	caller := ctx.Contract.Caller()        //from
	contractNonce := stateDB.GetNonce(contractAddr)

	if contractNonce != voteNum {
		log.Error("QuorumReset voteNum Err", "voteNum", voteNum, "contractNonce", contractNonce)
		return false
	}

	//查看资格
	isVoter := func(from common.Address) bool {
		for _, add := range ctx.Evm.chainConfig.Evertrust.QuorumResetAccounts {

			log.Info("查询资格地址", "add", add.Hex())
		}
		if len(ctx.Evm.chainConfig.Evertrust.QuorumResetAccounts) != 0 {
			//查看权限账户
			for _, add := range ctx.Evm.chainConfig.Evertrust.QuorumResetAccounts {
				log.Info("查看add", "add", add, "from", from)
				if add.Hash() == from.Hash() {
					return true
				}
			}
		}
		log.Error("QuorumReset 没有投票资格")
		return false
	}
	if !isVoter(caller) {
		log.Error("QuorumReset From No qualification", "caller", caller)
		return false
	}

	//纪录票数
	voteDate := stateDB.GetCRDState(contractAddr, getStoreLandKeyHash(voteNum))
	voteResult := make(map[common.Address]struct{})
	json.Unmarshal(voteDate, &voteResult)
	voteResult[caller] = struct{}{}
	date, _ := json.Marshal(voteResult)
	stateDB.SetCRDState(contractAddr, getStoreLandKeyHash(voteNum), date)

	//统计结果 是否到达2/3
	if len(voteResult) < len(ctx.Evm.chainConfig.Evertrust.QuorumResetAccounts)*2/3 {
		//还没有到达应该的票数
		log.Error("voteNum Less")
		return false
	}

	return true

}

//投票key生成
func getStoreLandKeyHash(nonce uint64) common.Hash {
	key := fmt.Sprintf("StoreLand%d", nonce)
	return util.EthHash([]byte(key))
}
