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
 *************************************************************************/
package utils

import (
	"fmt"
	"CRD-chain/common"
	"CRD-chain/CRDcc/util"
)

const (
	DepositContract           = "x-chain-transfer-deposit"
	WithdrawContract          = "x-chain-transfer-withdraw"
	TcUpdater                 = "tcUpdater"
	TrustTxWhiteList          = "trust-tx-white-list"
	BaapTrustTree             = ":baap-trusttree:v1.0"
	NodeUpdate                = "consensus-node-update"
	BaapDeploy                = "baap-deploy"
	CRDSafe                   = "CRDSafe"
	Hypothecation             = "hypothecation"
	Redamption                = "redamption"
	QuiteQuorum               = "quiteQuorum"
	AccessCtl                 = "AccessCtl"
	QuorumReset               = "QuorumReset"
	PublicAccountVoteContract = "public-account-vote"
	CashInContract            = "cash-in"
	CashOutContract           = "cash-out"
	BaapChainIaas             = ":baap-chainiaas"
	AllowIncrease             = "allow-increase"
	inCrease                  = "inCrease"
)

var (
	BaapDeployContract             = util.EthAddress(BaapDeploy)
	TcUpdaterContract              = util.EthAddress(TcUpdater)
	XChainTransferWithDrawContract = util.EthAddress(WithdrawContract)
	XChainTransferDepositContract  = util.EthAddress(DepositContract)
	TrustTxWhiteListContract       = util.EthAddress(TrustTxWhiteList)
	NodeUpdateContract             = util.EthAddress(NodeUpdate)
	CRDSafeContract                = util.EthAddress(CRDSafe)
	HypothecationContract          = util.EthAddress(Hypothecation)
	QuiteQuorumContract            = util.EthAddress(QuiteQuorum)
	RedamptionContract             = util.EthAddress(Redamption)
	AccessCtlContract              = util.EthAddress(AccessCtl)
	TrustTree                      = util.EthAddress(BaapTrustTree)
	QuorumResetContract            = util.EthAddress(QuorumReset)
	PublicAccountVote              = util.EthAddress(PublicAccountVoteContract)
	CashIn                         = util.EthAddress(CashInContract)
	CashOut                        = util.EthAddress(CashOutContract)
	BaapChainIaasContract          = util.EthAddress(BaapChainIaas)
	AllowIncreaseContract          = util.EthAddress(AllowIncrease)
	Increase                       = util.EthAddress(inCrease)
)

//for solidity and cc extra desc
type Meta map[string][]byte

type ContractInfo struct {
	ContractType int            `json:"contract_type"`
	Addr         common.Address `json:"addr"`
	Owner        string         `json:"owner"`
	Name         string         `json:"name"`
	Version      string         `json:"version"`
	Desc         string         `json:"desc"`
}

var (
	//cc code key hash stored in stateDB
	CCKeyHash = util.EthHash([]byte("chaincode:deploy"))

	CCBaapDeploy = util.EthAddress(":baap-deploy:v1.0")
)

//DepositKeyHash store user has completed deposit tx
func DepositKeyHash(from common.Address, txhash common.Hash, keyFlag string) common.Hash {
	key := fmt.Sprintf("%s:%s:%s:%s", keyFlag, "deposit", from.String(), txhash.String())
	return util.EthHash([]byte(key))
}

func DepositBlacklistKeyHash(from common.Address) common.Hash {
	key := fmt.Sprintf("deposit:blacklist:%s", from)
	return util.EthHash([]byte(key))
}

//addr of stateDB for storing tx that user has withdrew
func WithdrawTxKeyHash(from common.Address) common.Hash {
	return util.EthHash([]byte(fmt.Sprintf("withdraw_txs:%s", from.String())))
}

func deployedCCKeyHash() common.Hash {
	return util.EthHash([]byte("deployed_cc"))
}

//evertrust whether all tx is free
func IsFreeGas() bool {
	return util.Gasless
}

//evertrust whether tx is sent to deposit address
func IsDeposit(to *common.Address) bool {
	if to != nil && *to == XChainTransferDepositContract {
		return true
	}
	return false
}

func IsNodeUpdate(to *common.Address) bool {
	if to != nil && *to == NodeUpdateContract {
		return true
	}
	return false
}

func IsBaapChainIaas(to *common.Address) bool {
	if to != nil && *to == BaapChainIaasContract {
		return true
	}
	return false
}

func IsCashIn(to *common.Address) bool {
	if to != nil && *to == CashIn {
		return true
	}
	return false
}

var freeTx = map[common.Address][]byte{
	XChainTransferDepositContract: nil,
	TcUpdaterContract:             nil,
	TrustTree:                     nil,
	NodeUpdateContract:            nil,
	TrustTxWhiteListContract:      nil,
	BaapChainIaasContract:         nil,
	CashIn:                        nil,
}

//set particular tx is free
func IsFreeTx(to *common.Address) bool {
	if to == nil {
		return false
	}

	if _, ok := freeTx[*to]; ok {
		return true
	}

	return false
}

func IsTcUpdater(to *common.Address) bool {
	if to != nil && *to == TcUpdaterContract {
		return true
	}
	return false
}

func IsTrustTxWhiteList(to *common.Address) bool {
	if to != nil && *to == TrustTxWhiteListContract {
		return true
	}
	return false
}

func IsBaapTrustTree(to *common.Address) bool {
	if to != nil && *to == TrustTree {
		return true
	}
	return false
}

//evertrust whether tx is sent to withdraw address
func IsWithdraw(to *common.Address) bool {
	if to != nil && *to == XChainTransferWithDrawContract {
		return true
	}
	return false
}

func DepositContractAddr() common.Address {
	return XChainTransferDepositContract
}

func deployedSolidityKeyHash() []byte {
	hash := util.EthHash([]byte("deployed_solidity"))
	return hash[:]
}
