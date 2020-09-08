package vm

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"CRD-chain/common"
	"CRD-chain/log"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/CRDcc/util"
	"strings"
)

type PublicAccoutVote struct{}

type VoteData struct {
	Nonce         uint64         `json:"nonce"`
	PublicAccount common.Address `json:"public_account"`
}

func (x *PublicAccoutVote) RequiredGas(input []byte) uint64 {
	return 0
}

func (x *PublicAccoutVote) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	if len(extra[conf.TxEstimateGas]) > 0 {
		return nil, nil
	}

	//payload
	voteData := new(VoteData)
	err := json.Unmarshal(input, voteData)
	if err != nil {
		log.Error("json unmarshal voteData", "err", err)
		return nil, err
	}
	log.Debug("*****************投票：", "nonce", voteData.Nonce, "pA", voteData.PublicAccount.String())

	contractAddr := ctx.Contract.Address()
	caller := ctx.Contract.Caller()

	contractNonce := ctx.Evm.StateDB.GetNonce(contractAddr)
	//------------------------------->start
	//log.Debug("99999999999999999999999999999999999999")
	//ctx.Evm.StateDB.AddBalance(contractAddr, big.NewInt(0))
	//
	////if ctx.Evm.ChainConfig().IsEIP158(ctx.Evm.BlockNumber) {
	////	ctx.Evm.StateDB.SetNonce(contractAddr, 1)
	////}
	//kh := util.EthHash([]byte("abc"))
	//
	//nonce := ctx.Evm.StateDB.GetNonce(contractAddr)
	//log.Debug("current nonce===========>", "nonce", nonce)
	//
	//bt := ctx.Evm.StateDB.GetCRDState(contractAddr, kh)
	//pA := common.BytesToAddress(bt)
	//log.Debug("current public account============>", "addr", pA.String())
	//
	//ctx.Evm.StateDB.SetCRDState(contractAddr, kh, voteData.PublicAccount.Bytes())
	//ctx.Evm.StateDB.SetNonce(contractAddr, nonce)
	//
	////setAllState(ctx, contractAddr, kh, voteData.PublicAccount.Bytes())
	////ctx.Evm.StateDB.SetState(contractAddr, kh, util.EthHash(voteData.PublicAccount.Bytes()))
	//
	////ctx.Evm.StateDB.SetNonce(contractAddr, contractNonce + 1)
	//return nil, nil
	//------------------------------->end

	//判断投票轮数
	if voteData.Nonce != contractNonce {
		log.Error("vote nonce wrong", "nonce", voteData.Nonce, "should", contractNonce)
		return nil, errors.New("vote nonce wrong")
	}

	//拥有投票权限的人数大于0
	voters := getPublicAccountVoters(ctx)
	if len(voters) <= 0 {
		log.Error("voters num less 1")
		return nil, errors.New("voters num less 1")
	}

	//是否是投票人
	isVoter := func(from common.Address) bool {
		for _, v := range voters {
			if v == caller {
				return true
			}
		}

		return false
	}
	if !isVoter(caller) {
		log.Error("no vote authority", "caller", caller.String())
		return nil, errors.New("no vote authority")
	}

	// 获取投票结果
	type voterAddr string
	type publicAccountAddr common.Address
	voteResultKeyHash := getVoteResultKeyHash(contractNonce)
	byts := ctx.Evm.StateDB.GetCRDState(contractAddr, voteResultKeyHash)
	voteResult := make(map[voterAddr]publicAccountAddr)
	if len(byts) > 0 {
		err = json.Unmarshal(byts, &voteResult)
		if err != nil {
			log.Error("json unmarshal voteResult", "err", err)
			return nil, err
		}
	}

	// 记录票
	callerAddr := strings.ToLower(caller.String())
	voteResult[voterAddr(callerAddr)] = publicAccountAddr(voteData.PublicAccount)
	value, err := json.Marshal(voteResult)
	if err != nil {
		log.Error("json marshal voteResult", "err", err)
		return nil, err
	}
	setAllState(ctx, contractAddr, voteResultKeyHash, value)

	for k, v := range voteResult {
		log.Debug("*******************记录票", "voter", string(k), "pA", common.Address(v).String())
	}

	// 计算票数
	ticketNum := make(map[publicAccountAddr]int)
	for _, v := range voteResult {
		ticketNum[v]++
	}

	//是否达到2/3
	publicAccountKeyHash := getPublicAccountKeyHash()
	need := int(math.Ceil(float64(len(voters)*2) / float64(3)))
	for addr, n := range ticketNum {
		if n >= need {
			// 达到2/3
			log.Debug("*******************达到2/3", "n", n, "need", need)
			setAllState(ctx, contractAddr, publicAccountKeyHash, common.Address(addr).Bytes())
			ctx.Evm.StateDB.SetNonce(contractAddr, contractNonce+1) // 投票轮数加1
			return nil, nil
		}
	}

	return nil, nil
}

func setAllState(ctx *PrecompiledContractContext, addr common.Address, keyHash common.Hash, value []byte) {
	ctx.Evm.StateDB.SetCRDState(addr, keyHash, value)
	//ctx.Evm.StateDB.SetState(addr, keyHash, util.EthHash(value))
}

func getPublicAccountKeyHash() common.Hash {
	//key := fmt.Sprintf("CRD:public-account-vote:address")
	return util.EthHash([]byte("CRD:public-account-vote:address"))
}

func getVoteResultKeyHash(nonce uint64) common.Hash {
	key := fmt.Sprintf("CRD:public-account-vote:result:%d", nonce)
	return util.EthHash([]byte(key))
}

func getPublicAccountVoters(ctx *PrecompiledContractContext) []common.Address {
	var voters []common.Address

	//genesis中获取voters addr
	voters = ctx.Evm.chainConfig.Evertrust.VoterAddrs

	return voters
}
