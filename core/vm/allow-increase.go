package vm

import (
	"encoding/json"
	"errors"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/log"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/evertrustAccount"
)

type AllowIncrease struct {
}

func (a *AllowIncrease) RequiredGas(input []byte) uint64 {
	return 0
}

type AddData struct {
	Amount *big.Int `json:"amount"`
}

func (x *AllowIncrease) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	if len(extra[conf.TxEstimateGas]) > 0 {
		return nil, nil
	}

	allow := ctx.Evm.chainConfig.Evertrust.AllowIncrease
	if allow == (common.Address{}) {
		return nil, errors.New("not support increase")
	}

	add := new(AddData)
	err := json.Unmarshal(input, add)
	if err != nil {
		log.Error("json unmarshal add", "err", err)
		return nil, errors.New("input invalid")
	}

	if ctx.Contract.Caller() != allow {
		log.Error("sender invalid", "sender", ctx.Contract.Caller(), "should", allow)
		return nil, errors.New("sender invalid")
	}

	//log.Debug("add data------------>", "amount", add.Amount, "TotalRewardAddr", utils.TotalRewardAddr)

	before := ctx.Evm.StateDB.GetBalance(evertrustAccount.TotalRewardAddr)
	log.Debug("add balance before", "balance", before.String())

	// add is negative
	if add.Amount.Cmp(big.NewInt(0)) < 0 {
		// before + (-add) < 0
		if big.NewInt(0).Add(before, add.Amount).Cmp(big.NewInt(0)) < 0 {
			log.Error("balance not enough", "before", before, "add", add.Amount)
			return nil, errors.New("balance not enough")
		}
	}
	ctx.Evm.StateDB.AddBalance(evertrustAccount.TotalRewardAddr, add.Amount)

	after := ctx.Evm.StateDB.GetBalance(evertrustAccount.TotalRewardAddr)
	log.Debug("add balance after", "balance", after)

	return nil, nil
}
