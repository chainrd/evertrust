package vm

import (
	"encoding/json"
	"errors"
	"CRD-chain/common"
	"CRD-chain/log"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/CRDcc/util"
)

type AccessCtl struct{}

func (x *AccessCtl) RequiredGas(input []byte) uint64 {
	return 0
}

type BlacklistOpt struct {
	Opt string `json:"opt"`
	Addrlist []common.Address `json:"addrlist"`
}

func (x *AccessCtl) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	if len(extra[conf.TxEstimateGas]) > 0 {
		return nil, nil
	}

	log.Info("access ctl run")
	var blOpt *BlacklistOpt
	err := json.Unmarshal(input, &blOpt)
	if err != nil {
		log.Error("unmarshal blopt err", "err", err)
		return nil, err
	}

	switch blOpt.Opt {
	case "add":
		for _, addr := range blOpt.Addrlist {
			log.Trace("add bl", "addr", addr.String())
			addrHash := util.EthHash(addr.Bytes())
			ctx.Evm.StateDB.SetCRDState(ctx.Contract.Address(), addrHash, []byte("1"))
			ctx.Evm.StateDB.SetState(ctx.Contract.Address(), addrHash, util.EthHash([]byte("1")))
		}
	case "del":
		for _, addr := range blOpt.Addrlist {
			log.Trace("del bl", "addr", addr.String())
			addrHash := util.EthHash(addr.Bytes())
			ctx.Evm.StateDB.SetCRDState(ctx.Contract.Address(), addrHash, []byte("2"))
			ctx.Evm.StateDB.SetState(ctx.Contract.Address(), addrHash, util.EthHash([]byte("2")))
		}
	default:
		log.Error("opt no match")
		return nil, errors.New("opt no match")
	}

	return nil, nil

}
