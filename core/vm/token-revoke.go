package vm

import (
	"CRD-chain/log"
	"CRD-chain/CRDcc/util"
	"CRD-chain/rlp"
)

type TokenRevoke struct{}

func (x *TokenRevoke) RequiredGas(input []byte) uint64 {
	return 0
}

func (x *TokenRevoke) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	revokes := make([]string, 0)
	err := rlp.DecodeBytes(input, &revokes)
	if err != nil {
		log.Error("decode revoke input", "err", err)
		return nil, err
	}

	for _, v := range revokes {
		vH := util.EthHash([]byte(v))
		log.Debug("token revoke", "token", v, "hash", vH)
		ctx.Evm.StateDB.SetCRDState(ctx.Contract.Address(), vH, []byte{1})
	}

	return nil, nil
}
