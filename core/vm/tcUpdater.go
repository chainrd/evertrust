package vm

import (
	"CRD-chain/CRDcc/conf"
	"CRD-chain/evertrust/utils/tcUpdate"
)

type TcUpdate struct{}

func (c *TcUpdate) RequiredGas(input []byte) uint64 {
	return 0
}

func (c *TcUpdate) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	if len(extra[conf.TxEstimateGas]) > 0 {
		return nil, nil
	}
	trustChainUpdTxModel, err := tcUpdate.TrustChainUpdTxModelDecode(input)
	if err != nil {
		return nil, err
	}

	tcUpdate.TrustHosts.WriteTrustChain(trustChainUpdTxModel)

	return nil, nil
}
