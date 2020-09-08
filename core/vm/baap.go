package vm

import (
	"errors"
	"github.com/golang/protobuf/proto"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/log"
	"CRD-chain/CRDcc"
	"CRD-chain/CRDcc/conf"
	pb "CRD-chain/CRDcc/protos"
	"CRD-chain/CRDcc/util"
	"CRD-chain/evertrust/utils"
)

type BaapConnector struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *BaapConnector) RequiredGas(input []byte) uint64 {
	return 0
}

func (c *BaapConnector) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	if len(extra[conf.TxEstimateGas]) > 0 {
		return nil, nil
	}
	
	stateFunc := func(fcn string, key string, value []byte) []byte {
		switch fcn {
		case conf.GetETH:
			return getState(ctx, key)
		case conf.GetCRD:
			return getCRDState(ctx, key)
		case conf.SetETH:
			setState(ctx, key, value)
			return nil
		case conf.SetCRD:
			setCRDState(ctx, key, value)
			return nil
		default:
			return nil
		}
	}

	extra[conf.BaapDst] = ctx.Contract.Address().Bytes()
	extra[conf.BaapSender] = ctx.Contract.Caller().Bytes()

	inv, txType, contractAddr, owner, name, version, err := getInvocation(ctx.Evm, input)
	if err != nil {
		log.Error("get invocation error", "err", err)
		return nil, err
	}

	err = CRDcc.Apply(inv, extra, input, stateFunc)
	if txType == types.Transaction_deploy && err == nil {
		//store cc name
		log.Trace("store cc name")
		meta := utils.Meta{"name": []byte(name), "version": []byte(version)}
		StoreContractAddr(ctx.Evm, contractAddr, meta, owner, 2)
	}

	return nil, err
}

func getInvocation(evm *EVM, txd []byte) (inv *pb.Invocation, txType uint32, contractAddr common.Address, owner, name, version string, err error) {
	tx := &pb.Transaction{}
	err = proto.Unmarshal(txd, tx)
	if err != nil {
		log.Error("get invocation proto unmarshal", "err", err)
		return
	}

	txType = tx.Type
	switch txType {
	case types.Transaction_deploy:
		//if evm.chainConfig.ChainID.Cmp(big.NewInt(739)) == 0 {
		//	log.Error("main net deploy cc forbidden", "chain id", evm.chainConfig.ChainID)
		//	err = errors.New("main net deploy cc forbidden")
		//	return
		//}

		deploy := pb.Deployment{}
		err = proto.Unmarshal(tx.Payload, &deploy)
		if err != nil {
			log.Error("proto unmarshal deploy error", "err", err)
			return
		}
		inv = deploy.Payload

		//for user custom contract to put state
		owner = deploy.Owner
		name = deploy.Name
		version = deploy.Version
		cc := owner + ":" + name
		contractAddr = util.EthAddress(cc)
		addrStr := contractAddr.String()
		log.Debug("chaincode account addr", "cc", cc, "addr", addrStr)

		evm.StateDB.CreateAccount(contractAddr)
		if evm.ChainConfig().IsEIP158(evm.BlockNumber) {
			evm.StateDB.SetNonce(contractAddr, 1)
		}
		//cc store
		evm.StateDB.SetCode(contractAddr, tx.Payload)

	case types.Transaction_invoke: //start stop withdraw
		invocation := &pb.Invocation{}
		err = proto.Unmarshal(tx.Payload, invocation)
		if err != nil {
			log.Error("proto unmarshal invocation error", "err", err)
			return
		}

		inv = invocation
	default:
		log.Error("transaction type error")
		err = errors.New("transaction type error")
		return
	}

	return
}

func setState(ctx *PrecompiledContractContext, key string, value []byte) {
	keyHash := util.EthHash([]byte(key + conf.ETHKeyFlag))
	ctx.Evm.StateDB.SetState(ctx.Contract.Address(), keyHash, util.EthHash(value))
}

func setCRDState(ctx *PrecompiledContractContext, key string, value []byte) {
	keyHash := util.EthHash([]byte(key + conf.CRDKeyFlag))
	ctx.Evm.StateDB.SetCRDState(ctx.Contract.Address(), keyHash, value)
}

func getState(ctx *PrecompiledContractContext, key string) []byte {
	keyHash := util.EthHash([]byte(key + conf.ETHKeyFlag))
	hash := ctx.Evm.StateDB.GetState(ctx.Contract.Address(), keyHash)

	return hash.Bytes()
}

func getCRDState(ctx *PrecompiledContractContext, key string) []byte {
	keyHash := util.EthHash([]byte(key + conf.CRDKeyFlag))
	value := ctx.Evm.StateDB.GetCRDState(ctx.Contract.Address(), keyHash)

	return value
}
