package vm

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/log"
	"CRD-chain/params"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/CRDcc/util"
	"CRD-chain/evertrust/utils"
)

type XChainTransferWithDraw struct{}

type Withdraw struct {
	DstChainID      string         `json:"dst_chain_id"`
	DstChainOwner   common.Address `json:"dst_chain_owner"`
	DstUserAddr     common.Address `json:"dst_user_addr"`
	DstContractAddr string         `json:"dst_contract_addr"`
}

type WithdrawTx struct {
	Txid    string
	Payload Withdraw
}

func (x *XChainTransferWithDraw) RequiredGas(input []byte) uint64 {
	log.Info("RequiredGas", "gas", uint64(len(input)/192)*params.Bn256PairingPerPointGas, "l", len(input)/192)
	return uint64(len(input)/192) * params.Bn256PairingPerPointGas
}

func (x *XChainTransferWithDraw) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	// used for estimating gas
	if extra[conf.TxEstimateGas] != nil {
		log.Info("withdraw estimate gas limit")
		return nil, nil
	}

	log.Info("XChainTransferWithdraw run")

	log.Info("XChainTransferWithDraw run", "input", string(input))
	var payload Withdraw
	err := json.Unmarshal(input, &payload)
	if err != nil {
		log.Error("unmarshal payload error", "err", err)
		return nil, err
	}

	err = withdraw(ctx, payload)
	if err != nil {
		log.Error("withdraw error", "err", err)
		return nil, err
	}
	//for tx query
	if txid, find := extra[conf.BaapTxid]; find {
		//log.Info("tx hash", "hash", common.BytesToHash(txid).String())
		//withdrawTxAddr := utils.GenWithdrawTxAddr(ctx.Contract.CallerAddress)
		//log.Info("withdrawTxAddr", "is", withdrawTxAddr)
		//
		///*if !ctx.Evm.StateDB.Exist(withdrawTxAddr) {
		//	log.Info("not exist then add balance avoid state being deleted")
		//	ctx.Evm.StateDB.CreateAccount(withdrawTxAddr)
		//	ctx.Evm.StateDB.SetNonce(withdrawTxAddr, 1)
		//}*/
		//ctx.Evm.StateDB.AddBalance(withdrawTxAddr, big.NewInt(1))
		//
		//ctx.Evm.StateDB.SetCRDState(withdrawTxAddr, common.BytesToHash(txid), input)
		//log.Info("tx hash", "common", common.BytesToHash(txid))
		//log.Info("tx hash", "eth...", util.EthHash(txid))

		keyHash := utils.WithdrawTxKeyHash(ctx.Contract.CallerAddress)
		value := ctx.Evm.StateDB.GetCRDState(ctx.Contract.Address(), keyHash)
		var txs []WithdrawTx
		txidStr := common.BytesToHash(txid).String()
		if len(value) != 0 {
			err := json.Unmarshal(value, &txs)
			if err != nil {
				log.Error("unmarshal txs error", "err", err)
				return nil, err
			}
		}

		txs = append(txs, WithdrawTx{Txid: txidStr, Payload: payload})
		v, err := json.Marshal(txs)
		if err != nil {
			log.Error("marshal txs error", "err", err)
			return nil, err
		}

		ctx.Evm.StateDB.SetCRDState(ctx.Contract.Address(), keyHash, v)
	}

	return nil, nil

}

func withdraw(ctx *PrecompiledContractContext, payload Withdraw) error {
	//same chain transfer forbid
	if ctx.Evm.chainConfig.ChainID.String() == payload.DstChainID {
		log.Error("same chain transfer forbid")
		return errors.New("same chain transfer forbid")
	}
	stateDB := ctx.Evm.StateDB
	from := ctx.Contract.CallerAddress
	contractAddr := ctx.Contract.Address()
	fromBalance := stateDB.GetBalance(from)
	if fromBalance.Cmp(ctx.Contract.Value()) < 0 {
		log.Error("balance not enough", "from", fromBalance.String(), "value", ctx.Contract.Value())
		return ErrInsufficientBalance // 交易进入交易池之前已经进行了验证，所以此处不可能发生错误。
	}

	key := fmt.Sprintf("%s:%s:%s:%s:%s",
		conf.CRDKeyFlag,
		"withdraw",
		from.String(),
		payload.DstUserAddr.String(),
		payload.DstChainID,
	)
	keyHash := util.EthHash([]byte(key))
	state := stateDB.GetCRDState(contractAddr, keyHash)
	sum := new(big.Int).Add(new(big.Int).SetBytes(state), ctx.Contract.Value())

	stateDB.SetCRDState(contractAddr, keyHash, sum.Bytes())
	log.Info("是否存进去了？", "sum:", new(big.Int).SetBytes(stateDB.GetCRDState(contractAddr, keyHash)))

	log.Info("before withdraw", "balance", stateDB.GetBalance(from))

	stateDB.SubBalance(from, ctx.Contract.Value())

	log.Info("after withdraw", "balance", stateDB.GetBalance(from))

	return nil

}
