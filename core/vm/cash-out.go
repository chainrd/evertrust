package vm

import (
	"fmt"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/log"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/CRDcc/util"
	"CRD-chain/rlp"
)

type CashOut struct{}

func (x *CashOut) RequiredGas(input []byte) uint64 {
	return 0
}

//type CashOutData struct {
//	Amount *big.Int `json:"amount"` // 提现数
//}

type CashOutRecord struct {
	Amount    *big.Int       `json:"amount"` // 提现数
	From      common.Address `json:"to"` // 提现用户
	TxHash common.Hash `json:"tx_hash"` // 交易hash
}

var cashOutIndexKey = util.EthHash([]byte("cashOut:index"))

func (x *CashOut) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	if len(extra[conf.TxEstimateGas]) > 0 {
		return nil, nil
	}

	contractAddr := ctx.Contract.Address()

	txHash := common.BytesToHash(extra[conf.BaapTxid][:])
	record := CashOutRecord{
		Amount:ctx.Contract.value,
		From:ctx.Contract.CallerAddress,
		TxHash:txHash,
	}
	recordByts, err := rlp.EncodeToBytes(record)
	if err != nil {
		log.Error("rlp enc record", "err", err)
		return nil, err
	}

	// gen index
	indexByte := ctx.Evm.StateDB.GetCRDState(contractAddr, cashOutIndexKey)
	newIndex := new(big.Int).Add(new(big.Int).SetBytes(indexByte), big.NewInt(1))
	ctx.Evm.StateDB.SetCRDState(contractAddr, cashOutIndexKey, newIndex.Bytes())

	// index => txHash
	newIndexKey := genCashOutNewIndexKey(newIndex.String())
	ctx.Evm.StateDB.SetCRDState(contractAddr, newIndexKey, txHash.Bytes())

	// txHash => record
	txHashKey := genCashOutTxHashKey(txHash)
	ctx.Evm.StateDB.SetCRDState(contractAddr, txHashKey, recordByts)


	// 记录总的转出数
	totalKeyHash := genCashOutTotalKeyHash()
	byts := ctx.Evm.StateDB.GetCRDState(contractAddr, totalKeyHash)
	total := new(big.Int).Add(new(big.Int).SetBytes(byts), ctx.Contract.value)
	ctx.Evm.StateDB.SetCRDState(contractAddr, totalKeyHash, total.Bytes())
	log.Debug("cash out", "total", total.String())



	return nil, nil
}

func genCashOutTotalKeyHash() common.Hash {
	return util.EthHash([]byte("crd:cashOut:total"))
}

func getCashOutRecordKeyHash(caller common.Address) common.Hash {
	key := fmt.Sprintf("crd:cashOut:%s", caller.String())
	return util.EthHash([]byte(key))
}

func genCashOutNewIndexKey(index string) common.Hash {
	return util.EthHash([]byte(fmt.Sprintf("cashOut:index:%s", index)))
}

func genCashOutTxHashKey(txHash common.Hash) common.Hash {
	return util.EthHash([]byte(fmt.Sprintf("cashOut:txHash:%s",  txHash.String())))
}
