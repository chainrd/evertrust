package vm

import (
	"CRD-chain/evertrust/utils"
	"CRD-chain/params"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/log"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/CRDcc/util"
	"CRD-chain/rlp"
)

type CashIn struct{}

type CashInData struct {
	BankReceipt string `json:"bank_receipt"` //银行收据
	Amount *big.Int `json:"amount"` //充值钱数
	To common.Address `json:"to"` //给谁充值
}

type CashInRecord struct {
	BankReceipt string         `json:"bank_receipt"` // 银行收据
	Amount      *big.Int       `json:"amount"` // 充值数
	To          common.Address `json:"to"` // 充值给谁
	PublicAccount common.Address `json:"public_account"` // 公账户地址
	TxHash common.Hash `json:"tx_hash"` // 充值时间
}

func (x *CashIn) RequiredGas(input []byte) uint64 {
	return 0
}

var cashInIndexKey = util.EthHash([]byte("cashIn:index"))

func (x *CashIn) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	if len(extra[conf.TxEstimateGas]) > 0 {
		return nil, nil
	}

	cashInData := new(CashInData)
	err := json.Unmarshal(input, cashInData)
	if err != nil {
		log.Error("json unmarshal cashInData", "err", err)
		return nil, err
	}
	log.Debug("cash in data", "receipt", cashInData.BankReceipt, "amount", cashInData.Amount, "to", cashInData.To)

	contractAddr := ctx.Contract.Address()

	// 获取公账户
	publicAccount := getPublicAccount(ctx)
	if publicAccount == (common.Address{}) {
		log.Error("public account empty")
		return nil, err
	}
	log.Debug("public account", "addr", publicAccount.String())

	// 验证交易来自公账户
	if ctx.Contract.CallerAddress != publicAccount {
		log.Error("illegal public Account", "sender", ctx.Contract.CallerAddress)
		return nil, errors.New("illegal public Account")
	}

	// 给相应的账户加钱
	ctx.Evm.StateDB.AddBalance(cashInData.To, cashInData.Amount)

	txHash := common.BytesToHash(extra[conf.BaapTxid][:])
	record := CashInRecord{
		BankReceipt:cashInData.BankReceipt,
		Amount:cashInData.Amount,
		To:cashInData.To,
		PublicAccount:ctx.Contract.CallerAddress,
		TxHash:txHash,
	}
	recordByts, err := rlp.EncodeToBytes(record)
	if err != nil {
		log.Error("rlp enc record", "err", err)
		return nil, err
	}

	// 设置索引
	index := ctx.Evm.StateDB.GetCRDState(contractAddr, cashInIndexKey)
	newIndex := new(big.Int).Add(new(big.Int).SetBytes(index), big.NewInt(1))
	ctx.Evm.StateDB.SetCRDState(contractAddr, cashInIndexKey, newIndex.Bytes())

	// index=>txHash
	newIndexKey := genCashInNewIndexkey(newIndex.String())
	ctx.Evm.StateDB.SetCRDState(contractAddr, newIndexKey, txHash.Bytes())

	// txHash => record
	txHashKey := genCashInTxHashKey(txHash)
	ctx.Evm.StateDB.SetCRDState(contractAddr, txHashKey, recordByts)

	// 记录累次加钱数额
	totalKeyHash := genCashInTotalKeyHash()
	byts := ctx.Evm.StateDB.GetCRDState(contractAddr, totalKeyHash)
	total := new(big.Int).Add(new(big.Int).SetBytes(byts), cashInData.Amount)
	ctx.Evm.StateDB.SetCRDState(contractAddr, totalKeyHash, total.Bytes())
	log.Debug("cash in", "total", total.String())



	return nil, nil
}

func genCashInTotalKeyHash() common.Hash {
	return util.EthHash([]byte("crd:cashIn:total"))
}

func getCashInRecordKeyHash(caller common.Address) common.Hash {
	key := fmt.Sprintf("crd:cashIn:%s", caller.String())
	return util.EthHash([]byte(key))
}

func getPublicAccount(ctx *PrecompiledContractContext) common.Address {
	var publicAccount common.Address
	// 首先去库里获取
	publicAccountKeyHash := getPublicAccountKeyHash()
	byts := ctx.Evm.StateDB.GetCRDState(utils.PublicAccountVote, publicAccountKeyHash)
	if len(byts) > 0 {
		return common.BytesToAddress(byts)
	}
	// 否则从初始化配置中获取
	publicAccount = ctx.Evm.chainConfig.Evertrust.PublicAccount
	return publicAccount
}

func GetPublicAccount(stateDB StateDB, chainConf *params.ChainConfig) common.Address  {
	var publicAccount common.Address
	// 首先去库里获取
	publicAccountKeyHash := getPublicAccountKeyHash()
	byts := stateDB.GetCRDState(utils.PublicAccountVote, publicAccountKeyHash)
	if len(byts) > 0 {
		return common.BytesToAddress(byts)
	}
	// 否则从初始化配置中获取
	publicAccount = chainConf.Evertrust.PublicAccount
	return publicAccount
}



func genCashInNewIndexkey(index string) common.Hash {
	return util.EthHash([]byte(fmt.Sprintf("cashIn:%s", index)))
}

func genCashInTxHashKey(txHash common.Hash) common.Hash {
	return util.EthHash([]byte(fmt.Sprintf("cashIn:%s", txHash.String())))
}