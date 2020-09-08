package miner

import (
	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/CRDcc/util"
	"testing"
)

func TestFillTxsToBuckets(t *testing.T) {
	txs := make(map[common.Address]types.Transactions)
	from1 := util.EthAddress("from1")
	from2 := util.EthAddress("from2")
	from3 := util.EthAddress("from3")

	//to1 := util.EthAddress("to1")
	//to2 := util.EthAddress("to2")
	//to3 := util.EthAddress("to3")

	//// from1
	//tx1 := types.NewTransaction(0, to1, nil, 0, nil, nil)
	//tx2 := types.NewTransaction(1, to2, nil, 0, nil, nil)
	//// from2
	//tx3 := types.NewTransaction(2, to1, nil, 0, nil, nil)
	//tx4 := types.NewTransaction(3, to2, nil, 0, nil, nil)
	//tx5 := types.NewTransaction(4, to3, nil, 0, nil, nil)
	//// from3
	//tx6 := types.NewTransaction(5, to3, nil, 0, nil, nil)

	// from1
	tx1 := types.NewContractCreation(0, nil, 0, nil, nil)
	tx2 := types.NewContractCreation(1, nil, 0, nil, nil)
	// from2
	tx3 := types.NewContractCreation(2, nil, 0, nil, nil)
	tx4 := types.NewContractCreation(3, nil, 0, nil, nil)
	tx5 := types.NewContractCreation(4, nil, 0, nil, nil)
	// from3
	tx6 := types.NewContractCreation(5, nil, 0, nil, nil)

	var txs1 types.Transactions
	var txs2 types.Transactions
	var txs3 types.Transactions
	txs1 = append(txs1,  tx1, tx2)
	txs2 = append(txs2, tx3, tx4, tx5)
	txs3 = append(txs3, tx6)

	txs[from1] = txs1
	txs[from2] = txs2
	txs[from3] = txs3

	w := new(evertrustWorker)
	w.current = new(environment)
	w.current.txmap = make(map[common.Hash]*types.Transaction)

	bkts := w.fillTxsToBuckets(txs)
	t.Logf("bkts num:%v", len(bkts))

}
