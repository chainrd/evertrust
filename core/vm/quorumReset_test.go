package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/crypto"
	"CRD-chain/evertrust/utils/client"
	"testing"
	"time"
)

func TestQuorumReset(t *testing.T) {

	client, err := client.Connect("http://127.0.0.1:8547")

	gasLimit := uint64(4712388)
	gasPrice := big.NewInt(240000000000)
	privKey, err := crypto.HexToECDSA("d29ce71545474451d8292838d4a0680a8444e6e4c14da018b4a08345fb2bbb84")
	if err != nil {
		fmt.Printf(err.Error())
		return
	}
	from := crypto.PubkeyToAddress(privKey.PublicKey)
	fmt.Printf("from:%s\n", from.String())
	ctx, _ := context.WithTimeout(context.TODO(), 2*time.Second)
	nonce, err := client.EthClient.NonceAt(ctx, from, nil)
	if err != nil {
		fmt.Println("nonce err", err)
		return
	}
	amount := big.NewInt(0)
	to := common.BytesToAddress(crypto.Keccak256([]byte("QuorumReset"))[12:])
	fmt.Printf("to:%s\n", to.String())
	fmt.Println(from.String())
	vote, _ := client.EthClient.NonceAt(ctx, to, nil)
	if vote == 0 {
		vote = 1
	}
	fmt.Println("查询的合约账户的轮数是", "vote", vote)
	bytes, _ := json.Marshal(vote)
	tx := types.NewTransaction(uint64(nonce), to, amount, gasLimit, gasPrice, bytes)
	//EIP155 signer
	signer := types.NewEIP155Signer(big.NewInt(739))
	//signer := types.HomesteadSigner{}
	signedTx, _ := types.SignTx(tx, signer, privKey)
	// client.EthClient.SendTransaction(context.TODO(), signedTx)
	if txHash, err := client.SendRawTransaction(context.TODO(), signedTx); err != nil {
		fmt.Println("yerror", err.Error())
		return
	} else {
		fmt.Println("Transaction hash:", txHash.String(), "nonce", nonce)
		nonce++

	}
}
