package vm

import (
	"context"
	"fmt"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/crypto"
	"CRD-chain/p2p/discover"
	"CRD-chain/evertrust/utils/client"
	"testing"
)

func TestHypothecation2_Run(t *testing.T) {

	if client, err := client.Connect("http://192.168.0.121:8545"); err != nil {
		fmt.Printf(err.Error())
		return
	} else {

		if privKey, err := crypto.HexToECDSA("9ee905a8b9afcdc23a33d6f2da3cdae63a0e873bf24f27b99e97f6acc034af9a"); err != nil {
			fmt.Printf(err.Error())
			return
		} else {
			nodeID := discover.PubkeyID(&privKey.PublicKey)
			fmt.Printf("nodeID:%s \n", nodeID.String())
			from := crypto.PubkeyToAddress(privKey.PublicKey)
			fmt.Printf("from:%s\n", from.String())

			//质押
			to := common.BytesToAddress(crypto.Keccak256([]byte("hypothecation"))[12:])

			fmt.Printf("to:%s\n", to.String())
			fmt.Println(from.String())
			if nonce, err := client.EthClient.NonceAt(context.TODO(), from, nil); err != nil {
				fmt.Printf("ddddd:%s", err.Error())
				return
			} else {
				amount := big.NewInt(3000000000000000000)
				gasLimit := uint64(4712388)
				gasPrice := big.NewInt(240000000000) //todo 此处很重要，不可以太低，可能会报underprice错误，增大该值就没有问题了

				tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, nil)
				//EIP155 signer
				signer := types.NewEIP155Signer(big.NewInt(739))
				//signer := types.HomesteadSigner{}
				signedTx, _ := types.SignTx(tx, signer, privKey)
				// client.EthClient.SendTransaction(context.TODO(), signedTx)
				if txHash, err := client.SendRawTransaction(context.TODO(), signedTx); err != nil {
					fmt.Println("yerror", err.Error())
				} else {
					fmt.Printf("Transaction hash: %s\n", txHash.String())
				}
			}
		}
	}
}
