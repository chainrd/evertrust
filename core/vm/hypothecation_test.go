package vm

import (
	"context"
	"fmt"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/crypto"
	"CRD-chain/p2p/discover"
	"CRD-chain/rlp"
	"CRD-chain/evertrust/utils/client"
	"testing"
)

func TestHypothecation_Run(t *testing.T) {

	if client, err := client.Connect("http://127.0.0.1:8545"); err != nil {
		fmt.Printf(err.Error())
		return
	} else {

		if privKey, err := crypto.HexToECDSA("de69eae2e01673b54aa8ea69fae874cd1930af923bebd54015066942ca7732bc"); err != nil {
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

				type HypothecationAddress struct {
					Address common.Address `json:"address"` //抵押地址
				}

				//addr := common.HexToAddress("0x41b84E81Ba73ab6910ac9b2038d6F18C15a05367")

				recaption := &HypothecationAddress{
					from,
				}

				payload, _ := rlp.EncodeToBytes(recaption)

				tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, payload)
				//EIP155 signer
				signer := types.NewEIP155Signer(big.NewInt(738))
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
