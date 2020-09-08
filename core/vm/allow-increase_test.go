package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/crypto"
	"CRD-chain/crypto/sha3"
	"CRD-chain/evertrust/utils/client"
	"testing"
)

func TestAdditionalIssue(t *testing.T) {
	if client, err := client.Connect("http://127.0.0.1:8546"); err != nil {
		t.Fatal(err.Error())
	} else {
		if privKey, err := crypto.HexToECDSA("a2f1a32e5234f64a6624210b871c22909034f24a52166369c2619681390433aa"); err != nil {
			t.Fatal(err.Error())
		} else {
			from := crypto.PubkeyToAddress(privKey.PublicKey)
			t.Logf("from:%s", from)
			to := Keccak256ToAddress("allow-increase")

			fmt.Printf("to:%s\n", to.String())
			fmt.Println(from.String())
			if nonce, err := client.EthClient.NonceAt(context.TODO(), from, nil); err != nil {
				t.Fatal(err.Error())
			} else {
				amount := big.NewInt(0)
				gasLimit := uint64(41000)
				gasPrice := big.NewInt(200000000000)

				type AddData struct {
					Amount *big.Int `json:"amount"` //正数代表增，负数代表减
				}

				paload, err := json.Marshal(
					AddData{
						Amount: big.NewInt(0).Mul(big.NewInt(50), big.NewInt(1000000000000000000)),
					})
				if err != nil {
					t.Fatalf("marshal XChainTransferWithdraw err:%s", err)
				}

				fmt.Println("nounce:", nonce)
				tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, paload)
				signer := types.NewEIP155Signer(big.NewInt(738))
				signedTx, _ := types.SignTx(tx, signer, privKey)
				if txHash, err := client.SendRawTransaction(context.TODO(), signedTx); err != nil {
					fmt.Printf(err.Error())
				} else {
					fmt.Printf("Transaction hash: %s\n", txHash.String())

				}
			}
		}
	}
}

func Keccak256ToAddress(ccName string) common.Address {
	hash := sha3.NewKeccak256()

	var buf []byte
	hash.Write([]byte(ccName))
	buf = hash.Sum(buf)

	fmt.Println("keccak256ToAddress:", common.BytesToAddress(buf).String())

	return common.BytesToAddress(buf)
}
