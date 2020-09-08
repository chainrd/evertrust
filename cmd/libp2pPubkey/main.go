package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/cc14514/go-alibp2p"
	"CRD-chain/crypto"
)


func main() {
	var abiFlag = flag.String("pubkey", "", "pubkey转成libp2p所需要的公钥")
	flag.Parse()
	//r, _ := keystore.DecryptKey([]byte(`{"address":"9138bbf7d850995a03d2d43e74dfa1015d9b4c62","crypto":{"cipher":"aes-128-ctr","ciphertext":"d4d53ff21849ff24e3ee9eca497a1c96f139ea9b2fc00b1dc5ba9487da358912","cipherparams":{"iv":"09692a1245b744a609b7464840302797"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"799803f67a71e452ade9c1c2b344a91855cf5df99f4568bd95187df9b4599d0f"},"mac":"1bea64dd4eae1c012bb95e20519614ffb7026a58b7706639bc314d9ede62709e"},"id":"57a5e559-4162-4d56-9d14-5e005eb58f0f","version":3}`), "123456")
	//
	//fmt.Println("pub", hex.EncodeToString(PubkeyID(&r.PrivateKey.PublicKey)))
	//fmt.Println("pub",*abiFlag)
	if *abiFlag != "" {
		key ,_:= hex.DecodeString(*abiFlag)
		pub, err := crypto.UnmarshalPubkey(key)
		if err!=nil{
			panic("sssss")
		}
		id, err := alibp2p.ECDSAPubEncode(pub)
		if err!=nil{
			panic("wwwwww")
		}
		fmt.Println(id)
	}

	///ip4/127.0.0.1/tcp/12183/CRD/16Uiu2HAkx7auDeGKpEkwH2mHHzVMrhcQQp4enW3z5JsQumvKQsK9
}
