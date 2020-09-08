package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"CRD-chain/accounts/keystore"
	"CRD-chain/crypto"
	"CRD-chain/p2p/discover"
)

func main() {
	//keystore转私钥
	key, _ := keystore.DecryptKey([]byte(`{"address":"3a556e875389956068dd7662b35331f1ad5fc10f","crypto":{"cipher":"aes-128-ctr","ciphertext":"3c4b5b87f4377752be90ccdc6d7aba13a7c07c8971c6fdc58856c653f30d9086","cipherparams":{"iv":"c94c27a834b48979526db780944ce577"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"d870e753f7b5d7bb13901997015f5d1bbadaaa509dfb5e13a9a4f24ec09ecbf3"},"mac":"7f2ebfd07036ff1468fd1c85113b990ed4e637aa297f146239028f5e8999d9b5"},"id":"72b1bab5-3cd0-46fa-8356-fff6c9661a80","version":3}`), "edcc2dc8-e60f-4ffa-9fcb-10ca3e7d180a")

	//私钥类型转十六进制字符串
	privKey := fmt.Sprintf("%x", crypto.FromECDSA(key.PrivateKey))
	fmt.Println(privKey)
	//fmt.Println("pub", hex.EncodeToString())

	//公钥类型转nodeID
	fmt.Println(PubkeyID(&key.PrivateKey.PublicKey))

	fmt.Println(len("49f63021787886616c06da0cdcb14caf3b428bca84b54c1336f5a26514a47a2642fa2ea0764bffc0bd3e674f56c999e5253cb48fc3d6b32c7fc28d3d2f45c70c"))
}

func PubkeyID(pub *ecdsa.PublicKey) discover.NodeID {
	var id discover.NodeID
	pbytes := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	if len(pbytes)-1 != len(id) {
		panic(fmt.Errorf("need %d bit pubkey, got %d bits", (len(id)+1)*8, len(pbytes)))
	}
	copy(id[:], pbytes[1:])
	return id
}
