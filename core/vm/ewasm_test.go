/*************************************************************************
 * Copyright (C) 2016-2019 CRD Technologies, Inc. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *************************************************************************/

package vm

import (
	"context"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"io"
	"io/ioutil"
	"math/big"
	"path"
	"CRD-chain/accounts/keystore"
	"CRD-chain/common"
	"CRD-chain/common/hexutil"
	"CRD-chain/core/types"
	"CRD-chain/crypto"
	"CRD-chain/ethclient"
	"CRD-chain/params"
	"CRD-chain/evertrust"
	"CRD-chain/evertrust/utils"
	"strings"
	"testing"
)

var (
	wasmPreamble = []byte("\x00asm\x01\x00\x00\x00")
	jsonkey      = `{"address":"86082fa9d3c14d00a8627af13cfa893e80b39101","crypto":{"cipher":"aes-128-ctr","ciphertext":"71932cbcfdb4484433393044c0114aec0e737e7eeac908ec5edb23051c1e6e90","cipherparams":{"iv":"42424805dfad0ae0d8f08af898b56a03"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"5946638ccdf2e18f206ffbc86f7d1ffe8d91f4be904c07dae716c58cf5789802"},"mac":"d419b9583c16dd04fff155a1b946b6ec749954459cc745c70ce59742ac332809"},"id":"900ab389-4085-44a0-baa7-e14ab929e5fd","version":3}`
	ipc          = "/Users/liangc/Library/evertrust/testnet/evertrust.ipc"
	fp           = "/Users/liangc/app/rusthome/hello-wasm/pkg/hello_wasm_bg.wasm"
	fp1          = "/Users/liangc/app/rusthome/hello-wasm-abi/pkg/hello_wasm_abi_bg.wasm"
	fp2          = "/Users/liangc/app/rusthome/github.com/CRDbaap/ewasm-rust-demo/hello-wasm-sol/pkg/hello_wasm_sol_bg.wasm"
	ctx          = context.Background()
	signer       = types.NewEIP155Signer(big.NewInt(739))
	prvKey       = getPrvkeyByJsonkey(strings.NewReader(jsonkey), "123456")
	addr         = crypto.PubkeyToAddress(prvKey.PublicKey)
)

func TestEVMC_CanRun(t *testing.T) {
	// 0061 736d
	t.Log(wasmPreamble)

	b, _ := hex.DecodeString("0061736d01000000")
	t.Log(b)
}

func TestReadMagicHeader(t *testing.T) {
	fp := "/tmp/a.wasm"
	buff, err := ioutil.ReadFile(fp)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(buff[:8])
	t.Log(wasmPreamble)
}

func getPrvkeyByJsonkey(keyin io.Reader, passphrase string) *ecdsa.PrivateKey {
	json, err := ioutil.ReadAll(keyin)
	if err != nil {
		panic(err)
	}
	key, err := keystore.DecryptKey(json, passphrase)
	if err != nil {
		panic(err)
	}
	return key.PrivateKey
}

func FindPrvkeyInKeystore(coinbase, pwd, datadir string) (*ecdsa.PrivateKey, error) {
	var keystoredir = path.Join(datadir, "keystore")
	fl, _ := ioutil.ReadDir(keystoredir)
	for _, f := range fl {
		if strings.Contains(f.Name(), coinbase[2:]) {
			fp := path.Join(keystoredir, f.Name())
			jprv, _ := ioutil.ReadFile(fp)
			prvKey = getPrvkeyByJsonkey(strings.NewReader(string(jprv)), pwd)
			return prvKey, nil
		}
	}
	return nil, errors.New("account_not_found")
}

func TestCall(t *testing.T) {
	// wasm 合约交易：eth.getTransactionReceipt("0x29d96fd7a613d3897ded794ce3f28dbab6c23c6fe9159c76653afd8b28790996")
	// gasUsed: 21006
	to := common.HexToAddress("0xda3ce11d916ffba4a1289cef66a7f142ec5a0f74")

	// 普通转账交易：eth.getTransactionReceipt("0xf63eb952a7b64fb2f132570ed35b030ce640bdf83aa59a35330da75412fca687")
	// gasUsed: 21000
	client, err := ethclient.Dial(ipc)
	if err != nil {
		t.Error(err)
		return
	}
	nonce, err := client.PendingNonceAt(ctx, addr)
	if err != nil {
		t.Error(err)
		return
	}
	/*
		ewasm_test.go:152: GetCounter  =  0x476574436f756e746572
		ewasm_test.go:152: put:helloworld,foobar  =  0x7075743a68656c6c6f776f726c642c666f6f626172
		ewasm_test.go:152: get:helloworld  =  0x6765743a68656c6c6f776f726c64
	*/
	_tx := types.NewTransaction(
		nonce,
		to,
		big.NewInt(1),
		params.GenesisGasLimit,                            // gasLimit
		new(big.Int).Mul(big.NewInt(1e9), big.NewInt(18)), // gasPrice
		[]byte("put:helloworld,cc14514@icloud.com lance_fox0451@163.com linglingqi@imwallet.com"))

	tx, _ := types.SignTx(_tx, signer, prvKey)
	t.Log(nonce, tx)
	err = client.SendTransaction(ctx, tx)
	t.Log(err, tx.Hash().Hex())

}

func TestDeploy(t *testing.T) {
	code, err := ioutil.ReadFile(fp2)
	if err != nil {
		t.Error(err)
		return
	}
	t.Log(code)
	t.Log(hex.EncodeToString(code))
	client, err := ethclient.Dial(ipc)
	if err != nil {
		t.Error(err)
		return
	}
	nonce, err := client.PendingNonceAt(ctx, addr)
	if err != nil {
		t.Error(err)
		return
	}
	tx, _ := types.SignTx(
		types.NewContractCreation(
			nonce,
			new(big.Int),
			11826015,                                          //gasLimit
			new(big.Int).Mul(big.NewInt(1e9), big.NewInt(18)), // gasPrice
			code),
		signer,
		prvKey)
	t.Log(nonce, tx)
	err = client.SendTransaction(ctx, tx)
	t.Log(err, len(code), tx.Hash().Hex())
}

func TestHex(t *testing.T) {
	// GetCounter / GetCallerBalance
	var (
		actions = []string{"GetCounter", "GetCallerBalance", "put:helloworld,foobar", "get:helloworld"}
	)
	for _, action := range actions {
		t.Log(action, " = ", "0x"+hex.EncodeToString([]byte(action)))
	}

	buff, err := hex.DecodeString("ff733ba40b0000000046e22dfaffffff")
	t.Log(err, buff, new(big.Int).SetBytes(buff))
}

func TestFindPrvkeyInKeystore(t *testing.T) {
	var (
		coinbase = "0x86082fa9d3c14d00a8627af13cfa893e80b39101"
		pwd      = "123456"
		datadir  = "/tmp/ewasm-node/CRD"
	)
	prv, err := FindPrvkeyInKeystore(coinbase, pwd, datadir)
	t.Log(err, prv)
}

func TestSentinelContractCode(t *testing.T) {
	t.Log(len(sentinelContractCode) / 1024)
	fs := eeiFuncs(nil)
	t.Log(len(fs))
	buf, _ := hex.DecodeString("636331343531344069636c6f75642e636f6d206c616e63655f666f7830343531403136332e636f6d206c696e676c696e67716940696d77616c6c65742e636f6d")
	t.Log(string(buf))

	bb := make([]byte, 64, 64)
	l := big.NewInt(20)
	if len(l.Bytes()) < 64 {
		ll := len(l.Bytes())
		copy(bb[64-ll:], l.Bytes()[:])
		t.Log(ll, len(bb), bb)
		b2 := swapEndian(bb)
		b3 := swapEndian(b2)
		t.Log(b2)
		t.Log(b3)

	}

	code, _ := ioutil.ReadFile(fp)

	codehex := hex.EncodeToString(code)
	fmt.Println(len(code), len(codehex))
	fmt.Println(codehex)
	ioutil.WriteFile("/tmp/0.txt", []byte(codehex), 0755)
	md5h := md5.New()
	md5h.Write([]byte(codehex))
	codehexmd5 := md5.Sum(nil)
	hmd5 := hex.EncodeToString(codehexmd5[:])
	fmt.Println(hmd5)
	//4798a50339ae955dfcd574e51052bc95
}

func TestDecode(t *testing.T) {
	h := "636331343531344069636c6f75642e636f6d206c616e63655f666f7830343531403136332e636f6d206c696e676c696e67716940696d77616c6c65742e636f6d"
	b, _ := hex.DecodeString(h)
	t.Log(string(b))
}

func TestGenED25519Key(t *testing.T) {
	pub, prv, _ := ed25519.GenerateKey(rand.Reader)
	t.Log("prv", hex.EncodeToString(prv[:]))
	t.Log(string(prv[:]))
	t.Log(prv)
	t.Log("pub", hex.EncodeToString(pub[:]))
	t.Log(string(pub[:]))
	t.Log(pub)
}
func TestCodeSignVerify(t *testing.T) {
	var (
		//k   = "9fd7f553c0d4a0894367247164ddef8143571c6148b38a7a00b26e8344d406ae"
		p   = hexutil.MustDecode("0x4ed542e702d8208847e940847d2d4d65ded1b514d43eb52bbe57e70dc270f4b7")
		m   = []byte("0f4cb90dcba39a674dcd9c9ec898e419714d3eb77ef78c414994f7b54697ee64")
		sig = hexutil.MustDecode("0x84e12de68eb7e74e2062308de36b365a8788fb70077350a9482edda0bde1cc2e88b2463a89e61e32a831a6091cb732bdd01479a6cd6222fb59443804023fee00")
	)
	r := ed25519.Verify(p, m, sig)
	t.Log(r)
	t.Log("pub", p)
	t.Log("msg", m)
	t.Log("sig", len(sig), sig)
}

/*
prv 2a965caeb471ed43c66e045fa61ae3a365388385a33f2c83f7badd5c3e9efefa4ed542e702d8208847e940847d2d4d65ded1b514d43eb52bbe57e70dc270f4b7
&[42 150 92 174 180 113 237 67 198 110 4 95 166 26 227 163 101 56 131 133 163 63 44 131 247 186 221 92 62 158 254 250 78 213 66 231 2 216 32 136 71 233 64 132 125 45 77 101 222 209 181 20 212 62 181 43 190 87 231 13 194 112 244 183]
pub 4ed542e702d8208847e940847d2d4d65ded1b514d43eb52bbe57e70dc270f4b7
&[78 213 66 231 2 216 32 136 71 233 64 132 125 45 77 101 222 209 181 20 212 62 181 43 190 87 231 13 194 112 244 183]


------
kr = [42, 150, 92, 174, 180, 113, 237, 67, 198, 110, 4, 95, 166, 26, 227, 163, 101, 56, 131, 133, 163, 63, 44, 131, 247, 186, 221, 92, 62, 158, 254, 250, 78, 213, 66, 231, 2, 216, 32, 136, 71, 233, 64, 132, 125, 45, 77, 101, 222, 209, 181, 20, 212, 62, 181, 43, 190, 87, 231, 13, 194, 112, 244, 183]
pr = [78, 213, 66, 231, 2, 216, 32, 136, 71, 233, 64, 132, 125, 45, 77, 101, 222, 209, 181, 20, 212, 62, 181, 43, 190, 87, 231, 13, 194, 112, 244, 183]
m = [48, 102, 52, 99, 98, 57, 48, 100, 99, 98, 97, 51, 57, 97, 54, 55, 52, 100, 99, 100, 57, 99, 57, 101, 99, 56, 57, 56, 101, 52, 49, 57, 55, 49, 52, 100, 51, 101, 98, 55, 55, 101, 102, 55, 56, 99, 52, 49, 52, 57, 57, 52, 102, 55, 98, 53, 52, 54, 57, 55, 101, 101, 54, 52]
s = [132, 225, 45, 230, 142, 183, 231, 78, 32, 98, 48, 141, 227, 107, 54, 90, 135, 136, 251, 112, 7, 115, 80, 169, 72, 46, 221, 160, 189, 225, 204, 46, 136, 178, 70, 58, 137, 230, 30, 50, 168, 49, 166, 9, 28, 183, 50, 189, 208, 20, 121, 166, 205, 98, 34, 251, 89, 68, 56, 4, 2, 63, 238, 0]
sig = "84e12de68eb7e74e2062308de36b365a8788fb70077350a9482edda0bde1cc2e88b2463a89e61e32a831a6091cb732bdd01479a6cd6222fb59443804023fee00"

*/

func TestSentinel(t *testing.T) {
	s := int32(0)
	EwasmFuncs.Init(nil, nil, &s)
	sp := "/app/rusthome/sentinel-rs/pkg/sentinel_rs_bg.wasm"
	code, _ := ioutil.ReadFile(sp)
	metaBefore := utils.Meta{"name": []byte("tonysu"), "version": []byte("1.2"), "jwt": []byte("sdfwqefwf_ljldsf.lfdsfj")}
	//assemble
	jcode, _ := evertrust.AssemblePayload(code, metaBefore)
	final, _ := EwasmFuncs.Sentinel(jcode)
	finalcode, _ := EwasmFuncs.JoinTxdata(jcode, final)

	t.Log("code", crypto.Keccak256(code))
	t.Log("jcode", crypto.Keccak256(jcode))
	t.Log(len(jcode), len(code), EwasmFuncs.IsWASM(jcode))
	t.Log("final", len(final), crypto.Keccak256(final))
	t.Log("finalcode", len(finalcode), crypto.Keccak256(finalcode))

	code, final, err := EwasmFuncs.SplitTxdata(finalcode)
	t.Log(err)
	t.Log("code", crypto.Keccak256(code))
	t.Log("final", len(final), crypto.Keccak256(final))

}

func TestFoo(t *testing.T) {
	t.Log([]byte( "\000asm" ))
	t.Log([]byte( "\000CRD" ))
	data, err := hex.DecodeString("636331343531344069636c6f75642e636f6d206c616e63655f666f7830343531403136332e636f6d206c696e676c696e67716940696d77616c6c65742e636f6d")
	t.Log(err, string(data))

}
