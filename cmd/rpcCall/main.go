package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/crypto"
	"CRD-chain/p2p/discover"
	"CRD-chain/rlp"
	client2 "CRD-chain/evertrust/utils/client"
	"time"
)

func main() {
	fmt.Println("***********************************")
	fmt.Println("输入要查询链的端口号")
	port := ""

	fmt.Scanln(&port)

	for {
		time.Sleep(1 * time.Second)
		var st string
		fmt.Println("**********************************")
		fmt.Println("1.查询最新区块高度")
		fmt.Println("2.查询链上节点地址(节点是否在链上)")
		fmt.Println("3.查询运行时间")
		fmt.Println("4.查询链上委员会数量(是否有出块权限)")
		fmt.Println("5.奖励地址查询(挖矿奖励地址)")
		fmt.Println("6.修改奖励地址")
		fmt.Println("7.查询链上需要的质押金额")
		fmt.Println("8.发送质押交易(只有主链739链需要质押)")
		//fmt.Println("9.发送退出质押交易(只有主链739链可以退出质押)")
		fmt.Println("9.查询质押余额")
		fmt.Println("10.查询余额")
		//fmt.Println("11.查询质押余额")
		fmt.Println("0.退出")
		fmt.Println("**********************************")

		fmt.Scanln(&st)
		fmt.Printf("开始查询端口号是%s的链\n", port)
		switch st {

		case "1":
			fun := "eth_blockNumber"
			rpcCall(fun, port)
		case "2":
			fun := "eth_getNodeActivityInfo"
			rpcCall(fun, port)
		case "3":
			fun := "eth_getRunTime"
			rpcCall(fun, port)
		case "4":
			fun := "eth_getConsensusQuorum"
			rpcCall(fun, port)
		case "5":
			fun := "eth_getLocalMinerRewardAddress"
			rpcCall(fun, port)
		case "6":
			fun := "eth_changeMinerRewardAddress"
			var add string
			fmt.Println("输入要更改的地址")
			fmt.Scanln(&add)
			add = fmt.Sprintf(`"` + add + `"`)
			rpcCall(fun, port, add)
		case "7":
			fun := "eth_getAmountofHypothecation"
			rpcCall(fun, port)

		case "8":
			var port string
			fmt.Println("输入主链739的rpc端口号")
			fmt.Scanln(&port)
			var pri string
			fmt.Println("输入私钥")
			fmt.Scanln(&pri)
			var add string
			fmt.Println("输入要质押的地址(在739链上的unlock挖矿地址)")
			fmt.Scanln(&add)
			var value int64
			fmt.Println("输入要质押的金额(后面默认加18个0,只需要输入数量即可)")
			fmt.Scanln(&value)
			v:=new(big.Int).Mul(big.NewInt(value),big.NewInt(1e18))
			Hypothecation(port, pri, add, v)

		//case "9":
		//	var port, pri, collection string
		//	fmt.Println("输入主链739的rpc端口号")
		//	fmt.Scanln(&port)
		//	fmt.Println("输入私钥(必须是已经被质押的地址)")
		//	fmt.Scanln(&pri)
		//	fmt.Println("输入退款地址")
		//	fmt.Scanln(&collection)
		//	Recaption(port, pri, collection)
		case "10":
			fun := "eth_getBalance"
			var add string
			fmt.Println("输入要查询的地址")
			fmt.Scanln(&add)
			add = fmt.Sprintf(`"` + add + `"`)
			latest:=fmt.Sprintf(`,"` + "latest" + `"`)
			rpcCall(fun, port, add,latest)
		case "9":
			fun:="eth_getTotalAmountOfHypothecationWithAddress"
			var add string
			fmt.Println("输入要查询地址")
			fmt.Scanln(&add)

			add=common.HexToAddress(add).String()

			add = fmt.Sprintf(`"` + add + `"`)
			rpcCall(fun, port, add)
			
			
		case "0":
			os.Exit(0)

		}
	}

}

func rpcCall(fun, port string, params ... string) {
	var body string
	if len(params)==2{
		body = fmt.Sprintf(`{"jsonrpc":"2.0", "method":"%s","params":%s,"id":67}`, fun, params)

	}else {

		body = fmt.Sprintf(`{"jsonrpc":"2.0", "method":"%s","params":%s,"id":67}`, fun, params)
	}
	fmt.Println(body)
	req, _ := http.NewRequest(
		"GET",
		fmt.Sprintf("http://127.0.0.1:%s", port),
		bytes.NewBuffer([]byte(body)),

	)
	req.Header.Set("Content-Type", "application/json")
	cli := &http.Client{}
	response, err := cli.Do(req)
	if err!=nil{
		fmt.Println("查询出错啦1","err",err)
	}
	all, err := ioutil.ReadAll(response.Body)
	if err!=nil{
		fmt.Println("查询出错啦2","err",err)
	}
	fmt.Println("结果查询", string(all))
}

func Hypothecation(port, pri, add string, value *big.Int) {

	client, err := client2.Connect(fmt.Sprintf("http://127.0.0.1:%s", port))
	if err != nil {
		fmt.Printf("1", err.Error())
		return
	}
	gasLimit := uint64(4712388)
	gasPrice := big.NewInt(24000000000) //todo 此处很重要，不可以太低，可能会报underprice错误，增大该值就没有问题了

	privKey, err := crypto.HexToECDSA(pri)

	//privKey, err := crypto.HexToECDSA("d29ce71545474451d8292838d4a0680a8444e6e4c14da018b4a08345fb2bbb84")
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
	type HypothecationAddress struct {
		Address common.Address `json:"address"` //抵押地址
	}

	addr := common.HexToAddress(add)
	//addr := common.HexToAddress(add1[i])
	recaption := &HypothecationAddress{
		addr,
	}

	payload1, _ := rlp.EncodeToBytes(recaption)

	nodeID := discover.PubkeyID(&privKey.PublicKey)
	fmt.Printf("nodeID:%s \n", nodeID.String())
	amount :=value
	//质押
	to := common.BytesToAddress(crypto.Keccak256([]byte("hypothecation"))[12:])

	fmt.Printf("to:%s\n", to.String())
	fmt.Println(from.String())

	tx := types.NewTransaction(uint64(nonce), to, amount, gasLimit, gasPrice, payload1)
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

func Recaption(port, pri, collection string) {
	client, err := client2.Connect(fmt.Sprintf("http://127.0.0.1:%s", port))
	if err != nil {
		fmt.Printf("1", err.Error())
		return
	}
	gasLimit := uint64(4712388)
	gasPrice := big.NewInt(24000000000) //todo 此处很重要，不可以太低，可能会报underprice错误，增大该值就没有问题了

	privKey, err := crypto.HexToECDSA(pri)

	//privKey, err := crypto.HexToECDSA("d29ce71545474451d8292838d4a0680a8444e6e4c14da018b4a08345fb2bbb84")
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
	to := common.BytesToAddress(crypto.Keccak256([]byte("redamption"))[12:])
	fmt.Printf("to:%s\n", to.String())

	////退钱需要填充的
	type RecaptionInfo struct {
		HypothecationAddr common.Address `json:"hypothecation_addr"` //质押的地址

		RecaptionAddress common.Address `json:"recaption_address"` //退款地址
	}

	recaption := &RecaptionInfo{
		HypothecationAddr: from,

		RecaptionAddress: common.HexToAddress(collection),
	}
	payload1, err := rlp.EncodeToBytes(recaption)

	if err != nil {
		fmt.Printf("marshal XChainTransferWithdraw err:%s", err)
		return
	}

	tx := types.NewTransaction(uint64(nonce), to, amount, gasLimit, gasPrice, payload1)
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
