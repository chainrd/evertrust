package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"log"
	"CRD-chain/rlp"

	//"log"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"time"
)

func main()  {
	var blocks []*types.Block

	for i:=0;i<=100;i++{
		header := &types.Header{
			ParentHash:    common.HexToHash("01111111111111"),
			Number:      	big.NewInt(int64(i)),
			GasLimit:      1000000,
			Time:          big.NewInt(time.Now().Unix()),
			Difficulty:    big.NewInt(1024),
			//BlockExtra: types.BlockExtra{Rank:work.Rank},
		}


		blocks=append(blocks,types.NewBlock(header,nil,nil,nil,))

	}
	//size, _, err := rlp.EncodeToReader(blocks)
	//if err!=nil{
	//	log.Fatal("出错")
	//}
	//fmt.Println(size)  //53937

	var buff bytes.Buffer

	writer := gzip.NewWriter(&buff)

	defer writer.Close()
	t:=time.Now()
	toBytes, err := rlp.EncodeToBytes(blocks)   //json 压缩前 5859
	//toBytes, err := json.Marshal(blocks)   //json 压缩前 5859
	fmt.Println("查看时间",time.Since(t))

	if err!=nil{
		log.Fatal("出错")
	}
	_, err3 := writer.Write(toBytes)
	if err3!=nil{
		log.Fatal("出错1")
	}
	writer.Flush()
	fmt.Println("压缩后的长度",buff.Len(),"压缩前",len(toBytes))
	fmt.Println("查看时间1",time.Since(t))

	reader, err1 := gzip.NewReader(&buff)
	if err1!=nil{
		log.Fatal("出错2")
	}
	//all:=make([]byte,len(toBytes))
	//reader.Read(all)
	all,_:=ioutil.ReadAll(reader)
	//if err!=nil{
	//	fmt.Println(err)
	//}
	fmt.Println(len(all))

	var block1 []*types.Block
	//var block2 []*types.Block
	rlp.DecodeBytes(all,&block1)
	//json.Unmarshal(toBytes,&block1)
	fmt.Println("rlp区块长度",len(block1),"rlp",len(toBytes),"经过时间",time.Since(t))
	//fmt.Println("json区块长度",len(block2),"json",len(toBytes1))

}

