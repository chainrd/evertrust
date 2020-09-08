package engine

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"CRD-chain/common"
	"CRD-chain/crypto"
	"testing"
)

func TestCommitHeight2NodeDetailSet_Keys(t *testing.T) {
	eNode := "04d173890122ba3066b1d20c185c65555861b7de30066c6dc854cf6cb903d6b64223908d06053eddd9b0ccb87a87754dccd5aa0128b7e02a73efa8354bcca4bf31"
	buff, err := hex.DecodeString(eNode)
	t.Log(err, buff)
	x, y := elliptic.Unmarshal(crypto.S256(), buff)
	pub := new(ecdsa.PublicKey)
	pub.X = x
	pub.Y = y
	pub.Curve = crypto.S256()
	t.Log("x=", x, " ; y=", y)
	t.Log(pub)

	addr := crypto.PubkeyToAddress(*pub)
	t.Log(addr.Hex())

}

func Testevertrust_SetEventMux(t *testing.T) {
	var commitBlocksPath []common.Hash //标准
	var ExtraBlocks []common.Hash      //额外
	var BlockPath []common.Hash        //输入
	var kind int
	commitBlocksPath = append(commitBlocksPath, common.HexToHash("1"))
	commitBlocksPath = append(commitBlocksPath, common.HexToHash("2"))
	commitBlocksPath = append(commitBlocksPath, common.HexToHash("3"))
	commitBlocksPath = append(commitBlocksPath, common.HexToHash("4"))

	BlockPath = append(BlockPath, common.HexToHash("1"))
	BlockPath = append(BlockPath, common.HexToHash("2"))
	BlockPath = append(BlockPath, common.HexToHash("2"))
	BlockPath = append(BlockPath, common.HexToHash("4"))
	BlockPath = append(BlockPath, common.HexToHash("4"))

	switch {
	case len(commitBlocksPath) == len(BlockPath):
		kind = 1
	case len(commitBlocksPath) < len(BlockPath):
		kind = 2
	}

	for i, blockHash := range BlockPath {
		//sBlockHash 是选出来3/2标准的
		if i < len(commitBlocksPath) {
			sBlockHash := commitBlocksPath[i]
			if sBlockHash != blockHash {
				//得到跟标准blockPath不同的区块hash下标,并且把从这个区块开始后面所有的区块都保存起来
				//把每个节点BlockPath比共识的BlockPath多余的部分保存在condensedEvidence.ExtraBlocks中
				ExtraBlocks = BlockPath[i:]
				break
			}
		} else {
			ExtraBlocks = BlockPath[i:]
			break
		}
	}
	fmt.Println("ExtraBlocks", "ExtraBlocks", ExtraBlocks)

	total := make([]common.Hash, 0)

	//恢复每个节点的path  多余的区块Hash+标准的BlockPath
	if kind == 1 && len(ExtraBlocks) != 0 {
		total = append(commitBlocksPath[:len(commitBlocksPath)-len(ExtraBlocks)], ExtraBlocks...)
	}
	if kind == 2 {

		total = append(commitBlocksPath, ExtraBlocks...)
	}
	if len(ExtraBlocks) == 0 {

		total = commitBlocksPath
	}

	////恢复每个节点的path  标准的BlockPath-多的blockpath
	//condensedEvidenceMap := make(map[common.Hash]int, 0)
	//for _, v := range ExtraBlocks {
	//	condensedEvidenceMap[v] = 1
	//}
	//
	//for _, v := range BlockPath {
	//	if _, find := condensedEvidenceMap[v]; find {
	//		continue
	//	}
	//	total = append(total, v)
	//}
	fmt.Println("total", total)
}

func TestAssertCache_Del(t *testing.T) {

	a := []string{"2", "2"}
	b := []string{"1", "1"}

	i := copy(b, a)

	fmt.Println(b, i)

}
