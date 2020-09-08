package quorum

import (
	"fmt"
	"CRD-chain/common"
	"testing"
)

func TestPrepareQuorum_SetPrepareQuorum(t *testing.T) {
	quorum := newPrepareQuorum()

	c:=common.HexToHash("aaa123456789")
	//d:=common.HexToAddress("123")
	//d2:=common.HexToAddress("456")
	//d3:=common.HexToAddress("789")

	//quorum.SetPrepareQuorum(c,d,nil)
	//quorum.SetPrepareQuorum(c,d2,nil)
	//quorum.SetPrepareQuorum(c,d3,nil)

	sets1, ok := quorum.GetPrepareQuorum(c, nil)
	if !ok{
		fmt.Println("WER")
	}
	fmt.Println("ssss",sets1)

	set:=quorum.SortPrepareQuorum(c,nil)
	//
	//
	fmt.Println("测试",set)
	sets, _ := quorum.GetPrepareQuorum(c, nil)
	fmt.Println("ssss",sets)
}

func TestUpdateQuorum_CalculateNextUpdateHeight(t *testing.T) {
	UpdateQuorums:=NewUpdateQuorum()
	c:=common.HexToHash("00012345123f")
	fmt.Println(c.String())
	UpdateQuorums.CalculateNextUpdateHeight(c)
	fmt.Println(UpdateQuorums.NextUpdateHeight)
	f:=common.HexToHash("00012345123f")
	UpdateQuorums.CalculateNextAfterHeight(f)
	fmt.Println(UpdateQuorums.NextUpdateHeight)



}
