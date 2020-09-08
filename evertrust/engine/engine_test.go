package engine

import (
	"encoding/json"
	"fmt"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/evertrust/types"
	"CRD-chain/evertrust/utils"
	"testing"
)

func TestHalfReward(t *testing.T) {
	bns := []*big.Int{
		big.NewInt(1),
		big.NewInt(1500000),
		big.NewInt(3000000),
		big.NewInt(3000001),
		big.NewInt(4000003),
		big.NewInt(9000000),
		big.NewInt(9000001),
		big.NewInt(10000003),
		big.NewInt(27000000),
		big.NewInt(27000001),
		big.NewInt(37000001),
		big.NewInt(45000000),
		big.NewInt(45000001),
		big.NewInt(55000001),
		big.NewInt(63000000),
		big.NewInt(103000000),
	}

	for _, bn := range bns {
		halfN := HalfReward(bn)
		r := big.NewInt(0).Div(FrontierBlockReward, big.NewInt(halfN))
		fmt.Println(bn.String(), "--->", r.String(), "======", FrontierBlockReward, "--->", halfN)
	}
}

func TestBlockpath(t *testing.T) {
	type AssertionCase struct {
		Addr          string
		assertionInfo interface{}
	}
	var assertions *utils.SafeSet
	assertions = utils.NewSafeSet()
	assertionCases := []AssertionCase{
		{"0x044F2993a2327a8ff49B3f6132a1771246eFE611",
			&AssertInfo{AssertExtra: &types.AssertExtra{
				BlockPath: []common.Hash{
					common.HexToHash("0x1"), common.HexToHash("0x2"), common.HexToHash("0x3"), common.HexToHash("0x4"), common.HexToHash("0x5"),
				}}}},
		{"0x044F2993a2327a8ff49B3f6132a1771246eFE612",
			&AssertInfo{AssertExtra: &types.AssertExtra{
				BlockPath: []common.Hash{
					common.HexToHash("0x1"), common.HexToHash("0x2"), common.HexToHash("0x3"), common.HexToHash("0x4"), common.HexToHash("0x5"),
				}}}},
		{"0x044F2993a2327a8ff49B3f6132a1771246eFE613",
			&AssertInfo{AssertExtra: &types.AssertExtra{
				BlockPath: []common.Hash{
					common.HexToHash("0x1"), common.HexToHash("0x2"), common.HexToHash("0x333"), common.HexToHash("0x444"), common.HexToHash("0x555"),
				}}}},
		//{"0x044F2993a2327a8ff49B3f6132a1771246eFE614",
		//	&AssertInfo{AssertExtra: &types.AssertExtra{
		//		BlockPath: []common.Hash{
		//			common.HexToHash("0x1"), common.HexToHash("0x2"), common.HexToHash("0x3"), common.HexToHash("0x4"), common.HexToHash("0x5"),
		//		}}}},
		//{"0x044F2993a2327a8ff49B3f6132a1771246eFE615",
		//	&AssertInfo{AssertExtra: &types.AssertExtra{
		//		BlockPath: []common.Hash{
		//			common.HexToHash("0x1"), common.HexToHash("0x2"),common.HexToHash("0x3"), common.HexToHash("0x4"), common.HexToHash("0x5"),
		//		}}}},
		//{"0x044F2993a2327a8ff49B3f6132a1771246eFE616",
		//	&AssertInfo{AssertExtra: &types.AssertExtra{
		//		BlockPath: []common.Hash{
		//			common.HexToHash("0x1"), common.HexToHash("0x2"), common.HexToHash("0x3"), common.HexToHash("0x4"), common.HexToHash("0x5"),
		//		}}}},
	}

	for _, c := range assertionCases {
		assertions.Add(c.Addr, c.assertionInfo)
	}
	Cnfw.SetInt64(5)
	bp := blockPath(assertions, 2)

	blockPathMap := map[common.Hash]string{
		common.HexToHash("0x1"): "0x1",
		common.HexToHash("0x2"): "0x2",
		common.HexToHash("0x3"): "0x3",
		common.HexToHash("0x4"): "0x4",
		common.HexToHash("0x5"): "0x5",
	}

	for _, v := range bp {
		a, ok := blockPathMap[v]
		if !ok {
			t.Fatal("no exist in map", "hash", v.String())
		}

		t.Log("---------->", a)
	}

	bpB, err := json.Marshal(bp)
	if err != nil {
		t.Fatal("json marshal", "err", err)
	}
	t.Log("block path", "=============", string(bpB))

}
