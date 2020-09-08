package main

import (
	"container/list"
	"fmt"
	"CRD-chain/common"
	"time"
)

func main() {

	t:=time.Now()
	var blockPaths [][]common.Hash

	blockPaths = append(blockPaths,[]common.Hash{common.HexToHash("1"),common.HexToHash("2"),common.HexToHash("3"),common.HexToHash("4"),common.HexToHash("5")})
	blockPaths = append(blockPaths,[]common.Hash{common.HexToHash("1"),common.HexToHash("2"),common.HexToHash("3"),common.HexToHash("4"),common.HexToHash("5")})
	blockPaths = append(blockPaths,[]common.Hash{common.HexToHash("1"),common.HexToHash("2"),})
	blockPaths = append(blockPaths,[]common.Hash{common.HexToHash("1"),common.HexToHash("2"),})
	blockPaths = append(blockPaths,[]common.Hash{common.HexToHash("1"),common.HexToHash("2"),})

	matrix := list.New()

	for _, blockpath := range blockPaths {
		matrix.PushBack(blockpath)

	}

	result := make([]common.Hash, 0)
	for i := 0; int64(i) < 5; i++ { // the block sequence in the interval
		counters := make(map[string]int, 0)

		// blockpath里第i列，对块hash进行投票，
		for row := matrix.Front(); row != nil; row = row.Next() {

			blockpath := row.Value.([]common.Hash)

			for j := 0; j < len(blockpath); j++ {
				if j == i {
					counters[blockpath[j].Hex()] += 1
					break
				}
			}
		}

		if len(counters) == 0 {
			break
		}

		var acceptedBlock string
		vote := 0

		// 某列的最大投票数
		for key, val := range counters {
			if val > vote {
				vote = val          //出现次数
				acceptedBlock = key //区块hash
			}
		}

		// 投票达到2/3多数，放入result中
		if vote >= 3 {

			result = append(result, common.HexToHash(acceptedBlock))

			//remove failed assertion paths
		//loop:
		//	for row := matrix.Front(); row != nil; row = row.Next() {
		//		blockpath := row.Value.([]common.Hash)
		//		// 对于长度不够的，删除row
		//		if i >= len(blockpath) {
		//			row0 := row
		//			row = row.Next()
		//			if row == nil {
		//				break
		//			}
		//			matrix.Remove(row0)
		//			continue
		//		}
		//
		//		// 如果某row的第i列不是acceptedBlock，就删除该row
		//		for j := 0; j < len(blockpath); j++ {
		//			if j == i {
		//				if strings.Compare(blockpath[j].Hex(), acceptedBlock) != 0 {
		//					row0 := row
		//					row = row.Next()
		//					if row == nil {
		//						break loop
		//					}
		//					matrix.Remove(row0)
		//					continue
		//				}
		//			}
		//		}
		//	}
		} else {
			fmt.Println("出现测次数不大于3/2退出", "BlockPath长度", len(result))
			break
		}
	}
	fmt.Println(result,"时间",time.Since(t))
}
