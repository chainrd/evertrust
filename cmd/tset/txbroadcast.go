package main

import (
	"fmt"
	"math"
)

func main() {

	var transfer []string
	var peers []string
	peers = append(peers, "1")
	peers = append(peers, "2")
	peers = append(peers, "3")
	peers = append(peers, "4")
	peers = append(peers, "5")
	//peers = append(peers, "5")
	//peers = append(peers, "6")
	//peers = append(peers, "7")
	//peers = append(peers, "8")
	//peers = append(peers, "9")

	switch {
	case len(peers) <= 4:
		// peer列表小于等于4 全部广播
		transfer = peers
	default:
		var filter []string
		//查询当前高度委员会,peer列表大于4 过滤委员会
		consensusQuorum := make(map[string]string)
		consensusQuorum["1"] = "1"
		consensusQuorum["2"] = "2"
		consensusQuorum["3"] = "3"
		consensusQuorum["4"] = "4"
		consensusQuorum["5"] = "5"
		for _, peer := range peers {
			if _, ok := consensusQuorum[peer]; ok {
				transfer = append(transfer, peer)
			} else {
				filter = append(filter, peer)
			}
		}
		fmt.Println("transfer",transfer)
		fmt.Println("filter",filter)
		switch {
		case len(transfer) < 4:
			//过滤后小于4  补齐4个后广播
			fmt.Println("第一步")
			for i := 0; len(transfer) < 4; i++ {
				transfer = append(transfer, filter[i])
			}
		case len(transfer) > 16:
			fmt.Println("第二步")

			//过滤后大于16 按照平方根发送发
			transfer = transfer[:int(math.Sqrt(float64(len(transfer))))]

		default:
			//过滤后大于4 小于16  按4个随机广播
			fmt.Println("第三步")

			transfer = peers[:4]

		}

	}

	fmt.Println("结束",transfer)

}
