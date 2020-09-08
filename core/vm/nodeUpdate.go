package vm

import (
	"CRD-chain/common"
	"CRD-chain/CRDcc/conf"
	"sync"
)

const (
	consensus1 = 0
	observer   = 1
)

type NodeUpdate struct {
}

type ConsensusNodeUpdate struct {
	NodeType     int              `json:"nodeType"` //consensus=0 ,observer=1
	FromChainID  uint64           `json:"fromChainID"`
	ToChainID    uint64           `json:"toChainID"`
	Cert         string           `json:"cert"`
	Address      []common.Address `json:"address"`
	CommitHeight uint64           `json:"commitHeight"`
	NuAdmCrt     string           `json:"nuAdmCrt"`
}

//
//type NodeInfo struct {
//	Address      []common.Address
//	CommitHeight uint64
//}

func (n *NodeUpdate) RequiredGas(input []byte) uint64 {
	return 0
}

func (n *NodeUpdate) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	if len(extra[conf.TxEstimateGas]) > 0 {
		return nil, nil
	}
	//db := ethdb.ChainDb
	//consensusNodeUpdate := ConsensusNodeUpdate{}
	//json.Unmarshal(input, &consensusNodeUpdate)
	//log.Info("consensusNodeUpdate的信息", "address", consensusNodeUpdate.Address[0].String(), "加入到高度", consensusNodeUpdate.CommitHeight)
	//if consensusNodeUpdate.ToChainID == 739739 { //预估gaslimit直接退出,不往下执行
	//	return nil, nil
	//}
	//from := ctx.Contract.CallerAddress
	//log.Info("from.Hex()","from.Hex()",from.Hex(),"from",from,"hex",common.HexToAddress("0x485e2aaf37dfb76baa36b236b121fd97cc0affe1").Hex())
	//if from.Hex() != common.HexToAddress("0x485e2aaf37dfb76baa36b236b121fd97cc0affe1").Hex() {
	//	return nil, nil
	//}
	////commitHeight := consensusNodeUpdate.CommitHeight
	//commitHeight := public.BC.CurrentCommit().NumberU64()
	////for _, address := range consensusNodeUpdate.Address {
	////	commitQuorum, ok := quorum.CommitHeightToConsensusQuorum.Get(commitHeight, *db)
	////	if !ok {
	////		commitQuorum = quorum.NewNodeAddress()
	////	} else {
	////		commitQuorum.Add(address.Hex(), address)
	////	}
	////	for i := 0; i < int(qualification.ActiveDistant)+1; i++ {
	////		//nodeDetails, ok := qualification.CommitHeight2NodeDetailSetCache.Dup(commitHeight-uint64(i), *db)
	////		//if !ok {
	////		//	nodeDetails = qualification.NewNodeSet()
	////		//	nodeDetails.Add(address.Hex(), &qualification.NodeDetail{Address: address})
	////		//} else {
	////		//	minerDetail := nodeDetails.Get(address.Hex())
	////		//	if minerDetail == nil {
	////		//		nodeDetails.Add(address.Hex(), &qualification.NodeDetail{Address: address})
	////		//	}
	////		//}
	////		//nodeAddDetail := nodeDetails.Get(address.Hex())
	////		//nodeAddDetail.NumAssertionsAccepted++
	////		//nodeAddDetail.NumAssertionsTotal++
	////		//nodeDetails.Add(address.Hex(), nodeAddDetail)
	////		//qualification.CommitHeight2NodeDetailSetCache.Set(commitHeight-uint64(i), nodeDetails, *db)
	////		quorum.CommitHeightToConsensusQuorum.Set(commitHeight+uint64(i), commitQuorum, *db)
	////		nodeAddress, _ := quorum.CommitHeightToConsensusQuorum.Get(commitHeight+uint64(i), *db)
	////		log.Info("consensusNodeUpdate加入完成目前成员有", "成员", nodeAddress.KeysOrdered(), "高度", commitHeight)
	////	}
	//
	//NodeMap = NewNodeUpdateMap()
	//for _, address := range consensusNodeUpdate.Address {
	//	NodeMap.SetAddr(address, commitHeight+1)
	//
	//}

	return nil, nil
}

type NodeUpdateMap struct {
	NuMap map[uint64][]common.Address
	Lock  sync.RWMutex
}

var NodeMap *NodeUpdateMap

func NewNodeUpdateMap() *NodeUpdateMap {
	return &NodeUpdateMap{NuMap: make(map[uint64][]common.Address)}
}

func (n *NodeUpdateMap) SetAddr(add common.Address, height uint64) {
	n.Lock.Lock()
	defer n.Lock.Unlock()
	NodeMap.NuMap[height] = append(NodeMap.NuMap[height], add)

}

func (n *NodeUpdateMap) GetAddr(height uint64) []common.Address {
	n.Lock.Lock()
	defer n.Lock.Unlock()
	return NodeMap.NuMap[height]

}

func (n *NodeUpdateMap) QueryAddr(height uint64) bool {
	n.Lock.RLock()
	defer n.Lock.RUnlock()
	if _, ok := NodeMap.NuMap[height]; ok {
		return true
	}
	return false
}
