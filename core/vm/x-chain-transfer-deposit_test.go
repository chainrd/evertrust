package vm

import (
	"CRD-chain/params"
	"testing"
)

func TestInpointsChainConfig(t *testing.T) {
	//pointsChain := []params.pointsChain{
	//	{ChainId:"123", RpcHosts:[]string{"a", "b", "c"}},
	//	{ChainId:"456", RpcHosts:[]string{}},
	//	{ChainId:"789", RpcHosts:[]string{"a", "b"}},
	//	{ChainId:"abn", RpcHosts:[]string{"a"}},
	//	{ChainId:"ddd", RpcHosts:[]string{"a", "b", "d"}},
	//}

	pointsChain2 := []params.pointsChain{}
	chainID := "dsfgr"
	in := inpointsChainConfig(pointsChain2, chainID)
	t.Log("----------", in)
}
