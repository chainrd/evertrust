package public

import (
	"CRD-chain/core/types"
)

var BC PublicBlockChain

type PublicBlockChain interface {
	CurrentCommit() *types.Block
	CurrentBlock() *types.Block
	GetBlockByNumber(number uint64) *types.Block
	GetCommitBlock(height uint64) *types.Block

}
