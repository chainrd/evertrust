package workBlock

import (
	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/log"
	"sync"
)
var WorkBlockData WorkBlock

//当前正在处理的block
type WorkBlock struct {

	Num uint64
	Hash common.Hash

	lock sync.RWMutex
}

func (w *WorkBlock) AddBlockData(block *types.Block)  {
	w.lock.Lock()
	defer w.lock.Unlock()
	w.Num=block.NumberU64()
	w.Hash=block.Hash()
}

func (w *WorkBlock) VerifyBlockData(block *types.Block) bool {
	w.lock.RLock()
	defer w.lock.RUnlock()
	if w.Hash == block.ParentHash()&&w.Num==block.NumberU64()-1{
		log.Info("正在处理父区块,不需要同步")
		return true
	}else if (w.Num > block.NumberU64()) {
		return true
	}
	log.Info("开始进行同步","当前正在处理高度",w.Num,"收到的高度",block.NumberU64())
	return false
}






