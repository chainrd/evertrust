package engine

import (
	"CRD-chain/common"
	core_types "CRD-chain/core/types"
	"CRD-chain/ethdb"
	"CRD-chain/log"
	"CRD-chain/quorum"
	"CRD-chain/evertrust/engine/qualification"
	"CRD-chain/evertrust/types"
)

func UpdateConsensusQuorum(w *evertrustWorker, commitExtra *types.CommitExtra, block *core_types.Block) bool {
	//更新活跃度
	commitHeight := block.NumberU64()

	currentCommit := w.blockchain.CommitChain.GetBlockByNum(block.NumberU64() - 1)
	var currentCommitHeight uint64
	if currentCommit != nil {
		currentCommitHeight = currentCommit.NumberU64()
	} else {
		currentCommitHeight = 0
	}
	//更新委员会
	quorumAdditions := commitExtra.MinerAdditions
	commitHash := block.Hash()
	switch {
	case currentCommitHeight == 0:
		//第一次更新委员会
		firstMinerAdditions(quorumAdditions, w, commitHeight)
	case currentCommitHeight <= quorum.LessCommit || PerQuorum:
		log.Info("查询PerQuorum的数据", "PerQuorum", PerQuorum)
		//commit高度小于100,每次都更新委员会
		if !lessMinerAdditions(quorumAdditions, w, commitHeight, commitExtra) {
			log.Error("lessMinerAdditions fail")
			return false
		}
		if currentCommitHeight == quorum.LessCommit && quorum.UpdateQuorums.HistoryUpdateHeight.Uint64() == 0 &&
			!PerQuorum {
			//下次更新委员会的高度
			quorum.UpdateQuorums.CalculateNextUpdateHeight(commitHash,block,UIP1)
			quorum.UpdateQuorums.CalculateNextAfterHeight(commitHash)
			quorum.UpdateQuorums.HistoryUpdateHeight = block.Number()
			if !quorum.UpdateQuorumSnapshots.SetUpdateQuorum(quorum.UpdateQuorums, w.evertrust1.db) {
				log.Error("UpdateQuorums.SetUpdateQuorum fail")
				return false
			}
			log.Info("开发模式关闭", "下次更新高度", quorum.UpdateQuorums.NextUpdateHeight)
		}
	default:
		//commit高度大于100,按照新规则进行更新委员会列表
		//增加委员会列表成员

		currentQuorum, ok := quorum.CommitHeightToConsensusQuorum.Get(commitHeight-1, w.evertrust1.db)
		if !ok {
			log.Error("quorum.CommitHeightToConsensusQuorum fail")
			return false
		}

		currentQuorumCopy := currentQuorum.Copy()
		//清理失去资格的委员会成员

		currentQuorumCopy = delConsensusQuorum(currentQuorumCopy, w, commitHeight, commitExtra.MinerDeletions)

		quorum.CommitHeightToConsensusQuorum.Set(commitHeight, currentQuorumCopy, w.evertrust1.db)

		log.Info("下次更新高度", "下次的高度", quorum.UpdateQuorums.NextUpdateHeight,
			"block.Number()", block.Number())

		if block.Number().Cmp(quorum.UpdateQuorums.NextUpdateHeight) == 0 || block.Number().Cmp(UIP1) == 0 {
			set := quorum.SortPrepareQuorum(commitExtra.MinerAdditions, commitHash, w.evertrust1.db)
			log.Info("开始更新本地委员会", "更新高度", quorum.UpdateQuorums.NextUpdateHeight)

			if set != nil {
				for _, add := range set {
					currentQuorumCopy.Add(add.String(), add)
				}
				//更新当前高度委员会
				quorum.CommitHeightToConsensusQuorum.Set(commitHeight, currentQuorumCopy, w.evertrust1.db)
			}
		}
	}

	return true
}

func UpdateQuorumsHeight(block *core_types.Block, db ethdb.Database) bool {
	if block.Number().Cmp(quorum.UpdateQuorums.NextUpdateHeight) == 0 || block.Number().Cmp(UIP1) == 0 {
		//如果到了更新委员会的
		quorum.UpdateQuorums.CalculateNextUpdateHeight(block.Hash(),block,UIP1)
		quorum.UpdateQuorums.CalculateNextAfterHeight(block.Hash())
		quorum.UpdateQuorums.HistoryUpdateHeight = block.Number()
		if !quorum.UpdateQuorumSnapshots.SetUpdateQuorum(quorum.UpdateQuorums, db) {
			log.Error("UpdateQuorums.SetUpdateQuorum fail")
			return false
		}
	}
	log.Info("开始储存", "下次更新高度", quorum.UpdateQuorums.NextUpdateHeight,
		"本次更新高度", quorum.UpdateQuorums.HistoryUpdateHeight)
	return true
}

func firstMinerAdditions(quorumAdditions []common.Address, w *evertrustWorker, commitHeight uint64) {
	// recv'd first commit block after genesis commit block
	var commitQuorum = quorum.NewNodeAddress()
	if len(quorumAdditions) > 0 {
		for _, address := range quorumAdditions {
			commitQuorum.Add(address.Hex(), address)
		}
	}
	quorum.CommitHeightToConsensusQuorum.Set(commitHeight, commitQuorum, w.evertrust1.db)
}

func lessMinerAdditions(quorumAdditions []common.Address, w *evertrustWorker, commitHeight uint64, commitExtra *types.CommitExtra) bool {
	preCommitHeight := commitHeight - 1
	if preCommitHeight == 0 {
		preCommitHeight = 1
	}
	// retrieve previous node set
	// ignore genesisCommitBlock
	currentQuorum, ok := quorum.CommitHeightToConsensusQuorum.Get(preCommitHeight, w.evertrust1.db)
	if !ok {
		// the current commit block does NOT have quorum
		return false
	} else {
		commitQuorum := currentQuorum.Copy()
		// combine (add/delete)
		delConsensusQuorum(commitQuorum, w, commitHeight, commitExtra.MinerDeletions)

		if len(quorumAdditions) > 0 {
			for _, address := range quorumAdditions {
				commitQuorum.Add(address.Hex(), address)
			}
		}
		quorum.CommitHeightToConsensusQuorum.Set(commitHeight, commitQuorum, w.evertrust1.db)

	}
	return true
}

//TODO - 替换方法
func delConsensusQuorum(currentQuorum *quorum.NodeAddress, w *evertrustWorker, commitHeight uint64, quorumDeletions []common.Address) *quorum.NodeAddress {
	//删除委员会,并且清理活跃度
	if len(quorumDeletions) > 0 {
		for _, address := range quorumDeletions {
			currentQuorum.Del(address.Hex())
			currentHeightNodeDetails, ok := qualification.CommitHeight2NodeDetailSetCache.Get(commitHeight, w.evertrust1.db)
			if ok {
				nodeDetail := currentHeightNodeDetails.Get(address.Hex())
				if nodeDetail != nil {
					log.Info("delConsensusQuorum--清理nodeDetail", "reason", nodeDetail.DisqualifiedReason)
					if nodeDetail.DisqualifiedReason == qualification.EmptyString {
						nodeDetail = qualification.CleanUpNodeDetailInfo(nodeDetail, commitHeight, qualification.ExitOnHisOwn+qualification.ShouldStacking)
					}
					currentHeightNodeDetails.Add(address.String(), nodeDetail)
					qualification.CommitHeight2NodeDetailSetCache.Set(commitHeight, currentHeightNodeDetails, w.evertrust1.db)
				}
			}
		}
	}
	return currentQuorum

}
