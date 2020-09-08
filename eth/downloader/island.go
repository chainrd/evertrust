package downloader

import (
	"CRD-chain/log"
	"CRD-chain/CRDcc/util"
	"CRD-chain/evertrust/types"
	"CRD-chain/evertrust/utils"
	"time"
)

func (d *Downloader) IslandVersion(newCommitExtra types.CommitExtra, id string) bool {
	//查看岛屿版本号是否和自己相同
	currentBlock := d.Commitchain.CurrentBlock()
	_, currentCommitExtra := types.CommitExtraDecode(currentBlock)
	if currentCommitExtra.Version == newCommitExtra.Version {
		log.Info("版本号相同")
		return true
	}

	if currentCommitExtra.Island && newCommitExtra.Version > currentCommitExtra.Version {
		log.Info("新来commit比本地版本高")
		p := d.peers.Peer(id)
		p.peer.RequestIsland() //请求岛屿信息
		timeout := time.NewTimer(3 * time.Second)
		for {
			select {

			case blocks := <-d.IslandCH:
				if len(blocks) != int(newCommitExtra.Version) {
					//版本号要和更新交易的区块数量相同
					return false
				}
				//收到带有restoreLand的交易的区块 验证to
				sum := 0
				for _, block := range blocks {
					for _, transaction := range block.Transactions() {
						if *transaction.To() == util.EthAddress(utils.QuorumReset) {
							//todo 验证from
							sum++
						}

					}
				}
				//每升级一个版本需要2/3的RestoreLandAddr数量
				if sum >= int(newCommitExtra.Version)*len(d.Worker.Evertrust().Config().QuorumResetAccounts)*2/3 {
					//验证数量到达 验证成功
					return true
				}

			case <-timeout.C:
				//超时直接返回false
				return false

			}
		}
	}

	return false
}
