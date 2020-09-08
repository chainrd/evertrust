package vm

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"CRD-chain/common"
	public "CRD-chain/core/publicBC"
	"CRD-chain/log"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/CRDcc/util"
	"CRD-chain/rlp"
)

type TrustTree struct{}

type TrustTxData struct {
	PreTrustChainID     string      `json:"preTrustChainID"` // pre under layer trust chain ID
	CurTrustChainID     string      `json:"curTrustChainID"` // cur under layer trust chain ID
	CommitBlockNo       uint64      `json:"commitBlockNo"`
	CommitBlockHash     common.Hash `json:"commitBlockHash"`
	PrevCommitBlockHash common.Hash `json:"prevCommitBlockHash"`
	NodeAddress         string      `json:"nodeAddress"`
}

type TrustTxInfo struct {
	Datas []TrustTxData
	ChainId string
}

func (x *TrustTree) RequiredGas(input []byte) uint64 {
	return 0
}

func (x *TrustTree) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	// used for estimating gas
	if extra[conf.TxEstimateGas] != nil {
		return nil, nil
	}

	log.Info("trust tree precompile contract run")

	var info TrustTxInfo
	err := rlp.DecodeBytes(input, &info)
	if err != nil {
		log.Error("rlp decode payload", "err", err)
		return nil, err
	}

	if info.ChainId == "" {
		log.Error("cjhain id empty")
		return nil, errors.New("cjhain id empty")
	}

	curCommitBlock := public.BC.CurrentCommit()
	var commitBlockNum *big.Int
	if curCommitBlock == nil {
		log.Error("commit block is nil")
		commitBlockNum = big.NewInt(0)
	}else {
		commitBlockNum = curCommitBlock.Number()
	}

	if ctx.Evm.chainConfig.IsContractUIP1(commitBlockNum) {
		log.Info("into UIP1", "num", ctx.Evm.Header.Number.Uint64())
		for _, txData := range info.Datas {
			//maxNum
			var maxNum *big.Int
			maxNumKey := fmt.Sprintf("%s-trustTransactionHeight", info.ChainId)
			maxNumKeyHash := util.EthHash([]byte(maxNumKey + conf.CRDKeyFlag))
			maxNumSt := ctx.Evm.StateDB.GetCRDState(ctx.Contract.Address(), maxNumKeyHash)

			log.Info("trust tx data info", "chainID", info.ChainId, "pre TC chainID", txData.PreTrustChainID,
				"cur TC chainID", txData.CurTrustChainID, "block hash", txData.CommitBlockHash, "block num", txData.CommitBlockNo)
			if len(maxNumSt) > 0 {
				maxNum = big.NewInt(0).SetBytes(maxNumSt)
				log.Info("block num", "chainID", info.ChainId, "maxNum", maxNum, "payload", txData.CommitBlockNo)
				//判断块号是否连续
				if new(big.Int).Add(maxNum, big.NewInt(1)).Cmp(new(big.Int).SetUint64(txData.CommitBlockNo)) == 0 {
					commits := getHash(ctx, info.ChainId, maxNum.Uint64())
					cts, _ := json.Marshal(commits)
					log.Info("compare pre commit block hash", "pre", txData.PrevCommitBlockHash, "cur", string(cts))
					continuous := false
					for _, v := range commits {
						if txData.PrevCommitBlockHash == v {
							setHashAndNumber(ctx, info.ChainId, txData.CommitBlockNo, txData.CommitBlockHash, maxNumKeyHash)
							continuous = true
							break
						}
					}

					if !continuous {
						//hash 不连续
						log.Warn("block hash not continuous")
					}

				} else {
					if new(big.Int).Add(maxNum, big.NewInt(1)).Cmp(new(big.Int).SetUint64(txData.CommitBlockNo)) > 0 {
						//回滚
						commits := getHash(ctx,info.ChainId, txData.CommitBlockNo-1)
						if len(commits) == 0 {
							log.Info("roll-back to origin", "num", txData.CommitBlockNo)
							setHashAndNumber(ctx, info.ChainId, txData.CommitBlockNo, txData.CommitBlockHash, maxNumKeyHash)
						}else {
							cts, _ := json.Marshal(commits)
							log.Info("roll-back compare pre commit block hash", "pre", txData.PrevCommitBlockHash, "cur", string(cts))
							continuous := false
							for _, v := range commits {
								if v == txData.PrevCommitBlockHash {
									setHashAndNumber(ctx, info.ChainId, txData.CommitBlockNo, txData.CommitBlockHash, maxNumKeyHash)
									continuous = true
									break
								}
							}

							if !continuous {
								log.Warn("roll-back: block hash not continuous")
							}
						}

					} else {
						//块号过大
						log.Warn("block number too big")
					}
				}

			} else {
				//第一次存储
				log.Info("max num empty", "num", maxNumSt)
				setHashAndNumber(ctx, info.ChainId, txData.CommitBlockNo, txData.CommitBlockHash, maxNumKeyHash)
			}

		}
	}else {
		for _, txData := range info.Datas {
			//maxNum
			var maxNum *big.Int
			maxNumKey := fmt.Sprintf("%s-trustTransactionHeight", info.ChainId)
			maxNumKeyHash := util.EthHash([]byte(maxNumKey + conf.CRDKeyFlag))
			maxNumSt := ctx.Evm.StateDB.GetCRDState(ctx.Contract.Address(), maxNumKeyHash)

			log.Info("trust tx data info", "chainID", info.ChainId, "pre TC chainID", txData.PreTrustChainID,
				"cur TC chainID", txData.CurTrustChainID, "block hash", txData.CommitBlockHash, "block num", txData.CommitBlockNo)
			if len(maxNumSt) > 0 {
				maxNum = big.NewInt(0).SetBytes(maxNumSt)
				log.Info("block num", "chainID", info.ChainId, "maxNum", maxNum, "payload", txData.CommitBlockNo)
				//判断块号是否连续
				if new(big.Int).Add(maxNum, big.NewInt(1)).Cmp(new(big.Int).SetUint64(txData.CommitBlockNo)) == 0 {
					commits := getHash(ctx, info.ChainId, maxNum.Uint64())
					cts, _ := json.Marshal(commits)
					log.Info("compare pre commit block hash", "pre", txData.PrevCommitBlockHash, "cur", string(cts))
					for _, v := range commits {
						if txData.PrevCommitBlockHash == v {
							setHashAndNumber(ctx, info.ChainId, txData.CommitBlockNo, txData.CommitBlockHash, maxNumKeyHash)
							return nil, nil
						}
					}

					//hash 不连续
					log.Warn("block hash not continuous")

				} else {
					if new(big.Int).Add(maxNum, big.NewInt(1)).Cmp(new(big.Int).SetUint64(txData.CommitBlockNo)) > 0 {
						//回滚
						commits := getHash(ctx,info.ChainId, txData.CommitBlockNo-1)
						if len(commits) == 0 {
							log.Info("roll-back to origin", "num", txData.CommitBlockNo)
							setHashAndNumber(ctx, info.ChainId, txData.CommitBlockNo, txData.CommitBlockHash, maxNumKeyHash)
							return nil, nil
						}

						cts, _ := json.Marshal(commits)
						log.Info("roll-back compare pre commit block hash", "pre", txData.PrevCommitBlockHash, "cur", string(cts))
						for _, v := range commits {
							if v == txData.PrevCommitBlockHash {
								setHashAndNumber(ctx, info.ChainId, txData.CommitBlockNo, txData.CommitBlockHash, maxNumKeyHash)
								return nil, nil
							}
						}

						log.Warn("roll-back: block hash not continuous")

					} else {
						//块号过大
						log.Warn("block number too big")
					}
				}

			} else {
				//第一次存储
				log.Info("max num empty", "num", maxNumSt)
				setHashAndNumber(ctx, info.ChainId, txData.CommitBlockNo, txData.CommitBlockHash, maxNumKeyHash)
			}

		}
	}

	return nil, nil
}

func setHashAndNumber(ctx *PrecompiledContractContext, chainID string, commitBlockNumber uint64,
	commitBlockHash common.Hash, maxNumKeyHash common.Hash) {
	//set commit hash
	setHash(ctx, chainID, commitBlockNumber, commitBlockHash)

	//maxNum
	ctx.Evm.StateDB.SetCRDState(ctx.Contract.Address(), maxNumKeyHash, new(big.Int).SetUint64(commitBlockNumber).Bytes())
}

func setHash(ctx *PrecompiledContractContext, chainID string, commitBlockNumber uint64, commitBlockHash common.Hash) {
	//commit block hash
	commitBlockKeyHash := genCommitBlockKeyHash(chainID, commitBlockNumber)

	//get commit block hash
	commits := getHash(ctx, chainID, commitBlockNumber)
	for _, v := range commits {
		if v == commitBlockHash {
			log.Warn("hash already exist")
			return
		}
	}
	commits = append(commits, commitBlockHash)
	commitsB, err := json.Marshal(commits)
	if err != nil {
		log.Error("json m commitsB", "err", err)
		return
	}

	ctx.Evm.StateDB.SetCRDState(ctx.Contract.Address(), commitBlockKeyHash, commitsB)
}

func getHash(ctx *PrecompiledContractContext, chainID string, commitBlockNumber uint64) []common.Hash {
	//commit block hash
	commitBlockKeyHash := genCommitBlockKeyHash(chainID, commitBlockNumber)

	var commits []common.Hash
	res := ctx.Evm.StateDB.GetCRDState(ctx.Contract.Address(), commitBlockKeyHash)
	if len(res) > 0 {
		err := json.Unmarshal(res, &commits)
		if err != nil {
			log.Error("json unm commits", "err", err)
			return nil
		}
	}

	return commits
}

func genCommitBlockKeyHash(chainID string, commitBlockNumber uint64) common.Hash {
	//commit block hash
	commitBlockKey := fmt.Sprintf("%s:%d", chainID, commitBlockNumber)
	commitBlockKeyHash := util.EthHash([]byte(commitBlockKey + conf.CRDKeyFlag))

	return commitBlockKeyHash
}