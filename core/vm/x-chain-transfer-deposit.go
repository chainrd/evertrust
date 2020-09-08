package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/common/hexutil"
	"CRD-chain/core/types"
	"CRD-chain/log"
	"CRD-chain/params"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/rlp"
	"CRD-chain/evertrust"
	"CRD-chain/evertrust/iaasconn"
	"CRD-chain/evertrust/utils"
	"CRD-chain/evertrust/utils/blacklist"
	"CRD-chain/evertrust/utils/client"
	"strings"
	"time"
)

type XChainTransferDeposit struct{}

type Deposit struct {
	SrcChainID    string         `json:"src_chain_id"`
	SrcChainOwner common.Address `json:"src_chain_owner"`
	TxMsg         string         `json:"tx_msg"`
}

func (x *XChainTransferDeposit) RequiredGas(input []byte) uint64 {
	return 0
}

func (x *XChainTransferDeposit) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	// used for estimating gas
	if extra[conf.TxEstimateGas] != nil {
		log.Info("deposit estimate gas limit")
		return nil, nil
	}

	log.Info("XChainTraXChainTransferDeposit run")

	var payload Deposit
	err := json.Unmarshal(input, &payload)
	if err != nil {
		log.Error("unmarshal payload error", "err", err)
		return nil, err
	}

	err = deposit(ctx, payload)
	if err != nil {
		log.Error("deposit error", "err", err)
		return nil, err
	}

	return nil, nil
}

func deposit(ctx *PrecompiledContractContext, payload Deposit) error {
	//check tx
	from, dstUser, dstChain, txHash, err := GenMsgFromTxMsg(payload.TxMsg)
	if err != nil {
		log.Error("gen addr from txMsg error", "err", err)
		return err
	}
	contractFrom := ctx.Contract.caller.Address()
	contractAddr := ctx.Contract.Address() //deposit contract addr
	if contractFrom != from {
		//put in blacklist
		putInStateBlacklist(ctx, contractFrom)
		return errors.New("different sender between two tx")
	}

	//确认是否已经存款成功
	keyHash := utils.DepositKeyHash(contractFrom, txHash, conf.CRDKeyFlag)
	state := ctx.Evm.StateDB.GetCRDState(contractAddr, keyHash)
	if len(state) != 0 {
		log.Error("deposit has completed, then put in blacklist")
		//put in blacklist
		putInStateBlacklist(ctx, contractFrom)
		return errors.New("deposit has completed")
	}

	//去srcChain查询withdraw的状态
	dstChains := ctx.Evm.chainConfig.Evertrust.DstChain
	vl, err := CheckWithDrawTxStatus(contractFrom, dstChains, txHash, payload.SrcChainID)
	if err != nil {
		log.Error("withDraw tx not successful", "err", err)
		return err
	}

	if ctx.Contract.value.Cmp(vl) != 0 {
		log.Error("value not match", "deposit", ctx.Contract.value, "withdraw", vl)
		return errors.New("value not match")
	}

	if dstUser == (common.Address{}) {
		dstUser = ctx.Contract.CallerAddress
	}
	log.Info("before AddBalance", "balance", ctx.Evm.StateDB.GetBalance(dstUser), "dstUser", dstUser.String())
	ctx.Evm.StateDB.AddBalance(dstUser, vl)

	value := fmt.Sprintf("%s:%s:%s:%s", payload.SrcChainID, dstChain, vl.String(), txHash.String())
	ctx.Evm.StateDB.SetCRDState(contractAddr, keyHash, []byte(value))
	log.Info("SetCRDState", "value", value)

	log.Info("after AddBalance", "balance", ctx.Evm.StateDB.GetBalance(dstUser))
	return nil
}

func GenMsgFromTxMsg(txMsg string) (from common.Address, dstUser common.Address, dstChain string, txHash common.Hash, err error) {
	txMsgBuf, err := hexutil.Decode(txMsg)
	if err != nil {
		log.Error("hex decode txMsg error", "err", err)
		return
	}
	transaction := new(types.Transaction)
	if err = rlp.DecodeBytes(txMsgBuf, transaction); err != nil {
		log.Error("rlp decode txMsg error", "err", err)
		return
	}

	var signer types.Signer = types.HomesteadSigner{}
	if transaction.Protected() {
		signer = types.NewEIP155Signer(transaction.ChainId())
	}
	if transaction.IsSM2() {
		signer = types.NewSm2Signer(transaction.ChainId())
	}
	from, _ = types.Sender(signer, transaction)
	txHash = transaction.Hash()
	withdrawPayload := Withdraw{}
	payloadBuf := transaction.Data()
	if err = json.Unmarshal(payloadBuf, &withdrawPayload); err != nil {
		log.Error("unmarshal withdraw payload error", "err", err)
		return
	}
	dstChain = withdrawPayload.DstChainID
	dstUser = withdrawPayload.DstUserAddr

	log.Debug("GenAddrAndHashFromTxMsg", "from", from, "txHash", txHash)
	return
}

//返回交易的value和交易状态
func CheckWithDrawTxStatus(contractFrom common.Address, dstChains []params.PointsChain, txHash common.Hash, chainID string) (value *big.Int, err error) {
	if !inPointsChainConfig(dstChains, chainID) {
		return nil, errors.New("chainID not in Points chain config")
	}

	proxyServer := evertrust.Config.String("blockFreeCloud")
	iaasServer := evertrust.Config.String("iaas")
	currentChainId := conf.ChainId.String()

	points := evertrust.Getpoints(evertrust.MinerPrivateKey, currentChainId, chainID, evertrust.XChainpointsType)
	var hosts []string
	log.Debug("check withdraw tx status", "proxyServer", proxyServer, "iaasServer", iaasServer, "points", points)
	if proxyServer != "" && iaasServer != "" && points != "" {
		proxyRPC := fmt.Sprintf(evertrust.ProxyRPC, chainID)
		hosts = []string{proxyRPC, proxyRPC, proxyRPC, proxyRPC, proxyRPC}//for retry
	}else {
		hosts = getNodeFromConfig(dstChains, chainID)
	}

	evertrust.Shuffle(hosts)
	count := 0 //最大尝试次数
	var cliErr error
	for _, host := range hosts {
		count++
		if count > 4 {
			log.Error("try four times fail", "count", count)
			err = fmt.Errorf("try %d times fail", count)
			break
		}

		log.Debug("host", "is", host)
		cli, err := client.Connect(host, proxyServer, points)
		if err != nil {
			log.Error("client connect error", "err", err)
			continue
		}
		c, cancel := context.WithTimeout(context.Background(), 1000*time.Millisecond)
		var transactionMsg client.WithdrawRPCTransaction
		transactionMsg, cliErr = cli.GetWithDrawTransactionByHash(c, txHash)
		cancel()
		if cliErr != nil {
			log.Error("cli error", "err", cliErr)
			continue
		}

		currentCommit := transactionMsg.CurrentCommit.ToInt()
		commitNum := transactionMsg.CommitNumber.ToInt()
		log.Info("transactionMsg", "currentCommit", currentCommit, "commitNum", commitNum, "status", transactionMsg.Status)

		if currentCommit == nil ||
			commitNum == nil ||
			new(big.Int).Sub(currentCommit, commitNum).Cmp(big.NewInt(evertrust.XChainTransferCommitNum)) == -1 ||
			transactionMsg.Status == -1 ||
			transactionMsg.Status == 0 { //withdraw fail

			//put in blacklist
			blacklist.PutIn(contractFrom)
			return nil, fmt.Errorf("tx status not successful")
		}

		return (*big.Int)(transactionMsg.RPCTx.Value), nil
	}

	if cliErr != nil && strings.Contains(cliErr.Error(), "context deadline exceeded") {
		//不打包
		return nil, ErrCliRpcTimeOut
	}

	return nil, errors.New("hosts error")

}

func getNodeFromConfig(dstChains []params.PointsChain, chainID string) []string {
	//如果配置了iaas，去iaas获取活跃节点, 如果出错，使用genesis.json的配置。
	if evertrust.Config.String("iaas") != "" {
		hosts, err := iaasconn.GetNodeFromIaas(chainID)
		if err != nil {
			log.Error("getNodeFromConfig:GetNodeFromIaas", "err", err)
		}else {
			return hosts
		}
	}

	for _, v := range dstChains {
		if v.ChainId == chainID {
			l := len(v.RpcHosts)
			if l > 0 {
				return v.RpcHosts
			} else {
				log.Error("genesis no config for rpc hosts error")
				return nil
			}
		}
	}

	log.Error("cant find rpc host error")
	return nil
}

// 只有在genesis.json中的PointsChain中配置了源链ID，才可以跨链
func inPointsChainConfig(dstChains []params.PointsChain, chainID string) bool  {
	log.Info("in Points chain config", "PointsChain", dstChains, "chainID", chainID)

	for _, v := range dstChains {
		if v.ChainId == chainID {
			l := len(v.RpcHosts)
			if l > 0 {
				return true
			} else {
				log.Error("genesis no config for rpc hosts error")
				return false
			}
		}
	}

	return false
}

func putInStateBlacklist(ctx *PrecompiledContractContext, from common.Address) {
	contractAddr := ctx.Contract.Address() //deposit contract addr
	blacklistKeyHash := utils.DepositBlacklistKeyHash(from)
	expiredBlockNumber := big.NewInt(0).Add(ctx.Evm.BlockNumber, big.NewInt(int64(blacklist.BadExpiredBlockNum))) //过期的块号
	ctx.Evm.StateDB.SetCRDState(contractAddr, blacklistKeyHash, expiredBlockNumber.Bytes())
}
