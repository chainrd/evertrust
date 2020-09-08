package vm

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/core/publicBC"
	"CRD-chain/ethdb"
	"CRD-chain/log"
	"CRD-chain/params"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/CRDcc/util"
	"CRD-chain/quorum"
	"CRD-chain/rlp"
	"CRD-chain/evertrust"
	"CRD-chain/evertrust/engine/qualification"
	"CRD-chain/evertrust/types"
	"sync"
)

type Hypothecation struct{}

type QuiteQuorum struct{}

type Redamption struct{}

var (
	HypothecationLimit *big.Int = new(big.Int).Mul(big.NewInt(1e+18), big.NewInt(1e+5))
	EmptyByte                   = []byte{}
	//ChangeHeight       uint64         = engine.UIP1.Uint64()
	PunishAccount common.Address = common.HexToAddress("0x017BAa041131128D2C482a7f1ff6A729797De281")
)

type HypothecationAddress struct {
	Address common.Address `json:"address"` //抵押地址
}

type HypothecationInfo struct {
	Address common.Address `json:"address"`

	HypothecationAmount *big.Int `json:"hypothecation_amount"` //应该质押的金额      5 * 10%

	TotalPledgeAmount *big.Int `json:"total_hypothecationInfo_amount"` //总抵押额度

	HypothecationHeight uint64 `json:"hypothecation_height"` //第一次质押的高度
}

type QuiteQuorumInfo struct {
	QuiteAddress common.Address `json:"quite_address"` //推出会员会的节点地址
}

type RecaptionInfo struct {
	HypothecationAddr common.Address `json:"hypothecation_addr"` //质押的地址

	RecaptionAddress common.Address `json:"recaption_address"` //退款地址
}

type QuitStack struct {
	HypothecationAddr common.Address `json:"hypothecation_addr"` //质押的地址

	ShouldBeRecapHeight uint64 `json:"should_be_recap_height"` //允许被退款的高度

	HypothecationAmount *big.Int `json:"hypothecation_amount"` //应该质押的金额      5 * 10%

	TotalPledgeAmount *big.Int `json:"total_hypothecationInfo_amount"` //总抵押额度
}

func (p *HypothecationInfo) Encode() ([]byte, error) {
	return rlp.EncodeToBytes(p)
}

func (p *HypothecationInfo) Decode(data []byte) error {
	return rlp.DecodeBytes(data, &p)
}

func (r *RecaptionInfo) Encode() ([]byte, error) {
	return rlp.EncodeToBytes(r)
}

func (r *RecaptionInfo) Decode(data []byte) error {
	return rlp.DecodeBytes(data, &r)
}

func (q *QuiteQuorumInfo) Encode() ([]byte, error) {
	return rlp.EncodeToBytes(q)
}

func (q *QuiteQuorumInfo) Decode(data []byte) error {
	return rlp.DecodeBytes(data, &q)
}

type CacheMap struct {
	lock             sync.RWMutex
	HypothecationMap map[string]*HypothecationInfo
}

func NewCacheMap() *CacheMap {
	return &CacheMap{HypothecationMap: make(map[string]*HypothecationInfo)}
}

func (c *CacheMap) Set(key string, value *HypothecationInfo) {
	c.lock.Lock()
	defer c.lock.Unlock()
	_, ok := c.HypothecationMap[key]
	if ok {
		return
	}
	c.HypothecationMap[key] = value
}

func (c *CacheMap) Get(key string) (bool, *HypothecationInfo) {
	value, ok := c.HypothecationMap[key]
	if ok {
		return true, value
	}
	return false, nil
}

func (c *CacheMap) Del(key string) {
	_, ok := c.HypothecationMap[key]
	if ok {
		delete(c.HypothecationMap, key)
	}
}

func (c *CacheMap) Encode() ([]byte, error) {
	return json.Marshal(c.HypothecationMap)
}

func (c *CacheMap) Decode(data []byte) error {
	return json.Unmarshal(data, &c.HypothecationMap)
}

type CacheMap1 struct {
	lock         sync.RWMutex
	RecaptionMap map[string]*QuitStack
}

func NewCacheMap1() *CacheMap1 {
	return &CacheMap1{RecaptionMap: make(map[string]*QuitStack)}
}

func (c *CacheMap1) Set(key string, value *QuitStack) {
	c.lock.Lock()
	defer c.lock.Unlock()
	_, ok := c.RecaptionMap[key]
	if ok {
		return
	}
	c.RecaptionMap[key] = value
}

func (c *CacheMap1) Get(key string) (bool, *QuitStack) {
	value, ok := c.RecaptionMap[key]
	if ok {
		return true, value
	}
	return false, nil
}

func (c *CacheMap1) Del(key string) {
	_, ok := c.RecaptionMap[key]
	if ok {
		delete(c.RecaptionMap, key)
	}
}

func (c *CacheMap1) Encode() ([]byte, error) {
	return json.Marshal(c.RecaptionMap)
}

func (c *CacheMap1) Decode(data []byte) error {
	return json.Unmarshal(data, &c.RecaptionMap)
}

//计算gas消耗
func (mp *Hypothecation) RequiredGas(input []byte) uint64 {
	log.Info("RequiredGas", "gas", uint64(len(input)/192)*params.Bn256PairingPerPointGas, "l", len(input)/192)
	return uint64(len(input)/192) * params.Bn256PairingPerPointGas
}

func (mp *Hypothecation) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	log.Info("hypothecation run")

	var blockExtra types.BlockExtra
	blockExtra.Decode(ctx.Evm.Header.Extra)
	height := blockExtra.CNumber.Uint64()

	log.Info("质押所在commit区块高度", "height", height, "normal高度", ctx.Evm.Header.Number.Uint64(), "当前commit", public.BC.CurrentCommit().NumberU64())

	quorum, ok := quorum.CommitHeightToConsensusQuorum.Get(height, *ethdb.ChainDb)
	if !ok {
		log.Info("no quorum in the extra")
		return nil, ErrPledgeContractRunFailed
	}
	quorumNum := len(quorum.Keys())
	err := hypothecation(ctx, int64(quorumNum), height, input)
	if err != nil {
		log.Error("hypothecation error", "err", err)
		return nil, ErrPledgeContractRunFailed
	}

	return nil, nil
}

func hypothecation(ctx *PrecompiledContractContext, quorumNum int64, height uint64, input []byte) error {
	var from common.Address
	if len(input) != 0 {
		var hAddress HypothecationAddress
		err := rlp.DecodeBytes(input, &hAddress)
		if err != nil {
			log.Error("unmarshal payload error", "err", err)
			return ErrPledgeContractRunFailed
		}
		from = hAddress.Address
	} else {
		from = ctx.Contract.CallerAddress
	}

	stateDB := ctx.Evm.StateDB
	contractAddr := ctx.Contract.Address()
	redamptionAddr := util.EthAddress("redamption")
	hypothecationInfoKeyHash := hypothecationInfoKeyHash(from.Hex())
	var num int64
	state := stateDB.GetCRDState(contractAddr, hypothecationInfoKeyHash)
	var hypothInfo HypothecationInfo
	nodeType := evertrust.Config.Int64("nodeType")
	switch nodeType {
	case 0:
		//TRUST_CHAIN
		num = 16
	case 1:
		//SERVICE_CHAIN
		num = 128
	case 2:
		//BIZ_CHAIN
		num = 128
	default:
		num = 128
	}

	var cachemap = NewCacheMap()   //质押
	var cacheMap1 = NewCacheMap1() //退出质押
	cacheData := stateDB.GetCRDState(contractAddr, contractAddr.Hash())
	redeData := stateDB.GetCRDState(redamptionAddr, redamptionAddr.Hash())
	if len(cacheData) == 0 {
		//cachemap = NewCacheMap()
		//第一个打块人的记录也放进来
		firstMiner := public.BC.GetBlockByNumber(0).Extra()
		address := common.BytesToAddress(firstMiner)
		hypothInfo1 := HypothecationInfo{address, HypothecationLimit, HypothecationLimit, 0}
		cachemap.Set(address.Hex(), &hypothInfo1)
	} else {
		cachemap.Decode(cacheData)
	}

	if len(redeData) != 0 {
		cacheMap1.Decode(redeData)
	}

	if len(state) == 0 {
		count := quorumNum / num
		count += 1
		promitedPrice := new(big.Int).Mul(HypothecationLimit, big.NewInt(int64(count)))

		log.Info("查看一下质押金是多少", "金额", promitedPrice, "质押的金额", ctx.Contract.Value())
		if ctx.Contract.Value().Cmp(promitedPrice) < 0 {
			log.Error("balance not enough to hypothecation")
			return errors.New("balance not enough to hypothecation")
		}
		//这里需要查看一下退出质押的记录里面有没有，如果有就说明仅仅退出了共识委员会而没有退出质押压
		recaKeyHash := quiteQuorumInfoKeyHash(from.Hex())
		recaData := stateDB.GetCRDState(redamptionAddr, recaKeyHash)
		if len(recaData) == 0 {
			hypothInfo = HypothecationInfo{from, promitedPrice, ctx.Contract.Value(), height}
		} else {
			//需要解码
			var quitInfo QuitStack
			err := rlp.DecodeBytes(recaData, &quitInfo)
			if err != nil {
				return errors.New("退出质押解码失败")
			}
			amount := new(big.Int).Add(quitInfo.TotalPledgeAmount, ctx.Contract.Value())
			hypothInfo = HypothecationInfo{from, promitedPrice, amount, height}
			//清除退出质押的记录
			stateDB.SetCRDState(redamptionAddr, recaKeyHash, EmptyByte)
		}
	} else {

		err := rlp.DecodeBytes(state, &hypothInfo)
		if err != nil {
			log.Error("unmarshal failed")
			return err
		}

		//这里是为了查看是否失去资格
		nodeDetails, ok := qualification.CommitHeight2NodeDetailSetCache.Dup(height, *ethdb.ChainDb)
		if !ok {
			log.Error("no nodeDetails on this height", "height", height)
			return errors.New("no nodeDetails on this height")
		}

		if hypothInfo.HypothecationHeight == height || hypothInfo.HypothecationHeight == height-1 {
			amount := new(big.Int).Add(hypothInfo.TotalPledgeAmount, ctx.Contract.Value())
			hypothInfo.TotalPledgeAmount = amount
		} else {
			nodeDetail := nodeDetails.Get(from.String())
			if nodeDetail == nil {
				log.Error("no nodeDetail on this height")
				return errors.New("no nodeDetail on this height")
			}

			if nodeDetail.CanBeMaster == qualification.ShouldBePunished {
				log.Error("this address should be pinished , recaption first", "addr", from.String())
				return errors.New("this address should be pinished , recaption first")
			} else if nodeDetail.CanBeMaster == qualification.CanBeMaster {
				log.Info("质押了多少钱", "money", ctx.Contract.Value())
				log.Info("原本有多少钱", "money", hypothInfo.TotalPledgeAmount)
				amount := new(big.Int).Add(hypothInfo.TotalPledgeAmount, ctx.Contract.Value())
				log.Info("加完了以后是多少钱", "amount", amount)

				hypothInfo.TotalPledgeAmount = amount
			}
		}
	}

	cachemap.Set(from.Hex(), &hypothInfo)
	cacheMap1.Del(from.Hex())
	cacheData, err := cachemap.Encode()
	if err != nil {
		log.Error("存放这个数据的东西编码失败")
		return err
	}

	redeData, err = cacheMap1.Encode()
	if err != nil {
		log.Error("存放这个数据的东西编码失败")
		return err
	}

	stateDB.SetCRDState(contractAddr, contractAddr.Hash(), cacheData)
	stateDB.SetCRDState(redamptionAddr, redamptionAddr.Hash(), redeData)
	log.Info("质押信息", "address", hypothInfo.Address.Hex(), "质押总金额", hypothInfo.TotalPledgeAmount)
	dataByte, err := rlp.EncodeToBytes(hypothInfo)
	if err != nil {
		log.Error("marshal error", err)
		return err
	}

	log.Info("质押操作存在了高度", "height", height)
	stateDB.SetCRDState(contractAddr, hypothecationInfoKeyHash, dataByte)
	log.Info("质押成功")
	return nil
}

func hypothecationInfoKeyHash(address string) common.Hash {
	return util.EthHash([]byte(fmt.Sprintf("%s:%s:%s", conf.CRDKeyFlag, "hypothecationInfo", address)))
}

func (q *QuiteQuorum) RequiredGas(input []byte) uint64 {
	log.Info("RequiredGas", "gas", uint64(len(input)/192)*params.Bn256PairingPerPointGas, "l", len(input)/192)
	return uint64(len(input)/192) * params.Bn256PairingPerPointGas
}

func (q *QuiteQuorum) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	if len(extra[conf.TxEstimateGas]) > 0 {
		return nil, nil
	}

	log.Info("Mortgage QuiteQuorumInfo run")

	log.Info("Mortgage QuiteQuorumInfo run", "input", len(input))
	var payload QuiteQuorumInfo
	err := rlp.DecodeBytes(input, &payload)
	if err != nil {
		log.Error("unmarshal payload error", "err", err)
		return nil, ErrPledgeContractRunFailed
	}

	log.Info("查看一下解码数据", "address", payload.QuiteAddress.Hex())

	var blockExtra types.BlockExtra
	log.Info("查看一下数据", "数据", ctx.Evm.Header.Number.Uint64())
	blockExtra.Decode(ctx.Evm.Header.Extra)
	height := blockExtra.CNumber.Uint64()
	err = quite(ctx, payload, height)
	if err != nil {
		return nil, ErrPledgeContractRunFailed
	}
	return nil, nil
}

func quite(ctx *PrecompiledContractContext, payload QuiteQuorumInfo, height uint64) error {
	stateDB := ctx.Evm.StateDB
	contractAddr := util.EthAddress("hypothecation")
	recaContractAddr := util.EthAddress("redamption")
	//发送交易的地址
	callerAddr := ctx.Contract.CallerAddress

	if callerAddr != payload.QuiteAddress {
		return errors.New("caller address is no the same with quiteaddress")
	}

	keyHash := hypothecationInfoKeyHash(callerAddr.Hex())
	recaKeyHash := quiteQuorumInfoKeyHash(callerAddr.Hex())
	stateByte := stateDB.GetCRDState(contractAddr, keyHash)
	if len(stateByte) == 0 {
		log.Error("caller did not Hypothecation any money")
		return errors.New("caller did not Hypothecation any money")
	}

	//退出共识委员会
	nodeDetails, ok := qualification.CommitHeight2NodeDetailSetCache.Get(height-1, *ethdb.ChainDb)
	if !ok {
		log.Error("no nodeDetails on this height")
		return errors.New("no nodeDetails on this height")
	}

	quor, ok := quorum.CommitHeightToConsensusQuorum.Get(height, *ethdb.ChainDb)
	if !ok {
		log.Info("no quorum in the extra")
		return errors.New("no quorum in the extra")
	}

	evm := ctx.Evm
	if evm.ChainConfig().IsEIP158(evm.BlockNumber) {
		evm.StateDB.SetNonce(recaContractAddr, 1)
	}

	cacheMap := NewCacheMap()
	cacheMap1 := NewCacheMap1()

	cacheData := stateDB.GetCRDState(contractAddr, contractAddr.Hash())
	if len(cacheData) == 0 {
		log.Error("保存质押记录的没有查询到记录")
		return errors.New("保存质押记录的没有查询到记录")
	}

	err := cacheMap.Decode(cacheData)
	if err != nil {
		log.Error("保存数据的解码失败")
	}

	var hypothInfo HypothecationInfo
	err = rlp.DecodeBytes(stateByte, &hypothInfo)
	if err != nil {
		log.Error("unmarshal failed")
		return err
	}

	redaData := stateDB.GetCRDState(recaContractAddr, recaContractAddr.Hash())
	if len(redaData) != 0 {
		err = cacheMap1.Decode(redaData)
		if err != nil {
			log.Error("保存数据的解码失败")
		}
	}
	if addr := quor.Get(callerAddr.Hex()); addr != quorum.EmptyAddress {
		log.Info("在共识委员会中")
		//在共识委员会中
		quitInfo := &QuitStack{callerAddr, height + 20, hypothInfo.HypothecationAmount, hypothInfo.TotalPledgeAmount}
		data, err := rlp.EncodeToBytes(quitInfo)
		if err != nil {
			log.Error("quite info error")
			return errors.New("encode quit info error")
		}

		stateDB.SetCRDState(recaContractAddr, recaKeyHash, data)
		cacheMap1.Set(callerAddr.Hex(), quitInfo)
		cacheMap.Del(callerAddr.Hex())
		data, err = cacheMap.Encode()
		if err != nil {
			return errors.New("存储质押和退出质押的东西编码失败")
		}

		redaData, err := cacheMap1.Encode()
		if err != nil {
			return errors.New("存储质押和退出质押的东西编码失败")
		}
		stateDB.SetCRDState(contractAddr, contractAddr.Hash(), data)
		stateDB.SetCRDState(recaContractAddr, recaContractAddr.Hash(), redaData)
	} else {
		log.Info("不在共识委员会中")
		//可能需要退钱
		if nodeDetail := nodeDetails.Get(callerAddr.Hex()); nodeDetail.CanBeMaster == qualification.CanBeMaster {
			return errors.New("not in quorum please wait")
		}
		quitInfo := &QuitStack{callerAddr, 0, hypothInfo.HypothecationAmount, hypothInfo.TotalPledgeAmount}
		data, err := rlp.EncodeToBytes(quitInfo)
		if err != nil {
			log.Error("quite info error")
			return errors.New("encode quit info error")
		}
		stateDB.SetCRDState(recaContractAddr, recaKeyHash, data)

		cacheMap1.Set(callerAddr.Hex(), quitInfo)
		cacheMap.Del(callerAddr.Hex())
		data, err = cacheMap.Encode()
		if err != nil {
			return errors.New("存储质押和退出质押的东西编码失败")
		}

		redaData, err := cacheMap1.Encode()
		if err != nil {
			return errors.New("存储质押和退出质押的东西编码失败")
		}
		stateDB.SetCRDState(contractAddr, contractAddr.Hash(), data)
		stateDB.SetCRDState(recaContractAddr, recaContractAddr.Hash(), redaData)
	}
	stateDB.SetCRDState(contractAddr, keyHash, EmptyByte)
	log.Info("退出委员会调用成功")
	return nil
}

func (mr *Redamption) RequiredGas(input []byte) uint64 {
	log.Info("RequiredGas", "gas", uint64(len(input)/192)*params.Bn256PairingPerPointGas, "l", len(input)/192)
	return uint64(len(input)/192) * params.Bn256PairingPerPointGas
}

func (mr *Redamption) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	log.Info("Mortgage Recaption run")

	log.Info("Mortgage Recaption run", "input", len(input))
	var payload RecaptionInfo
	err := rlp.DecodeBytes(input, &payload)
	if err != nil {
		log.Error("unmarshal payload error", "err", err)
		return nil, ErrPledgeContractRunFailed
	}

	log.Info("查看一下解码数据", "address", payload.RecaptionAddress.Hex())

	var blockExtra types.BlockExtra
	blockExtra.Decode(ctx.Evm.Header.Extra)
	height := blockExtra.CNumber.Uint64()
	err = recaption(ctx, payload, height)
	if err != nil {
		return nil, ErrPledgeContractRunFailed
	}
	return nil, nil
}

func recaption(ctx *PrecompiledContractContext, payload RecaptionInfo, height uint64) error {

	stateDB := ctx.Evm.StateDB
	recaContractAddr := ctx.Contract.Address()
	contractAddr := util.EthAddress("hypothecation")
	//发送交易的地址
	callerAddr := ctx.Contract.CallerAddress
	if callerAddr != payload.HypothecationAddr {
		log.Error("caller address is not the some with the HypothecationAddr")
		return errors.New("caller address is not the some with the HypothecationAddr")
	}

	nodeDetails, ok := qualification.CommitHeight2NodeDetailSetCache.Get(height-1, *ethdb.ChainDb)
	if !ok {
		log.Error("no nodeDetails on this height")
		return errors.New("no nodeDetails on this height")
	}

	qur, ok := quorum.CommitHeightToConsensusQuorum.Get(height, *ethdb.ChainDb)
	if !ok {
		log.Info("no quorum in the extra")
		return errors.New("no quorum in the extra")
	}

	addr := qur.Get(callerAddr.Hex())
	if addr != quorum.EmptyAddress {
		return errors.New("still in the quorum please wait")
	}

	evm := ctx.Evm
	if evm.ChainConfig().IsEIP158(evm.BlockNumber) {
		evm.StateDB.SetNonce(recaContractAddr, 1)
	}

	cacheMap1 := NewCacheMap1()
	redaData := stateDB.GetCRDState(recaContractAddr, recaContractAddr.Hash())
	if len(redaData) != 0 {
		err := cacheMap1.Decode(redaData)
		if err != nil {
			log.Error("保存数据的解码失败")
		}
	}

	recaKeyHash := quiteQuorumInfoKeyHash(callerAddr.Hex())
	recaState := stateDB.GetCRDState(recaContractAddr, recaKeyHash)
	log.Info("退款记录查询结果", "记录数据", len(recaState), "recaContractAddr", recaContractAddr.Hex(), "recaKeyHash", recaKeyHash.String())
	if len(recaState) == 0 {
		return errors.New("没有退款记录")
	}

	//退出质押
	var quitInfo QuitStack
	err := rlp.DecodeBytes(recaState, &quitInfo)
	if err != nil {
		return errors.New("退出质押解码失败")
	}

	currentNorNum := public.BC.CurrentBlock().NumberU64() + 1
	if currentNorNum < quitInfo.ShouldBeRecapHeight {
		return errors.New("退出质押的高度不足，无法完成退款")
	}
	cacheMap1.Del(callerAddr.Hex())
	redaCache, _ := cacheMap1.Encode()
	stateDB.SetCRDState(recaContractAddr, recaContractAddr.Hash(), redaCache)

	var hypothecationInfoAmount *big.Int
	var money *big.Int

	hypothecationInfoAmount = quitInfo.HypothecationAmount
	nodeDetail := nodeDetails.Get(callerAddr.Hex())

	div := big.NewInt(0).Div(hypothecationInfoAmount, big.NewInt(10)) //罚金

	if ctx.Evm.chainConfig.IsContractUIP1(big.NewInt(int64(height))) {
		if nodeDetail.CanBeMaster == qualification.ShouldBePunished || nodeDetail.DisqualifiedReason == qualification.ActivityNotEnough+qualification.ShouldStacking || nodeDetail.DisqualifiedReason == qualification.MultSign+qualification.ShouldStacking {
			//总押金(quitInfo.TotalPledgeAmount) =  扣除惩罚之后的余额 + 罚金
			//扣除惩罚之后的余额  总押金  -  第一次质押金额的10%
			money = new(big.Int).Sub(quitInfo.TotalPledgeAmount, div) //扣除惩罚之后的余额
			//罚金转给基金会账户
			stateDB.AddBalance(PunishAccount, div)
			log.Info("基金会余额","余额",stateDB.GetBalance(PunishAccount))
		} else {
			//正常退出
			money = quitInfo.TotalPledgeAmount
		}
		//从合约账户取去所有的押金
		stateDB.SubBalance(contractAddr, quitInfo.TotalPledgeAmount)

	} else {
		log.Info("原先逻辑")
		if nodeDetail.CanBeMaster == qualification.ShouldBePunished {
			//扣除惩罚之后的余额 = 总押金  -  第一次质押金额的10%
			//money = new(big.Int).Sub(quitInfo.TotalPledgeAmount, div)
			money = new(big.Int).Sub(quitInfo.TotalPledgeAmount, hypothecationInfoAmount.Div(hypothecationInfoAmount, big.NewInt(10)))

		} else {
			//正常退出
			money = quitInfo.TotalPledgeAmount
		}
		log.Info("押金退回了", "退回的钱", money, "节点标识", nodeDetail.CanBeMaster)
		//从合约账户中把金额取出,合约账户中会剩余罚金
		stateDB.SubBalance(contractAddr, money)

	}

	//根据惩罚情况给用户退还押金
	log.Info("给用户退款","money",money)
	stateDB.AddBalance(payload.RecaptionAddress, money)
	stateDB.SetCRDState(recaContractAddr, recaKeyHash, EmptyByte)
	log.Info("余额查询","用户余额",stateDB.GetBalance(payload.RecaptionAddress),
		"基金会余额",stateDB.GetBalance(PunishAccount),"账户余额",stateDB.GetBalance(contractAddr))
	return nil
}

func quiteQuorumInfoKeyHash(address string) common.Hash {
	return util.EthHash([]byte(fmt.Sprintf("%s:%s:%s", conf.CRDKeyFlag, "recaption", address)))
}
