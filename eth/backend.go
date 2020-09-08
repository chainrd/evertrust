// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package eth implements the Ethereum protocol.
package eth

import (
	"errors"
	"fmt"
	"math/big"
	"CRD-chain/accounts/abi/bind"
	"CRD-chain/accounts/abi/bind/backends"
	"CRD-chain/accounts/keystore"
	"CRD-chain/CRDcc/util"
	"CRD-chain/evertrust/utils"
	"runtime"
	"sync"
	"sync/atomic"

	"CRD-chain/accounts"
	"CRD-chain/common"
	"CRD-chain/common/hexutil"
	"CRD-chain/consensus"
	"CRD-chain/consensus/clique"
	"CRD-chain/consensus/ethash"
	"CRD-chain/core"
	"CRD-chain/core/bloombits"
	"CRD-chain/core/rawdb"
	"CRD-chain/core/types"
	"CRD-chain/core/vm"
	"CRD-chain/eth/downloader"
	"CRD-chain/eth/filters"
	"CRD-chain/eth/gasprice"
	"CRD-chain/ethdb"
	"CRD-chain/event"
	"CRD-chain/internal/ethapi"
	"CRD-chain/log"
	"CRD-chain/node"
	"CRD-chain/p2p"
	"CRD-chain/params"
	"CRD-chain/CRDcc"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/rlp"
	"CRD-chain/rpc"

	"CRD-chain/evertrust"

	evertrustPkg "CRD-chain/evertrust"
	evertrust_engine "CRD-chain/evertrust/engine"
	evertrust_miner "CRD-chain/evertrust/miner"
)

type LesServer interface {
	Start(srvr *p2p.Server)
	Stop()
	Protocols() []p2p.Protocol
	SetBloomBitsIndexer(bbIndexer *core.ChainIndexer)
}

// Ethereum implements the Ethereum full node service.
type Ethereum struct {
	config      *Config
	chainConfig *params.ChainConfig

	// Channel for shutting down the service
	shutdownChan chan bool // Channel for shutting down the Ethereum

	// Handlers
	txPool          *core.TxPool
	blockchain      *core.BlockChain
	protocolManager *ProtocolManager
	lesServer       LesServer

	// DB interfaces
	chainDb ethdb.Database // Block chain database

	eventMux       *event.TypeMux
	engine         consensus.Engine
	accountManager *accounts.Manager

	bloomRequests chan chan *bloombits.Retrieval // Channel receiving bloom data retrieval requests
	bloomIndexer  *core.ChainIndexer             // Bloom indexer operating during block imports

	APIBackend *EthAPIBackend

	miner     *evertrust_miner.Miner
	gasPrice  *big.Int
	etherbase common.Address

	networkID     uint64
	netRPCService *ethapi.PublicNetAPI

	evertrustBackend bind.ContractBackend

	lock sync.RWMutex // Protects the variadic fields (e.g. gas price and etherbase)
}

func (s *Ethereum) AddLesServer(ls LesServer) {
	s.lesServer = ls
	ls.SetBloomBitsIndexer(s.bloomIndexer)
}

// New creates a new Ethereum object (including the
// initialisation of the common Ethereum object)
func New(ctx *node.ServiceContext, config *Config, stack *node.Node) (*Ethereum, error) {
	if config.SyncMode == downloader.LightSync {
		return nil, errors.New("can't run eth.Ethereum in light sync mode, use les.LightEthereum")
	}
	if !config.SyncMode.IsValid() {
		return nil, fmt.Errorf("invalid sync mode %d", config.SyncMode)
	}
	chainDb, err := CreateDB(ctx, config, "chaindata")
	if err != nil {
		return nil, err
	}

	ethdb.ChainDb = &chainDb //for evm call
	chainConfig, genesisHash, genesisErr := core.SetupGenesisBlock(chainDb, config.Genesis)

	if chainConfig.Evertrust.RewardTotal == nil {
		core.TotalReward = big.NewInt(0)
		log.Debug("New Ethereum chainConfig.RewardTotal==nil", "core.RewardTotal", core.TotalReward)
	} else {
		core.TotalReward = (*big.Int)(chainConfig.Evertrust.RewardTotal)
		log.Debug("New Ethereum chainConfig.RewardTotal!=nil", "core.RewardTotal", core.TotalReward)
	}

	// gasless & consortium
	util.Gasless = chainConfig.Evertrust.GasLess
	evertrust.Consortium = chainConfig.Evertrust.Consortium
	evertrust.ConsortiumDir = evertrust.DataDir + "/consortium/"
	//util.Gasless = ctx.GlobalBool(utils.evertrustGasLessFlag.Name)
	evertrust.RootIdCaMap = make(map[string]string)
	evertrust.UserCertPublicKeyMap = make(map[string]struct{})
	log.Info("Consortium", "Consortium", evertrust.Consortium)
	log.Info("ConsortiumDir", "ConsortiumDir", evertrust.ConsortiumDir)
	log.Info("Gasless", "Gasless", util.Gasless)
	if evertrust.Consortium {
		var err error
		evertrust.ConsortiumConf, evertrust.RootIdCaMap, evertrust.UserCertPublicKeyMap, evertrust.Cert, evertrust.CertRootId, err = evertrust.ConsortiumSet("")
		if err != nil {
			evertrust.Consortium = false
			log.Error("Consortium settings error", "err", err, "consortium", evertrust.Consortium)
		}
	}

	conf.ChainId = chainConfig.ChainID
	ccPort := evertrust.Config.Int("ccRpcPort")
	conf.NetWorkId = ccPort
	CRDcc.Start(ccPort)

	if _, ok := genesisErr.(*params.ConfigCompatError); genesisErr != nil && !ok {
		return nil, genesisErr
	}
	log.Info("Initialised chain configuration q", "config", chainConfig)

	eth := &Ethereum{
		config:         config,
		chainDb:        chainDb,
		chainConfig:    chainConfig,
		eventMux:       ctx.EventMux,
		accountManager: ctx.AccountManager,
		engine:         CreateConsensusEngine(ctx, chainConfig, &config.Ethash, config.MinerNotify, chainDb, stack),
		shutdownChan:   make(chan bool),
		networkID:      config.NetworkId,
		gasPrice:       config.MinerGasPrice,
		etherbase:      config.Etherbase,
		bloomRequests:  make(chan chan *bloombits.Retrieval),
		bloomIndexer:   NewBloomIndexer(chainDb, params.BloomBitsBlocks, bloomConfirms),
	}

	log.Info("Initialising Ethereum protocol", "versions", ProtocolVersions, "network", config.NetworkId)

	if !config.SkipBcVersionCheck {
		bcVersion := rawdb.ReadDatabaseVersion(chainDb)
		if bcVersion != core.BlockChainVersion && bcVersion != 0 {
			return nil, fmt.Errorf("Blockchain DB version mismatch (%d / %d).\n", bcVersion, core.BlockChainVersion)
		}
		rawdb.WriteDatabaseVersion(chainDb, core.BlockChainVersion)
	}

	var (
		vmConfig = vm.Config{
			EnablePreimageRecording: config.EnablePreimageRecording,
			// add by liangc for wasm
			// EWASMInterpreter: ewasmOptions,
		}
		cacheConfig = &core.CacheConfig{Disabled: config.NoPruning, TrieNodeLimit: config.TrieCache, TrieTimeLimit: config.TrieTimeout}
	)
	evertrust := eth.engine.(*evertrust_engine.Evertrust)

	eth.blockchain, err = core.NewBlockChain(chainDb, cacheConfig, eth.chainConfig, evertrust, vmConfig)

	if err != nil {
		return nil, err
	}
	eth.blockchain.SubscribePrepareNextBlockEvent(evertrust.ReorgChainCh)

	// Rewind the chain in case of an incompatible config upgrade.
	if compat, ok := genesisErr.(*params.ConfigCompatError); ok {
		log.Warn("Rewinding chain to upgrade configuration", "err", compat)
		eth.blockchain.SetHead(compat.RewindTo)
		rawdb.WriteChainConfig(chainDb, genesisHash, chainConfig)
	}
	eth.bloomIndexer.Start(eth.blockchain)

	if config.TxPool.Journal != "" {
		config.TxPool.Journal = ctx.ResolvePath(config.TxPool.Journal)
	}
	eth.txPool = core.NewTxPool(config.TxPool, eth.chainConfig, eth.blockchain)

	evertrust.SetBlockchain(eth.blockchain)
	evertrust.Init()
	config.SyncMode = downloader.FullSync
	log.Info("查看同步模式", "模式", config.SyncMode)
	if eth.protocolManager, err = NewProtocolManager(eth.chainConfig, config.SyncMode, config.NetworkId, eth.eventMux, eth.txPool, eth.engine, eth.blockchain, chainDb, config.Etherbase); err != nil {
		return nil, err
	}
	//CRD
	// add by liangc >>>>
	codeDb, err := CreateDB(ctx, config, "ewasmcode")
	if err != nil {
		return nil, err
	}

	utils.EwasmToolImpl.Init(chainDb, codeDb, &eth.protocolManager.downloader.Synchronis)
	// add by liangc <<<<
	evertrust.Syncing = &eth.protocolManager.downloader.Synchronis
	evertrustPkg.Syncing = &eth.protocolManager.downloader.Synchronis
	params.Syncing = &eth.protocolManager.downloader.Synchronis // for contract uip1
	evertrust.Fetcher = eth.protocolManager.fetcher
	evertrust.CommitFetcher = eth.protocolManager.commitFetcher
	evertrust.AccountManager = eth.accountManager

	ks := evertrust.AccountManager.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
	etherBase := evertrustPkg.Config.String("etherbase")
	evertrustPkg.MinerPrivateKey = ks.GetUnlocked(common.HexToAddress(etherBase)).PrivateKey
	//CRD: set evertrust miner
	eth.miner = evertrust_miner.New(eth, eth.chainConfig, eth.EventMux(), eth.engine, config.MinerRecommit)
	eth.miner.SetExtra(makeExtraData(config.MinerExtraData))

	if evertrust, ok := eth.engine.(*evertrust_engine.Evertrust); ok {
		wallet, err := eth.accountManager.Find(accounts.Account{Address: eth.etherbase})
		if wallet == nil || err != nil {
			log.Error("Etherbase account unavailable locally", "err", err)
		}

		if wallet == nil {
			evertrust.Authorize(eth.etherbase, nil)
		} else {
			evertrust.Authorize(eth.etherbase, wallet.SignHash)
		}

	}

	eth.APIBackend = &EthAPIBackend{eth, nil}
	gpoParams := config.GPO
	if gpoParams.Default == nil {
		gpoParams.Default = config.MinerGasPrice
	}
	eth.APIBackend.gpo = gasprice.NewOracle(eth.APIBackend, gpoParams)
	// add by liangc : 内部调用合约时需要使用这个对象
	eth.evertrustBackend = backends.NewevertrustContractBackend(eth, eth.chainConfig)
	return eth, nil
}

func makeExtraData(extra []byte) []byte {
	if len(extra) == 0 {
		// create default extradata
		extra, _ = rlp.EncodeToBytes([]interface{}{
			uint(params.VersionMajor<<16 | params.VersionMinor<<8 | params.VersionPatch),
			"evertrust",
			runtime.Version(),
			runtime.GOOS,
		})
	}
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		log.Warn("Miner extra data exceed limit", "extra", hexutil.Bytes(extra), "limit", params.MaximumExtraDataSize)
		extra = nil
	}
	return extra
}

// CreateDB creates the chain database.
func CreateDB(ctx *node.ServiceContext, config *Config, name string) (ethdb.Database, error) {
	db, err := ctx.OpenDatabase(name, config.DatabaseCache, config.DatabaseHandles)
	if err != nil {
		return nil, err
	}
	//if db, ok := db.(*ethdb.LDBDatabase); ok {
	//	db.Meter("eth/db/chaindata/")
	//}
	return db, nil
}

// CreateConsensusEngine creates the required type of consensus engine instance for an Ethereum service
func CreateConsensusEngine(ctx *node.ServiceContext, chainConfig *params.ChainConfig, config *ethash.Config, notify []string, db ethdb.Database, stack *node.Node) consensus.Engine {

	//CRD: If configured evertrust consensus
	if chainConfig.Evertrust != nil {
		log.Info("creating evertrust engine...")
		return evertrust_engine.New(chainConfig.Evertrust, db, stack)
	}
	log.Error("evertrust engine not configured")

	// If proof-of-authority is requested, set it up
	if chainConfig.Clique != nil {
		return clique.New(chainConfig.Clique, db)
	}
	// Otherwise assume proof-of-work
	switch config.PowMode {
	case ethash.ModeFake:
		log.Warn("Ethash used in fake mode")
		return ethash.NewFaker()
	case ethash.ModeTest:
		log.Warn("Ethash used in test mode")
		return ethash.NewTester(nil)
	case ethash.ModeShared:
		log.Warn("Ethash used in shared mode")
		return ethash.NewShared()
	default:
		engine := ethash.New(ethash.Config{
			CacheDir:       ctx.ResolvePath(config.CacheDir), //判断是否绝对路径
			CachesInMem:    config.CachesInMem,
			CachesOnDisk:   config.CachesOnDisk,
			DatasetDir:     config.DatasetDir,
			DatasetsInMem:  config.DatasetsInMem,
			DatasetsOnDisk: config.DatasetsOnDisk,
		}, notify)
		engine.SetThreads(-1) // Disable CPU mining
		return engine
	}
}

// APIs return the collection of RPC services the ethereum package offers.
// NOTE, some of these services probably need to be moved to somewhere else.
func (s *Ethereum) APIs() []rpc.API {
	apis := ethapi.GetAPIs(s.APIBackend)

	// Append any APIs exposed explicitly by the consensus engine
	apis = append(apis, s.engine.APIs(s.BlockChain())...)

	// Append all the local APIs and return
	return append(apis, []rpc.API{
		{
			Namespace: "eth",
			Version:   "1.0",
			Service:   NewPublicEthereumAPI(s),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   NewPublicMinerAPI(s),
			Public:    true,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   downloader.NewPublicDownloaderAPI(s.protocolManager.downloader, s.eventMux),
			Public:    true,
		}, {
			Namespace: "miner",
			Version:   "1.0",
			Service:   NewPrivateMinerAPI(s),
			Public:    false,
		}, {
			Namespace: "eth",
			Version:   "1.0",
			Service:   filters.NewPublicFilterAPI(s.APIBackend, false),
			Public:    true,
		}, {
			Namespace: "admin",
			Version:   "1.0",
			Service:   NewPrivateAdminAPI(s),
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPublicDebugAPI(s),
			Public:    true,
		}, {
			Namespace: "debug",
			Version:   "1.0",
			Service:   NewPrivateDebugAPI(s.chainConfig, s),
		}, {
			Namespace: "net",
			Version:   "1.0",
			Service:   s.netRPCService,
			Public:    true,
		},
	}...)
}

func (s *Ethereum) ResetWithGenesisBlock(gb *types.Block) {
	s.blockchain.ResetWithGenesisBlock(gb)
}

func (s *Ethereum) Etherbase() (eb common.Address, err error) {
	s.lock.RLock()
	etherbase := s.etherbase
	s.lock.RUnlock()

	if etherbase != (common.Address{}) {
		return etherbase, nil
	}
	if wallets := s.AccountManager().Wallets(); len(wallets) > 0 {
		if accounts := wallets[0].Accounts(); len(accounts) > 0 {
			etherbase := accounts[0].Address

			s.lock.Lock()
			s.etherbase = etherbase
			s.lock.Unlock()

			log.Info("Etherbase automatically configured", "address", etherbase)
			return etherbase, nil
		}
	}
	return common.Address{}, fmt.Errorf("etherbase must be explicitly specified")
}

// SetEtherbase sets the mining reward address.
func (s *Ethereum) SetEtherbase(etherbase common.Address) {
	s.lock.Lock()
	s.etherbase = etherbase
	s.lock.Unlock()

	s.miner.SetEtherbase(etherbase)
}

func (s *Ethereum) StartMining(local bool) error {
	eb, err := s.Etherbase()
	if err != nil {
		log.Error("Cannot start mining without etherbase", "err", err)
		return fmt.Errorf("etherbase missing: %v", err)
	}
	if clique, ok := s.engine.(*clique.Clique); ok {
		wallet, err := s.accountManager.Find(accounts.Account{Address: eb})
		if wallet == nil || err != nil {
			log.Error("Etherbase account unavailable locally", "err", err)
			return fmt.Errorf("signer missing: %v", err)
		}
		clique.Authorize(eb, wallet.SignHash)
	}
	if local {
		// If local (CPU) mining is started, we can disable the transaction rejection
		// mechanism introduced to speed sync times. CPU mining on mainnet is ludicrous
		// so none will ever hit this path, whereas marking sync done on CPU mining
		// will ensure that private networks work in single miner mode too.
		atomic.StoreUint32(&s.protocolManager.acceptTxs, 1)
	}
	go s.miner.Start(eb)
	return nil
}

func (s *Ethereum) StopMining()                { s.miner.Stop() }
func (s *Ethereum) IsMining() bool             { return s.miner.Mining() }
func (s *Ethereum) Miner() *evertrust_miner.Miner { return s.miner }

func (s *Ethereum) AccountManager() *accounts.Manager  { return s.accountManager }
func (s *Ethereum) BlockChain() *core.BlockChain       { return s.blockchain }
func (s *Ethereum) TxPool() *core.TxPool               { return s.txPool }
func (s *Ethereum) Genesis() *core.Genesis             { return s.config.Genesis }
func (s *Ethereum) Synchronising() int32               { return atomic.LoadInt32(&s.Downloader().Synchronis) }
func (s *Ethereum) EventMux() *event.TypeMux           { return s.eventMux }
func (s *Ethereum) Engine() consensus.Engine           { return s.engine }
func (s *Ethereum) ChainDb() ethdb.Database            { return s.chainDb }
func (s *Ethereum) IsListening() bool                  { return true } // Always listening
func (s *Ethereum) EthVersion() int                    { return int(s.protocolManager.SubProtocols[0].Version) }
func (s *Ethereum) NetVersion() uint64                 { return s.networkID }
func (s *Ethereum) Downloader() *downloader.Downloader { return s.protocolManager.downloader }
func (s *Ethereum) FiltersBackend() filters.Backend    { return s.APIBackend }

// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
func (s *Ethereum) Protocols() []p2p.Protocol {
	if s.lesServer == nil {
		return s.protocolManager.SubProtocols
	}
	return append(s.protocolManager.SubProtocols, s.lesServer.Protocols()...)
}

// Start implements node.Service, starting all internal goroutines needed by the
// Ethereum protocol implementation.
func (s *Ethereum) Start(srvr *p2p.Server) error {
	// Start the bloom bits servicing goroutines
	s.startBloomHandlers()

	// Start the RPC service
	s.netRPCService = ethapi.NewPublicNetAPI(srvr, s.NetVersion())

	// Figure out a max peers count based on the server limits
	maxPeers := srvr.MaxPeers
	if s.config.LightServ > 0 {
		if s.config.LightPeers >= srvr.MaxPeers {
			return fmt.Errorf("invalid peer config: light peer count (%d) >= total peer count (%d)", s.config.LightPeers, srvr.MaxPeers)
		}
		maxPeers -= s.config.LightPeers
	}
	// Start the networking layer and the light server if requested
	s.protocolManager.Start(maxPeers)
	if s.lesServer != nil {
		s.lesServer.Start(srvr)
	}

	s.engine.(*evertrust_engine.Evertrust).Start()
	go s.evertrustBackendLoop()
	// TODO : 启动 p2p.server MQ
	s.protocolManager.hiwayPeers = func() map[common.Address]*p2p.Peer { return make(map[common.Address]*p2p.Peer) }
	if srvr.Highway != "" {
		var (
			handleMsgFn = func(id common.Address, mrw p2p.MsgReadWriter) {
				p := newPeer(64, p2p.NewPeerWriter(id, mrw), mrw)
				for {
					if err := s.protocolManager.handleMsg(p); err != nil {
						if err != nil && err.Error() == "closed" {
							log.Error("highway_readMsg_error", "err", err, "action", "stop")
							return
						}
						log.Error("highway_readMsg_error", "err", err, "action", "skip")
					}
				}
			}
		)
		// 如果拿不到 rw 就一直阻塞吧
		log.Info("启动 Highway 服务 : Start")
		err := srvr.StartHighway(handleMsgFn)
		if err != nil {
			log.Error("Highway start fail", "err", err)
			return err
		}
		log.Info("启动 Highway 服务 : Success")
		s.protocolManager.hiwayPeers = srvr.HighwayPeers
	}

	go func() {
		peer := p2p.NewAlibp2pMailboxReader(srvr)
		p := newPeer(64, peer, peer.Conn())
		for {
			err := s.protocolManager.handleMsg(p)
			log.Warn("🎺 🎺 🎺 🎺 alibp2pMailboxReader-over", "err", err)
		}
	}()

	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// Ethereum protocol.
func (s *Ethereum) Stop() error {
	s.bloomIndexer.Close()
	s.blockchain.Stop()
	s.engine.Close()
	s.protocolManager.Stop()
	if s.lesServer != nil {
		s.lesServer.Stop()
	}
	s.txPool.Stop()
	s.miner.Stop()
	s.eventMux.Stop()

	s.chainDb.Close()
	close(s.shutdownChan)
	return nil
}

func (s *Ethereum) evertrustBackendLoop() {
	for {
		select {
		case <-s.shutdownChan:
			return
		case rch := <-params.EvertrustBackendInstanceCh:
			rch <- s.evertrustBackend
		}
	}
}
