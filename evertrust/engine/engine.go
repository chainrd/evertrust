/*************************************************************************
 * Copyright (C) 2016-2019 CRD Technologies, Inc. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *************************************************************************/
package engine

import (
	"CRD-chain/evertrust"
	//"bytes"
	"errors"
	math2 "math"
	"math/big"
	"CRD-chain/cacheBlock"
	"CRD-chain/eth/fetcher"
	"CRD-chain/p2p"
	"CRD-chain/evertrust/utils/blacklist"
	"CRD-chain/evertrust/utils/frequency"
	"CRD-chain/evertrust/utils/whitelist"
	"CRD-chain/evertrustAccount"

	//"math/rand"
	"sync"
	//"time"

	"CRD-chain/accounts"
	"CRD-chain/common"
	//"Evertrust-chain/common/hexutil"
	"CRD-chain/consensus"
	//"Evertrust-chain/consensus/misc"
	"CRD-chain/core/state"
	"CRD-chain/core/types"

	"CRD-chain/ethdb"
	//"Evertrust-chain/log"
	"CRD-chain/params"
	"CRD-chain/rpc"

	"CRD-chain/core"

	"CRD-chain/event"
	evertrust_types "CRD-chain/evertrust/types"

	"CRD-chain/node"
	"CRD-chain/p2p/discover"

	"CRD-chain/log"
	"time"
)

var (
	// errUnknownBlock is returned when the list of signers is requested for a block
	// that is not part of the local blockchain.
	errUnknownBlock = errors.New("unknown block")

	// errInvalidCheckpointBeneficiary is returned if a checkpoint/epoch transition
	// block has a beneficiary set to non-zeroes.
	errInvalidCheckpointBeneficiary = errors.New("beneficiary in checkpoint block non-zero")

	// errInvalidVote is returned if a nonce value is something else that the two
	// allowed constants of 0x00..0 or 0xff..f.
	errInvalidVote = errors.New("vote nonce not 0x00..0 or 0xff..f")

	// errInvalidCheckpointVote is returned if a checkpoint/epoch transition block
	// has a vote nonce set to non-zeroes.
	errInvalidCheckpointVote = errors.New("vote nonce in checkpoint block non-zero")

	// errMissingVanity is returned if a block's extra-data section is shorter than
	// 32 bytes, which is required to store the signer vanity.
	errMissingVanity = errors.New("extra-data 32 byte vanity prefix missing")

	// errMissingSignature is returned if a block's extra-data section doesn't seem
	// to contain a 65 byte secp256k1 signature.
	errMissingSignature = errors.New("extra-data 65 byte suffix signature missing")

	// errExtraSigners is returned if non-checkpoint block contain signer data in
	// their extra-data fields.
	errExtraSigners = errors.New("non-checkpoint block contains extra signer list")

	// errInvalidCheckpointSigners is returned if a checkpoint block contains an
	// invalid list of signers (i.e. non divisible by 20 bytes, or not the correct
	// ones).
	errInvalidCheckpointSigners = errors.New("invalid signer list on checkpoint block")

	// errInvalidMixDigest is returned if a block's mix digest is non-zero.
	errInvalidMixDigest = errors.New("non-zero mix digest")

	// errInvalidUncleHash is returned if a block contains an non-empty uncle list.
	errInvalidUncleHash = errors.New("non empty uncle hash")

	// errInvalidDifficulty is returned if the difficulty of a block is not either
	// of 1 or 2, or if the value does not match the turn of the signer.
	errInvalidDifficulty = errors.New("invalid difficulty")

	// ErrInvalidTimestamp is returned if the timestamp of a block is lower than
	// the previous block's timestamp + the minimum block period.
	ErrInvalidTimestamp = errors.New("invalid timestamp")

	// errInvalidVotingChain is returned if an authorization list is attempted to
	// be modified via out-of-range or non-contiguous headers.
	errInvalidVotingChain = errors.New("invalid voting chain")

	// errUnauthorized is returned if a header is signed by a non-authorized entity.
	errUnauthorized = errors.New("unauthorized")

	// errWaitTransactions is returned if an empty block is attempted to be sealed
	// on an instant chain (0 second period). It's important to refuse these as the
	// block reward is zero, so an empty block just bloats the chain... fast.
	errWaitTransactions = errors.New("waiting for transactions")

	// Ethash proof-of-work protocol constants.

	FrontierBlockReward    *big.Int = big.NewInt(0).Mul(big.NewInt(100), big.NewInt(1e+18)) // Block reward in wei for successfully mining a block
	ByzantiumBlockReward   *big.Int = big.NewInt(3e+18)                                     // Block reward in wei for successfully mining a block upward from Byzantium
	maxUncles                       = 2                                                     // Maximum number of uncles allowed in a single block
	allowedFutureBlockTime          = 15 * time.Second                                      // Max time from current time allowed for blocks, before they're considered future blocks
)

// Evertrust is the secure, fair, scalable and high performance consensus from jz@Evertrust.ltd
type Evertrust struct {
	config             *params.EvertrustConfig // Consensus engine configuration parameters
	db                 ethdb.Database       // Database to store and retrieve snapshot checkpoints
	blockchain         *core.BlockChain
	MinerCh            chan *evertrust_types.BlockMiningReq //trigger block mining if/when needed
	exitCh             chan struct{}
	assertCh           chan *types.Block
	commitCh           chan *types.Block
	ReorgChainCh       chan *types.Block
	CommitBroadcast    chan *types.Block
	NormalBroadcast    chan *types.Block
	AssertionBroadcast chan evertrust_types.NewAssertBlockEvent
	mux                *event.TypeMux
	signer             common.Address        // Ethereum address of the signing key
	signFn             evertrust_types.SignerFn // Signer function to authorize hashes with
	lock               sync.RWMutex          // Protects the signer fields
	worker             *evertrustWorker
	stack              *node.Node
	Fetcher            *fetcher.Fetcher
	CommitFetcher      *fetcher.CbFetcher
	AccountManager     *accounts.Manager
	//BlockChainNodeFeed event.Feed
	Syncing *int32
	Running *int32
	start   int32 //启动完成后开启按批次打块
}

// New creates a Evertrust proof-of-authority consensus engine with the initial
// signers set to the ones provided by the user.
func New(config *params.EvertrustConfig, db ethdb.Database, stack *node.Node) *Evertrust {
	// Set any missing consensus parameters to their defaults
	conf := *config
	evertrust := &Evertrust{
		config:             &conf,
		db:                 db,
		exitCh:             make(chan struct{}),
		assertCh:           make(chan *types.Block, 1),
		commitCh:           make(chan *types.Block, 1),
		ReorgChainCh:       make(chan *types.Block, 10),
		CommitBroadcast:    make(chan *types.Block, 100),
		NormalBroadcast:    make(chan *types.Block, 100),
		AssertionBroadcast: make(chan evertrust_types.NewAssertBlockEvent, 100),
		stack:              stack,
	}

	if evertrust.config.Cfd == 0 {
		evertrust.config.Cfd = 64
	}
	Cnfw.SetInt64(evertrust.config.Cfd)

	if evertrust.config.NumMasters == 0 {
		evertrust.config.NumMasters = 4
	}
	NumMasters = evertrust.config.NumMasters

	if evertrust.config.BlockDelay == 0 {
		evertrust.config.BlockDelay = 2000
	}
	BlockDelay = evertrust.config.BlockDelay

	blacklist.ExpiredBlockNum = blacklist.Expired / BlockDelay
	blacklist.BadExpiredBlockNum = blacklist.BadExpired / BlockDelay

	ConsensusQuorumLimt = evertrust.config.ConsensusQuorumLimt
	if ConsensusQuorumLimt == 0 {
		ConsensusQuorumLimt = 1000
	}

	if evertrust.config.BecameQuorumLimt == 0 {
		evertrust.config.BecameQuorumLimt = 5
	}
	BecameQuorumLimt = evertrust.config.BecameQuorumLimt

	Majority = evertrust.config.Majority

	PerQuorum = evertrust.config.PerQuorum

	//不写默认是0,0走最新逻辑
	if evertrust.config.UIP1 != nil {
		UIP1 = evertrust.config.UIP1
	} else {
		UIP1 = big.NewInt(0)
	}

	log.Info("UIP1","UIP1",UIP1)

	return evertrust
}

func (c *Evertrust) Start() {
	whitelist.InitTrustTxWhiteList()
	blacklist.InitFlush()
	frequency.InitFlush()
	go c.worker.Start()
}

func (c *Evertrust) Stop() {
	// add by liangc
	close(c.exitCh)
}

func (c *Evertrust) Init() {
	c.worker = newWorker(c)
}

func (c *Evertrust) DB() ethdb.Database {
	return c.db
}

func (c *Evertrust) Config() *params.EvertrustConfig {
	return c.config
}

func (c *Evertrust) Worker() *evertrustWorker {
	return c.worker
}

func (c *Evertrust) SetBlockchain(blockchain *core.BlockChain) {
	c.blockchain = blockchain
}

func (c *Evertrust) SetEventMux(mux *event.TypeMux) {
	c.mux = mux
}

func (c *Evertrust) SetMinerChannel(ch chan *evertrust_types.BlockMiningReq) {
	c.MinerCh = ch
}

func (c *Evertrust) Server() *p2p.Server {
	return c.stack.Server()
}

func (c *Evertrust) OnNormalBlock(block *types.Block) error {

	ProcessNormalBlock(block, c, c.worker.processNormalBlock, c.BroadcastNormalBlock, false)

	return nil
}

func (c *Evertrust) OnAssertBlock(assert evertrust_types.AssertExtra, name string) error {
	return c.worker.processBlockAssert(assert)
}

func (c *Evertrust) OnCommitBlock(block *types.Block) error {

	ProcessCommitBlock(block, c, c.worker.ProcessCommitBlock, c.BroadcastCommitBlock, true)

	return nil
}

func (c *Evertrust) BroadcastNormalBlock(block *types.Block) {

	cacheBlock.CacheBlocks.AddBlock(block)
	c.NormalBroadcast <- block
}

func (c *Evertrust) BroadcastCommitBlock(block *types.Block) {

	cacheBlock.CacheBlocks.AddBlock(block)
	c.CommitBroadcast <- block
}

func (c *Evertrust) PreConnectPeers(node *discover.Node) error {
	// if not already connected, connect, setup and add it to the p2p peerlist
	c.lock.Lock()
	defer c.lock.Unlock()
	peers := c.stack.Server().GetPeers()
	if _, ok := peers[node.ID.String()]; !ok {
		if node != nil {
			log.Info("PreConnectPeers发送新链接")
			go c.stack.Server().AddPeer(node)
		}
	}

	return nil
}

func (c *Evertrust) MulticastAssertBlock(assert evertrust_types.AssertExtra, nodes []discover.NodeID) error {
	log.Info("多播给了几个节点", "nodes", len(nodes))
	c.AssertionBroadcast <- evertrust_types.NewAssertBlockEvent{Assert: assert, Nodes: nodes}
	return nil
}

// Author implements consensus.Engine, returning the Ethereum address recovered
// from the signature in the header's extra-data section.
func (c *Evertrust) Author(header *types.Header) (common.Address, error) {
	return header.Coinbase, nil
}

// VerifyHeader checks whether a header conforms to the consensus rules.
func (c *Evertrust) VerifyHeader(chain consensus.ChainReader, header *types.Header, seal bool) error {
	return c.verifyHeader(chain, header, nil)
}

// VerifyHeaders is similar to VerifyHeader, but verifies a batch of headers. The
// method returns a quit channel to abort the operations and a results channel to
// retrieve the async verifications (the order is that of the input slice).
func (c *Evertrust) VerifyHeaders(chain consensus.ChainReader, headers []*types.Header, seals []bool) (chan<- struct{}, <-chan error) {
	abort := make(chan struct{})
	results := make(chan error, len(headers))

	go func() {
		for i, header := range headers {
			err := c.verifyHeader(chain, header, headers[:i])

			select {
			case <-abort:
				return
			case results <- err:
			}
		}
	}()
	return abort, results
}

// verifyHeader checks whether a header conforms to the consensus rules.The
// caller may optionally pass in a batch of parents (ascending order) to avoid
// looking those up from the database. This is useful for concurrently verifying
// a batch of new headers.
func (c *Evertrust) verifyHeader(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {

	if header.Number == nil {
		return errUnknownBlock
	}

	//Don't waste time checking blocks from the future
	if header.Time.Cmp(big.NewInt(time.Now().Unix())) > 0 {
		return consensus.ErrFutureBlock
	}

	// All basic checks passed, verify cascading fields
	//return c.verifyCascadingFields(chain, header, parents)
	return nil
}

// VerifyUncles implements consensus.Engine, always returning an error for any
// uncles as this consensus mechanism doesn't permit uncles.
func (c *Evertrust) VerifyUncles(chain consensus.ChainReader, block *types.Block) error {
	if len(block.Uncles()) > 0 {
		return errors.New("uncles not allowed")
	}
	return nil
}

// VerifySeal implements consensus.Engine, checking whether the signature contained
// in the header satisfies the consensus protocol requirements.
func (c *Evertrust) VerifySeal(chain consensus.ChainReader, header *types.Header) error {
	return c.verifySeal(chain, header, nil)
}

// verifySeal checks whether the signature contained in the header satisfies the
// consensus protocol requirements. The method accepts an optional list of parent
// headers that aren't yet part of the local blockchain to generate the snapshots
// from.
func (c *Evertrust) verifySeal(chain consensus.ChainReader, header *types.Header, parents []*types.Header) error {

	return nil
}

// Prepare implements consensus.Engine, preparing all the consensus fields of the
// header for running the transactions on top.
func (c *Evertrust) Prepare(chain consensus.ChainReader, header *types.Header) error {

	return nil
}

// Finalize implements consensus.Engine, ensuring no uncles are set, nor block
// rewards given, and returns the final block.
func (c *Evertrust) Finalize(chain consensus.ChainReader, header *types.Header, state *state.StateDB, txs []*types.Transaction, uncles []*types.Header, receipts []*types.Receipt) (*types.Block, error) {
	// Accumulate any block and uncle rewards and commit the final state root
	if !c.config.NoRewards {
		//genesis文件配置
		accumulateRewards(chain.Config(), state, header, uncles)
	}
	header.Root = state.IntermediateRoot(chain.Config().IsEIP158(header.Number))
	// Header seems complete, assemble into a block and return
	return types.NewBlock(header, txs, uncles, receipts), nil
}

// Some weird constants to avoid constant memory allocs for them.
var (
	big8  = big.NewInt(8)
	big32 = big.NewInt(32)
)

// AccumulateRewards credits the coinbase of the given block with the mining
// reward. The total reward consists of the static block reward and rewards for
// included uncles. The coinbase of each uncle block is also rewarded.
func accumulateRewards(config *params.ChainConfig, state *state.StateDB, header *types.Header, uncles []*types.Header) {
	halfN := HalfReward(header.Number)
	reward := big.NewInt(0).Div(FrontierBlockReward, big.NewInt(halfN))
	minerRewardAccount := config.Evertrust.MinerRewardAccount
	if minerRewardAccount != (common.Address{}) {
		//充值模式
		rewardAccountBalance := state.GetBalance(minerRewardAccount)
		if rewardAccountBalance.Cmp(reward) < 0 {
			log.Warn("reward account balance not enough", "balance", rewardAccountBalance, "reward", reward)
		} else {
			log.Info("check reward", "reward", reward, "rewardAccount", minerRewardAccount.String())
			state.SubBalance(minerRewardAccount, reward)
			state.AddBalance(header.RewardAddress, reward)
		}
	} else {
		//默认模式
		switch {
		case core.TotalReward.Cmp(big.NewInt(0)) == 0:
			//没有设置总量无限增发
			log.Info("check reward", "reward", new(big.Int).Div(reward, big.NewInt(1e18)))
			state.AddBalance(header.RewardAddress, reward)
		default:
			totalReward := state.GetBalance(evertrustAccount.TotalRewardAddr)
			log.Info("check reward", "reward", new(big.Int).Div(reward, big.NewInt(1e18)).String(), "totalReward", new(big.Int).Div(totalReward, big.NewInt(1e18)).String())
			if totalReward.Cmp(reward) >= 0 {
				//足够放发这次挖矿奖励
				state.SubBalance(evertrustAccount.TotalRewardAddr, reward)
				state.AddBalance(header.RewardAddress, reward)
			} else {
				log.Info("奖励不足", "totalReward", totalReward)
			}
		}
	}
}

// halfTh第几次奖励折半
// halfN折半系数
func HalfReward(blockNumber *big.Int) (halfN int64) {
	var halfTh int64
	switch {
	case blockNumber.Cmp(big.NewInt(3000000)) <= 0:
		halfTh = 0
	case blockNumber.Cmp(big.NewInt(9000000)) <= 0:
		halfTh = 1
	case blockNumber.Cmp(big.NewInt(27000000)) <= 0:
		halfTh = 2
	default:
		halfs := big.NewInt(0).Div(big.NewInt(0).Sub(blockNumber, big.NewInt(27000000)), big.NewInt(18000000))
		halfTh = halfs.Int64() + 2
	}

	halfN = int64(math2.Pow(float64(2), float64(halfTh)))

	return
}

// Authorize injects a private key into the consensus engine to mint new blocks
// with.
func (c *Evertrust) Authorize(signer common.Address, signFn evertrust_types.SignerFn) {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.signer = signer
	c.signFn = signFn
}

// Seal implements consensus.Engine, attempting to create a sealed block using
// the local signing credentials.
func (c *Evertrust) Seal(chain consensus.ChainReader, block *types.Block, stop <-chan struct{}) (*types.Block, error) {
	header := block.Header()

	// Sealing the genesis block is not supported
	number := header.Number.Uint64()
	if number == 0 {
		return nil, errUnknownBlock
	}

	if !evertrust.Perf {
		c.lock.RLock()
		signer, signFn := c.signer, c.signFn
		c.lock.RUnlock()

		signature, err := signFn(accounts.Account{Address: signer}, header.HashNoSignature().Bytes())
		if err != nil {
			return nil, err
		}

		header.Signature = signature
	}

	blockseal := block.WithSeal(header)

	return blockseal, nil
}

// CalcDifficulty is the difficulty adjustment algorithm. It returns the difficulty
// that a new block should have based on the previous blocks in the chain and the
// current signer.
func (c *Evertrust) CalcDifficulty(chain consensus.ChainReader, time uint64, parent *types.Header) *big.Int {
	difficulty := big.NewInt(128)
	return difficulty
}

// Close implements consensus.Engine. It's a noop for Evertrust as there is are no background threads.
func (c *Evertrust) Close() error {
	return nil
}

// APIs implements consensus.Engine, returning the user facing RPC API to allow
// controlling the signer voting.
func (c *Evertrust) APIs(chain consensus.ChainReader) []rpc.API {
	return []rpc.API{{
		Namespace: "Evertrust",
		Version:   "1.0",
		Service:   &API{chain: chain, evertrust: c},
		Public:    false,
	}}
}
func (c *Evertrust) GetP2pServer() *p2p.Server {
	return c.stack.Server()
}
