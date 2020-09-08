// Copyright 2015 The go-ethereum Authors
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

package eth

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"os"
	"os/exec"
	"CRD-chain/log"
	"CRD-chain/evertrust"
	"CRD-chain/evertrust/utils"
	"sync"
	"sync/atomic"
	"time"

	"github.com/deckarep/golang-set"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/p2p"
	"CRD-chain/rlp"
)

var (
	errClosed            = errors.New("peer set is closed")
	errAlreadyRegistered = errors.New("peer is already registered")
	errNotRegistered     = errors.New("peer is not registered")
)

const (
	maxKnownTxs    = 32768 // Maximum transactions hashes to keep in the known list (prevent DOS)
	maxKnownBlocks = 1024  // Maximum block hashes to keep in the known list (prevent DOS)

	// maxQueuedTxs is the maximum number of transaction lists to queue up before
	// dropping broadcasts. This is a sensitive number as a transaction list might
	// contain a single transaction, or thousands.
	maxQueuedTxs = 128

	// maxQueuedProps is the maximum number of block propagations to queue up before
	// dropping broadcasts. There's not much point in queueing stale blocks, so a few
	// that might cover uncles should be enough.
	maxQueuedProps = 4

	// maxQueuedAnns is the maximum number of block announcements to queue up before
	// dropping broadcasts. Similarly to block propagations, there's no point to queue
	// above some healthy uncle limit, so use that.
	maxQueuedAnns = 4

	handshakeTimeout = 5 * time.Second
)

// PeerInfo represents a short summary of the Ethereum sub-protocol metadata known
// about a connected peer.
type PeerInfo struct {
	Version    int      `json:"version"`    // Ethereum protocol version negotiated
	Difficulty *big.Int `json:"difficulty"` // Total difficulty of the peer's blockchain
	Head       string   `json:"head"`       // SHA3 hash of the peer's best owned block
}

// propEvent is a block propagation, waiting for its turn in the broadcast queue.
type propEvent struct {
	block     *types.Block
	td        *big.Int
	commitNum uint64
}

type peer struct {
	id string

	*p2p.Peer
	rw p2p.MsgReadWriter

	version  int         // Protocol version negotiated
	forkDrop *time.Timer // Timed connection dropper if forks aren't validated in time
	//CRD
	CommitNum uint64

	head common.Hash
	td   *big.Int
	lock sync.RWMutex

	knownTxs     mapset.Set                // Set of transaction hashes known to be known by this peer
	knownBlocks  mapset.Set                // Set of block hashes known to be known by this peer
	knownCBlocks mapset.Set                // CRD
	queuedTxs    chan []*types.Transaction // Queue of transactions to broadcast to the peer
	queuedProps  chan *propEvent           // Queue of blocks to broadcast to the peer
	queuedAnns   chan *types.Block         // Queue of blocks to announce to the peer
	term         chan struct{}             // Termination channel to stop the broadcaster
}

func newPeer(version int, p *p2p.Peer, rw p2p.MsgReadWriter) *peer {
	return &peer{
		Peer:         p,
		rw:           rw,
		version:      version,
		id:           fmt.Sprintf("%x", p.ID().Bytes()[:8]),
		knownTxs:     mapset.NewSet(),
		knownBlocks:  mapset.NewSet(),
		knownCBlocks: mapset.NewSet(),
		queuedTxs:    make(chan []*types.Transaction, maxQueuedTxs),
		queuedProps:  make(chan *propEvent, maxQueuedProps),
		queuedAnns:   make(chan *types.Block, maxQueuedAnns),
		term:         make(chan struct{}),
	}
}

// broadcast is a write loop that multiplexes block propagations, announcements
// and transaction broadcasts into the remote peer. The goal is to have an async
// writer that does not lock up node internals.
func (p *peer) broadcast() {
	for {
		select {
		case txs := <-p.queuedTxs:

			if err := p.SendTransactions(txs); err != nil {
				log.Error("SendTransactions error", "err", err)
				return
			}

			//p.Log().Info("Broadcast transactions", "count", len(txs))

		case prop := <-p.queuedProps:
			if err := p.SendNewBlock(prop.block, prop.td, prop.commitNum); err != nil {
				log.Error("SendNewBlock error", "err", err)
				return
			}

		case block := <-p.queuedAnns:
			if err := p.SendNewBlockHashes([]common.Hash{block.Hash()}, []uint64{block.NumberU64()}); err != nil {
				log.Error("SendNewBlockHashes error", "err", err)
				return
			}
			//p.Log().Info("Announced block broadcast loop", "number", block.Number(), "hash", block.Hash())

		case <-p.term:
			log.Error("Termination channel to stop the broadcaster")
			return
		}
	}
}

// close signals the broadcast goroutine to terminate.
func (p *peer) close() {
	close(p.term)
}

// Info gathers and returns a collection of metadata known about a peer.
func (p *peer) Info() *PeerInfo {
	hash, td := p.Head()

	return &PeerInfo{
		Version:    p.version,
		Difficulty: td,
		Head:       hash.Hex(),
	}
}

// Head retrieves a copy of the current head hash and total difficulty of the
// peer.
func (p *peer) Head() (hash common.Hash, td *big.Int) {
	p.lock.RLock()
	defer p.lock.RUnlock()

	copy(hash[:], p.head[:])
	return hash, new(big.Int).Set(p.td)
}

// SetHead updates the head hash and total difficulty of the peer.
func (p *peer) SetHead(hash common.Hash, td *big.Int, commitNum uint64) {
	p.lock.Lock()
	defer p.lock.Unlock()

	copy(p.head[:], hash[:])
	p.td.Set(td)
	atomic.StoreUint64(&p.CommitNum, commitNum)
}

// MarkBlock marks a block as known for the peer, ensuring that the block will
// never be propagated to this particular peer.
func (p *peer) MarkBlock(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known block hash
	for p.knownBlocks.Cardinality() >= maxKnownBlocks {
		p.knownBlocks.Pop()
	}
	p.knownBlocks.Add(hash)
}

func (p *peer) MarkCommitBlock(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known block hash
	for p.knownCBlocks.Cardinality() >= maxKnownBlocks {
		p.knownCBlocks.Pop()
	}
	p.knownCBlocks.Add(hash)
}

// MarkTransaction marks a transaction as known for the peer, ensuring that it
// will never be propagated to this particular peer.
func (p *peer) MarkTransaction(hash common.Hash) {
	// If we reached the memory allowance, drop a previously known transaction hash
	for p.knownTxs.Cardinality() >= maxKnownTxs {
		p.knownTxs.Pop()
	}
	p.knownTxs.Add(hash)
}

// SendTransactions sends transactions to the peer and includes the hashes
// in its transaction hash set for future reference.
func (p *peer) SendTransactions(txs types.Transactions) error {
	ewasmtool := utils.EwasmToolImpl
	for i, tx := range txs {
		if tx == nil {
			continue
		}
		p.knownTxs.Add(tx.Hash())
		// add by liangc : 广播交易时对部署 ewasm 合约 payload 重新封包
		if tx.To() == nil && ewasmtool.IsWASM(tx.Data()) {
			code := tx.Data()
			//codekey := crypto.Keccak256(code)
			codekey := ewasmtool.GenCodekey(code)
			final, ok := ewasmtool.GetCode(codekey)
			if ok && len(final) == 32 {
				final, ok = ewasmtool.GetCode(final)
			}
			if !ok {
				log.Error("ewasm 合约 code 没有正确处理，拒绝广播", "tx", tx.Hash().Hex(), "codekey", codekey)
				continue
			}
			finalcode, err := ewasmtool.JoinTxdata(code, final)
			if err != nil {
				log.Error("ewasm 合约 finalcode 合并失败失败，拒绝广播", "tx", tx.Hash().Hex(), "codekey", codekey, "err", err)
				continue
			}
			log.Trace("[SendTransactions] ewasm 合约重新封包", "code", len(code), "final", len(final), "finalcode", len(finalcode))
			ntx, err := tx.CloneAndResetPayload(finalcode)
			if err != nil {
				log.Error("ewasm 封包失败，拒绝广播", "tx", tx.Hash().Hex(), "codekey", codekey, "err", err)
				continue
			}
			txs[i] = ntx
		}
	}
	return p2p.Send(p.rw, TxMsg, txs)
}

// max is a helper function which returns the larger of the two given integers.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// AsyncSendTransactions queues list of transactions propagation to a remote
// peer. If the peer's broadcast queue is full, the event is silently dropped.
func (p *peer) AsyncSendTransactions(txs []*types.Transaction) {
	//log.Info("Dropping transaction AsyncSendTransactions", "通道长度", len(p.queuedTxs))
	select {
	case p.queuedTxs <- txs:
		// Mark all the transactions as known, but ensure we don't overflow our limits
		for p.knownTxs.Cardinality() > max(0, maxKnownTxs-len(txs)) {
			p.knownTxs.Pop()
		}

		for _, tx := range txs {
			p.knownTxs.Add(tx.Hash())
		}
	default:
		p.Log().Warn("Dropping transaction propagation", "count", len(txs))
	}
}

// SendNewBlockHashes announces the availability of a number of blocks through
// a hash notification.
func (p *peer) SendNewBlockHashes(hashes []common.Hash, numbers []uint64) error {
	// Mark all the block hashes as known, but ensure we don't overflow our limits
	for p.knownBlocks.Cardinality() > max(0, maxKnownBlocks-len(hashes)) {
		p.knownBlocks.Pop()
	}

	for _, hash := range hashes {
		p.knownBlocks.Add(hash)
	}
	request := make(newBlockHashesData, len(hashes))
	for i := 0; i < len(hashes); i++ {
		request[i].Hash = hashes[i]
		request[i].Number = numbers[i]
	}
	return p2p.Send(p.rw, NewBlockHashesMsg, request)
}

func (p *peer) SendNewCommitBlockHashes(hashes []common.Hash, numbers []uint64) error {

	request := make(newCommitBlockHashesData, len(hashes))
	for i := 0; i < len(hashes); i++ {
		request[i].Hash = hashes[i]
		request[i].Number = numbers[i]
	}
	return p2p.Send(p.rw, NewCommitBlockHashesMsg, request)
}

// AsyncSendNewBlockHash queues the availability of a block for propagation to a
// remote peer. If the peer's broadcast queue is full, the event is silently
// dropped.
func (p *peer) AsyncSendNewBlockHash(block *types.Block) {
	select {
	case p.queuedAnns <- block:
		p.knownBlocks.Add(block.Hash())
	default:
		p.Log().Debug("Dropping block announcement", "number", block.NumberU64(), "hash", block.Hash())
	}
}

// SendNewBlock propagates an entire block to a remote peer.
func (p *peer) SendNewBlock(block *types.Block, td *big.Int, commitNum uint64) error {
	p.knownBlocks.Add(block.Hash())
	// add by liangc >>>>
	nb, err := repackBlockTxdata(block)
	if err != nil {
		return err
	}
	// add by liangc <<<<
	return p2p.Send(p.rw, NewBlockMsg, []interface{}{nb, td, commitNum})
}

// AsyncSendNewBlock queues an entire block for propagation to a remote peer. If
// the peer's broadcast queue is full, the event is silently dropped.
func (p *peer) AsyncSendNewBlock(block *types.Block, td *big.Int, commitNum uint64) {
	select {
	case p.queuedProps <- &propEvent{block: block, td: td, commitNum: commitNum}:
		p.knownBlocks.Add(block.Hash())
	default:
		log.Debug("Dropping block propagation", "number", block.NumberU64(), "hash", block.Hash())
		//p.Log().Debug("Dropping block propagation", "number", block.NumberU64(), "hash", block.Hash())
	}
}

// SendBlockHeaders sends a batch of block headers to the remote peer.
func (p *peer) SendBlockHeaders(headers []*types.Header) error {
	return p2p.Send(p.rw, BlockHeadersMsg, headers)
}

//CRD
// SendCommitBlocks sends a batch of commit blocks to the remote peer.
func (p *peer) SendCommitBlocks(blocks []*types.Block) error {
	//log.Info("SendCommitBlocks", "blocks", len(blocks), "name", p.Name())
	err := p2p.Send(p.rw, CommitBlocksMsg, blocks)
	return err
}

func (p *peer) SendCommitSyncBlocks(blocks []*types.Block) error {
	return p2p.Send(p.rw, CommitSyncBlocksMsg, blocks)
}

func (p *peer) SendAssociatedCommitBlocks(blocks []*types.Block) error {
	return p2p.Send(p.rw, AssociatedCommitBlocksMsg, blocks)
}

//CRD
func (p *peer) SendCachedBlocksByHash(response cachedBlocksResponse) error {
	return p2p.Send(p.rw, BlocksByHashMsg, response)
}

func (p *peer) SendBlockPath(BlockPath []common.Hash) error {
	return p2p.Send(p.rw, syncBlockPathMsg, BlockPath)
}

func (p *peer) SendBlockSyncInPath(Blocks []*types.Block) error {
	return p2p.Send(p.rw, BlockSyncInPathMsg, Blocks)
}

//func (p *peer) SendBlockChainNode(blockChainNode quorum.BlockchainNode) error {
//	return p2p.Send(p.rw, BlockChainNodeSet, blockChainNode)
//}

// SendBlockBodies sends a batch of block contents to the remote peer.
func (p *peer) SendBlockBodies(bodies []*blockBody) error {
	return p2p.Send(p.rw, BlockBodiesMsg, blockBodiesData(bodies))
}

// SendBlockBodiesRLP sends a batch of block contents to the remote peer from
// an already RLP encoded format.
func (p *peer) SendBlockBodiesRLP(bodies []rlp.RawValue) error {
	err := p2p.Send(p.rw, BlockBodiesMsg, bodies)
	return err
}

func (p *peer) SendBlockBodyRLP(bodies []rlp.RawValue) error {
	err := p2p.Send(p.rw, BlockBodyMsg, bodies)
	return err
}

// SendNodeDataRLP sends a batch of arbitrary internal data, corresponding to the
// hashes requested.
func (p *peer) SendNodeData(data [][]byte) error {
	return p2p.Send(p.rw, NodeDataMsg, data)
}

// SendReceiptsRLP sends a batch of transaction receipts, corresponding to the
// ones requested from an already RLP encoded format.
func (p *peer) SendReceiptsRLP(receipts []rlp.RawValue) error {
	log.Info("SendReceiptsRLP", "id", p.id, "name", p.Name())
	return p2p.Send(p.rw, ReceiptsMsg, receipts)
}

// RequestOneHeader is a wrapper around the header query functions to fetch a
// single header. It is used solely by the fetcher.
func (p *peer) RequestOneHeader(hash common.Hash) error {
	p.Log().Debug("Fetching single header", "hash", hash)
	return p2p.Send(p.rw, GetBlockHeadersMsg, &getBlockHeadersData{Origin: hashOrNumber{Hash: hash}, Amount: uint64(1), Skip: uint64(0), Reverse: false})
}

// RequestHeadersByHash fetches a batch of blocks' headers corresponding to the
// specified header query, based on the hash of an origin block.
func (p *peer) RequestHeadersByHash(origin common.Hash, amount int, skip int, reverse bool) error {
	p.Log().Debug("Fetching batch of headers ByHash", "count", amount, "fromhash", origin, "skip", skip, "reverse", reverse)
	return p2p.Send(p.rw, GetBlockHeadersMsg, &getBlockHeadersData{Origin: hashOrNumber{Hash: origin}, Amount: uint64(amount), Skip: uint64(skip), Reverse: reverse})
}

// RequestHeadersByNumber fetches a batch of blocks' headers corresponding to the
// specified header query, based on the number of an origin block.
func (p *peer) RequestHeadersByNumber(origin uint64, amount int, skip int, reverse bool) error {
	p.Log().Debug("Fetching batch of headers ByNumber", "count", amount, "fromnum", origin, "skip", skip, "reverse", reverse)
	return p2p.Send(p.rw, GetBlockHeadersMsg, &getBlockHeadersData{Origin: hashOrNumber{Number: origin}, Amount: uint64(amount), Skip: uint64(skip), Reverse: reverse})
}

//CRD
func (p *peer) RequestCommitsByNumber(origin uint64, amount int, skip int, reverse bool) error {
	p.Log().Debug("Fetching batch of commit headers", "count", amount, "fromnum", origin, "skip", skip, "reverse", reverse)
	return p2p.Send(p.rw, GetCommitBlocksByNumMsg, &getBlockHeadersData{Origin: hashOrNumber{Number: origin}, Amount: uint64(amount), Skip: uint64(skip), Reverse: reverse})
}

//CRD
func (p *peer) RequestCommitsByHash(origin common.Hash, amount int, skip int, reverse bool) error {
	p.Log().Debug("Fetching batch of commit Hash", "name", p.Name(), "count", amount, "fromnum", origin, "skip", skip, "reverse", reverse)
	return p2p.Send(p.rw, GetCommitBlocksMsg, &getBlockHeadersData{Origin: hashOrNumber{Hash: origin}, Amount: uint64(amount), Skip: uint64(skip), Reverse: reverse})
}

func (p *peer) RequestLatest() error {
	return p2p.Send(p.rw, GetLatestCommitBlockMsg, &struct{}{})
}

func (p *peer) RequestNormalLatest() error {
	return p2p.Send(p.rw, GetLatestNormalBlockMsg, &struct{}{})
}

// RequestBodies fetches a batch of blocks' bodies corresponding to the hashes
// specified.
func (p *peer) RequestBodies(hashes []common.Hash) error {
	p.Log().Debug("Fetching batch of block bodies", "count", len(hashes), "name", p.Name())
	return p2p.Send(p.rw, GetBlockBodiesMsg, hashes)
}

func (p *peer) RequestBody(hashes []common.Hash) error {
	p.Log().Debug("Fetching batch of block body", "count", len(hashes), "name", p.Name())
	return p2p.Send(p.rw, GetBlockBodyMsg, hashes)
}

// RequestNodeData fetches a batch of arbitrary data from a node's known state
// data, corresponding to the specified hashes.
func (p *peer) RequestNodeData(hashes []common.Hash) error {
	p.Log().Debug("Fetching batch of state data", "count", len(hashes))
	return p2p.Send(p.rw, GetNodeDataMsg, hashes)
}

// RequestReceipts fetches a batch of transaction receipts from a remote node.
func (p *peer) RequestReceipts(hashes []common.Hash) error {
	p.Log().Debug("Fetching batch of receipts", "count", len(hashes))
	return p2p.Send(p.rw, GetReceiptsMsg, hashes)
}

func (p *peer) RequestIsland() error {
	p.Log().Debug("Fetching batch of Island")
	return p2p.Send(p.rw, ReceiptsIsland, nil)
}

func (p *peer) SendIslandBlock(Blocks []*types.Block) error {
	return p2p.Send(p.rw, SendIslandLand, Blocks)
}

// Handshake executes the eth protocol handshake, negotiating version number,
// network IDs, difficulties, head and genesis blocks.
func (p *peer) Handshake(network uint64, td *big.Int, head common.Hash, genesis common.Hash, commitNum uint64, flags p2p.ConnFlag) error {
	// Send out own handshake in a new thread
	errc := make(chan error, 2)
	var status statusData // safe to read after two values have been received from errc

	go func() {
		extension := make(map[string]interface{})
		extension["timestamp"] = time.Now().UnixNano() / 1000000
		//log.Debug("发送的时间戳", "timestamp", extension["timestamp"])
		if evertrust.Consortium {
			extension["cert"] = evertrust.Cert
			extension["certKeyId"] = evertrust.CertRootId
		}

		eByts, err := json.Marshal(extension)
		if err != nil {
			log.Error("json marshal extension", "err", err)
			return
		}

		log.Debug("<- status msg", "id", p.Peer.Name())
		errc <- p2p.Send(p.rw, StatusMsg, &statusData{
			ProtocolVersion: uint32(p.version),
			NetworkId:       network,
			TD:              td,
			CurrentBlock:    head,
			GenesisBlock:    genesis,
			CommitNum:       commitNum,
			Extension:       eByts,
			Flags:           uint32(flags),
		})
	}()
	local := time.Now().UnixNano() / 1000000
	go func() {
		errc <- p.readStatus(local, &status, genesis)
	}()
	timeout := time.NewTimer(handshakeTimeout)
	defer timeout.Stop()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errc:
			if err != nil {
				log.Error("handshake", "err", err)
				return err
			}
			// add by liangc
			if err := p.CheckFlags(int32(flags)); err != nil {
				log.Warn("local ignore handshake", "id", p.Name())
				return err
			}
		case <-timeout.C:
			return p2p.DiscReadTimeout
		}
	}
	p.td, p.head = status.TD, status.CurrentBlock
	atomic.StoreUint64(&p.CommitNum, status.CommitNum)
	return nil
}

func (p *peer) readStatus(local int64, status *statusData, genesis common.Hash) (err error) {
	msg, err := p.rw.ReadMsg()
	if err != nil {
		return err
	}
	if msg.Code != StatusMsg {
		return errResp(ErrNoStatusMsg, "first msg has code %x (!= %x)", msg.Code, StatusMsg)
	}
	if msg.Size > p2p.ProtocolMaxMsgSize {
		return errResp(ErrMsgTooLarge, "%v > %v", msg.Size, p2p.ProtocolMaxMsgSize)
	}
	// Decode the handshake and make sure everything matches
	if err := msg.Decode(&status); err != nil {
		return errResp(ErrDecode, "msg %v: %v", msg, err)
	}
	// add by liangc
	if err := p.CheckFlags(int32(status.Flags)); err != nil {
		log.Warn("remote peer reject handshake", "id", p.Name())
		return err
	}
	if status.GenesisBlock != genesis {
		return errResp(ErrGenesisBlockMismatch, "%x (!= %x)", status.GenesisBlock[:8], genesis[:8])
	}
	/*
		if status.NetworkId != network {
			return errResp(ErrNetworkIdMismatch, "%d (!= %d)", status.NetworkId, network)
		}*/
	if int(status.ProtocolVersion) != p.version {
		return errResp(ErrProtocolVersionMismatch, "%d (!= %d)", status.ProtocolVersion, p.version)
	}

	//timestamp verify
	extension := make(map[string]interface{})
	err = json.Unmarshal(status.Extension, &extension)
	if err != nil {
		log.Error("json unmarshal extension", "err", err)
		return err
	}

	timestamp, ok := extension["timestamp"].(float64)
	//log.Debug("接收到的时间戳1", "timestamp", timestamp, "extension", extension)
	if !ok {
		log.Error("assert timestamp fail")
		return errors.New("assert timestamp fail")
	}
	log.Debug("接收到的时间戳2", "local", local, "remote", timestamp,"gap",local-int64(timestamp))
	if err := VerifyTimestamp(int64(timestamp),local); err != nil {
		return p2p.DiscTimestampVerifyError
	}

	//consortium verify
	if evertrust.Consortium {
		//log.Debug("cert证书是什么？", "extension", extension, "type", reflect.TypeOf(extension["cert"]))
		cert, ok := extension["cert"].(string)
		if !ok {
			log.Error("assert cert fail")
			return errors.New("assert cert fail")
		}
		certKeyId, ok := extension["certKeyId"].(string)
		if !ok {
			log.New("assert keyId error")
			return errors.New("assert keyId error")
		}
		if err := VerifyConsortiumCert(cert, certKeyId); err != nil {
			return p2p.DiscCertVerifyError
		}
	}

	return nil
}

func VerifyTimestamp(remote,local int64) error {
	//log.Debug("into verify timestamp", "remote", remote)
	//local := time.Now().UnixNano() / 1000000
	gap := math.Abs(float64(local - remote))
	//log.Debug("@@@@@@@@@@", "gap", gap, "local", local)
	if gap > 500 { //500ms
		log.Error("timestamp gap too deep", "local", local, "remote", remote,"gap",local-remote)
		return fmt.Errorf("timestamp gap too deep, local:%d, remote:%d", local, remote)
	}

	return nil
}

func VerifyConsortiumCert(cert string, certKeyId string) error {
	//check cert func
	check := func(ca string, remotCert string) bool {
		if remotCert == "" {
			log.Error("certs empty")
			return false
		}
		nodeCrt := remotCert

		cert := evertrust.DataDir + "/cert_tmp.crt"
		f1, err := os.OpenFile(cert, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		defer f1.Close()
		if err != nil {
			log.Error("open cert error", "err", err)
			return false
		}
		_, err = f1.Write([]byte(nodeCrt))
		if err != nil {
			log.Error("write cert error", "err", err)
			return false
		}

		chain := evertrust.DataDir + "/chain_tmp.crt"
		f2, err := os.OpenFile(chain, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		defer f2.Close()
		if err != nil {
			log.Error("open chain error", "err", err)
			return false
		}
		_, err = f2.Write([]byte(ca))
		if err != nil {
			log.Error("write chain error", "err", err)
			return false
		}

		//check certificate chain
		shell := fmt.Sprintf("openssl verify -CAfile %s %s", chain, cert)
		out, err := exec.Command("/bin/bash", "-c", shell).Output()
		if err != nil {
			log.Error("command error", "err", err)
			return false
		}
		log.Info("command exec", "result", string(out))
		if string(out) == cert+": OK\n" {
			log.Info("cert chain verify success")
			return true
		}

		return false
	}

	//consortium chain check cert
	if evertrust.Consortium {
		if cert == "" {
			log.Error("cert is nil")
			return fmt.Errorf("cert is nil")
		}

		if certKeyId == "" {
			log.Error("keyId is nil")
			return fmt.Errorf("keyId is nil")

		}

		//var certs []string
		//err := rlp.DecodeBytes(cert, &certs)
		//if err != nil {
		//	log.Error("decode msg rest", "err", err)
		//	return fmt.Errorf("decode msg rest err:%v", err)
		//}
		//
		//var rootId string
		//err = rlp.DecodeBytes(certKeyId, &rootId)
		//if err != nil {
		//	log.Error("decode ca hash", "err", err)
		//	return fmt.Errorf("decode ca hash err:%v", err)
		//}

		//log.Debug("key id map!!!!!!!!!!!!!", "map", evertrust.RootIdCaMap)
		ca, ok := evertrust.RootIdCaMap[certKeyId]
		if !ok {
			log.Error("not find ca")
			return fmt.Errorf("not find ca")
		}

		//check certs
		if ok := check(ca, cert); !ok {
			return fmt.Errorf("check cert fail")
		}
	}

	return nil
}

// String implements fmt.Stringer.
func (p *peer) String() string {
	return fmt.Sprintf("Peer %s [%s]", p.id,
		fmt.Sprintf("eth/%2d", p.version),
	)
}

// peerSet represents the collection of active peers currently participating in
// the Ethereum sub-protocol.
type peerSet struct {
	peers  map[string]*peer
	lock   sync.RWMutex
	closed bool
}

// newPeerSet creates a new peer set to track the active participants.
func newPeerSet() *peerSet {
	return &peerSet{
		peers: make(map[string]*peer),
	}
}

// Register injects a new peer into the working set, or returns an error if the
// peer is already known. If a new peer it registered, its broadcast loop is also
// started.
func (ps *peerSet) Register(p *peer) error {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	if ps.closed {
		return errClosed
	}
	if _, ok := ps.peers[p.id]; ok {
		return errAlreadyRegistered
	}
	ps.peers[p.id] = p
	go p.broadcast()

	return nil
}

// Unregister removes a remote peer from the active set, disabling any further
// actions to/from that particular entity.
func (ps *peerSet) Unregister(id string) error {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	p, ok := ps.peers[id]
	if !ok {
		return errNotRegistered
	}
	delete(ps.peers, id)
	p.close()

	return nil
}

// Peer retrieves the registered peer with the given id.
func (ps *peerSet) Peer(id string) *peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return ps.peers[id]
}

// Len returns if the current number of peers in the set.
func (ps *peerSet) Len() int {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return len(ps.peers)
}

// Peers retrieves a list of all peers.
func (ps *peerSet) Peers() []*peer {
	log.Info("开始获取锁(ps *peerSet) Peers()")
	ps.lock.RLock()
	log.Info("获取锁成功(ps *peerSet) Peers()")
	defer ps.lock.RUnlock()

	list := make([]*peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		list = append(list, p)

	}
	return list
}

func (ps *peerSet) PeersMap() map[string]*peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	return ps.peers
}

// PeersWithoutBlock retrieves a list of peers that do not have a given block in
// their set of known hashes.
func (ps *peerSet) PeersWithoutBlock(hash common.Hash) []*peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	list := make([]*peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		if !p.knownBlocks.Contains(hash) {
			list = append(list, p)
		}
	}
	return list
}

//CRD
func (ps *peerSet) PeersWithoutCommitBlock(hash common.Hash) []*peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	list := make([]*peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		if !p.knownCBlocks.Contains(hash) {
			list = append(list, p)
		}
	}
	return list
}

// PeersWithoutTx retrieves a list of peers that do not have a given transaction
// in their set of known hashes.
func (ps *peerSet) PeersWithoutTx(hash common.Hash) []*peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	list := make([]*peer, 0, len(ps.peers))
	for _, p := range ps.peers {
		if !p.knownTxs.Contains(hash) {
			list = append(list, p)
		}
	}
	return list
}

// BestPeer retrieves the known peer with the currently highest total difficulty.
func (ps *peerSet) BestPeer() *peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	var (
		bestPeer *peer
		bestTd   *big.Int
	)
	for _, p := range ps.peers {
		if _, td := p.Head(); bestPeer == nil || td.Cmp(bestTd) > 0 {
			bestPeer, bestTd = p, td
		}
	}
	return bestPeer
}

// rand n peers
func (ps *peerSet) RandPeers(n int) (peers []*peer) {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	ln := len(ps.peers)
	if ln <= n {
		for _, p := range ps.peers {
			peers = append(peers, p)
		}
	} else {
		//shuffle
		rs := rand.Perm(ln)
		var rsm = make(map[int]struct{})
		for _, v := range rs[:n] {
			rsm[v] = struct{}{}
		}

		i := 0
		for _, p := range ps.peers {
			if _, ok := rsm[i]; ok {
				peers = append(peers, p)
			}
			i++
		}
	}

	return
}

func (ps *peerSet) SyncPeer() *peer {
	ps.lock.RLock()
	defer ps.lock.RUnlock()

	var (
		syncPeer *peer
		heighest uint64
	)
	for _, p := range ps.peers {
		commitNum := atomic.LoadUint64(&p.CommitNum)
		if syncPeer == nil || commitNum > heighest {
			syncPeer, heighest = p, commitNum
		}
	}
	return syncPeer
}

// Close disconnects all peers.
// No new peers can be registered after Close has returned.
func (ps *peerSet) Close() {
	ps.lock.Lock()
	defer ps.lock.Unlock()

	for _, p := range ps.peers {
		p.Disconnect(p2p.DiscQuitting)
	}
	ps.closed = true
}

// add by liangc : 广播新块时 ewasm 合约 payload 重新封包
func repackBlockTxdata(block *types.Block) (*types.Block, error) {
	var (
		nb        *types.Block
		nbtxs     types.Transactions
		ewasmtool = utils.EwasmToolImpl
	)
	for i, tx := range block.Transactions() {
		if tx.To() == nil && ewasmtool.IsWASM(tx.Data()) {
			if nb == nil {
				nb, _ = block.CloneAndResetTxs(nil, true)
				nbtxs = nb.Transactions()
			}
			code := tx.Data()
			// 处理 meta ，不接受任何异常
			//codekey := crypto.Keccak256(code)
			codekey := ewasmtool.GenCodekey(code)
			final, ok := ewasmtool.GetCode(codekey)
			if ok && len(final) == 32 {
				final, ok = ewasmtool.GetCode(final)
			}
			if !ok {
				log.Error("repackBlockTxdata-error 0", "tx", tx.Hash().Hex(), "codekey", codekey)
				return nil, errors.New("ewasm code notfound.")
			}
			finalcode, err := ewasmtool.JoinTxdata(code, final)
			log.Info("repackBlockTxdata------>",
				"txhash", tx.Hash().Hex(),
				"codekey", hex.EncodeToString(codekey),
				"code", len(code),
				"final", len(final),
				"finalcode", len(finalcode),
				"c", code[:128],
				"f", final[:128],
				"fc", finalcode[:128])

			if err != nil {
				log.Error("repackBlockTxdata-error 1", "tx", tx.Hash().Hex(), "codekey", codekey, "err", err)
				return nil, err
			}
			log.Debug("repackBlockTxdata-info", "code", len(code), "final", len(final), "finalcode", len(finalcode))
			ntx, err := tx.CloneAndResetPayload(finalcode)
			if err != nil {
				log.Error("repackBlockTxdata-error 2", "tx", tx.Hash().Hex(), "codekey", codekey, "err", err)
				return nil, err
			}
			if nbtxs != nil {
				nbtxs[i] = ntx
			}
		}
	}
	if nb != nil && nbtxs != nil {
		nb, err := nb.CloneAndResetTxs(nbtxs, false)
		if err != nil {
			log.Error("repackBlockTxdata-error 3", "err", err)
			return nil, err
		}
		log.Error("repackBlockTxdata-success", "block", nb.Number())
		return nb, nil
	}
	return block, nil
}
