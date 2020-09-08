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
package types

import (
	"crypto/ecdsa"
	"math/big"
	"math/rand"
	"CRD-chain/accounts"
	"CRD-chain/common"
	"CRD-chain/common/hexutil"
	"CRD-chain/core/types"
	"CRD-chain/crypto"
	"CRD-chain/log"
	"CRD-chain/p2p/discover"
	"CRD-chain/rlp"
	"sync/atomic"
	"time"
)

var (
	SyncCommit atomic.Value

	SyncCommitCh = make(chan uint64, 1)
)

const (
	EVIDENCE_ADD_EXTRA = 0
	EVIDENCE_DEL_EXTRA = 1
	EVIDENCE_EMP_EXTRA = 2
)

func (o *CondensedEvidence) Pubkey() *ecdsa.PublicKey {
	pubkey, _ := o.NodeID.Pubkey()
	return pubkey
}
func (o *CondensedEvidence) Address() common.Address {
	pubkey, _ := o.NodeID.Pubkey()
	addr := crypto.PubkeyToAddress(*pubkey)
	return addr
}

func (o *CondensedEvidence) SetPubkey(pk *ecdsa.PublicKey) {
	o.NodeID = discover.PubkeyID(pk)
}

type CondensedEvidence struct {
	NodeID discover.NodeID

	ExtraKind byte
	// Empty if the full BlockAssert.BlockPath is accepted
	// If ADD, signature on commitExtra.AcceptedBlocks + this.ExtraBlocks
	// IF DEL, signature on commitExtra.AcceptedBlocks - this.ExtraBlocks
	ExtraBlocks []common.Hash

	ParentCommitHash common.Hash //用来判断assertion是否适用于本次的commit
	// Signature of original assertion on CommitExtra.AcceptedBlocks + RejectedBlocks
	Signature []byte
}

// NewCommitBlockEvent is posted when a block has been imported.
type NewCommitBlockEvent struct{ Block *types.Block }

// Set in types.Block.header.Extra.Extra
//note:新的字段放到最后
type CommitExtra struct {
	NewBlockHeight *big.Int //new height of normal ledger confirmed

	AcceptedBlocks []common.Hash

	Evidences []CondensedEvidence

	// Changes on consensus nodes
	MinerAdditions []common.Address
	MinerDeletions []common.Address

	// Change on observatory nodes
	NodeAdditions []common.Address
	NodeDeletions []common.Address

	Reset bool

	Extra []byte

	MapExtension []byte // block extension(只存放map)

	AssertionSum *big.Int

	QualificationHash string
	//如果打commit的时候,收到assertion 不足2/3 就是岛屿
	IslandState
	Version uint64
}

//如果是岛屿块,保存当前commit高度和委员会成员
type IslandState struct {
	Quorum []string
	CNum   uint64
	Island bool
}

func (a *CommitExtra) Encode() ([]byte, error) {
	return rlp.EncodeToBytes(a)
}

func (a *CommitExtra) Decode(data []byte) error {
	return rlp.DecodeBytes(data, a)
}

//create comit block
func NewCommitblock(extra *BlockExtra, parentHash common.Hash, coinbase common.Address, signFn SignerFn) (*types.Block, error) {
	bytes, _ := extra.Encode()
	header := &types.Header{
		Number:     new(big.Int).SetUint64(extra.CNumber.Uint64()),
		Nonce:      types.EncodeNonce(rand.Uint64()),
		Time:       new(big.Int).SetUint64(uint64(time.Now().Unix())),
		ParentHash: parentHash,
		Extra:      bytes,
		GasLimit:   5000000,
		Difficulty: big.NewInt(1024),
		MixDigest:  common.BytesToHash(hexutil.MustDecode("0x0000000000000000000000000000000000000000000000000000000000000000")),
		Root:       crypto.Keccak256Hash(nil),
		Coinbase:   coinbase,
	}

	block := types.NewBlock(header, nil, nil, nil)

	signature, err := signFn(accounts.Account{Address: coinbase}, block.Header().HashNoSignature().Bytes())
	if err != nil {
		log.Error("commit block sign", "err", err)
		return nil, err
	}
	block.SetSignature(signature)

	return block, nil
}

func CommitExtraDecode(commitBlock *types.Block) (BlockExtra, CommitExtra) {
	var blockExtra BlockExtra
	var commitExtra CommitExtra
	if commitBlock != nil && commitBlock.Extra() != nil {
		err := blockExtra.Decode(commitBlock.Extra())
		if err != nil {
			log.Error("CommitExtraDecodeFail", "err", err)
		}
		commitExtra.Decode(blockExtra.Extra)
		if err != nil {
			log.Error("CommitExtraDecodeFail 1", "err", err)
		}
	}
	return blockExtra, commitExtra
}
