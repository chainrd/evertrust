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
	"math/big"
	"CRD-chain/common"
	core_types "CRD-chain/core/types"
	"CRD-chain/log"
	"CRD-chain/p2p/discover"
	"CRD-chain/rlp"
)

// NewAssertBlockEvent is posted when a block has been imported.
type NewAssertBlockEvent struct {
	Assert AssertExtra
	Nodes  []discover.NodeID
}

// Set in types.Block.header.Extra.Extra
type AssertExtra struct {
	// The block number and hash of last "commit" block
	LatestCommitBlockNumber *big.Int
	LatestCommitBlockHash   common.Hash

	// Asserted block path, since last committed normal block
	BlockPath []common.Hash

	// Signature of block path
	Signature []byte

	// For extension only
	Extra []byte

	ParentCommitHash common.Hash //用来判断assertion是否适用于本次的commit

	// block extension
	MapExtension []byte // block extension(只存放map)

	//multi sign block
	MultiSignBlockEvidence       [][]core_types.Header //normal block
	MultiSignCommitBlockEvidence [][]core_types.Header //commit block
	Version                      uint16
}

func (a *AssertExtra) Encode() ([]byte, error) {
	return rlp.EncodeToBytes(a)
}

func (a *AssertExtra) Decode(data []byte) error {
	return rlp.DecodeBytes(data, a)
}

func AssertExtraDecode(assertBlock *core_types.Block) (BlockExtra, AssertExtra) {
	var blockExtra BlockExtra
	var assertExtra AssertExtra
	err := blockExtra.Decode(assertBlock.Extra())
	if err != nil {
		log.Error("AssertExtraDecode Fail", "err", err)
	}
	err = assertExtra.Decode(blockExtra.Extra)
	if err != nil {
		log.Error("AssertExtraDecode Fail", "err", err)
	}

	return blockExtra, assertExtra
}
