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
package cacheBlock

import (
	"crypto/ecdsa"
	"fmt"
	"CRD-chain/common"
	"CRD-chain/log"
	"CRD-chain/p2p/discover"
	"sync"
)

type AddrAndPubkey struct {
	AddrPubkeyMap map[common.Address]*ecdsa.PublicKey
	PeerIDAddrMap map[string]common.Address //[peerID]add
	Lock          sync.RWMutex
}

var AddrAndPubkeyMap = AddrAndPubkey{

	AddrPubkeyMap: make(map[common.Address]*ecdsa.PublicKey),
	PeerIDAddrMap: make(map[string]common.Address),
}

func (p *AddrAndPubkey) AddrAndPubkeySet(add common.Address, pub *ecdsa.PublicKey) {
	p.Lock.Lock()
	defer p.Lock.Unlock()
	if _, ok := p.AddrPubkeyMap[add]; !ok {
		p.AddrPubkeyMap[add] = pub
		id := fmt.Sprintf("%x", discover.PubkeyID(pub).Bytes()[:8])
		log.Info("存入的id和地址","id",id,"add",add)
		p.PeerIDAddrMap[id] = add
	}

}

func (p *AddrAndPubkey) AddrAndPubkeyGet(add common.Address) (bool, *ecdsa.PublicKey) {
	p.Lock.RLock()
	defer p.Lock.RUnlock()
	pub, ok := p.AddrPubkeyMap[add]
	return ok, pub
}

func (p *AddrAndPubkey) PeerIDAddrMapGet(id string) common.Address {
	p.Lock.RLock()
	defer p.Lock.RUnlock()
	return p.PeerIDAddrMap[id]
}