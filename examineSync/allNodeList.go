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
package examineSync

import (
	"CRD-chain/common"
	"CRD-chain/p2p/discover"
	"sync"
)

type AllNodeList struct {
	AllNodeListMap map[common.Address]*discover.Node
	lock           sync.RWMutex
}

//维护所有的peer列表
//var AllNodeLists = AllNodeList{AllNodeListMap: make(map[common.Address]*discover.Node)}

func (n *AllNodeList) AddNode(address common.Address, node *discover.Node) {
	n.lock.Lock()
	defer n.lock.Unlock()
	n.AllNodeListMap[address] = node
}

func (n *AllNodeList) FindNode(address common.Address) *discover.Node {
	n.lock.RLock()
	defer n.lock.RUnlock()
	node, ok := n.AllNodeListMap[address]
	if !ok {
		return nil
	}
	return node

}
