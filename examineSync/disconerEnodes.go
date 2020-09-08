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
	"CRD-chain/p2p/discover"
	"sync"
)

//eNode和discover.Node
type discoverEncodes struct {
	DiscoverNode map[string]*discover.Node
	Lock         sync.RWMutex
}

var DiscoverEncode = discoverEncodes{DiscoverNode: make(map[string]*discover.Node)}

func (d *discoverEncodes) AddDiscoverEnode(id string, node *discover.Node) {
	d.Lock.Lock()
	defer d.Lock.Unlock()
	d.DiscoverNode[id] = node

}

//根据NodeID取出key
func (d *discoverEncodes) GetDiscoverEnodeKey(nodeID discover.NodeID) string {
	d.Lock.RLock()
	defer d.Lock.RUnlock()
	for id, node := range d.DiscoverNode {
			if node.ID.String() == nodeID.String() {
				return id
			}
		}
	return ""
}
func (d *discoverEncodes) DelDiscoverEnodeKey(key string)  {
	d.Lock.Lock()
	defer d.Lock.Unlock()
	delete(d.DiscoverNode,key)
}

func (d *discoverEncodes) GetDiscoverEnode(key string)(node *discover.Node)	{
	d.Lock.RLock()
	defer d.Lock.RUnlock()
	var ok bool
	if node,ok =d.DiscoverNode[key];!ok{
		return nil
	}
	return node
}

func (d *discoverEncodes) RandomGetDiscoverEnode()(node *discover.Node) {
	d.Lock.RLock()
	defer d.Lock.RUnlock()
	for _,node:=range d.DiscoverNode{
		return node
	}
	return nil
}
