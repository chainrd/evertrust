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
	"github.com/hashicorp/golang-lru"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"sync"
)

type cacheBlockChain struct {
	CacheBlock *lru.Cache
	//CacheBlockHash *lru.Cache
	CacheBlockHash map[common.Hash]int
	lock sync.RWMutex
}

//临时存储Normal和Commit
var CacheBlocks =cacheBlockChain{
	CacheBlock:NewCacheBlockLru(),
	CacheBlockHash:make(map[common.Hash]int),
}

func NewCacheBlockLru() *lru.Cache {
	cache, _ := lru.New(10)
	return cache
}


func (c *cacheBlockChain)AddBlock(block *types.Block)  {
	c.CacheBlock.Add(block.Hash(),block)
}

func (c *cacheBlockChain)GetBlock(key common.Hash)  (block *types.Block){
	if block,ok := c.CacheBlock.Get(key);ok{
		return block.(*types.Block)
	}
    return nil
}

func (c *cacheBlockChain)DelBlock(key common.Hash)  {
	c.CacheBlock.Remove(key)
}

//func (c *cacheBlockChain)AddBlockHash(hash common.Hash)  {
//	c.CacheBlockHash.Add(hash, struct{}{})
//}
//
//func (c *cacheBlockChain)CheckBlockHash(hash common.Hash)  bool{
//	 _,ok:=c.CacheBlockHash.Get(hash)
//	return ok
//}
//
//func (c *cacheBlockChain)ClearBlockHash(){
//	c.CacheBlockHash.Purge()
//	c.CacheBlock.Purge()
//	return
//}


func (c *cacheBlockChain)AddBlockHash(hash common.Hash)  {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.CacheBlockHash[hash]++
}

func (c *cacheBlockChain)CheckBlockHash(hash common.Hash)  bool{
	c.lock.Lock()
	defer c.lock.Unlock()
	//就取一次
	if _,ok:=c.CacheBlockHash[hash];ok{
		//如果接收到3条以下,就去拿块
		//sum++
		//if sum<=3{
		//	return false
		//}else {
		//	return true
		//}
		return true
	}

	return false
}

func (c *cacheBlockChain)ClearBlockHash(){
	c.lock.Lock()
	defer c.lock.Unlock()
	c.CacheBlockHash=make(map[common.Hash]int)
	return
}