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
	"math/big"
	"CRD-chain/ethdb"
	"CRD-chain/log"
	"sync"
)

//本地储存的所有commit高度对应的assertion的累计数量

type CommitHeightToAssertionSum struct {
	CommitHeightToAssertionSumLru *lru.Cache
	Lock                          sync.RWMutex
}

var CommitAssertionSum = NewCommitHeightToAssertionSum()

func NewCommitHeightToAssertionSumLru() *lru.Cache {
	cache, _ := lru.New(20)
	return cache
}

func NewCommitHeightToAssertionSum() CommitHeightToAssertionSum {
	return CommitHeightToAssertionSum{
		CommitHeightToAssertionSumLru: NewCommitHeightToAssertionSumLru(),
	}
}

func (c *CommitHeightToAssertionSum) SetAssertionSum(assertionSum, height *big.Int, db ethdb.Database) (err error) {
	//c.Lock.Lock()
	//defer c.Lock.Unlock()
	log.Info("SetAssertionSum存的key", "key", height.String(), "value", assertionSum)
	c.CommitHeightToAssertionSumLru.Add(height.String(), assertionSum.Bytes())

	err = db.Put([]byte(height.String()+"AssertionSum"), assertionSum.Bytes())
	if err != nil {
		log.Error("SetAssertionSum db.Pu fail", "err", err)
		return err
	}
	return nil
}

func (c *CommitHeightToAssertionSum) GetAssertionSum(height *big.Int, db ethdb.Database) (*big.Int, error) {
	//c.Lock.Lock()
	//defer c.Lock.Unlock()
	aasNum := big.NewInt(0)
	if Num, ok := c.CommitHeightToAssertionSumLru.Get(height.String()); ok {
		aasNum.SetBytes(Num.([]byte))
		return aasNum, nil
	}
	assNumByte, err := db.Get([]byte(height.String() + "AssertionSum"))
	if err != nil {
		log.Warn("Database Get fail")
		return nil, err
	}

	aasNum.SetBytes(assNumByte)

	return aasNum, nil
}

func (c *CommitHeightToAssertionSum) DelAssertionSum(height *big.Int, db ethdb.Database) error {

	c.CommitHeightToAssertionSumLru.Remove(height.String())
	err := db.Delete([]byte(height.String() + "AssertionSum"))
	return err
}
