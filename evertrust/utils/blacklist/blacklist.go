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
package blacklist

import (
	"math/big"
	"CRD-chain/core/publicBC"
	"CRD-chain/log"
	"sync"
	"time"
)

const (
	Expired                = 3 * 60 * 1000    //millisecond 普通用户在黑名单中的时长
	BadExpired             = 10 * 60 * 1000   //millisecond 恶意用户在黑名单中的时长
	flushBlacklistInterval = 10 * time.Minute //刷新黑名单
)

var (
	BlacklistControlMap sync.Map

	ExpiredBlockNum    int32 //普通用户的黑名单过期块数
	BadExpiredBlockNum int32 //恶意用户的黑名单过期块数
)

func InitFlush() {
	go flushBlacklistControl()
}

//put in 加入低级别黑名单（限制时间较短）
//key 用户的唯一标识
//expired 第几个块后用户从黑名单中剔除
func PutIn(key interface{}) {
	currentBlockNum := public.BC.CurrentBlock().Number()
	expiredBlockNumber := big.NewInt(0).Add(currentBlockNum, big.NewInt(int64(ExpiredBlockNum)))
	BlacklistControlMap.Store(key, expiredBlockNumber)
}

//put in 加入高级别黑名单（限制时间较长）
//key 用户的唯一标识
//expired 第几个块后用户从黑名单中剔除
func PutInBad(key interface{}) {
	currentBlockNum := public.BC.CurrentBlock().Number()
	expiredBlockNumber := big.NewInt(0).Add(currentBlockNum, big.NewInt(int64(BadExpiredBlockNum)))
	BlacklistControlMap.Store(key, expiredBlockNumber)
}

func flushBlacklistControl() {
	ticker := time.NewTicker(flushBlacklistInterval)
	for {
		select {
		case <-ticker.C:
			if public.BC == nil || public.BC.CurrentBlock() == nil {
				continue
			}
			currentBlockNum := public.BC.CurrentBlock().Number()

			BlacklistControlMap.Range(func(key, value interface{}) bool {
				expiredBlockNumber, ok := value.(*big.Int)
				if !ok {
					log.Warn("assertion fail in range blacklist")
				}
				if expiredBlockNumber != nil && expiredBlockNumber.Cmp(currentBlockNum) < 0 {
					BlacklistControlMap.Delete(key)
				}

				return true
			})

			log.Trace("flush blacklist end")
		}
	}
}
