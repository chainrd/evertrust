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
 * @Time   : 2020/4/2 1:03 下午
 * @Author : liangc
 *************************************************************************/

package p2p

import (
	"CRD-chain/event"
	"time"
)

type (
	AdvertiseEvent struct {
		Start  bool
		Period time.Duration
	}

	AddpeerHandshakeEvent struct {
		Id  []byte
		Err error
	}
)

var (
	alibp2pMailboxEvent   event.Feed // alibp2p 中 mailbox 通道的消息通过这个事件来完成
	alibp2pAdvertiseEvent event.Feed // 同步 commitBlock 和同步完成时都产生此事件
	addpeerHandshakeEvent event.Feed // 用于添加 peer 时广播握手结果
)

func SubscribeAlibp2pAdvertiseEvent(c chan *AdvertiseEvent) event.Subscription {
	return alibp2pAdvertiseEvent.Subscribe(c)
}

func SendAlibp2pAdvertiseEvent(e *AdvertiseEvent) int {
	return alibp2pAdvertiseEvent.Send(e)
}

func SubscribeAddpeerHandshakeEvent(c chan *AddpeerHandshakeEvent) event.Subscription {
	return addpeerHandshakeEvent.Subscribe(c)
}

func SendAddpeerHandshakeEvent(e *AddpeerHandshakeEvent) int {
	return addpeerHandshakeEvent.Send(e)
}
