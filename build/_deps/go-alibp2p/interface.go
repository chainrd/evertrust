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
 * @Time   : 2019/11/6 2:05 下午
 * @Author : liangc
 *************************************************************************/

package alibp2p

import (
	"context"
	"crypto/ecdsa"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"io"
	"time"
)

type (
	// Deprecated: Use StreamHandlerWithProtocol and SetHandlerWithProtocol / SetHandlerReuseStreamWithProtocol .
	StreamHandler             func(sessionId string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error
	StreamHandlerWithProtocol func(sessionId, protocol string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error

	PreMsg         func() (string, []byte)
	ConnectEventFn func(inbound bool, sessionId string, pubKey *ecdsa.PublicKey)
	// Deprecated: Use OnConnectedEvent and ConnectEventFn.
	ConnectEvent    func(inbound bool, sessionId string, pubKey *ecdsa.PublicKey, preRtn []byte)
	DisconnectEvent func(sessionId string, pubKey *ecdsa.PublicKey)

	Libp2pService interface {
		Alibp2pService
		SetStreamHandler(protoid string, handler func(s network.Stream))
		SendMsg(to, protocolID string, msg []byte) (peer.ID, network.Stream, int, error)
		Nodekey() *ecdsa.PrivateKey
	}

	Alibp2pService interface {
		Start()
		Myid() (id string, addrs []string)
		Connect(url string) error
		ClosePeer(pubkey *ecdsa.PublicKey) error
		SetBootnode(peer ...string) error

		// Deprecated: Use SetHandlerWithProtocol
		SetHandler(pid string, handler StreamHandler)
		// Deprecated: Use SetHandlerReuseStreamWithProtocol
		SetHandlerReuseStream(pid string, handler StreamHandler)

		SetHandlerWithProtocol(pid string, handler StreamHandlerWithProtocol)
		SetHandlerReuseStreamWithProtocol(pid string, handler StreamHandlerWithProtocol)

		SendMsgAfterClose(to, protocolID string, msg []byte) error
		Request(to, proto string, msg []byte) ([]byte, error)

		RequestWithTimeout(to, proto string, pkg []byte, timeout time.Duration) ([]byte, error)

		PreConnect(pubkey *ecdsa.PublicKey) error

		// Deprecated: Use OnConnectedEvent.
		OnConnected(ConnType, PreMsg, ConnectEvent)

		OnConnectedEvent(ConnType, ConnectEventFn)
		OnDisconnected(DisconnectEvent)

		Table() map[string][]string       // map => {id:addrs}
		RoutingTable() ([]peer.ID, error) // find in kbuckets

		Conns() (direct []string, relay []string)
		Peers() (direct []string, relay map[string][]string, total int)
		PeersWithDirection() (direct []PeerDirection, relay map[PeerDirection][]PeerDirection, total int)

		PutPeerMeta(id, key string, v interface{}) error
		GetPeerMeta(id, key string) (interface{}, error)

		GetSession(id string) (session string, inbound bool, err error)

		Addrs(id string) ([]string, error)

		Findpeer(id string) ([]string, error) // return addrs,err

		BootstrapOnce() error

		Put(k string, v []byte) error
		Get(k string) ([]byte, error)

		Protect(id, tag string) error
		Unprotect(id, tag string) (bool, error)

		// 设置 ns 的全局 ttl 值
		SetAdvertiseTTL(ns string, ttl time.Duration)
		Advertise(ctx context.Context, ns string)

		FindProviders(ctx context.Context, ns string, limit int) ([]string, error)

		Report(peerid ...string) []byte

		GetProtocols(id string) ([]string, error)
	}
)
