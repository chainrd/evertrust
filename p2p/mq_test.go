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
 * @Time   : 2019/9/21 3:38 下午
 * @Author : liangc
 *************************************************************************/

package p2p

import (
	"fmt"
	rabbithole "github.com/michaelklishin/rabbit-hole"
	"io/ioutil"
	"log"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/common/mclock"
	"CRD-chain/core/types"
	"CRD-chain/crypto"
	"CRD-chain/event"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/rlp"
	"sync"
	"testing"
	"time"
)

var (
	//mqhost := "39.98.202.72:5672,15672"
	mqhost  = "10.0.0.128:9999->39.98.202.72:5672,7777"
	//mqhost  = "10.0.0.110:5978->1.1.1.1:8888,7777"
	newmqFn = func(started int32) (*amqpImpl, common.Address) {
		defer func() {
			highwaystarted = started
		}()
		conf.ChainId = big.NewInt(14514)
		prv, _ := crypto.GenerateKey()
		addr := crypto.PubkeyToAddress(prv.PublicKey)
		amq, _ := NewAmqpChannel(mqhost, prv, new(event.Feed))
		err := amq.Start(addr)
		fmt.Println("start", err)

		return amq, addr
	}
	total    = 0
	doRecvFn = func(impl *amqpImpl) {
		mqr := NewMQMsgReader(common.HexToAddress("0x111"), impl)
		defer mqr.Close()
		for {
			data, err := mqr.ReadMsg()
			total += 1
			mid := crypto.PubkeyToAddress(impl.privateKey.PublicKey).Hex()
			if err != nil {
				fmt.Println("recv_over", mid)
				return
			}
			payload, _ := ioutil.ReadAll(data.Payload)
			fmt.Println("recv-->", mid, "size", data.Size, "code", data.Code, "total", total, "payload", string(payload))
			if string(payload) == "stop" {
				close(impl.stop)
			}
			//time.Sleep(time.Second)
			//fmt.Println("recv --> sleep 1s")
		}
	}
	_doSenderFn = func(impl *amqpImpl, to common.Address, data []byte, count int) {
		for i := 0; i < count; i++ {
			select {
			case <-impl.stop:
				fmt.Println("sender over 1.")
				return
			default:
				mid := crypto.PubkeyToAddress(impl.privateKey.PublicKey).Hex()
				fmt.Println("pub1", mid, "->", to.Hex())
				impl.Publish(to, data)
			}
		}
		impl.Publish(to, []byte("stop"))
	}
)

func TestBindkey(t *testing.T) {
	var (
		amq_recv1, addr1 = newmqFn(0)
		amq_recv2, addr2 = newmqFn(0)
		amq_sender, _    = newmqFn(1)
	)
	go doRecvFn(amq_recv1)
	go doRecvFn(amq_recv2)
	go doRecvFn(amq_sender)

	fmt.Println("p1", publishFn(amq_sender, exchangeName(), Routekeys.Address(addr1), []byte("Foobar 1.")))
	fmt.Println("p2", publishFn(amq_sender, exchangeName(), Routekeys.Address(addr2), []byte("Foobar 2.")))
	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		for i := 0; i < 200; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				fmt.Println("publish-peers", publishFn(amq_sender, exchangeName(Exchangekeys.Peers()), Routekeys.Peers(), []byte("hello")))
			}()
		}
		defer wg.Done()
	}()
	wg.Wait()
	fmt.Println("p2", publishFn(amq_sender, exchangeName(Exchangekeys.Peers()), Routekeys.Peers(), []byte("stop")))
	bis, err := amq_recv1.cli.ListExchangeBindings("/", exchangeName().ToString(), rabbithole.BindingSource)
	fmt.Println(err, bis)
	for i, b := range bis {
		fmt.Println("-->", i, b.RoutingKey, b)
	}
	<-amq_recv1.stop
	time.Sleep(2 * time.Second)
}

func TestRecvAndSend(t *testing.T) {
	var (
		amq_recv, recvAddr = newmqFn(0)
		amq_sender, _      = newmqFn(1)
	)
	go doRecvFn(amq_recv)
	go _doSenderFn(amq_sender, recvAddr, []byte("Hello world."), 1000)
	<-amq_recv.stop
}

func TestEncoder(t *testing.T) {
	data := &types.Header{
		Number: big.NewInt(111),
		Root:   common.HexToHash("0x123"),
		Extra:  []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
	}
	size, r, err := rlp.EncodeToReader(data)
	t.Log("data1", err, size)
	b1, err := ioutil.ReadAll(r)
	t.Log("data1", err, b1)

	data2, err := rlp.EncodeToBytes(data)
	data3, err := rlp.EncodeToBytes(data2)
	size2, r2, err := rlp.EncodeToReader(data2)
	b2, err := ioutil.ReadAll(r2)
	t.Log("data2-src", data2)
	t.Log("data2", err, size2)
	t.Log("data2", err, b2)

	t.Log("data3", err, data3)
}

func TestSSS(t *testing.T) {
	type x struct {
		rw      *conn
		running map[string]*protoRW
		log     log.Logger
		created mclock.AbsTime

		wg       sync.WaitGroup
		protoErr chan error
		closed   chan struct{}
		disc     chan DiscReason

		// events receives message send / receive events if set
		events *event.Feed
		id     common.Address // add by liangc : peer address , hash(pubkey)
		Mrw    MsgWriter      // add by liangc : abstract rw instance
	}
	fmt.Printf("================> x=%v\r\n", &x{})
}
