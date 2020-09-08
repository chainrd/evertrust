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
 * @Time   : 2019/10/12 2:16 下午
 * @Author : liangc
 *************************************************************************/

package p2p

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bitly/go-simplejson"
	"github.com/cc14514/go-alibp2p"
	"github.com/libp2p/go-libp2p-core/network"
	"io"
	"math/big"
	"net"
	"os"
	"CRD-chain/event"
	"CRD-chain/log"
	"CRD-chain/p2p/discover"
	"CRD-chain/rlp"
	"CRD-chain/rpc"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	def_reuseStream = true
	def_relay       = true
)

const (
	ProtocolPlume  = "/CRD/plume/1.0.0"  // 仅用来标示 Plume Node ，别无他用
	ProtocolBridge = "/CRD/bridge/1.0.0" // 仅用来标示 Bridge Node ，别无他用

	pingpid                      = "/ping/1.0.0"
	premsgpid                    = "/premsg/1.0.0"
	plumepid                     = "/plume/1.0.0"
	msgpid_tx                    = "/msg/1.0.0"
	msgpid_block                 = "/msg/block/1.0.0"
	mailboxpid                   = "/mailbox/1.0.0"
	senderpool                   = 256
	msgCache                     = 2048
	setupRetryPeriod             = 120              // sec
	bootstrapPeriod, lightPeriod = 45, 10           // sec
	global_chan_timeout          = 15 * time.Second // 全局的管道读写超时
	ProtocolMaxMsgSize           = 10 * 1024 * 1024 // Maximum cap on the size of a protocol message

)

var (
	chanTimeoutErr = func(a string) error {
		return fmt.Errorf("[%s] chan timeout (%v)", a, global_chan_timeout)
	}
)

const FULLNODE AdvertiseNs = "fullnode"

func (a AdvertiseNs) String() string { return string(a) }

const (
	INBOUND  connType = "inbound"
	OUTBOUND connType = "outbound"
	EMPTY    connType = ""
)

const (
	DELPEER_UNLINK  = "unlink"
	DELPEER_DISCONN = "onDisconnected"
)

const (
	setup  connBehaviour = 0x01 // 接受 连接请求
	ignore connBehaviour = 0x02 // 拒绝 连接请求
	relink connBehaviour = 0x03 // 重新 建立信任
	unlink connBehaviour = 0x04 // 解除 信任关系
)

func (b connBehaviour) Bytes() []byte {
	return []byte{byte(b)}
}

type (
	AdvertiseNs   string
	connType      string
	connBehaviour byte
	writeMsg      struct {
		to      string
		data    []byte
		msgType uint64
	}
	Alibp2p struct {
		unlinkEvent                       event.Feed
		started                           int32
		maxpeers                          int
		srv                               *Server
		cfg                               alibp2p.Config
		p2pservice                        alibp2p.Alibp2pService
		msgWriter                         chan writeMsg
		stop                              chan struct{}
		peerCounter                       *peerCounter
		asyncRunner                       *alibp2p.AsyncRunner
		packetFilter                      func(*ecdsa.PublicKey, uint16, uint32) error
		msgReaders, retryList, allowPeers *sync.Map
		disp                              *dispatcher
		advertiseCtxs                     map[AdvertiseNs]context.CancelFunc
		advertiseLock                     *sync.Mutex
	}
	alibp2pTransport struct {
		ctx        context.Context
		pubkey     *ecdsa.PublicKey
		sessionKey string
		service    *Alibp2p
		unlinkCh   chan string
		unlinkSub  event.Subscription
	}
	peerCounter struct {
		counter map[string]map[string]string
		lock    *sync.RWMutex
	}

	// 消息分发机
	dispatcher struct {
		m *sync.Map
		a *Alibp2p
	}
	msgBus struct {
		ctx     context.Context
		cancel  context.CancelFunc
		txCh    chan []byte
		blockCh chan []byte
	}

	ConnInfo struct {
		ID      string
		Addrs   []string
		Inbound bool
	}
)

func newDispatcher(a *Alibp2p) *dispatcher {
	return &dispatcher{
		m: new(sync.Map),
		a: a,
	}
}

func (d *dispatcher) bind(pc *peerCounter, id string) {
	if !pc.has(id) {
		ctx := context.Background()
		ctx, cancel := context.WithCancel(ctx)
		mb := &msgBus{
			ctx:     ctx,
			cancel:  cancel,
			txCh:    make(chan []byte, 1024),
			blockCh: make(chan []byte, 256),
		}
		hFn := func(p []byte) []byte {
			if p != nil && len(p) > 6 {
				return p[:6]
			}
			return nil
		}
		go func() {
			log.Trace("alibp2p::dispatcher-ch-start", "peerid", id)
			defer log.Trace("alibp2p::dispatcher-ch-stop", "peerid", id, "txCh", len(mb.txCh), "blkCh", len(mb.blockCh))
			for {
				var err error
				select {
				case packet := <-mb.txCh:
					//var s = time.Now()
					if d.a != nil {
						err = d.a.p2pservice.SendMsgAfterClose(id, msgpid_tx, packet)
						if err != nil {
							log.Error("alibp2p::dispatcher-ch-tx-error", "peerid", id, "head", hFn(packet), "txCh", len(mb.txCh), "blkCh", len(mb.blockCh), "err", err)
							//go d.a.tryReset(id, err)
						}
					}

					//log.Trace("alibp2p::dispatcher-ch-tx", "peerid", id, "head", hFn(packet), "txCh", len(mb.txCh), "blkCh", len(mb.blockCh), "ts", time.Since(s), "err", err)
				case packet := <-mb.blockCh:
					var s = time.Now()
					if d.a != nil {
						err = d.a.p2pservice.SendMsgAfterClose(id, msgpid_block, packet)
						if err != nil {
							log.Error("alibp2p::dispatcher-ch-block-error", "peerid", id, "head", hFn(packet), "txCh", len(mb.txCh), "blkCh", len(mb.blockCh), "err", err)
							//go d.a.tryReset(id, err)
						}
					}
					log.Trace("alibp2p::dispatcher-ch-block", "peerid", id, "head", hFn(packet), "txCh", len(mb.txCh), "blkCh", len(mb.blockCh), "ts", time.Since(s), "err", err)
				case <-ctx.Done():
					return
				}
			}
		}()
		d.m.Store(id, mb)
	}
}

func (d *dispatcher) unbind(pc *peerCounter, id string) {
	if !pc.has(id) {
		v, ok := d.m.Load(id)
		if ok {
			defer d.m.Delete(id)
			mb := v.(*msgBus)
			log.Trace("alibp2p::dispatcher-unbind-peer", "peerid", id, "txCh", len(mb.txCh), "blkCh", len(mb.blockCh))
			//close(mb.txCh)
			//close(mb.blockCh)
			mb.cancel()
		}
	}
}

func (d *dispatcher) doSendMsg(to string, msgType uint64, packet []byte) error {
	// tx 的 msgType 是 2 / 18
	v, ok := d.m.Load(to)
	if !ok {
		return fmt.Errorf("notfound dispatcher handler : id = %s , msgType = %d", to, msgType)
	}
	mb := v.(*msgBus)
	switch msgType {
	case 2, 18:
		select {
		case mb.txCh <- packet:
			log.Trace("alibp2p::dispatcher-doSendMsg-success", "peerid", to, "msgType", msgType, "datalen", len(packet))
		default:
			log.Trace("alibp2p::dispatcher-doSendMsg-fail", "peerid", to, "msgType", msgType, "txCh", len(mb.txCh))
			return fmt.Errorf("dispatcher-doSendMsg-fail : id = %s , msgType = %d", to, msgType)
		}
	default:
		select {
		case mb.blockCh <- packet:
			log.Trace("alibp2p::dispatcher-doSendMsg-success", "peerid", to, "msgType", msgType, "datalen", len(packet))
		default:
			log.Warn("alibp2p::dispatcher-doSendMsg-fail", "peerid", to, "msgType", msgType, "blockCh", len(mb.blockCh))
			return fmt.Errorf("dispatcher-doSendMsg-fail : id = %s , msgType = %d", to, msgType)
		}
	}
	return nil
}

func newPeerCounter() *peerCounter {
	return &peerCounter{make(map[string]map[string]string), new(sync.RWMutex)}
}

func (self *peerCounter) total(condition connType) int {
	self.lock.RLock()
	defer self.lock.RUnlock()
	total := 0
	for _, sm := range self.counter {
		for _, state := range sm {
			if condition == EMPTY && state != "" {
				total++
				break
			} else if condition != EMPTY && state == string(condition) {
				total++
				break
			}
		}
	}
	log.Trace("alibp2p::peerCounter-total", "condition", condition, "counter", len(self.counter))
	return total
}

func (self *peerCounter) del(id, session string, drop bool) {
	self.lock.Lock()
	defer self.lock.Unlock()
	sm, ok := self.counter[id]
	if drop {
		log.Trace("alibp2p::peerCounter-drop", "id", id, "map", sm)
		delete(self.counter, id)
	} else {
		log.Trace("alibp2p::peerCounter-del", "id", id, "session", session, "map", sm)
		if ok {
			delete(sm, session)
		}
		if len(sm) == 0 {
			delete(self.counter, id)
		}
	}
}

func (self *peerCounter) has(id string) bool {
	self.lock.RLock()
	defer self.lock.RUnlock()
	_, ok := self.counter[id]
	return ok
}

func (self *peerCounter) set(id, session, state string) {
	self.lock.Lock()
	defer self.lock.Unlock()
	sm, ok := self.counter[id]
	if !ok {
		sm = make(map[string]string)
		self.counter[id] = sm
	}
	sm[session] = state
	log.Trace("alibp2p::peerCounter-set", "id", id, "state", state, "session", session, "map", sm)
}

func (self *peerCounter) add(id, session string) {
	self.lock.Lock()
	defer self.lock.Unlock()
	sm, ok := self.counter[id]
	if !ok {
		sm = make(map[string]string)
		self.counter[id] = sm
	}
	sm[session] = ""
	log.Trace("alibp2p::peerCounter-add", "id", id, "session", session, "map", sm)
}

func (self *peerCounter) cmp(i int, condition connType) int {
	total := self.total(condition)
	self.lock.RLock()
	defer self.lock.RUnlock()
	log.Trace("alibp2p::peerCounter-cmp", "input", i, "total", total)
	if total > i {
		return 1
	} else if total < i {
		return -1
	}
	return 0
}

//var i int32

func newAlibp2pTransport2(pubkey *ecdsa.PublicKey, sessionKey string, service *Alibp2p) transport {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	var unlinkCh chan string
	var unlinkSub event.Subscription
	peerid := "mailbox"
	if pubkey != nil {
		peerid, _ = alibp2p.ECDSAPubEncode(pubkey)
		service.disp.bind(service.peerCounter, peerid)
		unlinkCh = make(chan string)
		unlinkSub = service.unlinkEvent.Subscribe(unlinkCh)
		wg := new(sync.WaitGroup)
		wg.Add(1)
		go func() {
			wg.Done()
			for id := range unlinkCh {
				//log.Trace("alibp2p::alibp2pTransport-read-unlink-event", "id", id, "sessionKey", sessionKey)
				if strings.Contains(sessionKey, id) {
					unlinkSub.Unsubscribe()
					cancel()
					log.Trace("alibp2p::alibp2pTransport-stop", "id", id, "sessionKey", sessionKey)
					return
				}
			}
		}()
		wg.Wait()
	}
	log.Trace("alibp2p::alibp2pTransport-start", "id", peerid, "sessionKey", sessionKey)
	return &alibp2pTransport{ctx: ctx, pubkey: pubkey, sessionKey: sessionKey, service: service, unlinkSub: unlinkSub, unlinkCh: unlinkCh}

}

func newAlibp2pTransport(_ net.Conn) transport {
	panic("TODO newAlibp2pTransport")
	return &alibp2pTransport{}
}

func (a alibp2pTransport) doEncHandshake(prv *ecdsa.PrivateKey, dialDest *discover.Node) (discover.NodeID, error) {
	log.Trace("alibp2p::alibp2pTransport.doEncHandshake", "peer", dialDest.ID.String())
	return dialDest.ID, nil
}

func (a alibp2pTransport) doProtoHandshake(our *protoHandshake) (*protoHandshake, error) {
	k, _ := alibp2p.ECDSAPubEncode(a.pubkey)
	//id, _ := discover.BytesID(append(a.pubkey.X.Bytes(), a.pubkey.Y.Bytes()...))
	id := discover.PubkeyID(a.pubkey)
	d := &protoHandshake{Version: baseProtocolVersion, Caps: our.Caps, Name: k, ID: id}
	log.Trace("alibp2p::alibp2pTransport.doProtoHandshake", "peer", id)
	return d, nil
}

func (a alibp2pTransport) ReadMsg() (Msg, error) {
	for !a.service.isStarted() {
		time.Sleep(1 * time.Second)
	}
	s := a.sessionKey
	if a.pubkey != nil {
		s, _ = alibp2p.ECDSAPubEncode(a.pubkey)
	}
	v, ok := a.service.msgReaders.Load(a.sessionKey)
	if !ok {
		log.Error("alibp2p_reader_not_registed : ", "sk", s)
		<-a.ctx.Done()
		return Msg{}, errors.New("alibp2p_reader_not_registed : " + s)
	}
	msgCh := v.(chan Msg)
	for {
		if len(msgCh) >= msgCache/2 {
			log.Warn("alibp2p::alibp2pTransport.read too busy", "session", a.sessionKey, "pendingMsg", len(msgCh))
		}
		select {
		case msg, ok := <-msgCh:
			if !ok {
				log.Error("alibp2p::alibp2pTransport.read : EOF", "peer", s, "msg", msg, "ok", ok, "sessionKey", a.sessionKey)
				return Msg{}, io.EOF
			}
			log.Trace("alibp2p::alibp2pTransport-read-end", "msg", msg)
			return msg, nil
		//case id := <-a.unlinkCh:
		//	if strings.Contains(a.sessionKey, id) {
		//		log.Trace("alibp2p::alibp2pTransport-read-unlink", "id", id)
		//		return Msg{}, errors.New(DELPEER_UNLINK)
		//	}
		case <-a.ctx.Done():
			log.Trace("alibp2p::alibp2pTransport-read-unlink-ctxdone", "session", a.sessionKey)
			return Msg{}, errors.New(DELPEER_UNLINK)
		}
	}
	return Msg{}, errors.New("readmsg error")
}

func (a alibp2pTransport) WriteMsg(msg Msg) error {
	now := time.Now()
	s, _ := alibp2p.ECDSAPubEncode(a.pubkey)
	data, err := msgToBytesFn(msg)
	if err != nil {
		log.Error("alibp2p::alibp2pTransport.write.error", "peer", s, "msg", msg, "err", err)
		return err
	}
	log.Trace("alibp2p::alibp2pTransport.WriteMsg", "to", s, "msg", msg)
	select {
	case a.service.msgWriter <- writeMsg{s, data, msg.Code}:
	case <-time.After(global_chan_timeout):
		log.Error("alibp2p::alibp2pTransport.write-timeout", "peer", s, "msg", msg)
		return chanTimeoutErr("WriteMsg")
	case <-a.ctx.Done():
		log.Trace("alibp2p::alibp2pTransport.write-ctxdone", "session", a.sessionKey)
		return errors.New(DELPEER_UNLINK)
	}
	log.Trace("alibp2p::alibp2pTransport.WriteMsg.success", "peer", s, "msg", msg, "ttl", time.Since(now))
	return nil
}

func (a alibp2pTransport) close(err error) {
	defer func() {
		if a.unlinkSub != nil {
			a.unlinkSub.Unsubscribe()
		}
		if a.unlinkCh != nil {
			close(a.unlinkCh)
		}
	}()
	if r, ok := err.(DiscReason); ok {
		size, p, err := rlp.EncodeToReader(r)
		if err != nil {
			log.Error("alibp2p::rlp encode disReason", "err", err)
		} else {
			log.Trace("alibp2p::write disconnect msg", "reason", r)
			a.WriteMsg(Msg{Code: discMsg, Size: uint32(size), Payload: p})
		}
	}
	// 如果不是 UNLINK 就要断开连接
	if err.Error() != DELPEER_UNLINK {
		closeErr := a.service.Close(a.pubkey)
		log.Trace("alibp2p::alibp2pTransport.close", "sessionkey", a.sessionKey, "err", err, "closeErr", closeErr)
		return
	}
	log.Trace("alibp2p::alibp2pTransport.close : unlink", "sessionkey", a.sessionKey, "err", err)
	_, session, _ := splitSessionkey(a.sessionKey)
	a.service.cleanConnect(a.pubkey, session, DELPEER_UNLINK)
	// >??? 为啥 : 是故意的吗 ???
	//a.service.cleanConnect(a.pubkey, "alibp2pTransport-close", DELPEER_UNLINK)
}

//func (a *Alibp2p) tryReset(id string, err error) {
//	/*	if pub, err2 := alibp2p.ECDSAPubDecode(id); err2 == nil {
//		err3 := a.Close(pub)
//		log.Info("alibp2p::tryReset-start", "id", id, "send-err", err, "close-err", err3)
//		//err4 := a.PreConnect(pub)
//		//log.Info("alibp2p::tryReset-end", "id", id, "close-err", err3, "reconn-err", err4)
//	}*/
//}

func (self *Alibp2p) isInbound(id string) bool {
	v, err := self.p2pservice.GetPeerMeta(id, string(INBOUND))
	if err != nil {
		return false
	}
	if inbound, ok := v.(bool); ok {
		return inbound
	}
	return false
}

func (self *Alibp2p) IsPlumeNode(id string) bool {
	if ps, err := self.p2pservice.GetProtocols(id); err == nil {
		for _, p := range ps {
			if p == ProtocolPlume {
				return true
			}
		}
	}
	return false
}

func (self *Alibp2p) setRetry(sessionkey string, inbound bool) error {
	id, session, err := splitSessionkey(sessionkey)
	if err != nil {
		return err
	}
	//inbound := self.isInbound(id)
	self.retryList.Store(id, []interface{}{inbound, session})
	log.Trace("alibp2p::reset retry", "id", id, "inbound", inbound, "session", session)
	return nil
}

func connLowHi(low, hi int) (uint64, uint64) {
	if connmgr := os.Getenv("CONNMGR"); connmgr != "" {
		lh := strings.Split(connmgr, ",")
		if len(lh) == 2 {
			l, h := lh[0], lh[1]
			a, aerr := strconv.Atoi(l)
			b, berr := strconv.Atoi(h)
			if aerr == nil && berr == nil {
				low, hi = a, b
				fmt.Println("---------------------------------")
				fmt.Println("ConnMgr", "low:", low, "hi:", hi)
				fmt.Println("---------------------------------")
			}
		}
	}
	return uint64(low), uint64(hi)
}

func NewAlibp2p(ctx context.Context, port, muxport, maxpeers int, networkid *big.Int, s *Server, disableRelay, disableInbound *big.Int, packetFilter func(*ecdsa.PublicKey, uint16, uint32) error) *Alibp2p {
	var (
		err              error
		loglevel         = 3
		connLow, connHi  = connLowHi(50, 1000)
		srv              = new(Alibp2p)
		_relay           = def_relay
		_disable_inbound = false
	)
	if os.Getenv("loglevel") != "3" {
		if ll, err := strconv.Atoi(os.Getenv("loglevel")); err == nil {
			loglevel = ll
		}
	}
	log.Info("alibp2p::alibp2p-loglevel =>", "env", os.Getenv("loglevel"), "ret", loglevel)

	// TODO : for test
	srv.packetFilter = packetFilter
	srv.srv = s
	atomic.StoreInt32(&srv.started, 0)
	srv.msgReaders = new(sync.Map)
	srv.retryList = new(sync.Map)
	srv.allowPeers = new(sync.Map)
	srv.msgWriter = make(chan writeMsg)
	srv.maxpeers = maxpeers
	srv.advertiseCtxs = make(map[AdvertiseNs]context.CancelFunc)
	srv.advertiseLock = new(sync.Mutex)
	var bootperiod uint64 = bootstrapPeriod
	if maxpeers == 0 { // light node
		bootperiod = lightPeriod
	}
	srv.peerCounter = newPeerCounter()
	srv.asyncRunner = alibp2p.NewAsyncRunner(ctx, 100, senderpool)

	if disableInbound != nil {
		_disable_inbound = true
	}
	if disableRelay != nil {
		_relay = false
	}

	opts := []alibp2p.Option{
		alibp2p.Context(ctx),
		alibp2p.Identity(s.PrivateKey),
		alibp2p.Network(uint64(port), uint64(muxport), networkid.Uint64()),
		alibp2p.Bootnodes(s.Alibp2pBootstrapNodes...),
		alibp2p.Loglevel(loglevel),
		alibp2p.ConnectManger(bootperiod, connLow, connHi),
		alibp2p.Discover(true),
		alibp2p.Relay(_relay),
		alibp2p.DisableInbound(_disable_inbound),
		alibp2p.EnableMetric(false),
		alibp2p.ClientProtocols(ProtocolPlume, ProtocolBridge),
		alibp2p.MaxMsgSize(ProtocolMaxMsgSize),
	}

	srv.p2pservice, srv.cfg, err = alibp2p.New(opts...)
	if err != nil {
		panic(err)
	}
	srv.disp = newDispatcher(srv)
	return srv
}

func (self *Alibp2p) AppendBlacklist(pubkey *ecdsa.PublicKey, duration time.Duration) error {
	id, err := alibp2p.ECDSAPubEncode(pubkey)
	if err != nil {
		return err
	}
	self.p2pservice.PutPeerMeta(id, "blacklist", time.Now().Add(duration).Unix())
	//self.blacklist.Store(id, time.Now().Add(duration).Unix())
	return nil
}

func (self *Alibp2p) verifyBlacklist(id string) error {
	v, err := self.p2pservice.GetPeerMeta(id, "blacklist")
	if err != nil {
		// Not found
		return nil
	}
	if expire := v.(int64); expire > time.Now().Unix() {
		return fmt.Errorf("reject conn : %s in blacklist , expire at %d", id, v)
	}
	return nil
}

func (self *Alibp2p) isStarted() bool {
	if atomic.LoadInt32(&self.started) == 1 {
		return true
	}
	return false
}

func (self *Alibp2p) BootstrapOnce() error {
	return self.p2pservice.BootstrapOnce()
}

func (self *Alibp2p) PingWithTimeout(id string, timeout time.Duration) (string, error) {
	log.Debug("alibp2p::<- alibp2p-ping <-", "id", id)
	resp, err := self.p2pservice.RequestWithTimeout(id, pingpid, []byte("ping"), timeout)
	if err != nil {
		log.Error("alibp2p::<- alibp2p-ping-error <-", "id", id, "err", err)
		//self.tryReset(id, err)
		return "", err
	}
	log.Debug("alibp2p::-> alibp2p-ping ->", "id", id, "pkg", string(resp), "err", err)
	return string(resp), err
}

func (self *Alibp2p) Ping(id string) (string, error) {
	return self.PingWithTimeout(id, 15*time.Second)
}

func (self *Alibp2p) pingservice() {
	hfn := func(session string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error {
		id, _ := alibp2p.ECDSAPubEncode(pubkey)
		buf := make([]byte, 4)
		t, err := rw.Read(buf)
		if err != nil {
			return err
		}
		log.Trace("alibp2p::-> alibp2p-ping ->", "from", session, "id", id, "pkg", string(buf[:t]))
		if bytes.Equal(buf[:t], []byte("ping")) {
			log.Trace("alibp2p::<- alibp2p-pong <-", "from", session, "id", id)
			rw.Write([]byte("pong"))
		} else {
			err = errors.New("error_msg")
			log.Trace("alibp2p::<- alibp2p-err <-", "from", session, "id", id)
			rw.Write([]byte(err.Error()))
			return err
		}
		return nil
	}
	if def_reuseStream {
		self.p2pservice.SetHandlerReuseStream(pingpid, hfn)
	} else {
		self.p2pservice.SetHandler(pingpid, hfn)
	}
}

func (self *Alibp2p) mailboxservice() {
	self.msgReaders.Store(mailboxpid, make(chan Msg, 512))
	hfn := func(session string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error {
		var (
			id, _ = alibp2p.ECDSAPubEncode(pubkey)
			buf   = alibp2p.GetBuf(6)
		)
		defer alibp2p.PutBuf(buf)
		t, err := rw.Read(buf)
		if t < 6 || err != nil {
			log.Error("alibp2p::mailboxservice read format error", "head-byte-len", t, "err", err, "id", id)
			return errors.New("error packet")
		}

		msgType, size, err := packetHeadDecode(buf)
		if err != nil {
			log.Error("alibp2p::mailboxservice msg head decode error", "err", err, "id", id)
			return errors.New("error packet")
		}
		if self.packetFilter != nil {
			if err := self.packetFilter(pubkey, msgType, size); err != nil {
				log.Error("alibp2p::mailboxservice packetFilter error", "err", err, "id", id)
				return err
			}
		}
		//log.Trace("alibp2p::mailboxservice head", "id", id, "msgType", msgType, "size", size, "session", session)
		data := alibp2p.GetBuf(int(size))
		defer alibp2p.PutBuf(data)
		s := time.Now()

		if _, err := io.ReadFull(rw, data); err != nil {
			log.Error("alibp2p::error_size_and_type?", "size", size, "type", msgType, "buf", buf)
			log.Error("alibp2p::mailboxservice msg read error", "err", err, "from", id, "msgType", msgType, "size", size, "session", session)
			return err
		}

		e := time.Now()
		u := time.Since(s)
		log.Trace("alibp2p::mailboxservice ->", "ts", e.Unix(), "timeused", u, "id", id, "msgType", msgType, "size", size, "session", session)

		msg, err := bytesToMsgFn(data)
		if err != nil {
			log.Error("alibp2p::mailboxservice bytesToMsgFn error", "err", err, "id", id)
			return errors.New("error packet")
		}

		v, ok := self.msgReaders.Load(mailboxpid)
		if ok {
			errCh := make(chan error)
			go func(errCh chan error) {
				defer func() {
					if err := recover(); err != nil {
						log.Error("alibp2p::mailboxservice may be disconnected", "err", err, "id", id)
						errCh <- io.EOF
					} else {
						errCh <- nil
					}
				}()
				v.(chan Msg) <- msg
			}(errCh)
			err := <-errCh
			log.Trace("alibp2p::mailboxservice read over", "err", err, "msg", msg, "id", id)
			return err
		}
		log.Error("alibp2p::mailboxservice error", "err", "handler not started", "id", id)
		return nil
	}
	// mailbox relay channel
	self.p2pservice.SetHandler(mailboxpid, hfn)
	/*
		if def_reuseStream {
			self.p2pservice.SetHandlerReuseStream(mailboxpid, hfn)
		} else {
			self.p2pservice.SetHandler(mailboxpid, hfn)
		}
	*/
}

func (self *Alibp2p) msgservice() {

	hfn := func(session string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error {
		var (
			id, _ = alibp2p.ECDSAPubEncode(pubkey)
			key   = genSessionkey(id, session)
			//counter = 0
			buf = alibp2p.GetBuf(6)
			now = time.Now()
		)
		defer alibp2p.PutBuf(buf)
		t, err := rw.Read(buf)
		if t < 6 || err != nil {
			log.Error("alibp2p::alibp2p msg format error ( need byte-len == 6 )", "head-byte-len", t, "err", err, "id", id)
			return errors.New("error packet")
		}
		msgType, size, _ := packetHeadDecode(buf)
		if self.packetFilter != nil {
			if err := self.packetFilter(pubkey, msgType, size); err != nil {
				return err
			}
		}
		data := alibp2p.GetBuf(int(size))
		defer alibp2p.PutBuf(data)

		if n, err := io.ReadFull(rw, data); err != nil {
			log.Error("alibp2p::error_size_and_type?", "size", size, "type", msgType, "buf", buf, "id", id)
			log.Error("alibp2p::alibp2p msg read err", "err", err, "from", id, "msgType", msgType, "size", size, "n", n, "session", session)
			return err
		}

		log.Trace("alibp2p::msgservice-read", "msgType", msgType, "size", size, "id", id)
		msg, err := bytesToMsgFn(data)
		if err != nil {
			log.Error("alibp2p::alibp2p msg decode read error", "err", err, "id", id)
			return err
		}
		// retry for delay
		v, ok := self.msgReaders.Load(key)
		if !ok && msgType == 16 {
			for i := 0; i < 3; i++ {
				time.Sleep(1 * time.Second)
				v, ok = self.msgReaders.Load(key)
			}
		}
		log.Trace("alibp2p::msg-dispatch", "from", id, "msg", msg, "found-recv", ok)
		if ok {
			var (
				errCh = make(chan error)
				mch   = v.(chan Msg)
				fn    = func() error {
					go func(errCh chan error) {
						defer func() {
							if err := recover(); err != nil {
								log.Error("alibp2p::may be disconnected", "err", err)
								errCh <- errors.New("may be disconnected")
							} else {
								errCh <- nil
							}
						}()
						switch msg.Code {
						case 2, 18:
							t := time.NewTimer(30 * time.Second)
							defer t.Stop()
							select {
							case mch <- msg:
							case <-t.C:
								log.Warn("alibp2p::TxHandlerTimeout", "id", id, "code", msg.Code, "size", msg.Size, "session", session)
							case <-self.stop:
								return
							}
						default:
							mch <- msg
						}
					}(errCh)
					err := <-errCh
					log.Trace("alibp2p::msg-handle", "from", id, "msg", msg, "err", err, "ttl", time.Since(now))
					return err
				}
			)
			if len(mch) < 20 || self.peerCounter.has(id) {
				return fn()
			}
			log.Warn("alibp2p::msgservice-will-clean-ghost-msgchan", "id", id, "sessionkey", key, "msgch", len(mch), "has", self.peerCounter.has(id))
		}
		resp, err := self.p2pservice.Request(id, premsgpid, unlink.Bytes())
		self.cleanConnect(pubkey, session, DELPEER_UNLINK)
		log.Warn("alibp2p::msg-dispatch-skip", "reason", "msg lost : recver not foun", "id", id, "err", err, "unlink-resp", resp)
		return nil
	}
	if def_reuseStream {
		self.p2pservice.SetHandlerReuseStream(msgpid_tx, hfn)
		self.p2pservice.SetHandlerReuseStream(msgpid_block, hfn)
	} else {
		self.p2pservice.SetHandler(msgpid_tx, hfn)
		self.p2pservice.SetHandler(msgpid_block, hfn)
	}
}

// 开始 advertise  :: ProtocolManager 中使用
func (self *Alibp2p) startAdvertise(ns AdvertiseNs, period time.Duration) {
	self.advertiseLock.Lock()
	defer self.advertiseLock.Unlock()
	_, ok := self.advertiseCtxs[ns]
	if ok {
		// already started
		return
	}
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	self.p2pservice.SetAdvertiseTTL(ns.String(), period)
	self.advertiseCtxs[ns] = cancel
	self.p2pservice.Advertise(ctx, ns.String())
	log.Info("startAdvertise", "ns", ns, "period", period)
}

// 停止 advertise :: ProtocolManager 中使用
func (self *Alibp2p) stopAdvertise(ns AdvertiseNs) {
	self.advertiseLock.Lock()
	defer self.advertiseLock.Unlock()
	_cancel, ok := self.advertiseCtxs[ns]
	if ok {
		delete(self.advertiseCtxs, ns)
		_cancel()
	}
	log.Info("stopAdvertise")
}

func (self *Alibp2p) Start() {
	defer atomic.StoreInt32(&self.started, 1)
	self.plumeservice()
	self.preservice()
	self.p2pservice.OnConnectedEvent(alibp2p.CONNT_TYPE_DIRECT, self.onConnectedEvent)
	//self.p2pservice.OnConnected(alibp2p.CONNT_TYPE_DIRECT, self.outboundPreMsg, self.onConnected)
	if self.maxpeers > 0 { // light node maxpeers == 0
		go self.loopMsg()
		go self.loopMailbox()
		go self.loopRetrySetup()
		self.pingservice()
		self.msgservice()
		self.mailboxservice()
		self.p2pservice.OnDisconnected(self.onDisconnected)
		go func() {
			t := time.NewTimer(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-self.stop:
					return
				case <-t.C:
					m := self.msgChanState()
					j, _ := json.Marshal(m)
					var out bytes.Buffer
					json.Indent(&out, j, "", "\t")
					fmt.Println(time.Now(), "msgchan_state =", string(out.Bytes()))
				}
				t.Reset(30 * time.Second)
			}
		}()
		go func() {
			advEventCh := make(chan *AdvertiseEvent)
			advSub := SubscribeAlibp2pAdvertiseEvent(advEventCh)
			for {
				select {
				case <-self.cfg.Ctx.Done():
					advSub.Unsubscribe()
					return
				case e := <-advEventCh:
					log.Info("AdvertiseEvent", "start", e.Start, "period", e.Period)
					if e.Start {
						self.startAdvertise(FULLNODE, e.Period)
					} else {
						self.stopAdvertise(FULLNODE)
					}
				}
			}
		}()
	}
	self.p2pservice.Start()
	log.Info("alibp2p::Alibp2p-started", "enable-relay", os.Getenv("alibp2prelay") == "enable")
}

func (self *Alibp2p) outboundPreMsg() (protocolID string, pkg []byte) {
	protocolID = premsgpid
	total := self.peerCounter.total(OUTBOUND)
	if total >= self.srv.Config.MaxPeers/3 || self.maxpeers == 0 {
		pkg = ignore.Bytes()
	} else {
		pkg = setup.Bytes()
	}
	log.Trace("alibp2p::outboundPreMsg",
		"req", pkg,
		"total", self.peerCounter.total(EMPTY),
		"total-in", self.peerCounter.total(INBOUND),
		"total-out", self.peerCounter.total(OUTBOUND),
		"maxpeers", self.srv.Config.MaxPeers)
	return
}

func (self *Alibp2p) preMsg() (protocolID string, pkg []byte) {
	protocolID = premsgpid
	total := self.peerCounter.total(EMPTY)
	if total >= self.srv.Config.MaxPeers {
		pkg = ignore.Bytes()
	} else {
		pkg = setup.Bytes()
	}
	log.Trace("alibp2p::preMsg", "pkg", pkg, "current", total, "maxpeers", self.srv.Config.MaxPeers)
	return
}

func (self *Alibp2p) preservice() {
	hfn := func(session string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error {

		id, _ := alibp2p.ECDSAPubEncode(pubkey)
		in := self.isInbound(id)
		sessionKey := genSessionkey(id, session)
		buf := make([]byte, 1)
		_, err := rw.Read(buf)
		if err != nil {
			log.Trace("alibp2p::preservice-recv-unlink", "action", buf, "id", id, "inbound", in, "resp-err", err, "session", session)
			return err
		}
		if bytes.Equal(buf, unlink.Bytes()) {
			_, err := rw.Write(buf)
			self.cleanConnect(pubkey, session, DELPEER_UNLINK)
			self.peerCounter.del(id, session, true)
			self.disp.unbind(self.peerCounter, id)
			log.Trace("alibp2p::preservice-recv-unlink", "action", buf, "id", id, "inbound", in, "resp-err", err, "session", session)
			return err
		}
		if self.maxpeers == 0 { // light node skip handshake
			rw.Write(ignore.Bytes())
			return nil
		}
		_, pkg := self.preMsg()
		if allow, ok := self.allowPeers.Load(sessionKey); ok && allow.(bool) && connBehaviour(pkg[0]) == ignore {
			pkg = setup.Bytes()
		}
		log.Trace("alibp2p::preservice-answer", "id", id, "inbound", in, "recv", buf, "answer", pkg, "session", session)
		rw.Write(pkg)

		if bytes.Equal(buf, relink.Bytes()) {
			log.Trace("alibp2p::preservice-recv-resetup", "resp", pkg, "action", buf, "id", id, "inbound", in, "session", session)
			self.onConnectedEvent(in, session, pubkey)
			//self.onConnected(in, session, pubkey, pkg)
		}
		return nil
	}

	if def_reuseStream {
		self.p2pservice.SetHandlerReuseStream(premsgpid, hfn)
	} else {
		self.p2pservice.SetHandler(premsgpid, hfn)
	}
}

func (self *Alibp2p) loopMailbox() {
	log.Info("alibp2p::Alibp2p-loopMailbox-start")
	var (
		msgCh  = make(chan []interface{})
		msgSub = alibp2pMailboxEvent.Subscribe(msgCh)
		sendFn = func(ctx context.Context, args []interface{}) {
			data := args[0].([]interface{})
			to, mt, rd := data[0].(*ecdsa.PublicKey), data[1].(uint64), data[2].([]byte)
			s, _ := alibp2p.ECDSAPubEncode(to)
			//log.Trace("alibp2p::loopMailbox-write-start", "datalen", len(rd), "tn", ctx.Value("tn"))
			pk := make([]byte, 0)
			header := packetHeadEncode(uint16(mt), rd)
			pk = append(pk, header...)
			pk = append(pk, rd...)

			log.Trace("alibp2p::loopMailbox-write-start", "id", s, "datalen", len(rd))
			err := self.p2pservice.SendMsgAfterClose(s, mailboxpid, pk)
			if err != nil {
				log.Error("alibp2p::Alibp2p.msgservice.loopMailbox.error", "err", err, "to", s, "header", header)
				//go self.tryReset(s, err)
			}
			log.Trace("alibp2p::loopMailbox-write-end", "id", s, "err", err, "datalen", len(rd))
		}
	)

	defer func() {
		msgSub.Unsubscribe()
		log.Warn("alibp2p::alibp2pMailboxEvent-Unsubscribe")
	}()

	for {
		select {
		case data := <-msgCh:
			self.asyncRunner.Apply(sendFn, data)
		case <-self.stop:
			return
		}
	}

	log.Info("alibp2p::Alibp2p-loopMailbox-end")
}

func (self *Alibp2p) loopMsg() {
	log.Info("alibp2p::Alibp2p-loopMsg-start")
	var sendFn = func(ctx context.Context, args []interface{}) {
		var (
			//now    = time.Now()
			//tsize  = self.asyncRunner.Size()
			packet = args[0].(writeMsg)
			pk     = make([]byte, 0)
		)
		log.Trace("alibp2p::Alibp2p.msgservice.send", "to", packet.to, "msgType", packet.msgType, "size", len(packet.data), "head", packet.data[:6], "tn", ctx.Value("tn"))
		header := packetHeadEncode(uint16(packet.msgType), packet.data)
		pk = append(pk, header...)
		pk = append(pk, packet.data...)
		// 分通道进行排队
		err := self.disp.doSendMsg(packet.to, packet.msgType, pk)
		//err := self.p2pservice.SendMsgAfterClose(packet.to, msgpid, pk)
		if err != nil {
			//log.Error("alibp2p::Alibp2p.msgservice.send.error", "tn", ctx.Value("tn"), "err", err, "to", packet.to, "header", header)
		}
	}
	for {
		select {
		case packet := <-self.msgWriter:
			self.asyncRunner.Apply(sendFn, packet)
		case <-self.stop:
			return
		}
	}
	close(self.msgWriter)
	log.Info("alibp2p::Alibp2p-loopMsg-end")
}

func (self *Alibp2p) Stop() {
	defer func() {
		recover()
		atomic.StoreInt32(&self.started, 0)
	}()
	close(self.stop)
}

func NewAlibp2pMailboxReader(srv *Server) *Peer {
	var c = &conn{
		transport: newAlibp2pTransport2(nil, mailboxpid, srv.alibp2pService), cont: make(chan error),
		alibp2pservice: srv.alibp2pService,
	}
	return &Peer{rw: c}
}

func (self *Alibp2p) loopRetrySetup() {
	var (
		timer       = time.NewTimer(setupRetryPeriod * time.Second)
		syncmapSize = func(m *sync.Map) int {
			t := 0
			m.Range(func(key, value interface{}) bool {
				t += 1
				return true
			})
			return t
		}
		contains = func(arr []string, s string) bool {
			for _, a := range arr {
				if strings.Contains(a, s) {
					return true
				}
			}
			return false
		}
		retry = func(fn func()) {
			var (
				directs, _ = self.p2pservice.Conns()
				totalPeer  = self.peerCounter.total(EMPTY)
			)
			log.Trace("alibp2p::loopRetrySetup >>",
				"directs", len(directs),
				"total", totalPeer,
				"total-in", self.peerCounter.total(INBOUND),
				"total-out", self.peerCounter.total(OUTBOUND),
				"maxpeers", self.maxpeers,
				"turnoff", self.maxpeers/3)

			if totalPeer < self.maxpeers/3 && len(directs) > totalPeer {
				if syncmapSize(self.retryList) == 0 {
					// reset retryList
					totalRetry := self.maxpeers * 2 / 3
					for _, saddr := range directs {
						id := strings.Split(saddr, "/p2p/")[1]
						if totalRetry == 0 {
							break
						}
						session, inbound, err := self.p2pservice.GetSession(id)
						if err != nil {
							log.Error("alibp2p::getsession fail", "id", id, "err", err)
							continue
						}
						if !self.peerCounter.has(id) && !self.IsPlumeNode(id) {
							self.setRetry(genSessionkey(id, session), inbound)
							totalRetry -= 1
						}
					}
					log.Trace("alibp2p::reset-retryList", "directs", len(directs), "retryList", syncmapSize(self.retryList))
				}
				fn()
			}
		}
		do = func() {
			target := self.maxpeers / 3
			self.retryList.Range(func(k, v interface{}) bool {
				id, args := k.(string), v.([]interface{})
				inbound, session := args[0].(bool), args[1].(string)
				proto, pkg := self.preMsg()
				directs, _ := self.p2pservice.Conns()
				if contains(directs, id) {
					resp, err := self.p2pservice.RequestWithTimeout(id, proto, relink.Bytes(), 3*time.Second)
					if err != nil {
						log.Error("alibp2p::setupRetryLoop-do-1", "err", err, "id", id)
						self.retryList.Delete(k)
					}
					pubkey, err := alibp2p.ECDSAPubDecode(id)
					if err != nil {
						log.Error("alibp2p::setupRetryLoop-do-2", "err", err, "id", id)
						self.retryList.Delete(k)
					}
					log.Trace("alibp2p::setupRetryLoop-do", "id", id, "inbound", inbound, "req", pkg, "resp", resp, "session", session)
					self.onConnectedEvent(inbound, session, pubkey)
					//self.onConnected(inbound, session, pubkey, resp)
					if bytes.Equal(resp, setup.Bytes()) {
						target -= 1
						if target == 0 {
							return false
						}
					}
				} else {
					log.Trace("alibp2p::setupRetryLoop-del : not a direct conn", "id", id)
					self.retryList.Delete(k)
				}
				return true
			})
		}
	)
	for {
		select {
		case <-timer.C:
			retry(do)
		case <-self.stop:
			return
		}
		timer.Reset(setupRetryPeriod * time.Second)
	}
}

func (self *Alibp2p) checkConn(id, session string, preRtn []byte, inbound bool) (err error) {
	if self.maxpeers == 0 {
		return errors.New("came a light node")
	}
	defer func() {
		if err != nil {
			self.setRetry(genSessionkey(id, session), inbound)
		}
	}()

	if self.peerCounter.cmp(self.maxpeers, EMPTY) >= 0 {
		err = errors.New("too many peers")
		return
	}
	// 连出去的，不能超过 1/3 maxpeers
	if !inbound && self.maxpeers > 3 && self.peerCounter.cmp(self.maxpeers/3, OUTBOUND) >= 0 {
		err = errors.New("too many outbounds")
		return
	}

	// inbound == false 时 (连出去的)，必须要带上 preRtn 消息，否则就是错误包
	if !inbound && (len(preRtn) == 0 || len(preRtn) > 1) {
		err = fmt.Errorf("error pre msg : %v", preRtn)
		return
	}

	if preRtn != nil && len(preRtn) > 0 && connBehaviour(preRtn[0]) == ignore {
		// 对方 peers 满了，定期重试
		err = errors.New("remote too many peers")
		return
	}
	return
}

func (self *Alibp2p) onConnectedEvent(inbound bool, session string, pubkey *ecdsa.PublicKey) {
	var (
		err   error
		id, _ = alibp2p.ECDSAPubEncode(pubkey)
		key   = genSessionkey(id, session)
		c     = &conn{
			session:   session,
			fd:        nil,
			transport: newAlibp2pTransport2(pubkey, key, self), cont: make(chan error),
			alibp2pservice: self,
		}
		//distID, _  = discover.BytesID(append(pubkey.X.Bytes(), pubkey.Y.Bytes()...))
		distID     = discover.PubkeyID(pubkey)
		distNode   = discover.NewNode(distID, net.IPv4(1, 1, 1, 1), 0, 0)
		errcleanFn = func(id, key string, err error) {
			log.Warn("alibp2p::alibp2p err clean msgReaders", "err", err, "id", id, "sessionKey", key)
			self.msgReaders.Delete(key)
			self.retryList.Delete(id)
		}
		bound connType
	)

	if self.IsPlumeNode(id) || self.maxpeers == 0 {
		log.Info("onConnectedEvent-ignore : plume", "id", id)
		return
	}

	self.peerCounter.add(id, session)
	self.msgReaders.Store(key, make(chan Msg, msgCache))
	self.retryList.Delete(id)
	_ = self.p2pservice.PutPeerMeta(id, string(INBOUND), inbound)

	if inbound {
		c.flags, bound = inboundConn, INBOUND
	} else {
		c.flags, bound = dynDialedConn, OUTBOUND
	}
	log.Debug("alibp2p::[->peer] onConnectedEvent",
		"inbound", inbound,
		"total", self.peerCounter.total(EMPTY),
		"total-in", self.peerCounter.total(INBOUND),
		"total-out", self.peerCounter.total(OUTBOUND),
		"id", id,
		"session", session)

	if err = self.verifyBlacklist(id); err != nil {
		log.Error("alibp2p::verifyBlacklist", "id", id, "err", err)
		errcleanFn(id, key, err)
		c.close(err)
	}

	if reason := self.checkConn(id, session, setup.Bytes(), inbound); reason != nil {
		log.Trace("alibp2p::unlink-task-gen", "id", id, "inbound", inbound, "reason", reason)
		errcleanFn(id, key, err)
		//c.close(errors.New("unlink"))
		//self.cleanConnect(pubkey, session, DELPEER_UNLINK)
		log.Debug("alibp2p::unlink-task-done", "id", id, "inbound", inbound, "reason", reason)
		c.flags = ignoreConn
	}

	log.Debug("alibp2p::[->peer] onConnectedEvent setupConn-start", "id", id)
	if err = self.srv.setupConn(c, c.flags, distNode, 10*time.Second); err != nil {
		errcleanFn(id, key, err)
		c.close(err)
		log.Error("alibp2p::[->peer] onConnectedEvent setupConn-fail", "id", c.id, "err", err)
		return
	}

	log.Debug("alibp2p::[->peer] onConnectedEvent setupConn-success", "id", id)

	self.allowPeers.Store(key, inbound)
	self.peerCounter.set(id, session, string(bound))
	self.p2pservice.Protect(id, "peer")
	log.Debug("alibp2p::peerscounter : add",
		"maxpeers", self.maxpeers,
		"total", self.peerCounter.total(EMPTY),
		"total-in", self.peerCounter.total(INBOUND),
		"total-out", self.peerCounter.total(OUTBOUND),
		"id", id, "session", session)
}

/*
func (self *Alibp2p) onConnected(inbound bool, session string, pubkey *ecdsa.PublicKey, preRtn []byte) {

	var (
		err   error
		id, _ = alibp2p.ECDSAPubEncode(pubkey)
		key   = genSessionkey(id, session)
		c     = &conn{
			session:   session,
			fd:        nil,
			transport: newAlibp2pTransport2(pubkey, key, self), cont: make(chan error),
			alibp2pservice: self,
		}
		//distID, _  = discover.BytesID(append(pubkey.X.Bytes(), pubkey.Y.Bytes()...))
		distID     = discover.PubkeyID(pubkey)
		distNode   = discover.NewNode(distID, net.IPv4(1, 1, 1, 1), 0, 0)
		errcleanFn = func(id, key string, err error) {
			log.Warn("alibp2p::alibp2p err clean msgReaders", "err", err, "id", id, "sessionKey", key)
			self.msgReaders.Delete(key)
			self.retryList.Delete(id)
		}
		bound       connType
		checkPreRtn = func() error {
			if preRtn != nil && len(preRtn) > 8 && bytes.Equal(make([]byte, 8), preRtn[:8]) {
				return errors.New(string(preRtn[8:]))
			}
			return nil
		}
	)

	self.disp.bind(self.peerCounter, id)
	self.peerCounter.add(id, session)

	self.msgReaders.Store(key, make(chan Msg, msgCache))
	self.retryList.Delete(id)
	self.p2pservice.PutPeerMeta(id, string(INBOUND), inbound)

	if inbound {
		c.flags, bound = inboundConn, INBOUND
	} else {
		c.flags, bound = dynDialedConn, OUTBOUND
	}
	log.Debug("alibp2p::[->peer] onConnected event",
		"inbound", inbound,
		"preRtn", preRtn,
		"total", self.peerCounter.total(EMPTY),
		"total-in", self.peerCounter.total(INBOUND),
		"total-out", self.peerCounter.total(OUTBOUND),
		"id", id,
		"session", session)

	if err = self.verifyBlacklist(id); err != nil {
		log.Error("alibp2p::verifyBlacklist", "id", id, "err", err)
		errcleanFn(id, key, err)
		c.close(err)
	}

	if err = checkPreRtn(); err != nil {
		log.Error("alibp2p::checkPreRtn", "id", id, "err", err)
		errcleanFn(id, key, err)
		c.close(err)
		self.setRetry(genSessionkey(id, session), inbound)
		return
	}

	if reason := self.checkConn(id, session, preRtn, inbound); reason != nil {
		log.Trace("alibp2p::unlink-task-gen", "id", id, "inbound", inbound, "reason", reason)
		errcleanFn(id, key, err)
		c.close(errors.New("unlink"))
		//self.cleanConnect(pubkey, session, DELPEER_UNLINK)
		log.Debug("alibp2p::unlink-task-done", "id", id, "inbound", inbound, "reason", reason)
		return
	}

	log.Debug("alibp2p::[->peer] onConnected setupConn-start", "id", id)
	if err = self.srv.setupConn(c, c.flags, distNode, 45*time.Second); err != nil {
		errcleanFn(id, key, err)
		c.close(err)
		log.Error("alibp2p::Setting up connection failed", "id", c.id, "err", err)
		return
	}

	log.Debug("alibp2p::[->peer] onConnected setupConn-success", "id", id)

	self.allowPeers.Store(key, inbound)
	self.peerCounter.set(id, session, string(bound))
	self.p2pservice.Protect(id, "peer")
	log.Debug("alibp2p::peerscounter : add",
		"maxpeers", self.maxpeers,
		"total", self.peerCounter.total(EMPTY),
		"total-in", self.peerCounter.total(INBOUND),
		"total-out", self.peerCounter.total(OUTBOUND),
		"id", id, "session", session)
}
*/

func (self *Alibp2p) onDisconnected(session string, pubkey *ecdsa.PublicKey) {
	id, _ := alibp2p.ECDSAPubEncode(pubkey)
	log.Trace("alibp2p::[<-peer] onDisconnected event", "id", id, "inbound", self.isInbound(id), "session", session)
	self.cleanConnect(pubkey, session, DELPEER_DISCONN)
	self.p2pservice.Unprotect(id, "peer")
}

func (self *Alibp2p) cleanConnect(pubkey *ecdsa.PublicKey, session, delpeerAction string) {
	id, _ := alibp2p.ECDSAPubEncode(pubkey)
	key := genSessionkey(id, session)
	log.Trace("alibp2p::cleanConnect", "id", id, "inbound", self.isInbound(id), "delpeer", delpeerAction)
	defer func() {
		//self.allowPeers.Delete(key)
		if errMsg := recover(); errMsg != nil {
			log.Warn("alibp2p::onDisconnected defer", "err", errMsg)
		}
		switch delpeerAction {
		case DELPEER_UNLINK:
			self.peerCounter.del(id, session, true)
		case DELPEER_DISCONN:
			self.peerCounter.del(id, session, false)
		}
		self.disp.unbind(self.peerCounter, id)

		log.Trace("alibp2p::peerscounter : del",
			"max", self.maxpeers,
			"total", self.peerCounter.total(EMPTY),
			"total-in", self.peerCounter.total(INBOUND),
			"total-out", self.peerCounter.total(OUTBOUND),
			"id", id, "session", session)
	}()
	log.Trace("alibp2p::cleanConnect-unlinkEvent-delpeer", "id", id)
	select {
	case self.srv.delpeer <- peerDrop{
		&Peer{rw: &conn{id: discover.PubkeyID(pubkey), session: session}},
		errors.New(delpeerAction),
		false}:
	default:
	}
	v, ok := self.msgReaders.Load(key)
	log.Trace("alibp2p::cleanConnect-unlinkEvent-closechannel", "id", id, "load-reader", ok)
	if ok && v != nil {
		close(v.(chan Msg))
		self.msgReaders.Delete(key)
		log.Trace("alibp2p::cleanConnect-unlinkEvent-send", "id", id, "sessionkey", key)
		n := self.unlinkEvent.Send(id)
		log.Trace("alibp2p::cleanConnect-unlinkEvent-done", "nsent", n, "id", id, "sessionkey", key)
	}
}

func (self *Alibp2p) Myid() (id string, addrs []string) {
	id, addrs = self.p2pservice.Myid()
	return
}

func (self *Alibp2p) Close(pubkey *ecdsa.PublicKey) error {
	peerid, _ := alibp2p.ECDSAPubEncode(pubkey)
	err := self.p2pservice.ClosePeer(pubkey)
	log.Info("alibp2p::Alibp2p.Close peer", "id", peerid, "err", err)
	return err
}

func (self *Alibp2p) Addrs(pubkey *ecdsa.PublicKey) (string, []string, error) {
	if pubkey == nil {
		return "", nil, errors.New("nil point of input pubkey")
	}
	if self.srv.PrivateKey.PublicKey == *pubkey {
		id, addr := self.Myid()
		return id, addr, nil
	}
	id, err := alibp2p.ECDSAPubEncode(pubkey)
	if err != nil {
		return "", nil, err
	}
	addrs, err := self.p2pservice.Addrs(id)
	if err != nil {
		return "", nil, err
	}
	return id, addrs, nil
}

func (self *Alibp2p) Findpeer(pubkey *ecdsa.PublicKey) (string, []string, error) {
	if pubkey == nil {
		return "", nil, errors.New("nil point of input pubkey")
	}
	if self.srv.PrivateKey.PublicKey == *pubkey {
		id, addr := self.Myid()
		return id, addr, nil
	}
	id, err := alibp2p.ECDSAPubEncode(pubkey)
	if err != nil {
		return "", nil, err
	}
	addrs, err := self.p2pservice.Findpeer(id)
	if err != nil {
		return "", nil, err
	}
	return id, addrs, nil
}

func (self *Alibp2p) Peers() (direct []string, relay map[string][]string, total int) {
	return self.p2pservice.Peers()
}

func (self *Alibp2p) Table() map[string][]string {
	return self.p2pservice.Table()
}

func (self *Alibp2p) PreConnect(pubkey *ecdsa.PublicKey) error {
	return self.p2pservice.PreConnect(pubkey)
}

func (self *Alibp2p) Connect(url string) error {
	return self.p2pservice.Connect(url)
}

func (self *Alibp2p) msgChanState() map[string]interface{} {
	m := make(map[string]interface{})
	self.msgReaders.Range(func(key, value interface{}) bool {
		session := key.(string)
		mch := value.(chan Msg)
		m[session] = len(mch)
		return true
	})
	return m
}

func packetHeadEncode(msgType uint16, data []byte) []byte {
	var psize = uint32(len(data))
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, &msgType)
	binary.Write(buf, binary.BigEndian, &psize)
	return buf.Bytes()
}

func packetHeadDecode(header []byte) (msgType uint16, size uint32, err error) {
	if len(header) != 6 {
		err = errors.New("error_header")
		return
	}
	msgTypeR := bytes.NewReader(header[:2])
	err = binary.Read(msgTypeR, binary.BigEndian, &msgType)
	if err != nil {
		return
	}
	sizeR := bytes.NewReader(header[2:])
	err = binary.Read(sizeR, binary.BigEndian, &size)
	return
}

func genSessionkey(id, session string) string {
	return fmt.Sprintf("%s%s", id, session)
}

func splitSessionkey(sessionkey string) (id, session string, err error) {
	arr := strings.Split(sessionkey, "session:")
	if len(arr) != 2 {
		return "", "", errors.New("error sessionkey format")
	}
	return arr[0], fmt.Sprintf("session:%s", arr[1]), nil
}

type plumeFuncs struct {
	whitelist, blacklist map[string]string
}

// TODO api whitelist filter , full node and plume node both be same rule
var _plumeFuncs = &plumeFuncs{
	whitelist: map[string]string{
		"eth":    "*",
		"txpool": "*",
		"web3":   "*",
		"rpc":    "modules",
	},
	blacklist: map[string]string{
		"eth": "accounts,sendTransaction,sign,signTransaction,sendIBANTransaction",
	},
}

func (p *plumeFuncs) verify(_m string) error {
	arr := strings.Split(_m, "_")
	if len(arr) != 2 {
		return fmt.Errorf("jsonrpc method format error: %s", _m)
	}
	m, f := arr[0], arr[1]
	_fw, ok := p.whitelist[m]
	if !ok {
		return fmt.Errorf("jsonrpc mode not support: %s", _m)
	}
	if _fw != "*" && !strings.Contains(_fw, f) {
		return fmt.Errorf("jsonrpc func not support: %s", _m)
	}
	if _fb, ok := p.blacklist[m]; ok {
		if strings.Contains(_fb, f) {
			return fmt.Errorf("jsonrpc func in blacklist: %s", _m)
		}
	}
	return nil
}

func (self *Alibp2p) plumeRequestVerify(data []byte) error {
	//{"jsonrpc":"2.0","id":167,"method":"eth_blockNumber","params":[]}
	j, err := simplejson.NewJson(data)
	if err != nil {
		return err
	}
	m, err := j.Get("method").String()
	if err != nil {
		return err
	}
	err = _plumeFuncs.verify(m)
	if err != nil {
		return err
	}
	return nil
}

func (self *Alibp2p) Plume(to string, data []byte) ([]byte, error) {
	fmt.Println("<------------ plume", to, string(data))
	if err := self.plumeRequestVerify(data); err != nil {
		return nil, err
	}
	header := packetHeadEncode(111, data)
	pk := make([]byte, 0)
	pk = append(pk, header...)
	pk = append(pk, data...)
	resp, err := self.p2pservice.Request(to, plumepid, pk)
	fmt.Println("------------> plume", err, string(resp))
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (self *Alibp2p) plumeservice() {
	var errResp = func(err error) []byte {
		return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"%s"}}`, err.Error()))
	}
	var hfn = func(session string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error {
		var buf = alibp2p.GetBuf(6)
		defer alibp2p.PutBuf(buf)
		t, err := rw.Read(buf)
		if t < 6 || err != nil {
			return errors.New("error packet")
		}
		msgType, size, _ := packetHeadDecode(buf)
		if msgType != 111 {
			return errors.New("error msgtype")
		}
		data := alibp2p.GetBuf(int(size))
		defer alibp2p.PutBuf(data)
		if _, err := io.ReadFull(rw, data); err != nil {
			return err
		}
		if err != nil {
			fmt.Println("--------plumeservice--------> error", session, err)
			return err
		}
		if err := self.plumeRequestVerify(data); err != nil {
			return err
		}
		fmt.Println("--------plumeservice-------->", session, string(data))
		var resp []byte
		respCh := make(chan []byte)
		select {
		case rpc.PlumeReqCh <- rpc.PlumeMsg{
			Request:  data,
			Response: respCh,
		}:
			resp = <-respCh
		default:
			resp = errResp(errors.New("busy_node"))
		}
		log.Info("-> plumeservice ->", "from", session, "pkg", string(data), "resp", string(resp))
		rw.Write(resp)
		return nil
	}

	if def_reuseStream {
		self.p2pservice.SetHandlerReuseStream(plumepid, hfn)
	} else {
		self.p2pservice.SetHandler(plumepid, hfn)
	}
}

func (self *Alibp2p) Alibp2pService() alibp2p.Alibp2pService {
	return self.p2pservice
}

func (self *Alibp2p) ConnInfos() (d []ConnInfo, r map[string][]ConnInfo, t int) {
	direct, relay, total := self.p2pservice.PeersWithDirection()
	dpis := make([]ConnInfo, 0)
	for _, p := range direct {
		pk, _ := alibp2p.ECDSAPubDecode(p.ID())
		if _, addrs, err := self.Findpeer(pk); err == nil {
			dpis = append(dpis, ConnInfo{p.Pretty(), addrs, p.Direction() == network.DirInbound})
		}
	}
	rpis := make(map[string][]ConnInfo)
	for pr, ps := range relay {
		pis := make([]ConnInfo, 0)
		for _, p := range ps {
			pk, _ := alibp2p.ECDSAPubDecode(p.Pretty())
			if _, addrs, err := self.Findpeer(pk); err == nil {
				pis = append(pis, ConnInfo{p.Pretty(), addrs, p.Direction() == network.DirInbound})
			}
		}
		rpis[pr.Pretty()] = pis
		total = total + len(pis)
	}
	return dpis, rpis, total
}
