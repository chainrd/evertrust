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
 * @Time   : 2019/9/11 1:43 下午
 * @Author : liangc
 *************************************************************************/

package p2p

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"github.com/michaelklishin/rabbit-hole"
	"github.com/streadway/amqp"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"CRD-chain/common"
	"CRD-chain/crypto"
	"CRD-chain/event"
	"CRD-chain/log"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/rlp"
	"CRD-chain/evertrust"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	//defproxy = "10.0.0.98:8080"
	//defproxy = "39.100.61.240:8080"
	//defproxy = "127.0.0.1:5978"
	//defhost = "39.98.202.72:5672"
	defhost  = "127.0.0.1:5672"
	defrpc   = "127.0.0.1:15672"
	chainTag = "evertrust"

	RAWMSG = 0xffffffff
)

type (
	MQSTATE       byte
	MQRoutekey    string
	MQExchangekey string
	mqroutekeys   struct{}
	exchangekeys  struct{}

	MQMsgWriter interface {
		MsgReadWriter
		PublishMsg(MQExchangekey, MQRoutekey, Msg) error
	}
	MQMsgReader interface {
		MsgReadWriter
		Close()
	}
	qmsg struct {
		Code       uint64
		Size       uint32 // size of the paylod
		ReceivedAt uint64
		Payload    []byte
	}
	publishPkg struct {
		e    MQExchangekey
		k    MQRoutekey
		data []byte
	}
	amqpImpl struct {
		qid     string
		conn    *amqp.Connection
		channel *amqp.Channel
		tag     string
		done    chan error
		handle  func(deliveries <-chan amqp.Delivery, done chan error)
		//recvMsg       chan []byte
		stop, restart chan struct{}
		cli           *rabbithole.Client
		auth          *amqp.PlainAuth
		privateKey    *ecdsa.PrivateKey
		msgEvent      event.Feed
		stateEvent    *event.Feed
		recvMap       map[string][]chan Msg // 先不考虑注销
		recvLock      *sync.RWMutex
		sendCh        chan publishPkg
		//rw            MQMsgReader
	}
	mrw struct {
		Id      common.Address
		Qid     string
		mq      *amqpImpl
		msgCh   chan []byte
		stateCh chan MQSTATE
		msgSub  event.Subscription
	}
)

func (s MQExchangekey) ToString() string      { return string(s) }
func (s *exchangekeys) MSG() MQExchangekey    { return chainTag + ".msg" }
func (s *exchangekeys) Tx() MQExchangekey     { return chainTag + ".tx" }
func (s *exchangekeys) Block() MQExchangekey  { return chainTag + ".block" }
func (s *exchangekeys) Assert() MQExchangekey { return chainTag + ".assert" }
func (s *exchangekeys) Peers() MQExchangekey  { return chainTag + ".peers" }

func (s MQRoutekey) ToString() string    { return string(s) }
func (s *mqroutekeys) Peers() MQRoutekey { return "routekey.peers" }
func (s *mqroutekeys) Address(myid common.Address) MQRoutekey {
	return MQRoutekey(strings.ToLower("routekey." + myid.Hex()))
}

const (
	MQ_STATE_START MQSTATE = iota
	MQ_STATE_CLOSE
	MQ_STATE_RESTART
	MQ_STATE_SHUTDOWN
)

var (
	highwaystarted = int32(0)
	Routekeys      = &mqroutekeys{}
	Exchangekeys   = &exchangekeys{}
	// host:port,rpcport
	// proxy:port->host:port,rpcport
	proxy, proxyport, host, port, rpcport string
	setMqconf                             = func(c string) (err error) {
		proxy, proxyport, host, port, rpcport, err = func(s string) (proxy, proxyport, host, port, rpcport string, err error) {
			s = strings.TrimSpace(s)
			a := strings.Split(s, "->")
			switch len(a) {
			case 1:
				b := strings.Split(a[0], ":")
				if len(b) != 2 {
					err = errors.New("format error 1")
					return
				}
				host = b[0]
				c := strings.Split(b[1], ",")
				if len(c) != 2 {
					err = errors.New("format error 2")
					return
				}
				port, rpcport = c[0], c[1]
			case 2:
				b := strings.Split(a[0], ":")
				if len(b) != 2 {
					err = errors.New("format error 3")
					return
				}
				proxy, proxyport = b[0], b[1]

				c := strings.Split(a[1], ":")
				if len(c) != 2 {
					err = errors.New("format error 4")
					return
				}
				host = c[0]
				d := strings.Split(c[1], ",")
				if len(d) != 2 {
					err = errors.New("format error 5")
					return
				}
				port, rpcport = d[0], d[1]
			default:
				err = errors.New("format error 6")
			}
			return
		}(c)
		return
	}

	rpcFn = func() string {
		if host != "" && rpcport != "" {
			r := fmt.Sprintf("http://%s:%s", host, rpcport)
			log.Info("highway-rpc-url", "url", r)
			return r
		}
		return fmt.Sprintf("http://%s", defrpc)
	}
	proxyFn = func() string {
		if proxy != "" && proxyport != "" {
			r := fmt.Sprintf("%s:%s", proxy, proxyport)
			return r
		}
		return ""
	}
	hostFn = func() string {
		if host != "" && port != "" {
			r := fmt.Sprintf("%s:%s", host, port)
			return r
		}
		return defhost
	}

	qid = func() string {
		return fmt.Sprintf("%s:%s->%s", exchangeName(), proxyFn(), hostFn())
	}
	makeConn = func(auth *amqp.PlainAuth) (*amqp.Connection, error) {
		var (
			cnf = amqp.Config{
				Heartbeat: 20 * time.Second,
				Locale:    "en_US",
				SASL:      []amqp.Authentication{auth},
				Vhost:     "/",
			}
			proxyConn = func() (*amqp.Connection, error) {
				conn, err := net.DialTimeout("tcp", proxyFn(), time.Second*5)
				if err != nil {
					return nil, err
				}
				s := make(chan error, 0)
				go func() {
					buff := make([]byte, 1024)
					total, err := conn.Read(buff)
					if err != nil {
						s <- err
					}
					if !bytes.Contains(buff, []byte("HTTP/1.1 200")) {
						s <- errors.New(string(buff[:total]))
					}
					s <- nil
				}()

				points := evertrust.Getpoints(evertrust.MinerPrivateKey, "", "", evertrust.RabbitMqpointsType)
				if _, err := conn.Write([]byte(fmt.Sprintf("CONNECT http://%s HTTP/1.1\r\nHost: localhost\r\nX-CRD-Proxy-Jwt: %s\r\n\r\n", hostFn(), points))); err != nil {
					return nil, err
				}
				if err := <-s; err != nil {
					return nil, err
				}
				return amqp.Open(conn, cnf)
			}
			directConn = func() (*amqp.Connection, error) {
				conn, err := net.DialTimeout("tcp", hostFn(), time.Second*5)
				if err != nil {
					return nil, err
				}
				return amqp.Open(conn, cnf)
			}
		)
		switch proxy {
		case "":
			return directConn()
		default:
			return proxyConn()
		}
	}

	queueName = func(addr common.Address) string {
		return strings.ToLower(fmt.Sprintf("%s.%d", strings.ToUpper(addr.Hex()), conf.ChainId))
	}

	// Exange 名称 默认:
	exchangeName = func(name ...MQExchangekey) MQExchangekey {
		t := Exchangekeys.MSG().ToString()
		if len(name) > 0 {
			t = string(name[0])
		}
		return MQExchangekey(strings.ToLower(fmt.Sprintf("CRD.%s.%d", t, conf.ChainId)))
	}

	// 声明 exange
	exchangeDeclareFn = func(impl *amqpImpl, name MQExchangekey) error {
		return impl.channel.ExchangeDeclare(
			name.ToString(), "direct",
			false, true,
			false, true, nil)
	}
	// 声明 queue

	// 绑定 queue
	queueBindFn = func(impl *amqpImpl, addr common.Address, e MQExchangekey, k MQRoutekey) error {
		if err := impl.channel.QueueBind(queueName(addr), k.ToString(), e.ToString(), false, nil); err != nil {
			err = fmt.Errorf("Queue Bind: %s", err)
			return err
		}
		return nil
	}

	publishFn = func(p *amqpImpl, e MQExchangekey, k MQRoutekey, data []byte) error {
		select {
		case p.sendCh <- publishPkg{e, k, data}:
			log.Info("publishFn-success", "e", e, "k", k)
		case <-p.stop:
			return errors.New("publishFn-stop")
		case <-p.restart:
			return errors.New("publishFn-restart")
		}
		return nil
	}
	publishLoop = func(p *amqpImpl) {
		execFn := func(p *amqpImpl, e MQExchangekey, k MQRoutekey, data []byte) {
			log.Info("<-[publishFn]", "e", e, "r", k, "len=", len(data))
			if p.conn == nil {
				log.Error("mq->conn->nil : lost msg")
				return
			}
			if p.channel == nil {
				channel, err := p.conn.Channel()
				if err != nil {
					log.Error("mq->conn->channel->error : lost msg", "err", err)
					return
				}
				p.channel = channel
			}

			if err := exchangeDeclareFn(p, e); err != nil {
				log.Error("mq->exchangeDeclareFn->err : lost msg", "err", err)
				return
			}

			myid := crypto.PubkeyToAddress(p.privateKey.PublicKey)
			if err := p.channel.Publish(e.ToString(), k.ToString(), false, false,
				amqp.Publishing{
					Headers:         amqp.Table{},
					ContentType:     "application/octet-stream",
					ContentEncoding: "",
					Body:            data,
					DeliveryMode:    amqp.Transient, // 1=non-persistent, 2=persistent
					Priority:        0,              // 0-9
					ReplyTo:         myid.Hex(),
				}, ); err != nil {
				return
			}
		}
		log.Debug("publishLoop-start")
		defer log.Debug("publishLoop-end")
		for {
			select {
			case pkg := <-p.sendCh:
				execFn(p, pkg.e, pkg.k, pkg.data)
			case <-p.stop:
				log.Info("highway stop : publishLoop return")
				return
			}
		}
	}

	msgToBytesFn = func(msg Msg) ([]byte, error) {
		data, err := ioutil.ReadAll(msg.Payload)
		//log.Debug("msgToBytesFn", "msgCode", msg.Code, "msgSize", msg.Size)
		if err != nil {
			log.Error("msgToBytesFn-error", "err", err)
			return nil, err
		}
		qm := &qmsg{
			Code:       msg.Code,
			Size:       msg.Size,
			ReceivedAt: uint64(time.Now().Unix()),
			Payload:    data,
		}
		dang, err := rlp.EncodeToBytes(qm)
		if err != nil {
			return nil, err
		}
		return dang, nil
	}
	bytesToMsgFn = func(data []byte) (Msg, error) {
		qm := new(qmsg)
		err := rlp.DecodeBytes(data, qm)
		if err != nil {
			log.Error("bytesToMsgFn_error : unknow msg will return rawmsg", "err", err)
			msg := Msg{}
			if len(data) > 0 {
				msg = Msg{
					Code:       RAWMSG,
					Size:       uint32(len(data)),
					ReceivedAt: time.Unix(int64(qm.ReceivedAt), 0),
					Payload:    bytes.NewReader(data),
				}
				log.Warn("bytesToMsgFn-raw-msg", "len", len(data), "data", data)
				err = nil
			}
			return msg, err
		} else {
			//log.Debug("bytesToMsgFn", "msgCode", qm.Code, "msgSize", qm.Size)
			msg := Msg{
				Code:       qm.Code,
				Size:       qm.Size,
				ReceivedAt: time.Unix(int64(qm.ReceivedAt), 0),
				Payload:    bytes.NewReader(qm.Payload),
			}
			return msg, nil
		}
	}
)

func NewAmqpChannel(highwayArg string, privateKey *ecdsa.PrivateKey, stateEvent *event.Feed) (*amqpImpl, error) {
	var (
		ctag = "evertrust"
		c    = &amqpImpl{
			privateKey: privateKey,
			qid:        qid(),
			tag:        ctag,
			done:       make(chan error),
			stop:       make(chan struct{}),
			restart:    make(chan struct{}),
			//recvMsg:    make(chan []byte),
			auth: &amqp.PlainAuth{
				Username: "guest",
				Password: "guest",
			},
			recvMap:    make(map[string][]chan Msg),
			recvLock:   new(sync.RWMutex),
			stateEvent: stateEvent,
			sendCh:     make(chan publishPkg),
		}
	)

	return c, setMqconf(highwayArg)
}

func (c *amqpImpl) Start(myaddr common.Address) error {
	if atomic.LoadInt32(&highwaystarted) == 1 {
		return errors.New("highway service already started.")
	}
	var (
		cli, err = rabbithole.NewClient(rpcFn(), c.auth.Username, c.auth.Password)
		handleFn = func(deliveries <-chan amqp.Delivery, done chan error) {
		endloop:
			for {
				select {
				case d := <-deliveries:
					//log.Error("deliveries", "d", d)
					if len(d.Body) > 0 {
						log.Debug("[Highway-handle] consumer ",
							"exange", d.Exchange,
							"key", d.RoutingKey,
							"tag", d.ConsumerTag,
							"replayTo", d.ReplyTo,
							"body.len", len(d.Body))
						c.msgEvent.Send(d.Body)
						func() {
							c.recvLock.RLock()
							defer c.recvLock.RUnlock()
							if list, ok := c.recvMap[d.Exchange+d.RoutingKey]; ok {
								if msg, err := bytesToMsgFn(d.Body); err == nil {
									for i, ch := range list {
										go func() {
											select {
											case ch <- msg:
												log.Debug("highway_msg_recv_dispatch", "idx", i, "from", d.Exchange+d.RoutingKey, "size", msg.Size, "code", msg.Code)
											case <-time.Tick(time.Second):
												log.Warn("highway_msg_recv_timeout", "from", d.Exchange+d.RoutingKey, "size", msg.Size, "code", msg.Code)
											}
										}()
									}
								}
							}
						}()
					}
				case <-c.restart:
					c.SendStateEvent(MQ_STATE_RESTART)
					log.Info("[Highway-handle] restart")
					return
				case <-c.stop:
					c.SendStateEvent(MQ_STATE_CLOSE)
					log.Info("[Highway-handle] stop")
					break endloop
				}
			}
			done <- nil
			log.Warn("highway-handleFn-returned")
		}
		notifyCloseFn = func() {
			errCh := c.conn.NotifyClose(make(chan *amqp.Error))
			for err := range errCh {
				if err != nil {
					log.Info("highway channel close", "err", err)
					select {
					case <-c.stop:
						log.Info("[Highway already shutdown]")
						return
					default:
						close(c.restart)
						log.Info("[Highway restart]")
					}
				}
			}
		}

		startlink = func(selfaddr common.Address) error {
			log.Debug("highway-startlink-start")
			defer log.Debug("highway-startlink-end")
			var err error
			c.restart = make(chan struct{})
			c.conn, err = makeConn(c.auth)
			if err != nil {
				return err
			}
			c.channel, err = c.conn.Channel()
			if err != nil {
				return err
			}

			err = exchangeDeclareFn(c, exchangeName())
			if err != nil {
				log.Error("exchangeDeclareFn-err", "err", err)
				return err
			}
			err = exchangeDeclareFn(c, exchangeName(Exchangekeys.Peers()))
			if err != nil {
				log.Error("exchangeDeclareFn-err", "err", err)
				return err
			}
			if _, err := c.channel.QueueDeclare(
				queueName(selfaddr), // name of the queue
				false,               // durable
				true,                // delete when unused
				false,               // exclusive
				true,                // noWait
				nil,                 // arguments
			); err != nil {
				log.Error("QueueDeclare-error", "err", err)
				return err
			}
			// 绑定 exange 、key、queue
			if err := queueBindFn(c, selfaddr, exchangeName(), Routekeys.Address(selfaddr)); err != nil {
				log.Error("queueBindFn-error", "err", err)
				return err
			}

			if err := queueBindFn(c, selfaddr, exchangeName(Exchangekeys.Peers()), Routekeys.Peers()); err != nil {
				log.Error("queueBindFn-error", "err", err)
				return err
			}

			deliveries, err := c.channel.Consume(
				queueName(selfaddr), // name
				c.tag,               // consumerTag,
				true,                // noAck
				false,               // exclusive
				false,               // noLocal
				true,                // noWait
				nil,                 // arguments
			)
			if err != nil {
				log.Error("Consume-err", "err", err)
				return err
			}
			go notifyCloseFn()
			go c.handle(deliveries, c.done)
			c.SendStateEvent(MQ_STATE_START)
			log.Info("MQ STARTED.")
			atomic.StoreInt32(&highwaystarted, 1)
			return nil
		}

		restartLoop = func(selfaddr common.Address, startFn func(selfaddr common.Address) error, resetCh chan struct{}) {
			log.Info("highway-restart-loop-start")
			defer log.Info("highway-restart-loop-end")
			for {
				select {
				case <-c.stop:
					log.Info("highway-restart-loop-end :: stop")
					return
				case <-c.restart:
					log.Info("highway-restart-loop-active :: restart")
					atomic.StoreInt32(&highwaystarted, 0)
					go func() {
						log.Info("highway restart task begin")
						t := time.NewTimer(3 * time.Second)
						for {
							select {
							case <-c.stop:
								return
							case <-t.C:
								_, err := c.cli.ListExchanges()
								t.Reset(15 * time.Second)
								if err == nil {
									err := startFn(selfaddr)
									if err != nil {
										log.Error("highway restart task error : ", "err", err)
										continue
									}
									defer func() {
										log.Warn("highway restart task success")
										resetCh <- struct{}{}
									}()
									return
								}
								log.Warn("highway restart task will try later")
							}
						}
					}()
					return
				}
			}
		}
	)

	if err != nil {
		return err
	}

	if proxyFn() != "" {
		proxy, err := url.Parse(fmt.Sprintf("http://%s", proxyFn()))
		if err != nil {
			return err
		}

		points := evertrust.Getpoints(evertrust.MinerPrivateKey, "", "", evertrust.RabbitMqpointsType)
		fmt.Println("points是什么？", "points", points)

		ProxyURLHeader := func (fixedURL *url.URL) func(*http.Request) (*url.URL, error) {
			return func(r *http.Request) (*url.URL, error) {
				r.Header.Set("X-CRD-PROXY-JWT", points)
				return fixedURL, nil
			}
		}

		cli.SetTransport(&http.Transport{
			Proxy: ProxyURLHeader(proxy),
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
				DualStack: true,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       120 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 3 * time.Second,
		})
	}

	c.cli = cli
	c.handle = handleFn

	defer func() {
		go publishLoop(c)
		restartCh := make(chan struct{})
		go func() {
			for {
				select {
				case <-restartCh:
					restartLoop(myaddr, startlink, restartCh)
				case <-c.stop:
					return
				}
			}
		}()
		restartCh <- struct{}{}
	}()

	return startlink(myaddr)
}

func (c *amqpImpl) SendStateEvent(s MQSTATE) {
	if c.stateEvent != nil {
		(*c.stateEvent).Send(s)
	}
}

func (c *amqpImpl) Shutdown() error {
	if atomic.LoadInt32(&highwaystarted) != 1 {
		return errors.New("shutdown : highway service not started")
	}
	var (
		cancelFn = func() error {
			if err := c.channel.Cancel(c.tag, true); c.channel != nil && err != nil {
				return fmt.Errorf("Consumer cancel failed: %s", err.Error())
			}
			return nil
		}
		closeFn = func() error {
			if err := c.conn.Close(); c.conn != nil && err != nil {
				return fmt.Errorf("AMQP connection close error: %s", err)
			}
			return nil
		}
		err error
	)
	log.Error("[Highway shutdown]")
	close(c.stop)
	c.SendStateEvent(MQ_STATE_SHUTDOWN)
	go func() { <-c.done }()
	if c != nil && c.channel != nil {
		err = cancelFn()
	}
	if err == nil && c != nil && c.conn != nil {
		err = closeFn()
	}
	return nil
}

func (p *amqpImpl) Publish(targetAddr common.Address, data []byte) error {
	return publishFn(p, exchangeName(), Routekeys.Address(targetAddr), data)
}

func (p *amqpImpl) publishTo(exchangekey MQExchangekey, routekey MQRoutekey, data []byte) error {
	e := exchangeName(exchangekey)
	return publishFn(p, e, routekey, data)
}

func (p *amqpImpl) recvRegister(exchangekey MQExchangekey, routekey MQRoutekey, recv chan Msg) error {
	p.recvLock.Lock()
	defer p.recvLock.Unlock()
	k := exchangekey.ToString() + routekey.ToString()
	l, ok := p.recvMap[k]
	if !ok {
		l = make([]chan Msg, 0)
	}
	l = append(l, recv)
	p.recvMap[k] = l
	return nil
}

func (p *amqpImpl) highwayPeers() (map[common.Address]*Peer, error) {
	if atomic.LoadInt32(&highwaystarted) != 1 {
		return nil, errors.New("highway service not ready yet")
	}
	bis, err := p.cli.ListExchangeBindings("/", exchangeName().ToString(), rabbithole.BindingSource)
	log.Debug("HighwayPeers", "exchangeName", exchangeName(), "binds", len(bis))
	if err != nil {
		return nil, err
	}
	myid := crypto.PubkeyToAddress(p.privateKey.PublicKey)
	peers := make(map[common.Address]*Peer)
	for _, bi := range bis {
		// 格式为 addressHex.chainid
		sd := bi.Destination
		addr := strings.Split(sd, ".")[0]
		paddr := common.HexToAddress(addr)
		if paddr != myid {
			o := NewMQMsgWriter(paddr, p)
			v := NewPeerWriter(paddr, o)
			peers[paddr] = v
		}
	}
	return peers, nil
}

func NewMQMsgWriter(id common.Address, mq *amqpImpl) MsgReadWriter {
	return &mrw{
		Id:  id,
		Qid: mq.qid,
		mq:  mq,
	}
}

func NewMQMsgReader(id common.Address, mq *amqpImpl) MQMsgReader {
	m := &mrw{
		Id:      id,
		Qid:     mq.qid,
		mq:      mq,
		msgCh:   make(chan []byte),
		stateCh: make(chan MQSTATE),
	}
	m.msgSub = mq.msgEvent.Subscribe(m.msgCh)
	return m
}

// 智能由 MQ 模拟启动的 pm.handMsg 调用,其他模块不能来读
func (m mrw) ReadMsg() (Msg, error) {
	doFn := func() (Msg, error) {
		select {
		case data := <-m.msgCh:
			return bytesToMsgFn(data)
		case <-m.mq.restart:
			return Msg{}, errors.New("restart")
		case <-m.mq.stop:
			return Msg{}, errors.New("closed")
		}
	}
	waitFn := func(msg Msg, err error) (Msg, error) {
		log.Debug("ReadMsg::waitFn::input", "err", err, "msg", msg)
		if m.mq.stateEvent != nil && err != nil && err.Error() == "restart" {
			stateSub := m.mq.stateEvent.Subscribe(m.stateCh)
			defer stateSub.Unsubscribe()
			log.Debug("ReadMSG-error : wait state event", "err", err)
			for state := range m.stateCh {
				switch state {
				case MQ_STATE_START:
					log.Debug("ReadMsg : MQ_STATE_START")
					msg, err = doFn()
					log.Debug("ReadMsg::waitFn::startevent", "err", err, "msg", msg)
					return msg, err
				case MQ_STATE_CLOSE:
					log.Debug("ReadMsg : MQ_STATE_CLOSE")
					return msg, errors.New("closed")
				case MQ_STATE_SHUTDOWN:
					log.Debug("ReadMsg : MQ_STATE_SHUTDOWN")
					return msg, errors.New("shutdown")
				}
			}
		}
		log.Debug("ReadMsg::waitFn::return", "err", err, "msg", msg)
		return msg, err
	}
	msg, err := doFn()
	return waitFn(msg, err)
}

func (m mrw) Close() {
	m.msgSub.Unsubscribe()
	fmt.Println("MQReader : ", m.Id.Hex(), "closed")
}

func (m mrw) PublishMsg(e MQExchangekey, r MQRoutekey, msg Msg) error {
	dang, err := msgToBytesFn(msg)
	if err != nil {
		return err
	}
	return m.mq.publishTo(e, r, dang)
}

func (m mrw) WriteMsg(msg Msg) error {
	dang, err := msgToBytesFn(msg)
	if err != nil {
		return err
	}
	return m.mq.Publish(m.Id, dang)
}
