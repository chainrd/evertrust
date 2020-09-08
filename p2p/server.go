// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

// Package p2p implements the Ethereum p2p network protocols.
package p2p

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cc14514/go-alibp2p"
	"github.com/cc14514/go-cookiekit/graph"
	"math/big"
	"net"
	"CRD-chain/core/types"
	"CRD-chain/crypto"
	"CRD-chain/rlp"
	"CRD-chain/evertrust"
	"CRD-chain/evertrust/utils/frequency"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"CRD-chain/common"
	"CRD-chain/event"
	"CRD-chain/log"
	"CRD-chain/p2p/discover"
	"CRD-chain/p2p/discv5"
	"CRD-chain/p2p/nat"
	"CRD-chain/p2p/netutil"
)

const (
	defaultDialTimeout = 15 * time.Second

	// Connectivity defaults.
	maxActiveDialTasks     = 16
	defaultMaxPendingPeers = 50
	defaultDialRatio       = 3

	// Maximum time allowed for reading a complete message.
	// This is effectively the amount of time a connection can be idle.
	frameReadTimeout = 30 * time.Second

	// Maximum amount of time allowed for writing a complete message.
	frameWriteTimeout = 20 * time.Second
)

var errServerStopped = errors.New("server stopped")
var errServerTimeout = errors.New("server timeout")

// Config holds Server options.
type Config struct {
	NetworkId uint64
	// This field must be set to a valid secp256k1 private key.
	PrivateKey *ecdsa.PrivateKey `toml:"-"`

	// MaxPeers is the maximum number of peers that can be
	// connected. It must be greater than zero.
	MaxPeers int

	// MaxPendingPeers is the maximum number of peers that can be pending in the
	// handshake phase, counted separately for inbound and outbound connections.
	// Zero defaults to preset values.
	MaxPendingPeers int `toml:",omitempty"`

	// DialRatio controls the ratio of inbound to dialed connections.
	// Example: a DialRatio of 2 allows 1/2 of connections to be dialed.
	// Setting DialRatio to zero defaults it to 3.
	DialRatio int `toml:",omitempty"`

	// NoDiscovery can be used to disable the peer discovery mechanism.
	// Disabling is useful for protocol debugging (manual topology).
	NoDiscovery bool

	// DiscoveryV5 specifies whether the the new topic-discovery based V5 discovery
	// protocol should be started or not.
	DiscoveryV5 bool `toml:",omitempty"`

	// Name sets the node name of this server.
	// Use common.MakeName to create a name that follows existing conventions.
	Name string `toml:"-"`

	// BootstrapNodes are used to establish connectivity
	// with the rest of the network.
	Alibp2pBootstrapNodes []string
	BootstrapNodes        []*discover.Node

	// BootstrapNodesV5 are used to establish connectivity
	// with the rest of the network using the V5 discovery
	// protocol.
	BootstrapNodesV5 []*discv5.Node `toml:",omitempty"`

	// Static nodes are used as pre-configured connections which are always
	// maintained and re-connected on disconnects.
	StaticNodes []*discover.Node

	// Trusted nodes are used as pre-configured connections which are always
	// allowed to connect, even above the peer limit.
	TrustedNodes []*discover.Node

	// Connectivity can be restricted to certain IP networks.
	// If this option is set to a non-nil value, only hosts which match one of the
	// IP networks contained in the list are considered.
	NetRestrict *netutil.Netlist `toml:",omitempty"`

	// NodeDatabase is the path to the database containing the previously seen
	// live nodes in the network.
	NodeDatabase string `toml:",omitempty"`

	// Protocols should contain the protocols supported
	// by the server. Matching protocols are launched for
	// each peer.
	Protocols []Protocol `toml:"-"`

	// If ListenAddr is set to a non-nil address, the server
	// will listen for incoming connections.
	//
	// If the port is zero, the operating system will pick a port. The
	// ListenAddr field will be updated with the actual address when
	// the server is started.
	ListenAddr string

	// If set to a non-nil value, the given NAT port mapper
	// is used to make the listening port available to the
	// Internet.
	NAT nat.Interface `toml:",omitempty"`

	// If Dialer is set to a non-nil value, the given Dialer
	// is used to dial outbound peer connections.
	Dialer NodeDialer `toml:"-"`

	// If NoDial is true, the server will not dial any peers.
	NoDial bool `toml:",omitempty"`

	// If EnableMsgEvents is set then the server will emit PeerEvents
	// whenever a message is sent to or received from a peer
	EnableMsgEvents bool

	// Logger is a custom logger to use with the p2p.Server.
	Logger log.Logger `toml:",omitempty"`

	// add by liangc
	Highway string
}

// Server manages all peer connections.
type Server struct {
	// Config fields may not be modified while the server is running.
	Config

	// Hooks for testing. These are useful because we can inhibit
	// the whole protocol stack.
	newTransport func(net.Conn) transport
	newPeerHook  func(*Peer)

	lock    sync.Mutex // protects running
	running bool

	ntab         discoverTable
	listener     net.Listener
	ourHandshake *protoHandshake
	lastLookup   time.Time
	DiscV5       *discv5.Network

	// These are for Peers, PeerCount (and nothing else).
	peerOp     chan peerOpFunc
	peerOpDone chan struct{}

	quit          chan struct{}
	addstatic     chan *discover.Node
	removestatic  chan *discover.Node
	addtrusted    chan *discover.Node
	removetrusted chan *discover.Node
	posthandshake chan *conn
	addpeer       chan *conn
	delpeer       chan peerDrop
	loopWG        sync.WaitGroup // loop, listenLoop
	peerFeed      event.Feed
	log           log.Logger
	// add by liangc >>>>
	mq             *amqpImpl
	mqStateEvent   event.Feed
	alibp2pService *Alibp2p
	// add by liangc <<<<
}

type peerOpFunc func(map[discover.NodeID]*Peer)

type peerDrop struct {
	*Peer
	err       error
	requested bool // true if signaled by the peer
}

type connFlag int32
type ConnFlag connFlag

const (
	dynDialedConn connFlag = 1 << iota
	staticDialedConn
	inboundConn
	trustedConn
	ignoreConn // add by liangc : 握手时如果得到这个标记则表明 忽略握手保持连接
)

// conn wraps a network connection with information gathered
// during the two handshakes.
type conn struct {
	fd net.Conn
	transport
	flags          connFlag
	cont           chan error      // The run loop uses cont to signal errors to SetupConn.
	id             discover.NodeID // valid after the encryption handshake
	caps           []Cap           // valid after the protocol handshake
	name, session  string          // valid after the protocol handshake
	alibp2pservice *Alibp2p
}

type transport interface {
	// The two handshakes.
	doEncHandshake(prv *ecdsa.PrivateKey, dialDest *discover.Node) (discover.NodeID, error)
	doProtoHandshake(our *protoHandshake) (*protoHandshake, error)
	// The MsgReadWriter can only be used after the encryption
	// handshake has completed. The code uses conn.id to track this
	// by setting it to a non-nil value after the encryption handshake.
	MsgReadWriter
	// transports must provide Close because we use MsgPipe in some of
	// the tests. Closing the actual network connection doesn't do
	// anything in those tests because NsgPipe doesn't use it.
	close(err error)
}

func (c *conn) String() string {
	s := c.flags.String()
	if (c.id != discover.NodeID{}) {
		s += " " + c.id.String()
	}
	//s += " " + c.fd.RemoteAddr().String()
	return s
}

func (f connFlag) String() string {
	s := ""
	if f&trustedConn != 0 {
		s += "-trusted"
	}
	if f&dynDialedConn != 0 {
		s += "-dyndial"
	}
	if f&staticDialedConn != 0 {
		s += "-staticdial"
	}
	if f&inboundConn != 0 {
		s += "-inbound"
	}
	if s != "" {
		s = s[1:]
	}
	return s
}

func (c *conn) is(f connFlag) bool {
	flags := connFlag(atomic.LoadInt32((*int32)(&c.flags)))
	return flags&f != 0
}

func (c *conn) set(f connFlag, val bool) {
	for {
		oldFlags := connFlag(atomic.LoadInt32((*int32)(&c.flags)))
		flags := oldFlags
		if val {
			flags |= f
		} else {
			flags &= ^f
		}
		if atomic.CompareAndSwapInt32((*int32)(&c.flags), int32(oldFlags), int32(flags)) {
			return
		}
	}
}

func (srv *Server) HighwayPeers() map[common.Address]*Peer {
	peers, err := srv.mq.highwayPeers()
	if err != nil {
		log.Error("HiwayPeers_error", "err", err)
		return nil
	}
	return peers
}

// add by liangc : 用来测试 highway
func (srv *Server) HighwayPing(addr common.Address, broadcast bool) string {
	// add by liangc : 用来测试 highway
	myid := crypto.PubkeyToAddress(srv.PrivateKey.PublicKey)
	code := big.NewInt(14514)
	data := &types.Header{
		Number:   code,
		Coinbase: myid,
		Root:     common.BytesToHash(code.Bytes()),
	}
	size, r, err := rlp.EncodeToReader(data)
	if err != nil {
		log.Error("HighwayPin_error", "err", err)
		return "pang"
	}
	msg := Msg{Code: code.Uint64(), Size: uint32(size), Payload: r}
	if broadcast {
		fmt.Println("<------------ [broadcast]")
		//TODO
		err = srv.HighwayPeersExchangeBroadcast(msg)
		if err != nil {
			log.Error("HighwayPing_error", "err", err)
			return "pang"
		}
	} else if peer, ok := srv.HighwayPeers()[addr]; ok {
		rw := peer.Mrw.(MQMsgWriter)
		err := rw.PublishMsg(Exchangekeys.MSG(), Routekeys.Address(peer.id), msg)
		//err := Send(peer.Mrw, code.Uint64(), data)
		fmt.Println("<------------ [highway-ping]", addr.Hex(), err)
		if err != nil {
			log.Error("HighwayPing_error", "err", err)
			return "pang"
		}
	}
	return "pong"
}

func (srv *Server) Alibp2pServer() *Alibp2p {
	return srv.alibp2pService
}

// Peers returns all connected peers.
func (srv *Server) Peers() []*Peer {
	var ps []*Peer
	select {
	// Note: We'd love to put this function into a variable but
	// that seems to cause a weird compiler error in some
	// environments.
	case srv.peerOp <- func(peers map[discover.NodeID]*Peer) {
		for _, p := range peers {
			ps = append(ps, p)
		}
	}:
		<-srv.peerOpDone
	case <-srv.quit:
	}
	return ps
}

func (srv *Server) GetPeers() map[string]*Peer {
	var ps = make(map[string]*Peer)
	select {
	case srv.peerOp <- func(peers map[discover.NodeID]*Peer) {
		for id, p := range peers {
			ps[id.String()] = p
		}
	}:
		<-srv.peerOpDone
	case <-srv.quit:
	}
	return ps
}

// PeerCount returns the number of connected peers.
func (srv *Server) PeerCount() int {
	var count int
	select {
	case srv.peerOp <- func(ps map[discover.NodeID]*Peer) { count = len(ps) }:
		<-srv.peerOpDone
	case <-srv.quit:
	}
	return count
}

// AddPeer connects to the given node and maintains the connection until the
// server is shut down. If the connection fails for any reason, the server will
// attempt to reconnect the peer.
func (srv *Server) AddPeer(node *discover.Node) {
	log.Info("TODO : add by liangc : 用 alibp2p 实现")
	/*
		select {
		case srv.addstatic <- node:
		case <-srv.quit:
		}
	*/
}

// RemovePeer disconnects from the given node
func (srv *Server) RemovePeer(node *discover.Node) {
	log.Info("TODO : add by liangc : 用 alibp2p 实现")
	/*
		select {
		case srv.removestatic <- node:
		case <-srv.quit:
		}
	*/
}

// AddTrustedPeer adds the given node to a reserved whitelist which allows the
// node to always connect, even if the slot are full.
func (srv *Server) AddTrustedPeer(node *discover.Node) {
	log.Info("TODO : add by liangc : 不支持的操作")
	/*
		select {
		case srv.addtrusted <- node:
		case <-srv.quit:
		}
	*/
}

// RemoveTrustedPeer removes the given node from the trusted peer set.
func (srv *Server) RemoveTrustedPeer(node *discover.Node) {
	log.Info("TODO : add by liangc : 不支持的操作")
	/*
		select {
		case srv.removetrusted <- node:
		case <-srv.quit:
		}
	*/
}

// SubscribePeers subscribes the given channel to peer events
func (srv *Server) SubscribeEvents(ch chan *PeerEvent) event.Subscription {
	return srv.peerFeed.Subscribe(ch)
}

// Self returns the local node's endpoint information.
func (srv *Server) Self() *discover.Node {
	srv.lock.Lock()
	defer srv.lock.Unlock()

	if !srv.running {
		return &discover.Node{IP: net.ParseIP("0.0.0.0")}
	}
	return srv.makeSelf(srv.listener, srv.ntab)
}

func (srv *Server) makeSelf(listener net.Listener, ntab discoverTable) *discover.Node {
	// If the server's not running, return an empty node.
	// If the node is running but discovery is off, manually assemble the node infos.
	if ntab == nil {
		// Inbound connections disabled, use zero address.
		if listener == nil {
			return &discover.Node{IP: net.ParseIP("0.0.0.0"), ID: discover.PubkeyID(&srv.PrivateKey.PublicKey)}
		}
		// Otherwise inject the listener address too
		addr := listener.Addr().(*net.TCPAddr)
		return &discover.Node{
			ID:  discover.PubkeyID(&srv.PrivateKey.PublicKey),
			IP:  addr.IP,
			TCP: uint16(addr.Port),
		}
	}
	// Otherwise return the discovery node.
	return ntab.Self()
}

// Stop terminates the server and all active peer connections.
// It blocks until all active connections have been closed.
func (srv *Server) Stop() {
	// add by liangc
	err := srv.mq.Shutdown()
	if err != nil {
		log.Error("[Highway shutdown error]", "err", err)
	}
	srv.lock.Lock()
	if !srv.running {
		srv.lock.Unlock()
		return
	}
	srv.running = false
	if srv.listener != nil {
		// this unblocks listener Accept
		srv.listener.Close()
	}
	close(srv.quit)
	srv.lock.Unlock()
	srv.loopWG.Wait()
}

// sharedUDPConn implements a shared connection. Write sends messages to the underlying connection while read returns
// messages that were found unprocessable and sent to the unhandled channel by the primary listener.
type sharedUDPConn struct {
	*net.UDPConn
	unhandled chan discover.ReadPacket
}

// ReadFromUDP implements discv5.conn
func (s *sharedUDPConn) ReadFromUDP(b []byte) (n int, addr *net.UDPAddr, err error) {
	packet, ok := <-s.unhandled
	if !ok {
		return 0, nil, fmt.Errorf("Connection was closed")
	}
	l := len(packet.Data)
	if l > len(b) {
		l = len(b)
	}
	copy(b[:l], packet.Data[:l])
	return l, packet.Addr, nil
}

// Close implements discv5.conn
func (s *sharedUDPConn) Close() error {
	return nil
}

// MQ 的状态信息
func (srv *Server) SubHighwayStatus(c chan MQSTATE) event.Subscription {
	return srv.mqStateEvent.Subscribe(c)
}

func (srv *Server) HighwayPeersExchangeBroadcast(msg Msg) error {
	if srv.mq == nil {
		return errors.New("highway object is nil")
	}
	data, err := msgToBytesFn(msg)
	if err != nil {
		return err
	}
	//log.Debug("HighwayPeersExchangeBroadcast", "err", err, "data", data)
	return srv.mq.publishTo(Exchangekeys.Peers(), Routekeys.Peers(), data)
}

// 需要在 Highway 启动后再调用，
func (srv *Server) HighwayPeersExchangeRecvReg(c chan Msg) error {
	if srv.mq == nil {
		return errors.New("highway object is nil")
	}
	return srv.mq.recvRegister(Exchangekeys.Peers(), Routekeys.Peers(), c)
}

// 读 MQ 通道上的消息，用完必须 Close , 否则会阻塞其他调用者
func (srv *Server) NewHighwayReader() (MQMsgReader, error) {
	if atomic.LoadInt32(&highwaystarted) != 1 {
		return nil, errors.New("highway service not ready yet")
	}
	return NewMQMsgReader(crypto.PubkeyToAddress(srv.PrivateKey.PublicKey), srv.mq), nil
}

// 启动 MQ 的通道实现，成功后返回一个 mrw 实例，用来处理通道上的消息
func (srv *Server) StartHighway(handler func(id common.Address, mrw MsgReadWriter)) (err error) {
	srv.mq, err = NewAmqpChannel(srv.Highway, srv.PrivateKey, &srv.mqStateEvent)
	if err != nil {
		return err
	}
	srv.PrivateKey.Public()
	myid := crypto.PubkeyToAddress(srv.PrivateKey.PublicKey)
	//go func() {
	//	mqreader := NewMQMsgReader(myid, srv.mq)
	//	defer mqreader.Close()
	//	go handler(myid, mqreader)
	//	<-srv.mq.stop
	//}()
	err = srv.mq.Start(myid)
	if err != nil {
		return err
	}
	return nil
}

// Start starts running the server.
// Servers can not be re-used after stopping.
func (srv *Server) Start() (err error) {
	srv.lock.Lock()
	defer srv.lock.Unlock()
	if srv.running {
		return errors.New("server already running")
	}
	srv.running = true
	srv.log = srv.Config.Logger
	if srv.log == nil {
		srv.log = log.New()
	}
	srv.log.Info("Starting P2P networking")

	// static fields
	if srv.PrivateKey == nil {
		return fmt.Errorf("Server.PrivateKey must be set to a non-nil key")
	}
	if srv.newTransport == nil {
		srv.newTransport = newRLPX
	}
	if srv.Dialer == nil {
		srv.Dialer = TCPDialer{&net.Dialer{Timeout: defaultDialTimeout}}
	}
	srv.quit = make(chan struct{})
	srv.addpeer = make(chan *conn)
	srv.delpeer = make(chan peerDrop)
	srv.posthandshake = make(chan *conn)
	srv.addstatic = make(chan *discover.Node)
	srv.removestatic = make(chan *discover.Node)
	srv.addtrusted = make(chan *discover.Node)
	srv.removetrusted = make(chan *discover.Node)
	srv.peerOp = make(chan peerOpFunc)
	srv.peerOpDone = make(chan struct{})
	// add by liangc : libp2p transport
	srv.newTransport = newAlibp2pTransport

	p2pport, err := strconv.Atoi(strings.Split(srv.Config.ListenAddr, ":")[1])
	if err != nil {
		p2pport = 0
	}
	var muxPort = 5978
	pub, _ := alibp2p.ECDSAPubEncode(&srv.PrivateKey.PublicKey)
	log.Info("###################################################")
	log.Info(fmt.Sprintf("# port = %d", p2pport))
	log.Info(fmt.Sprintf("# maxpeers = %d", srv.Config.MaxPeers))
	log.Info(fmt.Sprintf("# muxport = %d", muxPort))
	log.Info(fmt.Sprintf("# networkid = %d", srv.Config.NetworkId))
	log.Info(fmt.Sprintf("# bootnode = %v", srv.Config.Alibp2pBootstrapNodes))
	log.Info(fmt.Sprintf("# pubkey = %v", pub))
	log.Info("###################################################")
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	go func() {
		<-srv.quit
		cancel()
	}()
	srv.alibp2pService = NewAlibp2p(
		ctx,
		p2pport,
		muxPort,
		srv.Config.MaxPeers,
		big.NewInt(int64(srv.Config.NetworkId)), srv, nil, nil,
		func(pubkey *ecdsa.PublicKey, msgType uint16, size uint32) error {

			pubkeyHex := fmt.Sprintf("%x", crypto.FromECDSAPub(pubkey))
			//log.Info("---p2p pkg filter func---", "syncing", atomic.LoadInt32(evertrust.Syncing), "msgType", msgType, "size", size, "pubkey", pubkeyHex)
			if atomic.LoadInt32(evertrust.Syncing) == 1 {
				//log.Info("no pkg filter when syncing.......")
				return nil
			}

			//freq limit
			key := "p2p:" + strconv.Itoa(int(msgType)) + ":" + pubkeyHex
			switch msgType {
			case 7, 23, 247, 263, 253, 269, 255, 271, 9, 25: //block
				//size limit
				if size > 3*1024*1024 {
					log.Error("p2p msg oversize size", "pubkey", pubkeyHex, "msgType", msgType, "size", size)
					return fmt.Errorf("p2p msg oversize size: %d", size)
				}

				//freq limit
				err = frequency.PeriodFreqControl(key, 10*time.Second, 1000)
				if err != nil {
					log.Error("p2p frequency control", "pubkey", pubkeyHex, "msgType", msgType, "err", err)
					return fmt.Errorf("p2p frequency control:%s", err)
				}
			}

			return nil
		})
	srv.alibp2pService.Start()

	//var (
	//conn      *net.UDPConn
	//sconn     *sharedUDPConn
	//realaddr  *net.UDPAddr
	//unhandled chan discover.ReadPacket
	//)

	// modify by liangc : 无论如何都启动 discovery 功能
	//if !srv.NoDiscovery || srv.DiscoveryV5 {
	/*
		addr, err := net.ResolveUDPAddr("udp", srv.ListenAddr)
		if err != nil {
			return err
		}
		conn, err = net.ListenUDP("udp", addr)
		if err != nil {
			return err
		}
		realaddr = conn.LocalAddr().(*net.UDPAddr)
		if srv.NAT != nil {
			if !realaddr.IP.IsLoopback() {
				go nat.Map(srv.NAT, srv.quit, "udp", realaddr.Port, realaddr.Port, "ethereum discovery")
			}
			// TODO: react to external IP changes over time.
			if ext, err := srv.NAT.ExternalIP(); err == nil {
				realaddr = &net.UDPAddr{IP: ext, Port: realaddr.Port}
			}
		}
	*/

	//}

	/*
		if !srv.NoDiscovery && srv.DiscoveryV5 {
			unhandled = make(chan discover.ReadPacket, 100)
			sconn = &sharedUDPConn{conn, unhandled}
		}

		// node table
		if !srv.NoDiscovery {
			cfg := discover.Config{
				PrivateKey:   srv.PrivateKey,
				AnnounceAddr: realaddr,
				NodeDBPath:   srv.NodeDatabase,
				NetRestrict:  srv.NetRestrict,
				Bootnodes:    srv.BootstrapNodes,
				Unhandled:    unhandled,
			}
			ntab, err := discover.ListenUDP(conn, cfg, srv.addstatic)
			if err != nil {
				return err
			}
			srv.ntab = ntab
		}

		if srv.DiscoveryV5 {
			var (
				ntab *discv5.Network
				err  error
			)
			if sconn != nil {
				ntab, err = discv5.ListenUDP(srv.PrivateKey, sconn, realaddr, "", srv.NetRestrict) //srv.NodeDatabase)
			} else {
				ntab, err = discv5.ListenUDP(srv.PrivateKey, conn, realaddr, "", srv.NetRestrict) //srv.NodeDatabase)
			}
			if err != nil {
				return err
			}
			if err := ntab.SetFallbackNodes(srv.BootstrapNodesV5); err != nil {
				return err
			}
			srv.DiscV5 = ntab
		}
	*/

	dynPeers := srv.maxDialedConns()
	dialer := newDialState(srv.StaticNodes, srv.BootstrapNodes, srv.ntab, dynPeers, srv.NetRestrict)

	// handshake
	srv.ourHandshake = &protoHandshake{Version: baseProtocolVersion, Name: srv.Name, ID: discover.PubkeyID(&srv.PrivateKey.PublicKey)}
	for _, p := range srv.Protocols {
		srv.ourHandshake.Caps = append(srv.ourHandshake.Caps, p.cap())
	}

	// listen/dial
	/*
		if srv.ListenAddr != "" {
			if err := srv.startListening(); err != nil {
				return err
			}
		}
		if srv.NoDial && srv.ListenAddr == "" {
			srv.log.Warn("P2P server will be useless, neither dialing nor listening")
		}
	*/

	srv.loopWG.Add(1)
	go srv.run(dialer)
	srv.running = true

	return nil
}

func (srv *Server) startListening() error {
	// Launch the TCP listener.
	listener, err := net.Listen("tcp", srv.ListenAddr)
	if err != nil {
		return err
	}
	laddr := listener.Addr().(*net.TCPAddr)
	srv.ListenAddr = laddr.String()
	srv.listener = listener
	srv.loopWG.Add(1)
	go srv.listenLoop()
	// Map the TCP listening port if NAT is configured.
	if !laddr.IP.IsLoopback() && srv.NAT != nil {
		srv.loopWG.Add(1)
		go func() {
			nat.Map(srv.NAT, srv.quit, "tcp", laddr.Port, laddr.Port, "ethereum p2p")
			srv.loopWG.Done()
		}()
	}
	return nil
}

type dialer interface {
	newTasks(running int, peers map[discover.NodeID]*Peer, now time.Time) []task
	taskDone(task, time.Time)
	addStatic(*discover.Node)
	removeStatic(*discover.Node)
}

func (srv *Server) run(dialstate dialer) {
	defer srv.loopWG.Done()
	var (
		peers        = make(map[discover.NodeID]map[string]*Peer)
		peersLock    = new(sync.Mutex)
		inboundCount = 0
		trusted      = make(map[discover.NodeID]bool, len(srv.TrustedNodes))
		//taskdone     = make(chan task, maxActiveDialTasks)
		runningTasks []task
		//queuedTasks  []task // tasks that can't run yet
	)
	// Put trusted nodes into a map to speed up checks.
	// Trusted peers are loaded on startup or added via AddTrustedPeer RPC.
	/*	for _, n := range srv.TrustedNodes {
			trusted[n.ID] = true
		}

		// removes t from runningTasks
		delTask := func(t task) {
			for i := range runningTasks {
				if runningTasks[i] == t {
					runningTasks = append(runningTasks[:i], runningTasks[i+1:]...)
					break
				}
			}
		}
		// starts until max number of active tasks is satisfied
		startTasks := func(ts []task) (rest []task) {
			i := 0
			for ; len(runningTasks) < maxActiveDialTasks && i < len(ts); i++ {
				t := ts[i]
				srv.log.Trace("New dial task", "task", t, "ts长度", len(ts), "i", i)
				go func() { t.Do(srv); taskdone <- t }()
				runningTasks = append(runningTasks, t)
			}
			return ts[i:]
		}
		scheduleTasks := func() {
			// Start from queue first.
			queuedTasks = append(queuedTasks[:0], startTasks(queuedTasks)...)
			// Query dialer for new tasks and start as many as possible now.
			if len(runningTasks) < maxActiveDialTasks {
				nt := dialstate.newTasks(len(runningTasks)+len(queuedTasks), peers, time.Now())
				queuedTasks = append(queuedTasks, startTasks(nt)...)
			}
		}*/
running:
	for {
		//scheduleTasks()

		select {
		case <-srv.quit:
			// The server was stopped. Run the cleanup logic.
			break running
		case <-srv.addstatic:
			//case n := <-srv.addstatic:
			// This channel is used by AddPeer to add to the
			// ephemeral static peer list. Add it to the dialer,
			// it will keep the node connected.
			//srv.log.Trace("Adding static node", "node", n)
			/* modify by liangc
			if n == nil {
				break
			}
			if n.ID == srv.Self().ID {
				break
			}
			dialstate.addStatic(n)
			scheduleTasks()
			srv.log.Trace("Adding static node", "node", n)
			dialstate.addStatic(n)
			*/
			//case n := <-srv.removestatic:
			// This channel is used by RemovePeer to send a
			// disconnect request to a peer and begin the
			// stop keeping the node connected.
			//srv.log.Trace("Removing static node", "node", n)
			//dialstate.removeStatic(n)
			//if p, ok := peers[n.ID]; ok {
			//	p.Disconnect(DiscRequested)
			//}
			// modify by liangc
			//scheduleTasks()
			/*case n := <-srv.addtrusted:
			// This channel is used by AddTrustedPeer to add an enode
			// to the trusted node set.
			srv.log.Trace("Adding trusted node", "node", n)
			trusted[n.ID] = true
			// Mark any already-connected peer as trusted
			if p, ok := peers[n.ID]; ok {
				p.rw.set(trustedConn, true)
			}*/
			/*case n := <-srv.removetrusted:
			// This channel is used by RemoveTrustedPeer to remove an enode
			// from the trusted node set.
			srv.log.Trace("Removing trusted node", "node", n)
			if _, ok := trusted[n.ID]; ok {
				delete(trusted, n.ID)
			}
			// Unmark any already-connected peer as trusted
			if p, ok := peers[n.ID]; ok {
				p.rw.set(trustedConn, false)
			}*/
		case op := <-srv.peerOp:
			// This channel is used by Peers and PeerCount.
			rpeers := make(map[discover.NodeID]*Peer)

			for pid, pmap := range peers {
				for _, p := range pmap {
					rpeers[pid] = p
					break
				}
			}
			op(rpeers)
			srv.peerOpDone <- struct{}{}
			//case t := <-taskdone:
			// A task got done. Tell dialstate about it so it
			// can update its state and remove it from the active
			// tasks list.
			//srv.log.Trace("Dial task done", "task", t)
			//dialstate.taskDone(t, time.Now())
			//delTask(t)
		case c := <-srv.posthandshake:
			// A connection has passed the encryption handshake so
			// the remote identity is known (but hasn't been verified yet).
			if trusted[c.id] {
				// Ensure that the trusted flag is set before checking against MaxPeers.
				c.flags |= trustedConn
			}
			// TODO: track in-progress inbound node IDs (pre-Peer) to avoid dialing them.
			select {
			case c.cont <- srv.encHandshakeChecks(peers, inboundCount, c):
			case <-srv.quit:
				break running
			}
		case c := <-srv.addpeer:
			// At this point the connection is past the protocol handshake.
			// Its capabilities are known and the remote identity is verified.
			err := srv.protoHandshakeChecks(peers, inboundCount, c)
			if err == nil {
				// The handshakes are done and it passed all checks.
				p := newPeer(c, srv.Protocols)
				// If message events are enabled, pass the peerFeed
				// to the peer
				if srv.EnableMsgEvents {
					p.events = &srv.peerFeed
				}
				name := truncateName(c.name)
				srv.log.Debug("Adding p2p peer", "name", name, "peers", len(peers)+1)
				//srv.log.Debug("Adding p2p peer", "name", name, "addr", c.fd.RemoteAddr(), "peers", len(peers)+1)

				addpeerFn := func() {
					peersLock.Lock()
					defer peersLock.Unlock()
					pmap, ok := peers[c.id]
					if !ok {
						pmap = make(map[string]*Peer)
					}
					pmap[c.session] = p
					peers[c.id] = pmap
					//pubkey, _ := c.id.Pubkey()
					//id, _ := alibp2p.ECDSAPubEncode(pubkey)
					if p.Inbound() {
						inboundCount++
					}
				}
				addpeerEventCh := make(chan *AddpeerHandshakeEvent)
				addpeerEventSub := SubscribeAddpeerHandshakeEvent(addpeerEventCh)
				go srv.runPeer(p)
				go func() {
					defer func() {
						addpeerEventSub.Unsubscribe()
					}()
					log.Debug("-> addpeer-handshake-start", "id", c.name, "session", c.session)
					for e := range addpeerEventCh {
						if !bytes.Equal(e.Id, p.ID().Bytes()) {
							continue
						}
						if e.Err != nil {
							log.Debug("-> addpeer-handshake-fail", "id", c.name, "session", c.session, "err", e.Err)
							return
						}
						addpeerFn()
						log.Debug("-> addpeer-handshake-success", "id", c.name, "session", c.session, "pmap", len(peers[c.id]))
						return
					}
				}()
			}
			// The dialer logic relies on the assumption that
			// dial tasks complete after the peer has been added or
			// discarded. Unblock the task last.
			select {
			case c.cont <- err:
			case <-srv.quit:
				break running
			}
		case pd := <-srv.delpeer:
			func() {
				peersLock.Lock()
				defer peersLock.Unlock()
				// TODO 清理 session
				pmap, ok := peers[pd.ID()]
				pubkey, _ := pd.ID().Pubkey()
				id, _ := alibp2p.ECDSAPubEncode(pubkey)
				//dellogAdd(id, pd.rw.session)
				if pd.err.Error() == "unlink" {
					delete(peers, pd.ID())
				} else if ok {
					delete(pmap, pd.rw.session)
					log.Debug("<- delpeer : pmap-clean", "id", id, "session", pd.rw.session, "pmap", pmap)
					if len(pmap) == 0 {
						delete(peers, pd.ID())
						log.Debug("<- delpeer : pmap-0", "id", id)
					} else {
						peers[pd.ID()] = pmap
						log.Debug("<- delpeer : pmap-n", "id", id, "pmap", pmap)
					}
				}
				log.Debug("<- delpeer", "err", pd.err, "id", id, "session", pd.rw.session, "pmap", pmap)
				if pd.Inbound() {
					inboundCount--
				}
			}()
		}
	}

	srv.log.Trace("P2P networking is spinning down")

	// Terminate discovery. If there is a running lookup it will terminate soon.
	if srv.ntab != nil {
		srv.ntab.Close()
	}
	if srv.DiscV5 != nil {
		srv.DiscV5.Close()
	}
	// Disconnect all peers.
	for _, pmap := range peers {
		for s, p := range pmap {
			p.Disconnect(DiscQuitting)
			log.Debug("DiscQuitting", "id", s, "session", p.rw.session)
		}
	}
	// Wait for peers to shut down. Pending connections and tasks are
	// not handled here and will terminate soon-ish because srv.quit
	// is closed.
	for len(peers) > 0 {
		select {
		case p := <-srv.delpeer:
			log.Trace("<-delpeer (spindown)", "remainingTasks", len(runningTasks))
			delete(peers, p.ID())
		case <-srv.quit:
			return
		}

	}
}

/* modify by liangc
func delBlockChainNodeSets(pd peerDrop) {
	eNode := "04" + pd.GetFullID()
	buff, err := hex.DecodeString(eNode)
	if err != nil {
		log.Error("hex.DecodeString", "err", err)
	}
	pub, err := crypto.UnmarshalPubkey(buff)
	if err != nil {
		log.Error("crypto.UnmarshalPubkey", "err", err)
	}
	address := crypto.PubkeyToAddress(*pub)
	db := *ethdb.ChainDb
	quorum.BlockChainNodeSets.Del(address.String(), db)
}

func (srv *Server) peerNumCheck(peers map[discover.NodeID]*Peer) {
	currentCommitNum := atomic.LoadUint64(&current.CurrentCommitNum)
	consensusQuorum, ok := quorum.CommitHeightToConsensusQuorum.Get(currentCommitNum, *ethdb.ChainDb)
	if !ok {
		return
	}
	peerNum := len(peers) + 1
	address := current.CRDCoinBase
	//&&peerNum<int(engine.NumMasters)
	if peerNum < srv.MaxPeers && peerNum < consensusQuorum.Len() {
		log.Info("peer数量不足,开始链接委员会Node")
		for _, add := range consensusQuorum.Hmap {
			if address.Hex() == add.Hex() {
				log.Info("server是自己不加入")
				continue
			}
			node := examineSync.AllNodeLists.FindNode(add)
			if node != nil {
				//去除已经链接上的
				if ok := peers[node.ID]; ok == nil {
					go srv.AddPeer(node)
					//examineSync.DiscoverEnode.AddDiscoverEnode(node.ID.String(),node)
					break
				}

			}

		}

	}
}
*/

func (srv *Server) protoHandshakeChecks(peers map[discover.NodeID]map[string]*Peer, inboundCount int, c *conn) error {
	// Drop connections with no matching protocols.
	if len(srv.Protocols) > 0 && countMatchingProtocols(srv.Protocols, c.caps) == 0 {
		return DiscUselessPeer
	}
	// Repeat the encryption handshake checks because the
	// peer set might have changed between the handshakes.
	return srv.encHandshakeChecks(peers, inboundCount, c)
}

func (srv *Server) encHandshakeChecks(peers map[discover.NodeID]map[string]*Peer, inboundCount int, c *conn) error {
	// add by liangc : 这个验证放在 alibp2p 中实现去了
	/*
		switch {
		case !c.is(trustedConn|staticDialedConn) && len(peers) >= srv.MaxPeers:
			return DiscTooManyPeers
		case !c.is(trustedConn) && c.is(inboundConn) && inboundCount >= srv.maxInboundConns():
			return DiscTooManyPeers
		case peers[c.id] != nil:
			if peers[c.id][c.session] != nil {
				return DiscAlreadyConnected
			}
			return nil
		case c.id == srv.Self().ID:
			return DiscSelf
		default:
			return nil
		}
	*/
	return nil
}

/*
func (srv *Server) maxInboundConns() int {
	return srv.MaxPeers - srv.maxDialedConns()
}
*/
func (srv *Server) maxDialedConns() int {
	return srv.MaxPeers
	/*
		if srv.NoDiscovery || srv.NoDial {
			return 0
		}
		r := srv.DialRatio
		if r == 0 {
			r = defaultDialRatio
		}
		return srv.MaxPeers / r
	*/
}

type tempError interface {
	Temporary() bool
}

// listenLoop runs in its own goroutine and accepts
// inbound connections.
func (srv *Server) listenLoop() {
	defer srv.loopWG.Done()
	srv.log.Info("RLPx listener up", "self", srv.makeSelf(srv.listener, srv.ntab))

	pointss := defaultMaxPendingPeers
	if srv.MaxPendingPeers > 0 {
		pointss = srv.MaxPendingPeers
	}
	slots := make(chan struct{}, pointss)
	for i := 0; i < pointss; i++ {
		slots <- struct{}{}
	}

	for {
		// Wait for a handshake slot before accepting.
		<-slots

		var (
			fd  net.Conn
			err error
		)
		for {
			fd, err = srv.listener.Accept()
			if tempErr, ok := err.(tempError); ok && tempErr.Temporary() {
				srv.log.Debug("Temporary read error", "err", err)
				continue
			} else if err != nil {
				srv.log.Debug("Read error", "err", err)
				return
			}
			break
		}

		// Reject connections that do not match NetRestrict.
		if srv.NetRestrict != nil {
			if tcp, ok := fd.RemoteAddr().(*net.TCPAddr); ok && !srv.NetRestrict.Contains(tcp.IP) {
				srv.log.Debug("Rejected conn (not whitelisted in NetRestrict)", "addr", fd.RemoteAddr())
				fd.Close()
				slots <- struct{}{}
				continue
			}
		}

		fd = newMeteredConn(fd, true)
		srv.log.Trace("Accepted connection", "addr", fd.RemoteAddr())
		go func() {
			srv.SetupConn(fd, inboundConn, nil)
			slots <- struct{}{}
		}()
	}
}

// SetupConn runs the handshakes and attempts to add the connection
// as a peer. It returns when the connection has been added as a peer
// or the handshakes have failed.
func (srv *Server) SetupConn(fd net.Conn, flags connFlag, dialDest *discover.Node) error {
	self := srv.Self()
	if self == nil {
		return errors.New("shutdown")
	}
	c := &conn{fd: fd, transport: srv.newTransport(fd), flags: flags, cont: make(chan error)}
	err := srv.setupConn(c, flags, dialDest)
	if err != nil {
		c.close(err)
		srv.log.Error("Setting up connection failed", "id", c.id, "err", err)
	}
	return err
}

func (srv *Server) setupConn(c *conn, flags connFlag, dialDest *discover.Node, timeout ...time.Duration) error {
	// Prevent leftover pending conns from entering the handshake.
	srv.lock.Lock()
	running := srv.running
	srv.lock.Unlock()
	if !running {
		return errServerStopped
	}
	// Run the encryption handshake.
	var err error
	if c.id, err = c.doEncHandshake(srv.PrivateKey, dialDest); err != nil {
		srv.log.Error("Failed RLPx handshake", "conn", c.flags, "err", err)
		//srv.log.Error("Failed RLPx handshake", "addr", c.fd.RemoteAddr(), "conn", c.flags, "err", err)
		return err
	}
	clog := srv.log.New("id", c.id, "conn", c.flags)
	//clog := srv.log.New("id", c.id, "addr", c.fd.RemoteAddr(), "conn", c.flags)
	// For dialed connections, check that the remote public key matches.
	if dialDest != nil && c.id != dialDest.ID {
		clog.Error("Dialed identity mismatch", "want", c, dialDest.ID)
		return DiscUnexpectedIdentity
	}
	err = srv.checkpoint(c, srv.posthandshake, timeout...)
	if err != nil {
		clog.Error("Rejected peer before protocol handshake", "err", err)
		return err
	}
	// Run the protocol handshake
	phs, err := c.doProtoHandshake(srv.ourHandshake)
	if err != nil {
		clog.Error("Failed proto handshake", "err", err)
		return err
	}
	if phs.ID != c.id {
		clog.Error("Wrong devp2p handshake identity", "err", phs.ID)
		return DiscUnexpectedIdentity
	}
	c.caps, c.name = phs.Caps, phs.Name
	err = srv.checkpoint(c, srv.addpeer, timeout...)
	if err != nil {
		clog.Error("Rejected peer", "err", err)
		return err
	}
	// If the checks completed successfully, runPeer has now been
	// launched by run.
	clog.Trace("connection set up", "inbound", dialDest == nil)
	return nil
}

func truncateName(s string) string {
	if len(s) > 20 {
		return s[:20] + "..."
	}
	return s
}

// checkpoint sends the conn to run, which performs the
// post-handshake checks for the stage (posthandshake, addpeer).
func (srv *Server) checkpoint(c *conn, stage chan<- *conn, timeout ...time.Duration) error {
	tot := func() <-chan struct{} {
		rch := make(chan struct{})
		if len(timeout) > 0 && timeout[0] > 0 {
			go func() {
				<-time.After(timeout[0])
				close(rch)
			}()
		}
		return rch
	}
	select {
	case stage <- c:
	case <-srv.quit:
		return errServerStopped
	case <-tot():
		return errServerTimeout
	}
	select {
	case err := <-c.cont:
		return err
	case <-srv.quit:
		return errServerStopped
	case <-tot():
		return errServerTimeout
	}
}

// runPeer runs in its own goroutine for each peer.
// it waits until the Peer logic returns and removes
// the peer.
func (srv *Server) runPeer(p *Peer) {
	if srv.newPeerHook != nil {
		srv.newPeerHook(p)
	}

	// broadcast peer add
	srv.peerFeed.Send(&PeerEvent{
		Type: PeerEventTypeAdd,
		Peer: p.ID(),
	})
	// run the protocol
	remoteRequested, err := p.run()

	// broadcast peer drop
	srv.peerFeed.Send(&PeerEvent{
		Type:  PeerEventTypeDrop,
		Peer:  p.ID(),
		Error: err.Error(),
	})
	log.Debug("Server.runPeer delpeer <- ", "name", p.rw.name, "session", p.rw.session, "err", err)
	// Note: run waits for existing peers to be sent on srv.delpeer
	// before returning, so this send should not select on srv.quit.
	srv.delpeer <- peerDrop{p, err, remoteRequested}

}

// NodeInfo represents a short summary of the information known about the host.
type NodeInfo struct {
	ID    string   `json:"id"`    // Unique node identifier (also the encryption key)
	Name  string   `json:"name"`  // Name of the node, including client type, version, OS, custom data
	Enode string   `json:"enode"` // Enode URL for adding this peer from remote peers
	IP    string   `json:"ip"`    // IP address of the node
	Addrs []string `json:"addrs"` // add by liangc : from alibp2p
	Ports struct {
		Discovery int `json:"discovery"` // UDP listening port for discovery protocol
		Listener  int `json:"listener"`  // TCP listening port for RLPx
	} `json:"ports"`
	ListenAddr string                 `json:"listenAddr"`
	Protocols  map[string]interface{} `json:"protocols"`
}

// NodeInfo gathers and returns a collection of metadata known about the host.
func (srv *Server) NodeInfo() *NodeInfo {
	node := srv.Self()
	/*
		/ip4/127.0.0.1/tcp/10000/ipfs/16Uiu2HAkzfSuviNuR7ez9BMkYw98YWNjyBNNmSLNnoX2XADfZGqP
		/ip4/10.0.0.76/tcp/10000
	*/
	// Gather and assemble the generic node infos
	id, addrs := srv.alibp2pService.Myid()
	enode := id
	for _, addr := range addrs {
		if strings.Contains(addr, "p2p-circuit") || strings.LastIndex(addr, "/ip") != 0 {
			continue
		}
		enode = fmt.Sprintf("%s/p2p/%s", addr, id)
		break
	}

	info := &NodeInfo{
		Name:  id,
		Enode: enode,
		//Enode:      node.String(),
		Addrs:      addrs,
		ID:         node.ID.String(),
		IP:         node.IP.String(),
		ListenAddr: srv.ListenAddr,
		Protocols:  make(map[string]interface{}),
	}
	info.Ports.Discovery = int(node.UDP)
	info.Ports.Listener = int(node.TCP)

	// Gather all the running protocol infos (only once per protocol type)
	for _, proto := range srv.Protocols {
		if _, ok := info.Protocols[proto.Name]; !ok {
			nodeInfo := interface{}("unknown")
			if query := proto.NodeInfo; query != nil {
				nodeInfo = proto.NodeInfo()
			}
			info.Protocols[proto.Name] = nodeInfo
		}
	}
	return info
}

func (srv *Server) Alibp2pTable() map[string][]string {
	return srv.alibp2pService.Table()
}

func (srv *Server) Alibp2pBootstrap() error {
	return srv.alibp2pService.BootstrapOnce()
}

func (srv *Server) Alibp2pPeers() map[string]interface{} {
	m := make(map[string]interface{})
	d, r, t := srv.alibp2pService.p2pservice.Peers()
	m["direct"], m["relay"], m["total"] = d, r, t
	return m
}

func (srv *Server) Alibp2pPeermap() map[string]interface{} {
	rm := make(map[string]interface{})
	list0, list1 := srv.alibp2pService.p2pservice.Conns()
	if len(list0)+len(list1) < 2 {
		return rm
	}
	vi := 0
	vmap_i := make(map[int]string)
	vmap_n := make(map[string]int)
	for _, s := range list0 {
		arr := strings.Split(s, "/p2p/")
		t := arr[1]
		vmap_i[vi] = t
		vmap_n[t] = vi
		vi = vi + 1
	}
	edges := make(map[string]string)

	for _, s := range list1 {
		arr := strings.Split(s, "/p2p-circuit")
		f, t := arr[0][6:], arr[1][6:]
		edges[t] = f
		vmap_i[vi] = t
		vmap_n[t] = vi
		vi = vi + 1
	}

	graph := graph.NewGraph(len(list0) + len(list1))
	for t, f := range edges {
		v := vmap_n[t]
		w := vmap_n[f]
		graph.AddEdge(v, w)
	}

	adj := graph.GetAdj()
	for v, bag := range adj {
		if bag == nil {
			continue
		}
		sb := make([]string, 0)
		bag.Items(func(i interface{}) {
			_v := i.(int)
			sb = append(sb, vmap_i[_v])
		})
		rm[vmap_i[v]] = sb
	}
	return rm
}

// PeersInfo returns an array of metadata objects describing connected peers.
func (srv *Server) PeersInfo() []*PeerInfo {
	// Gather all the generic and sub-protocol specific infos
	infos := make([]*PeerInfo, 0, srv.PeerCount())
	for _, peer := range srv.Peers() {
		if peer != nil {
			if pi := peer.Info(); pi != nil {
				infos = append(infos, pi)
			}
		}
	}
	// Sort the result array alphabetically by node identifier
	for i := 0; i < len(infos); i++ {
		for j := i + 1; j < len(infos); j++ {
			if infos[i].ID > infos[j].ID {
				infos[i], infos[j] = infos[j], infos[i]
			}
		}
	}
	return infos
}

// add by liangc
func (srv *Server) HighwayPeersInfo() []*HighwayPeerInfo {
	peers := srv.HighwayPeers()
	peerinfos := make([]*HighwayPeerInfo, 0)
	for _, p := range peers {
		peerinfos = append(peerinfos, &HighwayPeerInfo{
			ID:   p.id.Hex(),
			Name: srv.mq.qid,
		})
	}
	return peerinfos
}

// add by liangc : 从 IAAS 拿到的 nodes 列表，反序列化以后丢入 nursery 集合，刷新组网节点
func (srv *Server) SetFallbackNodes(urls []string) error {
	boots := make([]string, 0)
	for _, u := range urls {
		boots = append(boots, strings.Replace(u, "CRD", "ipfs", -1))
	}
	log.Info("set-bootnodes", "nodes", boots)
	err := srv.alibp2pService.p2pservice.SetBootnode(boots...)
	if err != nil {
		return err
	}
	return srv.alibp2pService.BootstrapOnce()
}

func (srv *Server) Alibp2pFindpeer(id string) (string, []string, error) {
	pub, err := alibp2p.ECDSAPubDecode(id)
	if err != nil {
		return id, nil, err
	}
	return srv.alibp2pService.Findpeer(pub)
}
func (srv *Server) Alibp2pPing(id string) (string, error) {
	return srv.alibp2pService.Ping(id)
}

func (srv *Server) AlibAppendBlockList(pubkey *ecdsa.PublicKey, duration time.Duration) error {
	return srv.alibp2pService.AppendBlacklist(pubkey, duration)
}

func (srv *Server) Alibp2pTestmail(id string) string {
	from := srv.PrivateKey.PublicKey
	myid := crypto.PubkeyToAddress(srv.PrivateKey.PublicKey)
	code := big.NewInt(14514)
	data := &types.Header{
		Number:   code,
		Coinbase: myid,
		Root:     common.BytesToHash(code.Bytes()),
		Extra:    append(from.X.Bytes(), from.Y.Bytes()...),
	}
	pubkey, err := alibp2p.ECDSAPubDecode(id)
	if err != nil {
		return err.Error()
	}
	err = Send(pubkey, code.Uint64(), data)
	if err != nil {
		return err.Error()
	}
	return "success"
}

func (srv *Server) Alibp2pTestmsg(id string, total int) string {
	from := srv.PrivateKey.PublicKey
	myid := crypto.PubkeyToAddress(srv.PrivateKey.PublicKey)
	code := big.NewInt(0xA0) // 0xA0 + 16
	data := &types.Header{
		Number:   code,
		Coinbase: myid,
		Root:     common.BytesToHash(code.Bytes()),
		Extra:    append(from.X.Bytes(), from.Y.Bytes()...),
	}
	for _, peer := range srv.Peers() {
		if pk, err := peer.rw.id.Pubkey(); err == nil {
			pid, _ := alibp2p.ECDSAPubEncode(pk)
			if pid == id {
				for i := 0; i < total; i++ {
					err = Send(peer.rw, code.Uint64()+16, data)
					if err != nil {
						return err.Error()
					}
				}
				return fmt.Sprintf("success: %d", total)
			}
		}
	}
	return fmt.Sprintf("peer notfound : %s", id)
}

func (srv *Server) Alibp2pUnlink(id string) error {
	pubkey, err := alibp2p.ECDSAPubDecode(id)
	if err != nil {
		return err
	}
	resp, err := srv.alibp2pService.p2pservice.Request(id, premsgpid, unlink.Bytes())
	if err != nil {
		return err
	}
	srv.alibp2pService.cleanConnect(pubkey, "test-unlink", DELPEER_UNLINK)
	n := srv.alibp2pService.unlinkEvent.Send(id)
	fmt.Println("Alibp2pUnlink", "n =", n, "id =", id, "resp =", resp)
	return nil
}

func (srv *Server) Alibp2pAddPeer(url string) error {
	return srv.alibp2pService.Connect(url)
}

func (srv *Server) AppendBlacklist(peerid *ecdsa.PublicKey, expire time.Duration) error {
	return srv.alibp2pService.AppendBlacklist(peerid, expire)
}

func (srv *Server) Alibp2pMsgChanState() map[string]interface{} {
	return srv.alibp2pService.msgChanState()
}

func (srv *Server) Alibp2pReport(peerids ...string) (map[string]interface{}, error) {
	jbuf := srv.alibp2pService.p2pservice.Report(peerids...)
	m := make(map[string]interface{})
	err := json.Unmarshal(jbuf, &m)
	return m, err
}
