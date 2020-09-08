package alibp2p

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"github.com/google/uuid"
	lru "github.com/hashicorp/golang-lru"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/metrics"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/routing"
	discovery "github.com/libp2p/go-libp2p-discovery"
	"io"
	"math/big"
	"strings"
	"sync"
	"time"
)

var ns_notfound = errors.New("Namespace not registed")
var unknow_stream_handler_type = errors.New("Unknow Stream Handler Type")

type (
	RawData struct {
		Id   []byte
		Err  string
		Data []byte
	}

	SimplePacketHead []byte

	Service struct {
		ctx              context.Context
		homedir          string
		host             host.Host
		router           routing.Routing
		routingDiscovery *discovery.RoutingDiscovery
		bootnodes        []peer.AddrInfo
		cfg              Config
		notifiee         []*network.NotifyBundle
		isDirectFn       func(id string) bool
		bwc, msgc        metrics.Reporter
		asc              *AStreamCache
		nsttl            map[string]time.Duration
		clientProtocols  map[string]struct{}
	}

	blankValidator struct{}
	asyncFn        struct {
		fn   func(context.Context, []interface{})
		args []interface{}
	}

	AsyncRunner struct {
		sync.Mutex
		wg                *sync.WaitGroup
		ctx               context.Context
		counter, min, max int32
		fnCh              chan *asyncFn
		closeCh           chan struct{}
		close             bool
		gc                time.Duration
	}
	// 关于 key 的互斥锁
	KeyMutex struct {
		reglock *sync.Map
		timeout time.Duration
		kcache  *lru.Cache
	}
)

func NewRawData(id *big.Int, data []byte) *RawData {
	if id == nil {
		u := uuid.New()
		id = new(big.Int).SetBytes(u[:])
	}
	return &RawData{Id: id.Bytes(), Data: data}
}

func ReadSimplePacketHead(r io.Reader) (SimplePacketHead, error) {
	head := make([]byte, 6)
	t, err := r.Read(head)
	if t != 6 || err != nil {
		return nil, err
	}
	return head, nil
}

func NewSimplePacketHead(msgType uint16, data []byte) SimplePacketHead {
	var psize = uint32(len(data))
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, &msgType)
	binary.Write(buf, binary.BigEndian, &psize)
	return buf.Bytes()
}

func (header SimplePacketHead) Decode() (msgType uint16, size uint32, err error) {
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

func (blankValidator) Validate(_ string, _ []byte) error        { return nil }
func (blankValidator) Select(_ string, _ [][]byte) (int, error) { return 0, nil }

func (d *RawData) Len() int     { return len(d.Data) }
func (d *RawData) ID() *big.Int { return new(big.Int).SetBytes(d.Id) }

type PeerDirection string

func NewPeerDirection(id string, dir network.Direction) PeerDirection {
	switch dir {
	case network.DirInbound:
		return PeerDirection(id + "(IN)")
	case network.DirOutbound:
		return PeerDirection(id + "(OUT)")
	default:
		return PeerDirection(id)
	}
}

func (o PeerDirection) Direction() network.Direction {
	if strings.Contains(string(o), "(IN)") {
		return network.DirInbound
	}
	if strings.Contains(string(o), "(OUT)") {
		return network.DirOutbound
	}
	return network.DirUnknown
}

func (o PeerDirection) Pretty() string {
	if strings.Contains(o.ID(), "/p2p/") {
		return strings.Split(o.ID(), "/p2p/")[1]
	}
	if strings.Contains(o.ID(), "ipfs") {
		return strings.Split(o.ID(), "ipfs/")[1]
	}
	return o.ID()
}
func (o PeerDirection) ID() string {
	id := strings.Split(string(o), "(")[0]
	return id
}

func (o PeerDirection) String() string { return string(o) }
