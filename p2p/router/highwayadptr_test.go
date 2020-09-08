package router

import (
	"bytes"
	"testing"
	"time"

	"CRD-chain/crypto"
	"CRD-chain/p2p"
	"CRD-chain/p2p/discover"
)

func TestNewHighWayAdp(t *testing.T) {
	config := p2p.Config{}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Error("GenerateKey", err)
	}
	config.PrivateKey = key
	srv := &p2p.Server{Config: config}

	dr := newTestRouter()
	err = dr.Start(srv)
	if err != nil {
		t.Error("startDR", err)
	}

	adp := NewHighWayAdp(srv, dr)
	adp.Start()

	for i := 0; i < 5; i++ {
		dr.rtLock.RLock()
		if len(dr.neighbors) != 0 {
			dr.rtLock.RUnlock()
			break
		}
		dr.rtLock.RUnlock()
		if i == 4 {
			t.Error("highway peers add failed, timeout")
			return
		}
		time.Sleep(1 * time.Second)
	}
	nb, ok := dr.neighbors[adp.vPeer.SID()]
	if !ok || nb.rw != adp.rrw {
		t.Error("HighWay Adapter initialized failed", "adapter", adp)
	}

	if len(adp.hPeers) != len(dr.routeTable)-1 {
		t.Error("vPeer route table update failed", "router", dr.routeTable)
	}

	for id := range adp.hPeers {
		if dr.routeTable[id][0].Hops != 1 || dr.routeTable[id][0].Id != adp.vPeer.SID() {
			t.Error("route item miss matched", "routeItem", dr.routeTable[id])
		}
	}

	a := discover.ShortID{0xa}
	b := discover.ShortID{0xb}
	mData := []byte("HighWay adapter test")
	dr.UniCastMsg(a, UniCastMsgType(1), mData)
	msg, err := adp.hPeers[b].Mrw.(p2p.MsgReadWriter).ReadMsg()
	if err != nil {
		t.Error("highway read/write test failed", "err", err)
	}
	if msg.Code != UNICAST {
		t.Error("invalid msg type", "type", msg.Code)
	}
	var data uniCastData
	err = msg.Decode(&data)
	if err != nil {
		t.Error("decode received msg failed", "err", err)
	}
	if bytes.Compare(data.Data, mData) != 0 {
		t.Error("received incorrect msg data", data, mData)
	}
}

// modify HighwayPeers function in p2p.server.go before running this test case
//func (srv *Server) HighwayPeers() map[common.Address]*Peer {
//	if srv.mq == nil {
//		testMap := make(map[common.Address]*Peer)
//		a:= common.Address{0xa}
//		b:= common.Address{0xb}
//		c:= common.Address{0xc}
//		d:= common.Address{0xd}
//		e:= common.Address{0xe}
//		f:= common.Address{0xf}
//		awr, bwr := MsgPipe()
//		testMap[a] = NewPeer2(a, awr)
//		testMap[b] = NewPeer2(b, bwr)
//
//		testMap[c] = NewPeer2(c, awr)
//		testMap[d] = NewPeer2(d, bwr)
//
//		testMap[e] = NewPeer2(e, awr)
//		testMap[f] = NewPeer2(f, bwr)
//		return testMap
//	}
//	peers, err := srv.mq.highwayPeers()
//	if err != nil {
//		log.Error("HiwayPeers_error", "err", err)
//		return nil
//	}
//	return peers
//}
