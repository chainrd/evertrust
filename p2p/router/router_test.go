package router

import (
	"bytes"
	"io"
	"testing"

	"CRD-chain/crypto"
	"CRD-chain/p2p"
	"CRD-chain/p2p/discover"
)

//func testPeer(protos []p2p.Protocol) (func(), *conn, *Peer, <-chan error) {
//	fd1, fd2 := net.Pipe()
//	c1 := &conn{fd: fd1, transport: newTestTransport(randomID(), fd1)}
//	c2 := &conn{fd: fd2, transport: newTestTransport(randomID(), fd2)}
//	for _, p := range protos {
//		c1.caps = append(c1.caps, p.cap())
//		c2.caps = append(c2.caps, p.cap())
//	}
//
//	peer := p2p.newPeer(c1, protos)
//	errc := make(chan error, 1)
//	go func() {
//		_, err := peer.run()
//		errc <- err
//	}()
//
//	closer := func() { c2.close(errors.New("close func called")) }
//	return closer, c2, peer, errc
//}
//
//
//func TestDynamicRouter_Run(t *testing.T) {
//	closer, rw, _, errc := p2p.testPeer(DR.Protocols())
//}

type rwMock struct {
}

func (rw *rwMock) WriteMsg(p2p.Msg) error {
	return nil
}

func (rw *rwMock) ReadMsg() (p2p.Msg, error) {
	return p2p.Msg{}, nil
}

func initDR(t *testing.T, dr *DynamicRouter) discover.NodeID {
	//var DR = NewRouter()
	config := p2p.Config{}
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Error("initDR", err)
		return discover.NodeID{}
	}
	config.PrivateKey = key
	srv := &p2p.Server{Config: config}
	err = dr.Start(srv)
	if err != nil {
		t.Error("initDR", err)
	}
	//fmt.Println("router started")
	var nID discover.NodeID
	copy(nID[:], crypto.FromECDSAPub(&srv.PrivateKey.PublicKey)[1:])
	return nID
}

func TestGetUpRoutes(t *testing.T) {
	//initDR(t)
	var DR = newTestRouter()
	a := discover.ShortID{0xa}
	b := discover.ShortID{0xb}
	n1 := discover.ShortID{0x1}
	n2 := discover.ShortID{0x2}
	n3 := discover.ShortID{0x3}
	n4 := discover.ShortID{0x4}
	n5 := discover.ShortID{0x5}

	DR.upTable[a] = append(DR.upTable[a], b)
	DR.upTable[n1] = append(DR.upTable[n1], a)
	DR.upTable[n2] = append(DR.upTable[n2], n1)
	DR.upTable[n3] = append(DR.upTable[n3], n2)
	DR.upTable[n4] = append(DR.upTable[n4], n3)
	DR.upTable[n5] = append(DR.upTable[n5], n4)

	DR.upTable[n1] = append(DR.upTable[n1], n2)
	DR.upTable[n2] = append(DR.upTable[n2], n3)
	DR.upTable[n3] = append(DR.upTable[n3], n4)
	DR.upTable[n4] = append(DR.upTable[n4], n5)
	DR.upTable[n5] = append(DR.upTable[n5], a)

	tmp := DR.getUpRoutes(n1)
	//fmt.Println(tmp)
	if len(tmp) != 6 {
		t.Errorf("getUpRoutes returned unexpected values:%v", tmp)
	}
	tmp = removeNID(tmp, a)
	tmp = removeNID(tmp, b)
	tmp = removeNID(tmp, n2)
	tmp = removeNID(tmp, n3)
	tmp = removeNID(tmp, n4)
	tmp = removeNID(tmp, n5)

	if len(tmp) != 0 {
		t.Errorf("getUpRoutes returned unexpected values:%v", tmp)
	}

	tmp = DR.getUpRoutes(a)
	if len(tmp) != 1 || tmp[0] != b {
		t.Errorf("getUpRoutes returned unexpected values:%v", tmp)
	}

	tmp = DR.getUpRoutes(n5)
	if len(tmp) != 6 {
		t.Errorf("getUpRoutes returned unexpected values:%v", tmp)
	}
	tmp = removeNID(tmp, a)
	tmp = removeNID(tmp, b)
	tmp = removeNID(tmp, n2)
	tmp = removeNID(tmp, n3)
	tmp = removeNID(tmp, n4)
	tmp = removeNID(tmp, n1)

	if len(tmp) != 0 {
		t.Errorf("getUpRoutes returned unexpected values:%v", tmp)
	}

	n7 := discover.ShortID{0x7}
	n8 := discover.ShortID{0x8}
	DR.upTable[n8] = append(DR.upTable[n8], n3)
	DR.upTable[n7] = append(DR.upTable[n7], n3)
	DR.upTable[n8] = append(DR.upTable[n8], n7)
	DR.upTable[n7] = append(DR.upTable[n7], n8)

	tmp = DR.getUpRoutes(n7)
	//fmt.Println(tmp)
	if len(tmp) != 8 {
		t.Errorf("getUpRoutes returned unexpected values:%v", tmp)
	}
	tmp = removeNID(tmp, a)
	tmp = removeNID(tmp, b)
	tmp = removeNID(tmp, n1)
	tmp = removeNID(tmp, n2)
	tmp = removeNID(tmp, n3)
	tmp = removeNID(tmp, n4)
	tmp = removeNID(tmp, n5)
	tmp = removeNID(tmp, n8)

	if len(tmp) != 0 {
		t.Errorf("getUpRoutes returned unexpected values:%v", tmp)
	}
}

func TestUpdateRoute(t *testing.T) {
	var DR = newTestRouter()
	a := discover.NodeID{0xa}
	b := discover.NodeID{0xb}
	n1 := discover.ShortID{0x1}
	n2 := discover.ShortID{0x2}
	n3 := discover.ShortID{0x3}
	n4 := discover.ShortID{0x4}
	n5 := discover.ShortID{0x5}

	pa := p2p.NewPeer(a, "nodea", nil)
	aid := pa.SID()
	DR.neighbors[aid] = neighbor{pa, nil}
	DR.routeTable[aid] = append(DR.routeTable[aid], routeItem{aid, 0})

	pb := p2p.NewPeer(b, "nodeb", nil)
	bid := pb.SID()
	DR.neighbors[bid] = neighbor{pb, nil}
	DR.routeTable[bid] = append(DR.routeTable[bid], routeItem{bid, 0})

	DR.upTable[aid] = append(DR.upTable[aid], bid)
	DR.updateRoute(aid)
	if len(DR.routeTable[aid]) != 2 {
		t.Errorf("neighbor routeTable update failed %v", DR.routeTable[aid])
	}
	for _, ri := range DR.routeTable[aid] {
		if ri.Id == bid {
			if ri.Hops != 1 {
				t.Errorf("neighbor routeTable update failed, ri.Hops:1!=%d", ri.Hops)
			}
			continue
		}
		if ri.Id == aid {
			if ri.Hops != 0 {
				t.Errorf("neighbor routeTable update failed, ri.Hops:0!=%d", ri.Hops)
			}
			continue
		}
		t.Errorf("neighbor routeTable update failed, wrong routeItemd %v", ri)
	}

	DR.upTable[n1] = append(DR.upTable[n1], aid)
	DR.upTable[n2] = append(DR.upTable[n2], n1)
	DR.upTable[n3] = append(DR.upTable[n3], n2)
	DR.upTable[n4] = append(DR.upTable[n4], n3)
	DR.upTable[n5] = append(DR.upTable[n5], n4)
	DR.updateRoute(n1)
	DR.updateRoute(n2)
	DR.updateRoute(n3)
	DR.updateRoute(n4)
	DR.updateRoute(n5)

	DR.upTable[n1] = append(DR.upTable[n1], n2)
	DR.upTable[n2] = append(DR.upTable[n2], n3)
	DR.upTable[n3] = append(DR.upTable[n3], n4)
	DR.upTable[n4] = append(DR.upTable[n4], n5)
	DR.upTable[n5] = append(DR.upTable[n5], aid)
	DR.updateRoute(n1)
	DR.updateRoute(n2)
	DR.updateRoute(n3)
	DR.updateRoute(n4)
	DR.updateRoute(n5)
	//fmt.Println("n2", DR.routeTable[n2])

	n7 := discover.ShortID{0x7}
	n8 := discover.ShortID{0x8}
	DR.upTable[n8] = append(DR.upTable[n8], n3)
	DR.upTable[n7] = append(DR.upTable[n7], n3)
	DR.updateRoute(n7)
	DR.updateRoute(n8)
	DR.upTable[n8] = append(DR.upTable[n8], n7)
	DR.upTable[n7] = append(DR.upTable[n7], n8)
	DR.updateRoute(n7)
	DR.updateRoute(n8)
	//fmt.Println("n7", DR.routeTable[n7])
	if len(DR.routeTable[n7]) != 2 {
		t.Errorf("loop routeTable update failed, wrong routes n7:%v", DR.routeTable[n7])
	}
	if len(DR.routeTable[n8]) != 2 {
		t.Errorf("loop routeTable update failed, wrong routes n8:%v", DR.routeTable[n8])
	}
	for _, ri := range DR.routeTable[n7] {
		if ri.Id == bid {
			if ri.Hops != 5 {
				t.Errorf("loop routeTable update failed, ri.Hops:5!=%d", ri.Hops)
			}
			continue
		}
		if ri.Id == aid {
			if ri.Hops != 4 {
				t.Errorf("loop routeTable update failed, ri.Hops:4!=%d", ri.Hops)
			}
			continue
		}
		t.Errorf("loop routeTable update failed, wrong routeItemd %v", ri)
	}
	for _, ri := range DR.routeTable[n8] {
		if ri.Id == bid {
			if ri.Hops != 5 {
				t.Errorf("loop routeTable update failed, ri.Hops:1!=%d", ri.Hops)
			}
			continue
		}
		if ri.Id == aid {
			if ri.Hops != 4 {
				t.Errorf("loop routeTable update failed, ri.Hops:0!=%d", ri.Hops)
			}
			continue
		}
		t.Errorf("loop routeTable update failed, wrong routeItemd %v", ri)
	}
}

func TestUpdateSubTree(t *testing.T) {
	var DR = NewRouter()
	a := discover.NodeID{0xa}
	b := discover.NodeID{0xb}
	n1 := discover.ShortID{0x1}
	n2 := discover.ShortID{0x2}
	n3 := discover.ShortID{0x3}
	n4 := discover.ShortID{0x4}
	n5 := discover.ShortID{0x5}
	n7 := discover.ShortID{0x7}
	n8 := discover.ShortID{0x8}

	pa := p2p.NewPeer(a, "nodea", nil)
	aid := pa.SID()
	DR.neighbors[aid] = neighbor{pa, &rwMock{}}
	DR.routeTable[aid] = append(DR.routeTable[aid], routeItem{aid, 0})

	pb := p2p.NewPeer(b, "nodeb", nil)
	bid := pb.SID()
	DR.neighbors[bid] = neighbor{pb, &rwMock{}}
	DR.routeTable[bid] = append(DR.routeTable[bid], routeItem{bid, 0})

	DR.upTable[aid] = append(DR.upTable[aid], bid)
	DR.updateRoute(aid)

	tmpTree := newTreeNode()
	tmpTree.addLeaf(n1)
	tmpTree.addLeaf(n5)
	DR.peerTree[aid] = tmpTree

	tmpTree = newTreeNode()
	tmpTree.addLeaf(aid)
	tmpTree.addLeaf(n2)
	DR.peerTree[n1] = tmpTree

	tmpTree = newTreeNode()
	tmpTree.addLeaf(n1)
	tmpTree.addLeaf(n3)
	DR.peerTree[n2] = tmpTree

	tmpTree = newTreeNode()
	tmpTree.addLeaf(n4)
	tmpTree.addLeaf(n2)
	tmpTree.addLeaf(n7)
	tmpTree.addLeaf(n8)
	DR.peerTree[n3] = tmpTree

	tmpTree = newTreeNode()
	tmpTree.addLeaf(n3)
	tmpTree.addLeaf(n5)
	DR.peerTree[n4] = tmpTree

	tmpTree = newTreeNode()
	tmpTree.addLeaf(aid)
	tmpTree.addLeaf(n4)
	DR.peerTree[n5] = tmpTree

	tmpTree = newTreeNode()
	tmpTree.addLeaf(n3)
	tmpTree.addLeaf(n8)
	DR.peerTree[n7] = tmpTree

	tmpTree = newTreeNode()
	tmpTree.addLeaf(n3)
	tmpTree.addLeaf(n7)
	DR.peerTree[n8] = tmpTree

	DR.upTable[n1] = append(DR.upTable[n1], aid)
	DR.upTable[n2] = append(DR.upTable[n2], n1)
	DR.upTable[n3] = append(DR.upTable[n3], n2)
	DR.upTable[n4] = append(DR.upTable[n4], n3)
	DR.upTable[n5] = append(DR.upTable[n5], n4)

	DR.upTable[n1] = append(DR.upTable[n1], n2)
	DR.upTable[n2] = append(DR.upTable[n2], n3)
	DR.upTable[n3] = append(DR.upTable[n3], n4)
	DR.upTable[n4] = append(DR.upTable[n4], n5)
	DR.upTable[n5] = append(DR.upTable[n5], aid)

	DR.upTable[n8] = append(DR.upTable[n8], n3)
	DR.upTable[n7] = append(DR.upTable[n7], n3)
	DR.upTable[n8] = append(DR.upTable[n8], n7)
	DR.upTable[n7] = append(DR.upTable[n7], n8)

	subTree := []rTree{{DR.peerTree[aid], aid, DR.routerID}}

	DR.updateSubTree(subTree)

	//DR.updateRoute(n7)
	//DR.updateRoute(n8)
	//fmt.Println("n7", DR.routeTable[n7])
	//if len(DR.routeTable[n7]) != 3 {
	//	t.Errorf("loop routeTable update failed, wrong routes n7:%v", DR.routeTable[n7])
	//}
	//if len(DR.routeTable[n8]) != 3 {
	//	t.Errorf("loop routeTable update failed, wrong routes n8:%v", DR.routeTable[n8])
	//}
	//for _, ri := range DR.routeTable[n7] {
	//	if ri.Id == b {
	//		if ri.hops != 5 {
	//			t.Errorf("loop routeTable update failed, ri.hops:5!=%d", ri.hops)
	//		}
	//		continue
	//	}
	//	if ri.Id == a {
	//		if ri.hops != 4 && ri.hops != 5 {
	//			t.Errorf("loop routeTable update failed, ri.hops:4!=%d", ri.hops)
	//		}
	//		continue
	//	}
	//	t.Errorf("loop routeTable update failed, wrong routeItemd %v", ri)
	//}
	//for _, ri := range DR.routeTable[n8] {
	//	if ri.Id == b {
	//		if ri.hops != 5 {
	//			t.Errorf("loop routeTable update failed, ri.hops:1!=%d", ri.hops)
	//		}
	//		continue
	//	}
	//	if ri.Id == a {
	//		if ri.hops != 4 && ri.hops != 5 {
	//			t.Errorf("loop routeTable update failed, ri.hops:0!=%d", ri.hops)
	//		}
	//		continue
	//	}
	//	t.Errorf("loop routeTable update failed, wrong routeItemd %v", ri)
	//}
}

func TestGenRouteTable(t *testing.T) {
	var DR = newTestRouter()
	initDR(t, DR)
	a := discover.NodeID{0xa}
	b := discover.NodeID{0xb}
	c := discover.NodeID{0xc}
	n1 := discover.ShortID{0x1}
	n2 := discover.ShortID{0x2}
	n3 := discover.ShortID{0x3}
	n4 := discover.ShortID{0x4}
	n5 := discover.ShortID{0x5}
	n7 := discover.ShortID{0x7}
	n8 := discover.ShortID{0x8}

	pa := p2p.NewPeer(a, "nodea", nil)
	aid := pa.SID()
	DR.in <- neighbor{pa, &rwMock{}}
	//DR.neighbors[a] = neighbor{pa, &rwMock{}}
	//DR.routeTable[a] = append(DR.routeTable[a], routeItem{a, 0})

	pb := p2p.NewPeer(b, "nodeb", nil)
	bid := pb.SID()
	DR.in <- neighbor{pb, &rwMock{}}
	//DR.neighbors[b] = neighbor{pb, &rwMock{}}
	//DR.routeTable[b] = append(DR.routeTable[b], routeItem{b, 0})

	//DR.upTable[a] = append(DR.upTable[a], b)
	//DR.updateRoute(a)
	pc := p2p.NewPeer(c, "nodec", nil)
	DR.in <- neighbor{pc, &rwMock{}}

	pd := p2p.NewPeer(discover.NodeID{0xd}, "noded", nil)
	DR.out <- pd

	tmpTree := newTreeNode()
	tmpTree.addLeaf(aid)
	DR.rtLock.Lock()
	DR.peerTree[bid] = tmpTree
	DR.rtLock.Unlock()
	DR.genRouteTable(DR.peerTree[bid], bid)

	tmpTree = newTreeNode()
	tmpTree.addLeaf(n1)
	//tmpTree.addLeaf(n5)
	DR.rtLock.Lock()
	DR.peerTree[aid] = tmpTree
	DR.rtLock.Unlock()
	DR.genRouteTable(DR.peerTree[aid], aid)

	tmpTree = newTreeNode()
	tmpTree.addLeaf(aid)
	tmpTree.addLeaf(n2)
	DR.rtLock.Lock()
	DR.peerTree[n1] = tmpTree
	DR.rtLock.Unlock()
	DR.genRouteTable(DR.peerTree[n1], n1)

	tmpTree = newTreeNode()
	tmpTree.addLeaf(n1)
	tmpTree.addLeaf(n3)
	DR.rtLock.Lock()
	DR.peerTree[n2] = tmpTree
	DR.rtLock.Unlock()
	DR.genRouteTable(DR.peerTree[n2], n2)

	tmpTree = newTreeNode()
	tmpTree.addLeaf(n4)
	tmpTree.addLeaf(n2)
	DR.rtLock.Lock()
	DR.peerTree[n3] = tmpTree
	DR.rtLock.Unlock()
	DR.genRouteTable(DR.peerTree[n3], n3)

	tmpTree = newTreeNode()
	tmpTree.addLeaf(n3)
	tmpTree.addLeaf(n5)
	DR.rtLock.Lock()
	DR.peerTree[n4] = tmpTree
	DR.rtLock.Unlock()
	DR.genRouteTable(DR.peerTree[n4], n4)

	tmpTree = newTreeNode()
	tmpTree.addLeaf(aid)
	tmpTree.addLeaf(n4)
	DR.rtLock.Lock()
	DR.peerTree[n5] = tmpTree
	DR.rtLock.Unlock()
	DR.genRouteTable(DR.peerTree[n5], n5)

	DR.rtLock.Lock()
	tmpTree = DR.peerTree[n3]
	tmpTree.addLeaf(n7)
	tmpTree.addLeaf(n8)
	DR.peerTree[n3] = tmpTree
	DR.rtLock.Unlock()

	tmpTree = newTreeNode()
	tmpTree.addLeaf(n3)
	tmpTree.addLeaf(n8)
	DR.rtLock.Lock()
	DR.peerTree[n7] = tmpTree
	DR.rtLock.Unlock()

	tmpTree = newTreeNode()
	tmpTree.addLeaf(n3)
	tmpTree.addLeaf(n7)
	DR.rtLock.Lock()
	DR.peerTree[n8] = tmpTree
	DR.rtLock.Unlock()

	DR.genRouteTable(DR.peerTree[n3], n3)

	//DR.genRouteTable(DR.peerTree[n7], n7)
	//DR.genRouteTable(DR.peerTree[n8], n8)

	//subTree := []rTree{{DR.peerTree[a], a, DR.routerID}}
	//
	//DR.updateSubTree(subTree)

	//DR.updateRoute(n7)
	//DR.updateRoute(n8)
	//fmt.Println("n7", DR.routeTable[n7])
	checkRouteA := func() {
		if len(DR.routeTable[n7]) != 2 {
			t.Errorf("genRouteTable update failed, wrong routes n7:%v", DR.routeTable[n7])
		}
		if len(DR.routeTable[n8]) != 2 {
			t.Errorf("genRouteTable update failed, wrong routes n8:%v", DR.routeTable[n8])
		}
		for _, ri := range DR.routeTable[n7] {
			if ri.Id == bid {
				if ri.Hops != 5 {
					t.Errorf("genRouteTable update failed, ri.Hops:5!=%d", ri.Hops)
				}
				continue
			}
			if ri.Id == aid {
				if ri.Hops != 4 {
					t.Errorf("genRouteTable update failed, ri.Hops:4!=%d", ri.Hops)
				}
				continue
			}
			t.Errorf("genRouteTable update failed, wrong routeItemd %v", ri)
		}
		for _, ri := range DR.routeTable[n8] {
			if ri.Id == bid {
				if ri.Hops != 5 {
					t.Errorf("genRouteTable update failed, ri.Hops:1!=%d", ri.Hops)
				}
				continue
			}
			if ri.Id == aid {
				if ri.Hops != 4 {
					t.Errorf("genRouteTable update failed, ri.Hops:0!=%d", ri.Hops)
				}
				continue
			}
			t.Errorf("genRouteTable update failed, wrong routeItemd %v", ri)
		}
	}

	checkRouteA()

	DR.out <- pa
	DR.out <- pc
	DR.out <- pd

	// onNeighborDown
	//delete(DR.neighbors, a)
	// delete route item
	//DR.routeTable[a] = DR.routeTable[a][1:]
	//pTree := DR.peerTree[DR.routerID]
	//pTree.delLeaf(a)
	//pTree = r.peerTree[id]
	//pTree.delLeaf(r.routerID)
	//DR.onNeighborDown(a)

	if DR.routeTable[aid][0].Id != bid && DR.routeTable[aid][0].Hops != 1 {
		t.Errorf("onNeighborDown update failed, wrong routes a:%v", DR.routeTable[aid])
	}

	if len(DR.routeTable[n7]) != 1 {
		t.Errorf("onNeighborDown update failed, wrong routes n7:%v", DR.routeTable[n7])
	}
	if len(DR.routeTable[n8]) != 1 {
		t.Errorf("onNeighborDown update failed, wrong routes n8:%v", DR.routeTable[n8])
	}
	for _, ri := range DR.routeTable[n7] {
		if ri.Id == bid {
			if ri.Hops != 5 {
				t.Errorf("onNeighborDown update failed, ri.Hops:5!=%d", ri.Hops)
			}
			continue
		}
		t.Errorf("onNeighborDown update failed, wrong routeItemd %v", ri)
	}
	for _, ri := range DR.routeTable[n8] {
		if ri.Id == bid {
			if ri.Hops != 5 {
				t.Errorf("onNeighborDown update failed, ri.Hops:1!=%d", ri.Hops)
			}
			continue
		}

		t.Errorf("onNeighborDown update failed, wrong routeItemd %v", ri)
	}

	// onNeighborUp
	DR.in <- neighbor{pa, &rwMock{}}
	DR.in <- neighbor{pc, &rwMock{}}

	var pt peerTOPO
	pt.ID = aid
	pt.Peers = append(pt.Peers, n1)
	pt.Peers = append(pt.Peers, n5)
	pt.Peers = append(pt.Peers, bid)
	DR.receiveCh <- &pt
	DR.out <- pc
	DR.out <- pd
	//DR.genRouteTable(DR.peerTree[a], a)
	checkRouteA()

	// onConnectionDown
	var info topoInfo
	info.From = bid
	info.To = aid
	info.Up = false
	var update topoUpdate
	update.info = &info
	update.orig = bid
	DR.updateCh <- &update
	DR.out <- pc
	DR.out <- pd

	if DR.routeTable[aid][0].Id != aid && DR.routeTable[aid][0].Hops != 0 {
		t.Errorf("onConnectionDown update failed, wrong routes a:%v", DR.routeTable[aid])
	}

	if DR.routeTable[n5][0].Id != aid && DR.routeTable[aid][0].Hops != 1 {
		t.Errorf("onConnectionDown update failed, wrong routes a:%v", DR.routeTable[aid])
	}

	if len(DR.routeTable[n7]) != 1 {
		t.Errorf("onConnectionDown update failed, wrong routes n7:%v", DR.routeTable[n7])
	}
	if len(DR.routeTable[n8]) != 1 {
		t.Errorf("onConnectionDown update failed, wrong routes n8:%v", DR.routeTable[n8])
	}
	for _, ri := range DR.routeTable[n7] {
		if ri.Id == aid {
			if ri.Hops != 4 {
				t.Errorf("onNeighborDown update failed, ri.Hops:5!=%d", ri.Hops)
			}
			continue
		}
		t.Errorf("onNeighborDown update failed, wrong routeItemd %v", ri)
	}
	for _, ri := range DR.routeTable[n8] {
		if ri.Id == aid {
			if ri.Hops != 4 {
				t.Errorf("onNeighborDown update failed, ri.Hops:1!=%d", ri.Hops)
			}
			continue
		}

		t.Errorf("onNeighborDown update failed, wrong routeItemd %v", ri)
	}

	// onConnectionUp
	info.From = bid
	info.To = aid
	info.Up = true
	update.info = &info
	update.orig = bid
	DR.updateCh <- &update
	DR.out <- pc
	DR.out <- pd
	checkRouteA()

	DR.Stop()
}

func TestUniCastMsg(t *testing.T) {
	var ra = newTestRouter()
	var rb = newTestRouter()
	var rc = newTestRouter()

	aID := initDR(t, ra)
	bID := initDR(t, rb)
	cID := initDR(t, rc)

	pa := p2p.NewPeer(aID, "nodea", nil)
	pb := p2p.NewPeer(bID, "nodeb", nil)
	pc := p2p.NewPeer(cID, "nodec", nil)
	pd := p2p.NewPeer(discover.NodeID{0xa}, "noded", nil)

	rwa, rwac := p2p.MsgPipe()
	rwb, rwbc := p2p.MsgPipe()
	afunc := ra.Run()
	bfunc := rb.Run()
	cfunc := rc.Run()
	go afunc(pb, rwb)
	go bfunc(pa, rwa)

	msgBuffer := func(rw1, rw2 p2p.MsgReadWriter) {
		chanA := make(chan p2p.Msg, 200)
		chanB := make(chan p2p.Msg, 200)
		readF := func(rw p2p.MsgReadWriter, ch chan p2p.Msg) {
			for {
				buf := make([]byte, 2000)
				m, err := rw.ReadMsg()
				if err != nil {
					t.Errorf("readMsg err:%v", err)
				}
				n, err := m.Payload.Read(buf)
				if err != nil && err != io.EOF {
					t.Errorf("readMsg err:%v, %d", err, n)
				}
				m.Payload = bytes.NewBuffer(buf[:n])
				ch <- m

			}
		}
		writeF := func(rw p2p.MsgReadWriter, ch chan p2p.Msg) {
			for {
				select {
				case m := <-ch:
					err := rw.WriteMsg(m)
					if err != nil {
						t.Errorf("writeMsg err:%v", err)
					}

				}
			}
		}
		go readF(rw1, chanA)
		go readF(rw2, chanB)
		go writeF(rw2, chanA)
		go writeF(rw1, chanB)
	}

	ra.out <- pd
	rb.out <- pd
	go msgBuffer(rwac, rwbc)

	rwb1, rwb1c := p2p.MsgPipe()
	rwc, rwcc := p2p.MsgPipe()
	go bfunc(pc, rwc)
	go cfunc(pb, rwb1)

	go msgBuffer(rwb1c, rwcc)

	ra.out <- pd
	rc.out <- pd

	//if len(ra.routeTable[rc.routerID]) != 1 || ra.routeTable[rc.routerID][0].Id != rb.routerID || ra.routeTable[rc.routerID][0].Hops != 1 {
	//	t.Errorf("UniCastMsg, wrong routes rc:%v", ra.routeTable[rc.routerID])
	//}

	var ain chan []byte
	ain = make(chan []byte, 200)
	ra.RegisterMsgListener(1, ain)
	msgA := "Hello, UniCast msg to A"
	ra.UniCastMsg(ra.routerID, 1, []byte(msgA))

	ma := <-ain
	if string(ma) != msgA {
		t.Errorf("UniCastMsg To A failed msg=%s", ma)
	}

	var bin chan []byte
	bin = make(chan []byte, 200)
	rb.RegisterMsgListener(1, bin)
	msgB := "hello, UniCast msg to B"
	ra.UniCastMsg(rb.routerID, 1, []byte(msgB))

	mb := <-bin
	if string(mb) != msgB {
		t.Errorf("UniCastMsg To B failed msg=%s", mb)
	}

	var cin chan []byte
	cin = make(chan []byte, 200)
	rc.RegisterMsgListener(1, cin)
	msgC := "hello, UniCast msg to C"
	ra.UniCastMsg(rc.routerID, 1, []byte(msgC))

	mc := <-cin
	if string(mc) != msgC {
		t.Errorf("UniCastMsg To C failed msg=%s", mc)
	}
}
