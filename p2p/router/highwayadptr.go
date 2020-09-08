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
 * @Time   : 2019/9/11
 * @Author : Brian Shang
 *************************************************************************/

package router

import (
	"errors"
	"sync/atomic"

	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"math/big"
	"CRD-chain/common/hexutil"
	"CRD-chain/crypto/sha3"
	"CRD-chain/log"
	"CRD-chain/p2p"
	"CRD-chain/p2p/discover"
	"CRD-chain/rlp"
)

const maxVPeerRWLength = 200
const retrieveHPeerInterval = 20 //seconds

//const ethAssertionMsgType = 0xFE // hard code from BlockAssertMsg

// adapter for highway peers
type highWayAdp struct {
	srv     *p2p.Server
	dr      *DynamicRouter
	rId     discover.ShortID
	vPeer   *p2p.Peer
	vrw     *vpRW
	rrw     *vpRW
	run     func(peer *p2p.Peer, rw p2p.MsgReadWriter) error
	hPeers  map[discover.ShortID]*p2p.Peer
	lock    sync.RWMutex
	rCache  *lru.Cache
	msgCh   chan p2p.Msg
	hwCh    chan *hwMsg
	running int32
}

// virtual peer ReadWrite interface
type vpRW struct {
	wCh  chan p2p.Msg
	rCh  chan p2p.Msg
	err  error
	done chan struct{}
}

type hwMsg struct {
	msg p2p.Msg
	id  discover.ShortID
}
type hwRW struct {
	rwCh chan *hwMsg
	id   discover.ShortID
}

func (rw *hwRW) WriteMsg(msg p2p.Msg) error {
	var hwmsg hwMsg
	hwmsg.msg = msg
	hwmsg.id = rw.id
	rw.rwCh <- &hwmsg
	return nil
}

func (rw *hwRW) ReadMsg() (p2p.Msg, error) {
	msg := <-rw.rwCh
	return msg.msg, nil
}

func NewHighWayAdp(srv *p2p.Server, r *DynamicRouter) *highWayAdp {
	vrw, rrw := newRW()
	vid := discover.NodeID{}
	copy(vid[:], r.routerID[:])
	iCache, _ := lru.New(maxInfoCacheLimit)
	rCache, _ := lru.New(maxInfoCacheLimit)

	adp := &highWayAdp{
		srv:    srv,
		vPeer:  p2p.NewPeer(vid, "vPeer", nil),
		vrw:    vrw,
		rrw:    rrw,
		hPeers: make(map[discover.ShortID]*p2p.Peer),
		run:    r.Run(),
		dr:     newTestRouter(),
		rId:    r.routerID,
		rCache: rCache,
		msgCh:  make(chan p2p.Msg, maxConnections),
		hwCh:   make(chan *hwMsg, maxConnections),
	}
	adp.dr.infoCache = iCache
	return adp
}

// get highway peers from highway MQ periodically
// add highway peers tree to router
func (adp *highWayAdp) Start() {
	vid := adp.vPeer.SID()
	log.Info("Highway adapter start", "id", hexutil.Encode(vid[:]))
	go adp.vPeerLoop()
	go adp.updatePeers()
	go adp.highwayLoop()
	go adp.forwardLoop()
}

func (adp *highWayAdp) vPeerLoop() {
	for {
		msg, _ := adp.vrw.ReadMsg()
		switch msg.Code {
		case UNICAST:
			var uData uniCastData
			if err := msg.Decode(&uData); err != nil {
				log.Error("vPeer decode uniCastData", "err", err)
				continue
			}
			if uData.Ttl == 0 || uData.Ttl > maxUniCastTTL {
				log.Warn("vPeer received invalid ttl", "To", hexutil.Encode(uData.To[:]))
				continue
			}
			uData.Ttl--
			var invNum uint32
			var flag bool
			adp.dr.rtLock.RLock()
			for _, rt := range adp.dr.routeTable[uData.To] {
				nb, ok := adp.dr.neighbors[rt.Id]
				if !ok {
					invNum++
					continue
				}
				err := p2p.Send(nb.peer.Mrw, UNICAST, uData)
				if err != nil {
					log.Error("vPeer uniCastData", "neighbor", nb, "err", err)
					continue
				}
				flag = true
				break
			}
			adp.dr.rtLock.RUnlock()

			if flag {
				log.Debug("vPeer uniCastData success", "To", hexutil.Encode(uData.To[:]))
			} else {
				log.Warn("vPeer uniCastData failed", "To", hexutil.Encode(uData.To[:]))
			}
			if invNum > 0 {
				adp.dr.rtLock.Lock()
				adp.dr.routeTable[uData.To] = adp.dr.routeTable[uData.To][invNum:]
				adp.dr.rtLock.Unlock()
			}

		case TOPO_REQ:
			var id discover.ShortID
			err := msg.Decode(&id)
			if err != nil {
				//
				log.Error("vPeer decode TOPO_REQ", "error", err)
				continue
			}
			var res peerTOPO
			res.ID = id
			if id == adp.vPeer.SID() {
				adp.lock.RLock()
				for hPeer := range adp.hPeers {
					res.Peers = append(res.Peers, hPeer)
				}
				adp.lock.RUnlock()
				log.Debug("vPeer getRes", "res", res)
			} else {
				// find it from routeTable
				// send to hPeer
				adp.dr.rtLock.RLock()
				pt := adp.dr.peerTree[id]
				for i := uint32(0); pt != nil && i < pt.num; i++ {
					res.Peers = append(res.Peers, pt.leafs[i])
				}
				adp.dr.rtLock.RUnlock()
			}
			err = p2p.Send(adp.vrw, TOPO_RES, &res)
			if err != nil {
				log.Error("vPeer Send TOPO_RES", "err", err)
			}
			// get topo from adp.dr.peerTree or return []
			//adp.dr.sendTopo(&res)

		case TOPO_RES:
			adp.msgCh <- msg

		case TOPO_INFO:
			var info topoInfo
			if err := msg.Decode(&info); err != nil {
				log.Error("vPeer decode TOPO_INFO", "err", err)
				continue
			}
			// check info.to is in send list, if so, broadcast this to mq, or get topo from router, and broadcast topo to mq, and add topo to send list
			// broadcast it to highway
			buf, _ := rlp.EncodeToBytes(info)
			ikey := sha3.Sum256(buf)
			if adp.dr.infoCache.Contains(ikey) {
				continue
			}
			adp.dr.infoCache.Add(ikey, true)
			_, r, err := rlp.EncodeToReader(info)
			if err != nil {
				log.Debug("vPeer encodeToReader", "err", err)
				continue
			}
			msg.Payload = r
			err = adp.srv.HighwayPeersExchangeBroadcast(msg)
			if err != nil {
				log.Error("Highway adapter broadcast msg", "err", err)
			}

		default:
			log.Warn("vPeer received invalid msg", "msg", msg)

		}
	}
}

func (adp *highWayAdp)  highwayLoop() {

	var hReader p2p.MQMsgReader
	for {
		var err error
		hReader, err = adp.srv.NewHighwayReader()
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}
	log.Info("highwayLoop started")
	for {
		msg, err := hReader.ReadMsg()
		if err != nil {
			log.Error("Highway ReadMsg", "err", err)
			time.Sleep(1 * time.Second)
		}

		if atomic.LoadInt32(&adp.running) == 0 {
			if msg.Code != TOPO_RES {
				continue
			}
		}
		log.Debug("Highway ReadMsg", "msg.code", msg.Code)
		switch msg.Code {
		case TOPO_REQ:
			var id discover.ShortID
			err := msg.Decode(&id)
			if err != nil {
				//
				log.Error("Highway decode TOPO_REQ", "err", err)
				continue
			}
			key := big.NewInt(0).SetBytes(id[:])
			key.Add(key, big.NewInt(time.Now().Unix()))
			if !adp.rCache.Contains(key) {
				adp.rCache.Add(key, struct{}{})
				err = p2p.Send(adp.vrw, TOPO_REQ, id)
				if err != nil {
					log.Error("Highway send TOPO_REQ", "err", err)
				}
			}

		case UNICAST:
			// write directly
			err := adp.vrw.WriteMsg(msg)
			if err != nil {
				log.Error("Highway WriteMsg", "err", err)
			}

		case TOPO_RES:
			var res peerTOPO
			if err := msg.Decode(&res); err != nil {
				log.Error("Highway Decode TOPO_RES", "err", err)
				continue
			}
			adp.dr.receiveCh <- &res

			// cache broadcast info or send it to router and get it back????
		case TOPO_INFO:
			var info topoInfo
			if err := msg.Decode(&info); err != nil {
				log.Error("Highway decode TOPO_INFO", "err", err)
				continue
			}
			var uData topoUpdate
			uData.info = &info
			uData.orig = adp.vPeer.SID()
			adp.dr.updateCh <- &uData

		default:
			log.Warn("Highway received unknown msg", "code", msg.Code)
		}
	}
}

func (adp *highWayAdp) updatePeers() {
	retrieveTimer := time.NewTimer(retrieveHPeerInterval * time.Second)
	log.Debug("Highway adapter updatePeers")
	for {
		select {
		case res := <-adp.dr.receiveCh:
			var tn treeNode
			tn.leafs = make(map[uint32]discover.ShortID)
			tn.num = uint32(len(res.Peers))
			for idx, id := range res.Peers {
				tn.leafs[uint32(idx)] = id
			}
			adp.dr.rtLock.Lock()
			adp.dr.peerTree[res.ID] = &tn
			adp.dr.rtLock.Unlock()
			if _, ok := adp.dr.routeTable[res.ID]; ok {
				adp.dr.genRouteTable(&tn, res.ID)
			}

		case uData := <-adp.dr.updateCh:
			if uData.info.Up {
				adp.dr.onConnectionUp(uData.info, uData.orig)
			} else {
				adp.dr.onConnectionDown(uData.info, uData.orig)
			}

		case msg := <-adp.msgCh:
			var res peerTOPO
			if err := msg.Decode(&res); err != nil {
				log.Error("Highway adapter msg decode", "err", err)
				continue
			}

			var tn treeNode
			tn.leafs = make(map[uint32]discover.ShortID)
			tn.num = uint32(len(res.Peers))
			for idx, id := range res.Peers {
				tn.leafs[uint32(idx)] = id
			}
			adp.dr.rtLock.Lock()
			adp.dr.peerTree[res.ID] = &tn
			adp.dr.rtLock.Unlock()

			// broadcast it to highway
			size, r, err := rlp.EncodeToReader(res)
			msg.Payload = r
			msg.Size = uint32(size)
			err = adp.srv.HighwayPeersExchangeBroadcast(msg)
			if err != nil {
				log.Error("Highway adapter broadcast msg", "err", err)
			}

			// recursively get
			for _, id := range res.Peers {
				if id == adp.vPeer.SID() {
					continue
				}
				_, ok := adp.dr.peerTree[id]
				adp.dr.queueLock.RLock()
				_, ok1 := adp.dr.reqQueue[id]
				adp.dr.queueLock.RUnlock()
				if !ok && !ok1 {
					adp.dr.queueLock.Lock()
					adp.dr.reqQueue[id] = reqRecord{nil, time.Now()}
					adp.dr.queueLock.Unlock()
					log.Debug("bshang debug", "req id", hexutil.Encode(id[:]))
					err := p2p.Send(adp.vrw, TOPO_REQ, id)
					if err != nil {
						log.Error("Highway adapter send TOPO_REQ", "err", err)
					}
				}
			}

		case <-retrieveTimer.C:
			hPeers := adp.srv.HighwayPeers()
			if len(adp.hPeers) == 0 {
				if len(hPeers) != 0 {
					adp.lock.Lock()
					for id, pr := range hPeers {
						var _id discover.ShortID
						copy(_id[:], id[:])
						adp.hPeers[_id] = pr
					}
					adp.lock.Unlock()
					adp.startPeer(adp.vPeer, adp.rrw)
				}
			} else {
				newPr := make(map[discover.ShortID]*p2p.Peer)
				vid := adp.vPeer.SID()
				for id, pr := range hPeers {
					var _id discover.ShortID
					copy(_id[:], id[:])
					newPr[_id] = pr
					if _, ok := adp.hPeers[_id]; ok {
						adp.lock.Lock()
						delete(adp.hPeers, _id)
						adp.lock.Unlock()
					} else {
						adp.addNeighbor(_id, pr)
						adp.updateTopo(vid, _id, true)
					}
				}

				adp.lock.Lock()
				tmp := adp.hPeers
				adp.hPeers = newPr
				adp.lock.Unlock()
				if len(hPeers) == 0 {
					adp.stopPeer("No highway peers connected")
				} else {
					// highway peers need to be deleted
					for _id, _ := range tmp {
						adp.delNeighbor(_id)
						adp.updateTopo(vid, _id, false)
					}
				}
			}
			log.Debug("Highway adapter end update")
			retrieveTimer.Reset(retrieveHPeerInterval * time.Second)
		}

	}
}

func (adp *highWayAdp) forwardLoop() {
	for {
		hwmsg := <-adp.hwCh
		switch hwmsg.msg.Code {
		case TOPO_INFO:
			continue

		default:
			adp.lock.RLock()
			hPeer, ok := adp.hPeers[hwmsg.id]
			adp.lock.RUnlock()
			if ok {
				err := hPeer.Mrw.WriteMsg(hwmsg.msg)
				if err != nil {
					log.Error("Highway adapter forwardLoop", "err", err)
				}
			}

		}
	}
}

func (adp *highWayAdp) addNeighbor(id discover.ShortID, pr *p2p.Peer) {

	log.Debug("Highway adapter addNeighbor", "id", hexutil.Encode(id[:]))
	var tmp []routeItem
	hwrw := &hwRW{rwCh: adp.hwCh, id: id}
	nb := neighbor{pr, hwrw}
	tmp = append(tmp, routeItem{Id: id, Hops: 0})
	adp.dr.rtLock.Lock()
	adp.dr.neighbors[id] = nb
	adp.dr.routeTable[id] = tmp
	adp.dr.rtLock.Unlock()

	if tn, ok := adp.dr.peerTree[id]; ok {
		adp.dr.genRouteTable(tn, id)
	}
}

func (adp *highWayAdp) delNeighbor(id discover.ShortID) {
	log.Debug("Highway adapter delNeighbor", "id", hexutil.Encode(id[:]))
	adp.dr.rtLock.Lock()
	if _, ok := adp.dr.neighbors[id]; ok {
		delete(adp.dr.neighbors, id)
	}

	pTree := adp.dr.peerTree[id]
	adp.dr.rtLock.Unlock()
	adp.dr.updateRoute(id)
	adp.dr.onNeighborDown(id, pTree)
}

func (adp *highWayAdp) startPeer(peer *p2p.Peer, rw p2p.MsgReadWriter) {
	for id, pr := range adp.hPeers {
		adp.addNeighbor(id, pr)
	}
	err := p2p.Send(adp.vrw, TOPO_REQ, adp.rId)
	if err != nil {
		log.Error("Highway adapter startPeer", "err", err)
	}
	log.Debug("Highway adapter startPeer")
	go func() {
		err := adp.run(peer, rw)
		if err != nil {
			log.Warn("vPeer returned", "err", err)
		}
	}()
	atomic.StoreInt32(&adp.running, 1)
}

func (adp *highWayAdp) stopPeer(reason string) {
	log.Debug("Highway adapter stopPeer")
	atomic.StoreInt32(&adp.running, 0)
	adp.dr.rtLock.Lock()
	adp.dr.neighbors = make(map[discover.ShortID]neighbor)
	adp.dr.routeTable = make(map[discover.ShortID][]routeItem)
	adp.dr.peerTree = make(map[discover.ShortID]*treeNode)
	adp.dr.upTable = make(map[discover.ShortID][]discover.ShortID)
	adp.dr.rtLock.Unlock()
	adp.rrw.close(reason)
}

func (adp *highWayAdp) updateTopo(from, to discover.ShortID, up bool) {
	var info topoInfo
	info.From = from
	info.To = to
	info.Up = up
	info.At = uint64(time.Now().Unix())
	err := p2p.Send(adp.vrw, TOPO_INFO, &info)
	if err != nil {
		log.Error("Highway updateTopo", "err", err)
	}
}

func newRW() (rw1, rw2 *vpRW) {
	rc := make(chan p2p.Msg, maxVPeerRWLength)
	wc := make(chan p2p.Msg, maxVPeerRWLength)

	rw1 = &vpRW{wc, rc, nil, make(chan struct{})}
	rw2 = &vpRW{rc, wc, nil, make(chan struct{})}
	return
}

func (rw *vpRW) WriteMsg(msg p2p.Msg) error {
	select {
	case rw.wCh <- msg:
		return nil

	case <-rw.done:
		return rw.err
	}

}

func (rw *vpRW) ReadMsg() (p2p.Msg, error) {
	select {
	case msg := <-rw.rCh:
		return msg, nil

	case <-rw.done:
		return p2p.Msg{}, rw.err
	}

}

func (rw *vpRW) close(resaon string) {
	rw.err = errors.New(resaon)
	rw.done <- struct{}{}
}
