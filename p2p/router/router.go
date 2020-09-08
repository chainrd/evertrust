package router

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"CRD-chain/common/hexutil"
	"CRD-chain/common/math"
	"CRD-chain/crypto"
	"CRD-chain/crypto/sha3"
	"CRD-chain/log"
	"CRD-chain/p2p"
	"CRD-chain/p2p/discover"
	"CRD-chain/rlp"
	"CRD-chain/rpc"
)

const (
	maxRouterSize      = 1024 * 1024
	maxCheckLength     = 2000
	maxRouteHops       = 5
	maxRoutePathNums   = 3
	maxConnections     = 50
	maxRequestInterval = 500 // microseconds
	maxTripTime        = 300 // seconds
	selfCheckInterval  = 60  // seconds
	maxUniCastTTL      = 16
	maxInfoCacheLimit  = 1024
)

type UniCastMsgType uint8

type routeItem struct {
	//peer *p2p.Peer
	Id   discover.ShortID
	Hops uint32
	//upstream []discover.ShortID
}

type neighbor struct {
	peer *p2p.Peer
	rw   p2p.MsgReadWriter
}

// TOPO_RES data structure
type peerTOPO struct {
	ID    discover.ShortID
	Peers []discover.ShortID
}

// used to informing connection Up/Down
type topoInfo struct {
	From discover.ShortID
	To   discover.ShortID
	Up   bool
	At   uint64
}

type topoUpdate struct {
	info *topoInfo
	orig discover.ShortID
}

// data to be uniCasted
type uniCastData struct {
	To   discover.ShortID
	Data []byte
	Typ  UniCastMsgType
	Ttl  uint8
}

// request data in reqQueue
type reqRecord struct {
	pr *p2p.Peer
	at time.Time
}

// p2p dynamic router
type DynamicRouter struct {
	routerID discover.ShortID

	neighbors  map[discover.ShortID]neighbor //connected or disconnected
	routeTable map[discover.ShortID][]routeItem
	peerTree   map[discover.ShortID]*treeNode
	upTable    map[discover.ShortID][]discover.ShortID // record up to root connections

	rtLock sync.RWMutex

	in  chan neighbor  // peer in
	out chan *p2p.Peer // peer out

	// uniCast data listener
	listener  map[UniCastMsgType]chan []byte
	lLock     sync.Mutex
	uniCastCh chan *uniCastData

	receiveCh chan *peerTOPO
	updateCh  chan *topoUpdate

	checkQueue []discover.ShortID

	infoQueue map[discover.ShortID]*topoInfo
	exclQueue map[discover.ShortID][]discover.ShortID
	infoCache *lru.Cache

	// request NodeId from Peer
	reqQueue  map[discover.ShortID]reqRecord
	queueLock sync.RWMutex

	exit    chan struct{}
	running bool
}

var newOnce sync.Once
var router *DynamicRouter

func NewRouter() *DynamicRouter {
	newOnce.Do(func() {
		router = &DynamicRouter{
			neighbors:  make(map[discover.ShortID]neighbor),
			routeTable: make(map[discover.ShortID][]routeItem),
			upTable:    make(map[discover.ShortID][]discover.ShortID),
			peerTree:   make(map[discover.ShortID]*treeNode),
			receiveCh:  make(chan *peerTOPO, maxConnections),
			updateCh:   make(chan *topoUpdate, maxConnections),
			uniCastCh:  make(chan *uniCastData, maxConnections),
			infoQueue:  make(map[discover.ShortID]*topoInfo),
			exclQueue:  make(map[discover.ShortID][]discover.ShortID),
			reqQueue:   make(map[discover.ShortID]reqRecord),
			listener:   make(map[UniCastMsgType]chan []byte),
			in:         make(chan neighbor, maxConnections),
			out:        make(chan *p2p.Peer, maxConnections),
			exit:       make(chan struct{}),
		}
	})
	return router
}

// newTestRouter create a new router for unit test only
func newTestRouter() *DynamicRouter {
	return &DynamicRouter{
		neighbors:  make(map[discover.ShortID]neighbor),
		routeTable: make(map[discover.ShortID][]routeItem),
		upTable:    make(map[discover.ShortID][]discover.ShortID),
		peerTree:   make(map[discover.ShortID]*treeNode),
		receiveCh:  make(chan *peerTOPO, maxConnections),
		updateCh:   make(chan *topoUpdate, maxConnections),
		uniCastCh:  make(chan *uniCastData, maxConnections),
		infoQueue:  make(map[discover.ShortID]*topoInfo),
		exclQueue:  make(map[discover.ShortID][]discover.ShortID),
		reqQueue:   make(map[discover.ShortID]reqRecord),
		listener:   make(map[UniCastMsgType]chan []byte),
		in:         make(chan neighbor, 1),
		out:        make(chan *p2p.Peer, 0),
		exit:       make(chan struct{}),
	}
}

func (r *DynamicRouter) Protocols() []p2p.Protocol {
	return []p2p.Protocol{
		{
			Name:     ProtocolName,
			Version:  ProtocolVersion,
			Length:   ProtocolLength,
			Run:      r.Run(),
			NodeInfo: routerInfo,
		},
	}
}

// generate and update route table
// main loop to receive information
// 1. peer connected
// 2. peer disconnected
// 3. TOPO_INFO
// according to this information, update route table
// loop to TOPO_REQ to get enough peers until: 1. route table full 2. no peers found
func (r *DynamicRouter) Start(srv *p2p.Server) error {

	r.running = true
	buf := make([]byte, 64)
	math.ReadBits(srv.PrivateKey.PublicKey.X, buf[:32])
	math.ReadBits(srv.PrivateKey.PublicKey.Y, buf[32:])
	copy(r.routerID[:], crypto.Keccak256(buf)[12:])
	//fmt.Println(crypto.FromECDSAPub(&srv.PrivateKey.PublicKey))

	r.peerTree[r.routerID] = newTreeNode()

	// start highway adapter
	if len(srv.Highway) != 0 {
		//var vid discover.ShortID
		adp := NewHighWayAdp(srv, r)
		//vid = adp.vPeer.SID()
		adp.Start()
	}

	cache, _ := lru.New(maxInfoCacheLimit)
	r.infoCache = cache

	go func() {
		timeCheck := time.NewTimer(0)
		<-timeCheck.C
		defer timeCheck.Stop()
		timeCheck.Reset(selfCheckInterval * time.Second)
		log.Info("p2p dynamic router started", "routerID", hexutil.Encode(r.routerID[:]))
		for {
			select {
			case n := <-r.in:
				// neighbor connected
				id := n.peer.SID()
				r.rtLock.Lock()
				r.neighbors[id] = n
				pTree := r.peerTree[r.routerID]
				pTree.addLeaf(id)
				var tmp []routeItem
				tmp = append(tmp, routeItem{Id: id, Hops: 0})
				// get valid route
				for _, ri := range r.routeTable[id] {
					if _, ok := r.neighbors[ri.Id]; ok {
						tmp = append(tmp, ri)
					}
					if len(tmp) == maxRoutePathNums {
						break
					}
				}
				r.routeTable[id] = tmp
				r.rtLock.Unlock()

				var info topoInfo
				info.From = r.routerID
				info.To = id
				info.Up = true
				info.At = uint64(time.Now().Unix())
				// broadcast to neighbors
				excludes := append([]discover.ShortID{}, id)

				buf, err := rlp.EncodeToBytes(info)
				if err != nil {
					log.Error("DR Start encode", "err", err)
					continue
				}
				ikey := sha3.Sum256(buf)
				r.infoCache.Add(ikey, true)

				//log.Debug("requestTopo", "in", hexutil.Encode(id[:]))
				if len(r.routeTable) > maxRouterSize {
					log.Warn("routeTable is full", "len", len(r.routeTable), "maxRouterSize", maxRouterSize)
					r.sendToNeighbors(&info, excludes)
				} else {
					r.infoQueue[info.To] = &info
					r.exclQueue[info.To] = excludes
					go r.requestTopo(n, id)
				}

			case p := <-r.out:
				// neighbor disconnected
				//r.printRouter()
				id := p.SID()
				r.rtLock.Lock()
				if _, ok := r.neighbors[id]; ok {
					delete(r.neighbors, id)

					// delete route item
					//r.routeTable[id] = r.routeTable[id][1:]
				}
				// cut off connection
				pTree := r.peerTree[r.routerID]
				pTree.delLeaf(id)
				pTree = r.peerTree[id]
				pTree.delLeaf(r.routerID)
				//for _, ri := range r.routeTable[id] {
				//	if ri.id == id {
				//		tmp = append(tmp, ri)
				//		break
				//	}
				//}
				r.rtLock.Unlock()
				r.updateRoute(id)
				r.onNeighborDown(id, pTree)
				//r.onConnectionDown(&info, r.routerID)

				var info topoInfo
				info.From = r.routerID
				info.To = id
				info.Up = false
				info.At = uint64(time.Now().Unix())
				// broadcast to neighbors excluding p's neighbors
				var excludes []discover.ShortID
				for i := uint32(0); pTree != nil && i < pTree.num; i++ {
					excludes = append(excludes, pTree.leafs[i])
				}

				buf, err := rlp.EncodeToBytes(info)
				if err != nil {
					log.Error("DR Start encode", "err", err)
					continue
				}
				ikey := sha3.Sum256(buf)
				r.infoCache.Add(ikey, true)

				//log.Debug("sendToNeighbors", "out", hexutil.Encode(id[:]), "len", len(r.neighbors))
				r.sendToNeighbors(&info, excludes)

			case p := <-r.receiveCh:
				var tn treeNode
				tn.leafs = make(map[uint32]discover.ShortID)
				tn.num = uint32(len(p.Peers))
				for idx, id := range p.Peers {
					tn.leafs[uint32(idx)] = id
				}
				if tn.num > 0 {
					r.rtLock.Lock()
					r.peerTree[p.ID] = &tn
					r.rtLock.Unlock()
					r.genRouteTable(&tn, p.ID)
				} else {
					if len(r.checkQueue) < maxCheckLength && !contains(r.checkQueue, p.ID) {
						r.checkQueue = append(r.checkQueue, p.ID)
					}
				}

				r.queueLock.Lock()
				delete(r.reqQueue, p.ID)
				r.queueLock.Unlock()

				if info, ok := r.infoQueue[p.ID]; ok {
					delete(r.infoQueue, p.ID)
					excludes := r.exclQueue[p.ID]
					delete(r.exclQueue, p.ID)

					log.Debug("sendToNeighbors", "info", hexutil.Encode(p.ID[:]), "len", len(r.neighbors))
					r.sendToNeighbors(info, excludes)
				}

			case uData := <-r.updateCh:

				if uData.info.Up {
					r.onConnectionUp(uData.info, uData.orig)
				} else {
					r.onConnectionDown(uData.info, uData.orig)
				}

			case <-timeCheck.C:
				now := time.Now()
				r.queueLock.Lock()
				for id, rc := range r.reqQueue {
					// clear timeout request
					if now.After(rc.at.Add(maxTripTime * time.Second)) {
						delete(r.reqQueue, id)
						delete(r.infoQueue, id)
						delete(r.exclQueue, id)
					}
				}
				r.queueLock.Unlock()

				var tmp []discover.ShortID
				tmp = append(tmp, r.checkQueue...)
				r.checkQueue = r.checkQueue[:0]
				checkGo := func() {
					// dynamic get neighbors from leaf node to fulfill routeTable
					// goroutine interval loop
					r.rtLock.RLock()
					if len(r.routeTable) > maxRouterSize {
						r.rtLock.RUnlock()
						return
					}
					r.rtLock.RUnlock()
					for _, id := range tmp {
						r.rtLock.RLock()
						items := r.routeTable[id]
						r.rtLock.RUnlock()
						for _, ri := range items {
							r.rtLock.RLock()
							nb, ok := r.neighbors[ri.Id]
							r.rtLock.RUnlock()
							if ok {
								go r.requestTopo(nb, id)
								time.Sleep(maxRequestInterval * time.Microsecond)
								break
							}
						}
					}
					timeCheck.Reset(selfCheckInterval * time.Second)
				}
				go checkGo()

			case uData := <-r.uniCastCh:
				log.Debug("DR UniCast data received", "routerID", hexutil.Encode(r.routerID[:]), "To", hexutil.Encode(uData.To[:]))
				if uData.To == r.routerID {
					log.Debug("DR UniCast to myself")
					go r.receiveData(uData)
					// getRegisteredUp and put it in
				} else {
					if uData.Ttl == 0 || uData.Ttl > maxUniCastTTL {
						log.Warn("DR invalid ttl", "To", hexutil.Encode(uData.To[:]))
						continue
					}
					uData.Ttl--
					var invNum uint32
					var flag bool
					for _, rt := range r.routeTable[uData.To] {
						p, ok := r.neighbors[rt.Id]
						if !ok {
							invNum++
							continue
						}
						// workaround for hPeers
						//if rt.Id == vid && !r.peerTree[vid].contains(uData.To) {
						//	invNum++
						//	continue
						//}
						err := p2p.Send(p.rw, UNICAST, uData)
						if err != nil {
							// how to deal with it
							log.Error("DR forward uniCastData", "neighbor", p, "err", err)
							continue
						}
						flag = true
						break
					}

					if flag {
						log.Debug("DR forward uniCastData success", "To", hexutil.Encode(uData.To[:]))
					} else {
						log.Warn("DR forward uniCastData failed", "route", r.routeTable[uData.To], "To", hexutil.Encode(uData.To[:]))
					}
					if invNum > 0 {
						r.rtLock.Lock()
						r.routeTable[uData.To] = r.routeTable[uData.To][invNum:]
						r.rtLock.Unlock()
					}
				}

			case <-r.exit:
				log.Info("p2p dynamic router stopped")
				r.running = false
				// no need to close neighbors
				return

			}
		}
	}()

	return nil
}

func (r *DynamicRouter) Stop() error {
	r.exit <- struct{}{}
	return nil
}

func (r *DynamicRouter) APIs() []rpc.API {
	return []rpc.API{
		{
			Namespace: "router",
			Version:   "1.0",
			Service:   NewRouterAPI(),
			Public:    true,
		},
	}
}

type RouterAPI struct {
	*DynamicRouter
}

func NewRouterAPI() *RouterAPI {
	return &RouterAPI{NewRouter()}
}

func (api *RouterAPI) GetRouter(sid string) []string {
	var id discover.ShortID
	tid, err := hexutil.Decode(sid)
	if err != nil {
		es := fmt.Sprintf("decode err %v", err)
		return []string{es}
	}
	copy(id[:], tid[:])
	api.rtLock.RLock()
	defer api.rtLock.RUnlock()
	var ret []string
	for _, ri := range api.routeTable[id] {
		tmp := fmt.Sprintf("%s %d", hexutil.Encode(ri.Id[:]), ri.Hops)
		ret = append(ret, tmp)
	}
	return ret
}

func (api *RouterAPI) GetNeighbors() []string {
	api.rtLock.RLock()
	defer api.rtLock.RUnlock()
	var ret []string
	for id := range api.neighbors {
		tmp := fmt.Sprintf("%s", hexutil.Encode(id[:]))
		ret = append(ret, tmp)
	}
	return ret
}

// used for debug only
func (r *DynamicRouter) printRouter() {
	fmt.Println("routerID:", r.routerID, "routeTable:", r.routeTable,
		"Uptable:", r.upTable,
		"neighbors:", r.neighbors,
		"peerTree:", r.peerTree)
}

// recursively get ups avoiding loops
func (r *DynamicRouter) rGetUps(id discover.ShortID, path []discover.ShortID) []discover.ShortID {
	var ret []discover.ShortID
	//nUps := r.upTable[id]
	//path = append(path, nUps...)
	for _, up := range r.upTable[id] {
		if contains(path, up) {
			continue
		}
		ret = append(ret, up)
		path = append(path, up)
		upRet := r.rGetUps(up, path)
		ret = append(ret, upRet...)
		path = append(path, upRet...)
	}
	return ret
}

// getUpRoutes return id's up peer in upTable, neighbor has no up peer
func (r *DynamicRouter) getUpRoutes(id discover.ShortID) []discover.ShortID {
	var ret []discover.ShortID
	var path []discover.ShortID

	//ups := r.upTable[id]
	path = append(path, id)

	for _, up := range r.upTable[id] {
		if contains(path, up) {
			continue
		}
		ret = append(ret, up)
		path = append(path, up)
		upRet := r.rGetUps(up, path)
		ret = append(ret, upRet...)
		path = append(path, upRet...)
		//ups = append(ups, r.upTable[ups[i]]...)
	}
	return ret
}

// genRouteTable generate route table according to peer tree
func (r *DynamicRouter) genRouteTable(peers *treeNode, id discover.ShortID) {
	// find it from routeTable
	var pRoute []routeItem
	for _, item := range r.routeTable[id] {
		if _, ok := r.neighbors[item.Id]; ok {
			item.Hops++
			pRoute = append(pRoute, item)
		}
	}

	if len(pRoute) == 0 {
		log.Debug("DR genRouteTable", "router", r.routeTable, "root", hexutil.Encode(id[:]), "treeNode", peers)
		return
	}
	// add peers to routeTable and get peers of these peers
	// check if the peer is already in routeTable for every peer
	for i := uint32(0); i < peers.num; i++ {
		cid := peers.leafs[i]
		// self
		if cid == r.routerID {
			continue
		}
		// peer is neighbor
		//if _, ok := r.neighbors[cid]; ok {
		//	continue
		//}
		if contains(r.upTable[id], cid) {
			continue
		}

		// cut loop circuit
		if contains(r.getUpRoutes(id), cid) {
			// insert into cid tree
			pTree := r.peerTree[cid]
			for i := uint32(0); pTree != nil && i < pTree.num; i++ {
				if pTree.leafs[i] == id {
					break
				}
				if i == pTree.num-1 {
					r.rtLock.Lock()
					pTree.leafs[i+1] = id
					pTree.num++
					r.rtLock.Unlock()
					break
				}
			}
			// update id's upTable
			if !contains(r.upTable[id], cid) {
				r.upTable[id] = append(r.upTable[id], cid)
				// update id's routeTable
				r.updateRoute(id)
			}
			continue
		}
		// update upTable and exclude the same item
		if !contains(r.upTable[cid], id) {
			r.upTable[cid] = append(r.upTable[cid], id)
		}
		r.updateRoute(cid)

		// check if it is necessary to get enough peers
		// ignore Hops prt[0].Hops<5
		if r.peerTree[cid] == nil && len(r.routeTable) < maxRouterSize {
			if r.routeTable[cid][0].Hops > maxRouteHops {
				log.Debug("DR genRouteTable", "hops", r.routeTable[cid][0].Hops, "peer:", hexutil.Encode(cid[:]))
			}

			go r.requestTopo(r.neighbors[r.routeTable[cid][0].Id], cid)
		} else {
			cTree := r.peerTree[cid]
			subTree := []rTree{{cTree, cid, id}}
			r.updateSubTree(subTree)
		}
	}
}

func (r *DynamicRouter) getNextHop(id discover.ShortID) *neighbor {
	if nb, ok := r.neighbors[id]; ok {
		return &nb
	}
	for idx, ri := range r.routeTable[id] {
		if nb, ok := r.neighbors[ri.Id]; ok {
			if idx != 0 {
				r.routeTable[id] = r.routeTable[id][idx:]
			}

			return &nb
		}
		if idx == len(r.routeTable[id]) {
			r.routeTable[id] = r.routeTable[id][:0]
		}
	}
	log.Debug("DR getNextHop", "routerID", hexutil.Encode(r.routerID[:]), "id", hexutil.Encode(id[:]))
	return nil
}

func (r *DynamicRouter) requestTopo(n neighbor, id discover.ShortID) {
	//if len(r.routeTable) > maxRouterSize {
	//	log.Warn("routeTable is full", "len", len(r.routeTable), "maxRouterSize", maxRouterSize)
	//	return
	//}

	record := reqRecord{n.peer, time.Now()}
	r.queueLock.Lock()
	// this id has been requested
	if _, ok := r.reqQueue[id]; ok {
		r.queueLock.Unlock()
		return
	}
	r.reqQueue[id] = record
	r.queueLock.Unlock()

	//log.Debug("DR requestTopo", "id", hexutil.Encode(id[:]))
	err := p2p.Send(n.rw, TOPO_REQ, id)
	if err != nil {
		r.queueLock.Lock()
		delete(r.reqQueue, id)
		r.queueLock.Unlock()
		log.Error("DR requestTopo", "err", err, "id", hexutil.Encode(id[:]))
		return
	}
}

func (r *DynamicRouter) Run() func(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	return func(peer *p2p.Peer, rw p2p.MsgReadWriter) error {

		timeTrick := time.NewTimer(5 * time.Second)
		errCh := make(chan struct{})
		var wFlag int32
		go func() {
			select {
			case <-timeTrick.C:
				if atomic.CompareAndSwapInt32(&wFlag, 0, 2) {
					r.in <- neighbor{peer, rw}
				}

			case <-errCh:
				return
			}
		}()

		// handle received message and forward it to the main routine
		for {
			msg, err := rw.ReadMsg()
			if atomic.CompareAndSwapInt32(&wFlag, 0, 1) {
				if err == nil {
					r.in <- neighbor{peer, rw}
					wFlag = 2
				}
				close(errCh)
			}
			if err != nil {
				log.Error("DR ReadMsg", "err", err)
				if wFlag == 2 {
					r.out <- peer
				}
				return err
			}

			switch msg.Code {
			case TOPO_REQ:
				// unpack msg and return response
				var id discover.ShortID
				err = msg.Decode(&id)
				if err != nil {
					//
					r.out <- peer
					log.Error("DR decode TOPO_REQ", "error", err)
					// optimise err code
					return err
				}
				var res peerTOPO
				res.ID = id
				r.rtLock.RLock()
				prt := r.peerTree[id]
				for i := uint32(0); prt != nil && i < prt.num; i++ {
					res.Peers = append(res.Peers, prt.leafs[i])
				}
				r.rtLock.RUnlock()
				//fmt.Println("TOPO_REQ", "res:", res)

				err = p2p.Send(rw, TOPO_RES, &res)
				if err != nil {
					r.out <- peer
					log.Error("DR Send TOPO_RES", "err", err)
					return err
				}

			case TOPO_RES:
				var res peerTOPO
				if err = msg.Decode(&res); err != nil {
					r.out <- peer
					log.Error("DR Decode TOPO_RES", "err", err)
					return err
				}
				//fmt.Println("TOPO_RES", "msg", res)

				r.queueLock.RLock()
				if rc, ok := r.reqQueue[res.ID]; !ok || rc.pr != peer {
					r.queueLock.RUnlock()
					r.out <- peer
					return errors.New(fmt.Sprint("received TOPO_RES data from invalid peer", "ok", ok, rc.pr, peer, hexutil.Encode(res.ID[:])))
				}
				//delete(r.reqQueue, res.ID)
				r.queueLock.RUnlock()
				r.receiveCh <- &res

			case TOPO_INFO:
				var info topoInfo
				if err = msg.Decode(&info); err != nil {
					r.out <- peer
					log.Error("DR decode TOPO_INFO", "err", err)
					return err
				}
				//fmt.Println("TOPO_INFO received", info, peer.SID())
				var uData topoUpdate
				uData.info = &info
				uData.orig = peer.SID()
				r.updateCh <- &uData

			case UNICAST:
				// FIXME: check unicast loop(add timestamp)
				var uData uniCastData
				if err = msg.Decode(&uData); err != nil {
					r.out <- peer
					log.Error("DR decode uniCastData", "err", err)
					return err
				}
				r.uniCastCh <- &uData

			}
		}
	}
}

// sendToNeighbors send TOPO update information to neighbors
func (r *DynamicRouter) sendToNeighbors(info *topoInfo, excludes []discover.ShortID) {
	//r.rtLock.RLock()
	//defer r.rtLock.RUnlock()

	for id, nb := range r.neighbors {
		if contains(excludes, id) {
			continue
		}

		//fmt.Println("sendToNeighbors", info, id)
		go func(nb neighbor) {
			err := p2p.Send(nb.rw, TOPO_INFO, info)
			if err != nil {
				log.Error("DR sendToNeighbors", "error", err, "peer", nb.peer)
			}
		}(nb)
	}
}

// onNeighborDown on neighbor connection down
func (r *DynamicRouter) onNeighborDown(id discover.ShortID, pTree *treeNode) {
	// update routeTable
	subTree := []rTree{{pTree, id, r.routerID}}
	// if routeTable is nil, delete it from peerTree
	r.updateSubTree(subTree)
}

// deletePeer if there is no route to peer(id), it should be deleted from router
func (r *DynamicRouter) deletePeer(id discover.ShortID) {
	if id == r.routerID {
		return
	}
	delete(r.routeTable, id)
	delete(r.upTable, id)
	delete(r.peerTree, id)
}

// updateRoute update id's route according id's upstreams
// upstream change will cause route change
// update routeTable must update upTable, and its relations
func (r *DynamicRouter) updateRoute(id discover.ShortID) {
	var ups []discover.ShortID
	var upRoute []routeItem
	for _, up := range r.upTable[id] {
		var tmp []routeItem
		for _, ri := range r.routeTable[up] {
			if _, ok := r.neighbors[ri.Id]; ok {
				tmp = append(tmp, ri)
			}
		}
		// update on read
		if len(tmp) == 0 {
			r.rtLock.Lock()
			r.deletePeer(up)
			r.rtLock.Unlock()
		} else {
			// need to update up's routeTable
			if len(tmp) != len(r.routeTable[up]) {
				r.rtLock.Lock()
				r.routeTable[up] = append(r.routeTable[up][:0], tmp...)
				r.rtLock.Unlock()
			}
			ups = append(ups, up)
			upRoute = mergeRI(upRoute, tmp)
		}
	}

	if len(upRoute) > 0 {
		// neighbor doesn't have up peer
		var i int
		var tmp []discover.ShortID
		if _, ok := r.neighbors[id]; ok {
			r.rtLock.Lock()
			r.routeTable[id] = r.routeTable[id][0:1]
			r.rtLock.Unlock()
			tmp = append(tmp, r.routeTable[id][0].Id)
		} else {
			upRoute[0].Hops++
			r.rtLock.Lock()
			r.routeTable[id] = append(r.routeTable[id][:0], upRoute[0])
			r.rtLock.Unlock()
			i++
			tmp = append(tmp, upRoute[0].Id)
		}
		for ; i < len(upRoute); i++ {
			rl := len(r.routeTable[id])
			if rl < maxRoutePathNums && !contains(tmp, upRoute[i].Id) {
				upRoute[i].Hops++
				tmp = append(tmp, upRoute[i].Id)
				r.rtLock.Lock()
				r.routeTable[id] = append(r.routeTable[id], upRoute[i])
				r.rtLock.Unlock()
			}
		}
		r.upTable[id] = ups
	} else {
		if _, ok := r.neighbors[id]; ok {
			r.rtLock.Lock()
			r.routeTable[id] = r.routeTable[id][0:1]
			r.rtLock.Unlock()
			delete(r.upTable, id)
		} else {
			r.rtLock.Lock()
			r.deletePeer(id)
			r.rtLock.Unlock()
		}
	}
}

// onConnectionDown when connection between two peers disconnected, we just cut this connection
// in our router, it does not mean the peer is down.
// process: 1. cut and check the connection, if it doesn't exist return.
//          2. update info.To's upTable
//          3. update info.To's routeTable, if there is no route, cut this tree
//          4. recursively update routeTable of info.To's subTree
func (r *DynamicRouter) onConnectionDown(info *topoInfo, orig discover.ShortID) {
	tTree := r.peerTree[info.To]
	fTree := r.peerTree[info.From]

	r.rtLock.Lock()
	// cut off the connection{info.From-> info.To}
	tFlag := tTree.delLeaf(info.From)
	fFlag := fTree.delLeaf(info.To)
	r.rtLock.Unlock()

	// check whether this info has been processed
	if !tFlag && !fFlag {
		// return if the connection already cut off
		return
	}

	buf, _ := rlp.EncodeToBytes(info)
	ikey := sha3.Sum256(buf)
	if r.infoCache.Contains(ikey) {
		return
	}
	r.infoCache.Add(ikey, true)

	// update info.To's routeTable and upTable
	toUps := r.upTable[info.To]

	// check whether info.To can be reached to after cutting down info.From
	toUps = removeNID(toUps, info.From)
	r.upTable[info.To] = toUps
	r.updateRoute(info.To)

	// recursive tree
	subTree := []rTree{{tTree, info.To, info.From}}
	r.updateSubTree(subTree)

	// don't broadcast to orig("from", "to") and its neighbors
	excludes := append([]discover.ShortID{}, orig)
	log.Debug("sendToNeighbors", "down", hexutil.Encode(info.To[:]), "from", hexutil.Encode(info.From[:]), "len", len(r.neighbors))
	r.sendToNeighbors(info, excludes)
}

type rTree struct {
	leaf *treeNode
	root discover.ShortID
	up   discover.ShortID
}

// updateSubTree recursively update route of subtree
// caused by the changing of root's route
func (r *DynamicRouter) updateSubTree(subTree []rTree) {
	cached := make(map[*treeNode]struct{})
	cached[subTree[0].leaf] = struct{}{}
	for idx := 0; idx < len(subTree); idx++ {
		if idx > 2000 {
			log.Error("exceed_max_length", "subTree", subTree, "routeTable", r.routeTable)
		}
		sub := subTree[idx]
		// for every leaf node
		//fmt.Println("updateSubTree", r.routerID, sub)
		for i := uint32(0); sub.leaf != nil && i < sub.leaf.num; i++ {
			leafID := sub.leaf.leafs[i]
			if leafID == sub.up {
				continue
			}
			//if contains(r.upTable[sub.root], leafID) {
			if contains(r.getUpRoutes(sub.root), leafID) {
				continue
			}
			// root has other route, so update root's route and its sub trees' route
			if _, ok := r.routeTable[sub.root]; !ok {
				// delete sub.leaf's upstream(sub.root) from upTable
				ups := r.upTable[leafID]
				ups = removeNID(ups, sub.root)
				r.upTable[leafID] = ups
			}

			r.updateRoute(leafID)

			if leafTree, ok := r.peerTree[leafID]; ok {
				if _, ok = cached[leafTree]; !ok {
					cached[leafTree] = struct{}{}
					subTree = append(subTree, rTree{leafTree, leafID, sub.root})
				}
			}
		}
	}
}

func (r *DynamicRouter) onConnectionUp(info *topoInfo, orig discover.ShortID) {
	// if info.from not in local routeTable return
	if _, ok := r.routeTable[info.From]; !ok {
		return
	}

	if info.To == r.routerID {
		return
	}
	// if info.to's upTable contains info.from, return and has been processed
	ups := r.upTable[info.To]
	if contains(ups, info.From) {
		return
	}

	buf, _ := rlp.EncodeToBytes(info)
	ikey := sha3.Sum256(buf)
	if r.infoCache.Contains(ikey) {
		return
	}
	r.infoCache.Add(ikey, true)

	r.rtLock.Lock()
	fTree, ok := r.peerTree[info.From]
	if !ok {
		fTree = newTreeNode()
	}
	fTree.addLeaf(info.To)

	tTree, ok := r.peerTree[info.To]
	if !ok {
		tTree = newTreeNode()
	}
	tTree.addLeaf(info.From)

	r.peerTree[info.From] = fTree
	r.peerTree[info.To] = tTree
	r.rtLock.Unlock()

	r.upTable[info.To] = append(r.upTable[info.To], info.From)
	r.updateRoute(info.To)

	var reqFalg bool
	if tTree.num == 1 && r.routeTable[info.To] != nil {
		if r.routeTable[info.To][0].Hops > maxRouteHops {
			log.Debug("onConnectionUp", "hops", r.routeTable[info.To][0].Hops, "peer:", hexutil.Encode(info.To[:]))
		}
		// routeTable is full
		if len(r.routeTable) < maxRouterSize {
			go r.requestTopo(r.neighbors[r.routeTable[info.To][0].Id], info.To)
			r.infoQueue[info.To] = info
			r.exclQueue[info.To] = append(r.exclQueue[info.To], orig)
			reqFalg = true
		}
	} else {
		// update subtree routes
		subTree := []rTree{{tTree, info.To, info.From}}
		r.updateSubTree(subTree)
	}

	if !reqFalg {
		// broadcast this info to neighbors
		var excludes []discover.ShortID
		excludes = append(excludes, orig)
		log.Debug("sendToNeighbors", "up", hexutil.Encode(info.To[:]), "len", len(r.neighbors))
		r.sendToNeighbors(info, excludes)
	}

}

func (r *DynamicRouter) getNeighbors(id discover.ShortID) *treeNode {
	//r.rtLock.RLock()
	//defer r.rtLock.RUnlock()
	return r.peerTree[id]
}

// receiveData put data to registered listener
func (r *DynamicRouter) receiveData(udata *uniCastData) {
	r.lLock.Lock()
	in, ok := r.listener[udata.Typ]
	r.lLock.Unlock()
	if ok {
		in <- udata.Data
		log.Debug("DR receiveData", "data.To", hexutil.Encode(udata.To[:]))
	} else {
		log.Warn("DR receiveData, data received with no listener", "data.To", hexutil.Encode(udata.To[:]))
	}
}

// UniCastMsg try to forward msg to dst
// data must be encoded by rlp.encoder
func (r *DynamicRouter) UniCastMsg(dst discover.ShortID, msgType UniCastMsgType, data []byte) {
	var uData uniCastData
	uData.To = dst
	uData.Data = make([]byte, len(data))
	copy(uData.Data, data)
	uData.Typ = msgType
	uData.Ttl = maxUniCastTTL

	r.uniCastCh <- &uData
}

// RegisterMsgListener register a msg chan in router, and when this type
// msg arrived, it will be forwarded to this chan.
func (r *DynamicRouter) RegisterMsgListener(msgType UniCastMsgType, in chan []byte) bool {
	r.lLock.Lock()
	defer r.lLock.Unlock()
	if _, ok := r.listener[msgType]; ok {
		return false
	}
	r.listener[msgType] = in
	return true
}
