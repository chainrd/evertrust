package router

import (
	"CRD-chain/p2p"
)

var ProtocolName = "router"
var ProtocolVersion = uint(1)
var ProtocolLength = uint64(8)

const ProtocolMaxMsgSize = 10 * 1024 * 1024 // Maximum cap on the size of a protocol message

const (
	TOPO_REQ  = 0x0
	TOPO_RES  = 0x1
	TOPO_INFO = 0x2
	UNICAST   = 0x3
)


func routerInfo() interface{} {
	//return router status, peer numbers, status version?
	return nil
}

func routerRun(peer *p2p.Peer, rw p2p.MsgReadWriter) error {
	//handshake and get peer router status
	peer.ID()
	// if peer.neighbor != 0
	err := p2p.Send(rw, TOPO_REQ, peer.ID())
	if err != nil {
		return err
	}

	// handle received message and forward it to the main routine
	// unpack the msg and put it in channel
	for {
		msg, err := rw.ReadMsg()
		if err != nil {
			return err
		}
		var headers []*int
		if err := msg.Decode(&headers); err != nil {
			return err
		}

		switch msg.Code {
		case TOPO_REQ:
			// unpack msg and return response

			return nil
		case TOPO_RES:
			return nil
		case TOPO_INFO:
			return nil
		case UNICAST:
			//forward it to the next peer
			return nil
		}
	}


	peer.Name()
	return nil
}
