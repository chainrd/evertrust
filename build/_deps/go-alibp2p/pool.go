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
 * @Time   : 2020/3/6 3:11 下午
 * @Author : liangc
 *************************************************************************/

package alibp2p

import (
	"bytes"
	"context"
	"fmt"
	"github.com/libp2p/go-libp2p-core/helpers"
	"github.com/libp2p/go-libp2p-core/metrics"
	"github.com/libp2p/go-libp2p-core/network"
	"io/ioutil"
	"strings"
	"sync"
	"time"
)

const def_expire = 30 * 60 // 10sec for debug

type (
	reuse_conn struct {
		ctx    context.Context
		reader *bytes.Buffer
		writer *bytes.Buffer
	}
	reuse_stream struct {
		expire int64
		stream network.Stream
	}
	StreamKey    string
	SessionKey   string
	AStreamCache struct {
		// { aconnkey -> { session -> conn } }
		pool   map[StreamKey]map[SessionKey]*reuse_stream
		reg    map[string]interface{}
		kmutex *KeyMutex
		lock   *sync.RWMutex
		msgc   metrics.Reporter
		expire int64
	}
)

func (a *reuse_stream) Stream() network.Stream {
	if a != nil {
		return a.stream
	}
	return nil
}

var (
	fullClose = func(s network.Stream) {
		if s != nil {
			stream, session := newStreamSessionKey(s)
			log.Debug("alibp2p-service::AStreamCache-fn->fullClose", "streamkey", stream, "session", session)
			go helpers.FullClose(s)
		}
	}
	cleanSession = func(sm map[SessionKey]*reuse_stream) {
		for _, s := range sm {
			fullClose(s.Stream())
		}
	}
	newStreamSessionKey = func(s network.Stream) (stream StreamKey, session SessionKey) {
		stream = newStreamKey(s.Conn().RemotePeer().Pretty(), string(s.Protocol()))
		session = SessionKey(
			fmt.Sprintf("session:%s%s",
				s.Conn().RemoteMultiaddr().String(),
				s.Conn().LocalMultiaddr().String()),
		)
		return
	}
)

func (a *reuse_conn) Read(p []byte) (int, error) {
	return a.reader.Read(p)
}

func (a *reuse_conn) Write(p []byte) (int, error) {
	return a.writer.Write(p)
}

func newStreamKey(to, protoid string) StreamKey { return StreamKey(protoid + "@" + to) }

func (s StreamKey) Id() string      { return strings.Split(string(s), "@")[1] }
func (s StreamKey) Protoid() string { return strings.Split(string(s), "@")[0] }

func NewAStreamCatch(msgc metrics.Reporter) *AStreamCache {
	return &AStreamCache{
		pool: make(map[StreamKey]map[SessionKey]*reuse_stream),
		lock: new(sync.RWMutex),
		reg:  make(map[string]interface{}),
		//reglock: new(sync.Map),
		kmutex: NewKeyMutex(45 * time.Second),
		//reglock: make(map[string]*sync.Mutex),
		msgc:   msgc,
		expire: def_expire,
	}
}

func (p *AStreamCache) del(s network.Stream) {
	streamkey, sessionkey := newStreamSessionKey(s)
	p.del2(streamkey.Id(), streamkey.Protoid(), sessionkey)
}

func (p *AStreamCache) del2(to, protoid string, session SessionKey) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.cleanlock(to, protoid)
	log.Infof("alibp2p-service::AStreamCache-del2.input : id=%s , protocolID=%s , session=%s , poolsize=%d", to, protoid, session, len(p.pool))
	if protoid == "" {
		// 1: protoid == nil 删除全部包含 to 的 key, 不会很多，遍历即可
		for streamkey, sm := range p.pool {
			if streamkey.Id() == to {
				cleanSession(sm)
				delete(p.pool, streamkey)
				log.Debug("alibp2p-service::AStreamCache-del2-1", "id", to, "key", streamkey, "asc.len", len(p.pool))
			}
		}
	} else if session == "" {
		// 2: session == nil 删除 streamkey 下所有 session
		k := newStreamKey(to, protoid)
		cleanSession(p.pool[k])
		delete(p.pool, k)
		log.Debug("alibp2p-service::AStreamCache-del2-2", "id", to, "protoid", protoid, "key", k, "asc.len", len(p.pool))
	} else if sm, ok := p.pool[newStreamKey(to, protoid)]; ok {
		fullClose(sm[session].Stream())
		delete(sm, session)
		log.Debug("alibp2p-service::AStreamCache-del2-3", "id", to, "protoid", protoid, "session", session, "asc.len", len(p.pool))
		k := newStreamKey(to, protoid)
		if len(sm) == 0 {
			delete(p.pool, k)
		} else {
			p.pool[k] = sm
		}
	}
}

func (p *AStreamCache) get(to, protoid string) (network.Stream, bool, bool) {
	streamKey := newStreamKey(to, protoid)
	p.lock.RLock()
	defer p.lock.RUnlock()
	sm, ok := p.pool[streamKey]
	if !ok {
		return nil, false, false
	}
	for k, v := range sm {
		if v.expire < time.Now().Unix() {
			log.Info("alibp2p-service::AStreamCache-get-expire", v.expire, to, protoid, k)
			return v.stream, false, true
		}
		log.Debug("alibp2p-service::AStreamCache-get", "id", to, "protoid", protoid, "asc.len", len(p.pool))
		return v.stream, true, false
	}
	return nil, false, false
}

func (p *AStreamCache) put(s network.Stream, opts ...interface{}) {
	if opts == nil {
		p.lock.Lock()
		defer p.lock.Unlock()
	}
	streamkey, sessionkey := newStreamSessionKey(s)
	sm, ok := p.pool[streamkey]
	if !ok {
		sm = make(map[SessionKey]*reuse_stream)
	}
	_, ok = sm[sessionkey]
	if ok {
		//fullClose(old)
		return
	}
	sm[sessionkey] = &reuse_stream{
		expire: time.Now().Add(time.Duration(p.expire) * time.Second).Unix(),
		stream: s,
	}
	p.pool[streamkey] = sm
	log.Debug("alibp2p-service::AStreamCache-put", "id", streamkey.Id(), "protoid", streamkey.Protoid(), "session", sessionkey, "asc.len", len(p.pool))
}

func (p *AStreamCache) has(pid string) bool {
	if p == nil {
		return false
	}
	_, ok := p.reg[pid]
	return ok
}

func (p *AStreamCache) handleStream(s network.Stream) {
	go p.doHandleStream(s)
}

func (p *AStreamCache) doHandleStream(s network.Stream) {
	var (
		pid         = string(s.Protocol())
		conn        = s.Conn()
		sid         = fmt.Sprintf("session:%s%s", conn.RemoteMultiaddr().String(), conn.LocalMultiaddr().String())
		id          = s.Conn().RemotePeer().Pretty()
		pk, _       = id2pubkey(s.Conn().RemotePeer())
		ctx, cancel = context.WithCancel(context.Background())
		rw          = &reuse_conn{
			ctx:    ctx,
			reader: new(bytes.Buffer),
			writer: new(bytes.Buffer),
		}
		logid    = time.Now().UnixNano()
		protocol = string(s.Protocol())
	)
	log.Infof("%d# alibp2p-service::HandleStream-start %s@%s inbound=%v", logid, pid, id, s.Conn().Stat().Direction == network.DirInbound)
	defer func() {
		log.Infof("%d# alibp2p-service::HandleStream-end %s@%s inbound=%v", logid, pid, id, s.Conn().Stat().Direction == network.DirInbound)
		//p.del(s)
		fullClose(s)
	}()
	// TODO How to return error to the handlerFn ?
	for {
		var (
			ret         []byte
			req         = new(RawData)
			err         error
			c           int64
			callHandler = func(handler interface{}) error {
				if fn, ok := handler.(StreamHandler); ok {
					return fn(sid, pubkeyToEcdsa(pk), rw)
				}
				if fn, ok := handler.(StreamHandlerWithProtocol); ok {
					return fn(sid, protocol, pubkeyToEcdsa(pk), rw)
				}
				return unknow_stream_handler_type
			}
		)
		c, err = FromReader(s, req)
		if req.Err != "" {
			log.Errorf("%d# alibp2p-service::HandleStream_error_from_reader %s@%s read_size=%d err=%s", logid, pid, id, c, req.Err)
			return
		}
		log.Debugf("%d# alibp2p-service::HandleStream_request %s@%s msgid=%d msgsize=%d", logid, pid, id, req.ID(), req.Len())
		if err != nil {
			log.Errorf("%d# alibp2p-service::HandleStream_reader %s@%s read_size=%d err=%v", logid, pid, id, c, err)
			cancel()
		} else if _, err = rw.reader.Write(req.Data); err != nil {
			log.Errorf("%d# alibp2p-service::HandleStream_rw %s@%s read_size=%d err=%v", logid, pid, id, c, err)
			cancel()
		} else if err = callHandler(p.reg[pid]); err != nil {
			log.Errorf("%d# alibp2p-service::HandleStream_fn %s@%s read_size=%d err=%v", logid, pid, id, c, err)
			cancel()
		} else if ret, err = ioutil.ReadAll(rw.writer); err != nil {
			log.Errorf("%d# alibp2p-service::HandleStream_ret %s@%s read_size=%d err=%v", logid, pid, id, c, err)
			cancel()
		} else if ret != nil {
			rsp := NewRawData(req.ID(), ret)
			if _, err := ToWriter(s, rsp); err != nil {
				log.Errorf("%d# alibp2p-service::HandleStream_response_error %s@%s , msgid=%d , size=%d , err=%v", logid, pid, id, rsp.ID(), rsp.Len(), err)
				cancel()
			} else {
				log.Debugf("%d# alibp2p-service::HandleStream_response %s@%s , msgid=%d , size=%d", logid, pid, id, rsp.ID(), rsp.Len())
				if p.msgc != nil {
					p.msgc.LogSentMessage(1)
					p.msgc.LogSentMessageStream(1, s.Protocol(), s.Conn().RemotePeer())
				}
			}
		}
		select {
		case <-ctx.Done():
			if err != nil {
				ToWriter(s, &RawData{Id: req.Id, Err: err.Error()})
			}
			return
		default:
			if p.msgc != nil {
				p.msgc.LogRecvMessage(1)
				p.msgc.LogRecvMessageStream(1, s.Protocol(), s.Conn().RemotePeer())
			}
		}
	}

}

func (p *AStreamCache) regist(pid string, handler interface{}) {
	_, ok1 := handler.(StreamHandler)
	_, ok2 := handler.(StreamHandlerWithProtocol)
	if !ok1 && !ok2 {
		panic(unknow_stream_handler_type)
	}
	if _, ok := p.reg[pid]; ok {
		panic("alibp2p-service::ReuseStreamHandler Duplicate Registration")
	}
	p.reg[pid] = handler
	p.kmutex.Regist(pid)
}

func (p *AStreamCache) takelock(id, pid string) error {
	return p.kmutex.Lock(pid, id)
}

func (p *AStreamCache) cleanlock(id, pid string) {
	p.kmutex.Clean(pid, id)
}

func (p *AStreamCache) unlock(id, pid string) error {
	return p.kmutex.Unlock(pid, id)
}
