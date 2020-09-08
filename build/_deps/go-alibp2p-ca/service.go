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
 * @Time   : 2019/12/2 3:48 下午
 * @Author : liangc
 *************************************************************************/

package ca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/cc14514/go-alibp2p"
	"github.com/cc14514/go-certool"
	"github.com/cc14514/go-lightrpc/rpcserver"
	"io"
	"log"
	"math/big"
)

type (
	MsgType uint16
	PingMsg string
)

func (m MsgType) Raw() uint16 { return uint16(m) }

const (
	CAL_REQ  MsgType = 0x01
	CAL_RSP  MsgType = 0x02
	PING_REQ MsgType = 0x03
	PING_RSP MsgType = 0x04
	CSR_REQ  MsgType = 0x05
	CSR_RSP  MsgType = 0x06
	CRT_REQ  MsgType = 0x07
	CRT_RSP  MsgType = 0x08
)

const (
	PING_MSG PingMsg = "ping"
	PONG_MSG         = "pong"
	PANG_MSG         = "pang"
)

const (
	PID_CSR  = "/ca/csr/0.0.1"
	PID_CRT  = "/ca/crt/0.0.1" // CRL 也在这个通道上
	PID_CAL  = "/ca/cal/0.0.1"
	PID_PING = "/ca/ping/0.0.1"
)

var (
	BadMsgError     = errors.New("bad msg")
	CsrMsgTypeError = errors.New("error msgtype on csr channel")
)

type caService struct {
	ctx        context.Context
	p2pservice alibp2p.Libp2pService
	alibp2pCA  Alibp2pCA
	capwd      string
}

func NewCAService2(ctx context.Context, p2pservice alibp2p.Libp2pService, alibp2pCA Alibp2pCA) (Alibp2pCAService, error) {
	return &caService{
		ctx:        ctx,
		alibp2pCA:  alibp2pCA,
		p2pservice: p2pservice,
	}, nil
}

func NewCAService(ctx context.Context, datadir string, p2pservice alibp2p.Libp2pService) (Alibp2pCAService, error) {
	return NewCAService2(ctx, p2pservice, NewAlibp2pCA(datadir))
}

// 不是 CA 也没有 CERT List，所以只针对 CA 开放这个 API
func (self *caService) GetCERTs() ([]Cert, error) {
	_, err := self.GetAlibp2pCA().GetCA(self.capwd)
	if err != nil {
		return nil, err
	}
	pl, err := self.alibp2pCA.listCRT()
	//for _, p := range pl {
	//	fmt.Println("===========>", p.String())
	//}
	cl := make([]Cert, 0)
	for _, p := range pl {
		b, _ := hex.DecodeString(p)
		cl = append(cl, b)
	}
	return cl, err
}

func (self *caService) UnlockCAKey(pwd string) error {
	_, err := self.GetAlibp2pCA().GetCA(pwd)
	if err != nil {
		return err
	}
	self.capwd = pwd
	return nil
}

func (self *caService) AcceptCsr(id ID, expire int) (Cert, error) {
	return self.alibp2pCA.AcceptCsr(id, expire, self.capwd)
}

func (self *caService) SendCsr(pubkey *ecdsa.PublicKey, csr Csr) (ID, error) {
	id, err := alibp2p.ECDSAPubEncode(pubkey)
	if err != nil {
		return "", err
	}
	req, _ := json.Marshal(&rpcserver.AppRequest{
		Service: "csr",
		Method:  "request",
		Params:  csr.String(),
	})
	head := alibp2p.NewSimplePacketHead(CSR_REQ.Raw(), req)
	msg := append(head, req...)
	_, s, _, err := self.p2pservice.SendMsg(id, PID_CSR, msg)
	if err != nil {
		return "", err
	}
	data, err := ReadSimpleMsg(s, CSR_RSP)
	if err != nil {
		return "", err
	}
	success := rpcserver.SuccessFromBytes(data)
	if success.Success {
		return ID(success.Entity.(string)), nil
	}
	reason := success.Entity.(map[string]interface{})
	return "", errors.New(reason["reason"].(string))
}

func (self *caService) CsrStatus(pubkey *ecdsa.PublicKey, csrid ID) (CSR_STATE, error) {
	id, err := alibp2p.ECDSAPubEncode(pubkey)
	if err != nil {
		return "", err
	}
	req, _ := json.Marshal(&rpcserver.AppRequest{
		Service: "csr",
		Method:  "status",
		Params:  csrid,
	})
	head := alibp2p.NewSimplePacketHead(CSR_REQ.Raw(), req)
	msg := append(head, req...)
	_, s, _, err := self.p2pservice.SendMsg(id, PID_CSR, msg)
	if err != nil {
		return "", err
	}
	data, err := ReadSimpleMsg(s, CSR_RSP)
	if err != nil {
		return "", err
	}
	success := rpcserver.SuccessFromBytes(data)
	if success.Success {
		return CSR_STATE(success.Entity.(string)), nil
	}
	reason := success.Entity.(map[string]interface{})
	//errCode
	ec := reason["errCode"].(string)
	return CSR_STATE(ec), errors.New(reason["reason"].(string))
}

func (self *caService) GetCRLs(nodeid *ecdsa.PublicKey) ([]Crl, error) {
	id, err := alibp2p.ECDSAPubEncode(nodeid)
	if err != nil {
		return nil, err
	}
	req, _ := json.Marshal(&rpcserver.AppRequest{
		Service: "crt",
		Method:  "getcrls",
	})
	head := alibp2p.NewSimplePacketHead(CRT_REQ.Raw(), req)
	msg := append(head, req...)
	_, s, _, err := self.p2pservice.SendMsg(id, PID_CRT, msg)
	if err != nil {
		return nil, err
	}
	data, err := ReadSimpleMsg(s, CRT_RSP)
	if err != nil {
		return nil, err
	}
	success := rpcserver.SuccessFromBytes(data)
	if success.Success {
		crls := success.Entity
		ret := make([]Crl, 0)
		for _, c := range crls.([]interface{}) {
			b, err := hex.DecodeString(c.(string))
			if err != nil {
				return nil, err
			}
			ret = append(ret, Crl(b))
		}
		return ret, nil
	}
	reason := success.Entity.(map[string]interface{})
	return nil, errors.New(reason["reason"].(string))
}

func (self *caService) GetCert(nodeid *ecdsa.PublicKey, cid ID) (Cert, error) {
	id, err := alibp2p.ECDSAPubEncode(nodeid)
	if err != nil {
		return nil, err
	}
	req, _ := json.Marshal(&rpcserver.AppRequest{
		Service: "crt",
		Method:  "getcert",
		Params:  cid,
	})
	head := alibp2p.NewSimplePacketHead(CRT_REQ.Raw(), req)
	msg := append(head, req...)
	_, s, _, err := self.p2pservice.SendMsg(id, PID_CRT, msg)
	if err != nil {
		return nil, err
	}
	data, err := ReadSimpleMsg(s, CRT_RSP)
	if err != nil {
		return nil, err
	}
	success := rpcserver.SuccessFromBytes(data)
	if success.Success {
		certRaw, _ := hex.DecodeString(success.Entity.(string))
		certPem := &pem.Block{Type: "CERTIFICATE", Headers: make(map[string]string), Bytes: certRaw}
		buf := new(bytes.Buffer)
		err = pem.Encode(buf, certPem)
		if err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
	reason := success.Entity.(map[string]interface{})
	return nil, errors.New(reason["reason"].(string))
}

func (self *caService) RevokeCert(nodeid *ecdsa.PublicKey, ros ...RevokeObj) (Crl, error) {
	id, err := alibp2p.ECDSAPubEncode(nodeid)
	if err != nil {
		return nil, err
	}
	myid, _ := self.p2pservice.Myid()

	// CA 才可以批量强制撤销，否则只能撤销自己的
	if myid == id {
		snl := make([]*big.Int, 0)
		for _, ro := range ros {
			sn := ro.SerialNumber
			if sn == nil {
				return nil, errors.New("RevokeObj SerialNumber nil")
			}
			sign := ro.Sign
			pk, _ := alibp2p.ECDSAPubDecode(myid)
			if err = verifyECS256Sign(pk, sn.Bytes(), sign); err != nil {
				return nil, err
			}
			snl = append(snl, sn)
		}
		return self.alibp2pCA.RevokeService(self.capwd, ros...)
	} else {
		cert := ros[0].Cert
		sign := ros[0].Sign
		p := Pem(cert)
		certObj, err := p.PaserCert()
		if err != nil {
			return nil, err
		}
		pubkey, err := alibp2p.ECDSAPubDecode(certObj.Subject.CommonName)
		if err != nil {
			return nil, err
		}

		if err = verifyECS256Sign(pubkey, certObj.SerialNumber.Bytes(), sign); err != nil {
			return nil, err
		}

		req, _ := json.Marshal(&rpcserver.AppRequest{
			Service: "crt",
			Method:  "revoke",
			Params: map[string]interface{}{
				"cert": cert.Hex(),
				"sign": hex.EncodeToString(sign),
			},
		})
		buff := new(bytes.Buffer)
		_, err = SendSimpleMsg(buff, CRT_REQ, req)
		if err != nil {
			return nil, err
		}
		_, s, _, err := self.p2pservice.SendMsg(id, PID_CRT, buff.Bytes())
		if err != nil {
			return nil, err
		}
		data, err := ReadSimpleMsg(s, CRT_RSP)
		if err != nil {
			return nil, err
		}
		success := rpcserver.SuccessFromBytes(data)
		if success.Success {
			crlRaw, _ := hex.DecodeString(success.Entity.(string))
			return crlRaw, nil
		}
		reason := success.Entity.(map[string]interface{})
		return nil, errors.New(reason["reason"].(string))
	}
	return nil, errors.New("nothing todo")
}

func (self *caService) GetAlibp2pCA() Alibp2pCA {
	return self.alibp2pCA
}
func (self *caService) Ping(pubkey *ecdsa.PublicKey) (PingMsg, error) {
	id, err := alibp2p.ECDSAPubEncode(pubkey)
	if err != nil {
		return PANG_MSG, err
	}
	arg := []byte(PING_MSG)
	head := alibp2p.NewSimplePacketHead(PING_REQ.Raw(), arg)
	msg := append(head, arg...)
	_, s, _, err := self.p2pservice.SendMsg(id, PID_PING, msg)
	if err != nil {
		return PANG_MSG, err
	}
	data, err := ReadSimpleMsg(s, PING_RSP)
	return PingMsg(data), nil
}

// 同步 CAL
func (self *caService) GetCAL(pubkey *ecdsa.PublicKey) (certool.Keychain, error) {
	if pubkey == nil {
		return self.alibp2pCA.GetKeychain(), nil
	}
	id, err := alibp2p.ECDSAPubEncode(pubkey)
	if err != nil {
		return nil, err
	}
	arg := []byte("GETCAL")
	head := alibp2p.NewSimplePacketHead(CAL_REQ.Raw(), arg)
	msg := append(head, arg...)
	_, s, _, err := self.p2pservice.SendMsg(id, PID_CAL, msg)
	if err != nil {
		return nil, err
	}
	data, err := ReadSimpleMsg(s, CAL_RSP)
	if err != nil {
		return nil, err
	}
	log.Println("send get cal msg:", "to", id, "response", string(data))
	kc, err := certool.LoadKeychain(data)
	if err != nil {
		return nil, err
	}
	err = self.alibp2pCA.SetKeychain(kc)
	return kc, err
}

func (self *caService) Start() error {
	self.pingService()
	self.calService()
	self.csrService()
	self.crtService()
	return nil
}

func (self *caService) pingService() {
	self.p2pservice.SetHandler(PID_PING, func(sessionId string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error {
		a, err := ReadSimpleMsg(rw, PING_REQ)
		log.Println("handle getcal msg", sessionId, "err", err, "arg", a)
		if err != nil {
			SendSimpleMsg(rw, PING_RSP, []byte(PANG_MSG))
			return err
		}
		SendSimpleMsg(rw, PING_RSP, []byte(PONG_MSG))
		return nil
	})
}

func (self *caService) calService() {
	self.p2pservice.SetHandler(PID_CAL, func(sessionId string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error {
		a, err := ReadSimpleMsg(rw, CAL_REQ)
		log.Println("handle getcal msg", sessionId, "err", err, "arg", a)
		if err != nil {
			SendSimpleMsg(rw, CAL_RSP, []byte(err.Error()))
			return err
		}
		kc := self.alibp2pCA.GetKeychain()
		if kc != nil {
			data, err := kc.Serialize()
			if err != nil {
				SendSimpleMsg(rw, CAL_RSP, []byte(err.Error()))
				return err
			}
			SendSimpleMsg(rw, CAL_RSP, data)
		} else {
			SendSimpleMsg(rw, CAL_RSP, []byte("empty-cal"))
		}
		return err
	})
}

func (self *caService) crtService() {
	self.p2pservice.SetHandler(PID_CRT, func(sessionId string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error {
		var (
			ret       = &rpcserver.Success{Sn: sessionId, Success: true}
			getcertFn = func(id ID) error {
				cert, err := self.GetAlibp2pCA().GetCertByID(id)
				if err != nil {
					ret.Error("20000", err.Error())
					return err
				}
				p := Pem(cert)
				certObj, err := p.PaserCert()
				if err != nil {
					ret.Error("20001", err.Error())
					return err
				}
				certHex := hex.EncodeToString(certObj.Raw)
				ret.Entity = certHex
				return nil
			}

			revokeFn = func(params map[string]interface{}) error {
				certH, signH := params["cert"].(string), params["sign"].(string)
				cert, err := hex.DecodeString(certH)
				if err != nil {
					ret.Error("30000", err.Error())
					return err
				}
				sign, err := hex.DecodeString(signH)
				if err != nil {
					ret.Error("30001", err.Error())
					return err
				}

				crl, err := self.GetAlibp2pCA().RevokeService(self.capwd, RevokeObj{
					Cert: cert,
					Sign: sign,
				})
				if err != nil {
					ret.Error("30002", err.Error())
					return err
				}
				err = self.alibp2pCA.UpdateCRL(crl)
				if err != nil {
					ret.Error("30003", err.Error())
					return err
				}
				ret.Entity = hex.EncodeToString(crl)
				return nil
			}
			getcrlsFn = func() error {
				crls, err := self.GetAlibp2pCA().ListCRL()
				if err != nil {
					ret.Error("40000", err.Error())
					return err
				}
				retcrls := make([]string, 0)
				for _, crl := range crls {
					retcrls = append(retcrls, crl.RawHex)
				}
				ret.Entity = retcrls
				return nil
			}
		)
		defer func() {
			data, _ := json.Marshal(ret)
			SendSimpleMsg(rw, CRT_RSP, data)
		}()
		req, err := ReadSimpleMsg(rw, CRT_REQ)
		if err != nil {
			ret.Error("10000", err.Error())
			return err
		}
		reqObj := new(rpcserver.AppRequest)
		err = json.Unmarshal(req, reqObj)
		if err != nil {
			ret.Error("10001", err.Error())
			return err
		}
		switch reqObj.Method {
		case "getcert":
			return getcertFn(ID(reqObj.Params.(string)))
		case "revoke":
			return revokeFn(reqObj.Params.(map[string]interface{}))
		case "getcrls":
			return getcrlsFn()
		}
		return nil
	})
}
func (self *caService) csrService() {
	self.p2pservice.SetHandler(PID_CSR, func(sessionId string, pubkey *ecdsa.PublicKey, rw io.ReadWriter) error {
		var (
			ret = &rpcserver.Success{Sn: sessionId, Success: true}

			requestFn = func(csr Csr) error {
				id, err := self.alibp2pCA.CsrHandler(csr)
				if err == nil {
					ret.Entity = id
				} else {
					ret.Error("20000", err.Error())
				}
				return err
			}

			statusFn = func(id ID) error {
				state, err := self.alibp2pCA.CsrStatus(id)
				if err == nil {
					ret.Entity = state
				} else {
					ret.Error(string(state), err.Error())
				}
				return nil
			}
		)
		defer func() {
			data, _ := json.Marshal(ret)
			SendSimpleMsg(rw, CSR_RSP, data)
		}()

		log.Println("csr msg from", pubkey, sessionId)
		req, err := ReadSimpleMsg(rw, CSR_REQ)

		if err != nil {
			ret.Error("10000", err.Error())
			return err
		}

		reqObj := new(rpcserver.AppRequest)
		err = json.Unmarshal(req, reqObj)
		if err != nil {
			ret.Error("10001", err.Error())
			return err
		}

		switch reqObj.Method {
		case "request":
			return requestFn(Csr(reqObj.Params.(string)))
		case "status":
			return statusFn(ID(reqObj.Params.(string)))
		}
		return err
	})
}

var (
	SendSimpleMsg = func(rw io.Writer, mt MsgType, data []byte) (int, error) {
		head := alibp2p.NewSimplePacketHead(mt.Raw(), data)
		packet := append(head, data...)
		t, err := rw.Write(packet)
		log.Println("resp", "err", err, "msgtype", mt, "t", t)
		return t, err
	}
	ReadSimpleMsg = func(rw io.Reader, mt MsgType) ([]byte, error) {
		head, err := alibp2p.ReadSimplePacketHead(rw)
		if err != nil {
			return nil, err
		}
		msgtype, size, err := head.Decode()
		if err != nil {
			return nil, err
		}
		if mt != MsgType(msgtype) {
			return nil, CsrMsgTypeError
		}
		data := make([]byte, size)
		t, err := io.ReadFull(rw, data)
		if err != nil {
			return nil, err
		}
		if uint32(t) != size {
			return nil, BadMsgError
		}
		return data, nil
	}
)
