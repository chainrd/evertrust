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
 * @Time   : 2019/11/28 11:53 上午
 * @Author : liangc
 *************************************************************************/

package ca

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/cc14514/go-alibp2p"
	"github.com/cc14514/go-alibp2p-ca/ldb"
	"github.com/cc14514/go-certool"
	"github.com/libp2p/go-libp2p-core/peer"
	"log"
	"math/big"
	"os"
	"path"
	"time"
)

const CADB = "cadb"

var (
	RCA_KEY   = []byte("RCA-KEY")
	RCA_CRT   = []byte("RCA-CRT")
	CAL       = []byte("CAL")
	CRT_TABLE = []byte("CRT-")
	CSR_TABLE = []byte("CSR-")
	REJ_TABLE = []byte("REJ-")
	CRL_TABLE = []byte("CRL-")
	kfilter   = func(prefix, k []byte) bool {
		if k != nil && len(k) > len(prefix) {
			return bytes.Equal(k[:len(prefix)], prefix)
		}
		return false
	}
	rcaSaveFn = func(db ldb.Database, k, c []byte) {
		db.Put(RCA_KEY, k)
		db.Put(RCA_CRT, c)
	}
)

func NewAlibp2pCA(datadir string) Alibp2pCA {
	datadir = path.Join(datadir, CADB)
	os.MkdirAll(datadir, 0755)
	db, err := ldb.NewLDBDatabase(datadir, 256, 256)
	if err != nil {
		panic(err)
	}

	return &Alibp2pCAImpl{
		db:      db,
		crtdb:   ldb.NewTable(db, string(CRT_TABLE)),
		csrdb:   ldb.NewTable(db, string(CSR_TABLE)),
		rejdb:   ldb.NewTable(db, string(REJ_TABLE)),
		crldb:   ldb.NewTable(db, string(CRL_TABLE)),
		keytool: certool.NewKeytool(),
		notify:  NewNotify(),
		datadir: datadir,
	}
}

func (self *Alibp2pCAImpl) GenRootCA(pwd string, subj *certool.Subject) error {
	priv, _ := self.GenKey(pwd, subj)
	key, _ := self.keytool.ParsePriv(priv, []byte(pwd))
	ca := certool.NewCA(key, nil)
	user := certool.NewUser(subj, key.Public(), nil, true, 70)
	cert, err := self.keytool.GenCert(ca, user)
	if err != nil {
		return err
	}
	rcaSaveFn(self.db, priv, cert)
	self.SetCert(subj.CommonName, cert)
	return nil
}

func (self *Alibp2pCAImpl) GetCA(pwd string) (*certool.CA, error) {
	priv, err := self.db.Get(RCA_KEY)
	if err != nil {
		return nil, errors.New("current node is not rootca")
	}
	key, err := self.keytool.ParsePriv(priv, []byte(pwd))
	if err != nil {
		return nil, err
	}
	buf, err := self.db.Get(RCA_CRT)
	if err != nil {
		return nil, errors.New("current node is not rootca")
	}
	cert, err := self.keytool.ParseCert(buf)
	if err != nil {
		return nil, err
	}
	return certool.NewCA(key, cert.(*x509.Certificate)), nil
}

func (self *Alibp2pCAImpl) ExportRootCA(pwd string) (Pem, error) {
	_, err := self.GetCA(pwd)
	if err != nil {
		return nil, err
	}

	priv, err := self.db.Get(RCA_KEY)
	if err != nil {
		return nil, err
	}
	cert, err := self.db.Get(RCA_CRT)
	if err != nil {
		return nil, err
	}
	ret := append(priv, cert...)
	return ret, nil
}

func (self *Alibp2pCAImpl) ImportRootCA(pwd string, p Pem) error {
	key, err := p.PaserKey(pwd)
	if err != nil {
		return err
	}
	bpriv, _ := x509.MarshalECPrivateKey(key)
	pemblock, _ := x509.EncryptPEMBlock(rand.Reader, certool.TITLE_KEY, bpriv, []byte(pwd), x509.PEMCipherAES128)
	buf := new(bytes.Buffer)
	pem.Encode(buf, pemblock)
	privRaw := buf.Bytes()
	crt, err := p.PaserCert()
	if err != nil {
		return err
	}
	certPem := &pem.Block{Type: certool.TITLE_CRT, Headers: make(map[string]string), Bytes: crt.Raw}
	buf = new(bytes.Buffer)
	pem.Encode(buf, certPem)
	certRaw := make([]byte, buf.Len())
	copy(certRaw, buf.Bytes())
	rcaSaveFn(self.db, privRaw, certRaw)
	return nil
}

func (self *Alibp2pCAImpl) GenKey(pwd string, subj *certool.Subject) (Key, Csr) {
	privRaw, _ := self.keytool.GenKey(pwd)
	key, _ := self.keytool.ParsePriv(privRaw, []byte(pwd))
	csrRaw, _ := self.keytool.GenCsr(subj, key)
	return privRaw, csrRaw
}

func (self *Alibp2pCAImpl) GenCertByCsr(pwd string, csr Csr, isCA bool, expire int) (Cert, error) {
	rca, err := self.GetCA(pwd)
	if err != nil {
		return nil, err
	}
	obj, err := self.keytool.ParseCert(csr)
	if err != nil {
		return nil, err
	}
	csrObj := obj.(*x509.CertificateRequest)
	u := certool.NewUser(nil, csrObj.PublicKey, csrObj, isCA, expire)
	crt, err := self.keytool.GenCert(rca, u)
	if err != nil {
		return nil, err
	}
	obj2, _ := self.keytool.ParseCert(crt)
	crtObj := obj2.(*x509.Certificate)
	err = self.crtdb.Put(crtObj.SerialNumber.Bytes(), crt)
	if err != nil {
		return nil, err
	}
	return crt, nil
}

func (self *Alibp2pCAImpl) ListCert() []*Summary {
	//it := self.crtdb.NewIterator(nil)
	it := self.crtdb.NewIterator()
	sl := make([]*Summary, 0)
	for it.Next() {
		if kfilter(CRT_TABLE, it.Key()) {
			p := Pem(it.Value())
			sl = append(sl, p.ToSummary())
		}
	}
	return sl
}

// 处理从 Stream 上接收的 CSR, 产生待处理任务
func (self *Alibp2pCAImpl) CsrHandler(csr Csr) (ID, error) {
	p := Pem(csr)
	csrObj, err := p.PaserCsr()
	if err != nil {
		return "", err
	}
	if err := csrObj.CheckSignature(); err != nil {
		return "", err
	}
	id := csr.ToID()
	return id, self.csrdb.Put(id.ToBytes(), csr)
}

// 如果拒绝了会以 error 返回
func (self *Alibp2pCAImpl) CsrStatus(id ID) (CSR_STATE, error) {
	rej, err := self.rejdb.Get(id.ToBytes())
	if err == nil {
		return CSR_STATE_REJECT, errors.New(string(rej))
	}
	x, err := self.csrdb.Get(id.ToBytes())
	if err != nil {
		return CSR_STATE_NOTFOUND, nil
	}
	if CSR_STATE(x) == CSR_STATE_PASSED {
		return CSR_STATE_PASSED, nil
	}
	return CSR_STATE_NORMAL, nil
}

// 待处理的 CSR 摘要信息
func (self *Alibp2pCAImpl) ListCsr() []*Summary {
	it := self.crtdb.NewIterator()
	sl := make([]*Summary, 0)
	for it.Next() {
		if kfilter(CSR_TABLE, it.Key()) {
			p := Pem(it.Value())
			if _, err := p.PaserCsr(); err == nil {
				sl = append(sl, p.ToSummary())
			}
		}
	}
	return sl
}

// 接受 CSR 签发证书
func (self *Alibp2pCAImpl) AcceptCsr(id ID, expire int, pwd string) (Cert, error) {
	data, err := self.csrdb.Get(id.ToBytes())
	if err != nil {
		return nil, err
	}
	p := Pem(data)
	csr, err := p.PaserCsr()
	if err != nil {
		return nil, err
	}
	rca, err := self.GetCA(pwd)
	if err != nil {
		return nil, err
	}
	u := certool.NewUser(nil, nil, csr, false, expire)
	crtRaw, err := self.keytool.GenCert(rca, u)
	if err != nil {
		return nil, err
	}
	crt, err := Pem(crtRaw).PaserCert()
	if err != nil {
		return nil, err
	}
	err = self.csrdb.Put(id.ToBytes(), []byte(CSR_STATE_PASSED))
	if err != nil {
		return nil, err
	}
	err = self.crtdb.Put(crt.SerialNumber.Bytes(), crtRaw)
	if err != nil {
		return nil, err
	}
	return crtRaw, nil
}

// 不接受证书请求，并拒绝签发
func (self *Alibp2pCAImpl) RejectCsr(id ID, reason string) (Csr, error) {
	err := self.rejdb.Put(id.ToBytes(), []byte(reason))
	if err != nil {
		return nil, err
	}
	csrRaw, err := self.csrdb.Get(id.ToBytes())
	if err != nil {
		return nil, err
	}
	err = self.csrdb.Delete(id.ToBytes())
	if err != nil {
		return nil, err
	}
	self.db.Put(id.ToBytes(), csrRaw)
	return csrRaw, nil
}

func (self *Alibp2pCAImpl) RevokeCert(pwd string, certs ...Cert) (Crl, error) {
	rca, err := self.GetCA(pwd)
	if err != nil {
		return nil, err
	}
	revokes := make([]*x509.Certificate, 0)
	for _, cert := range certs {
		p := Pem(cert)
		crt, err := p.PaserCert()
		if err != nil {
			return nil, err
		}
		revokes = append(revokes, crt)
	}
	return self.keytool.RevokedCert(rca.Cert, rca.Priv, time.Now(), revokes...)
}

// 用户发起的撤销，需要携带正确的签名
func (self *Alibp2pCAImpl) RevokeService(pwd string, ros ...RevokeObj) (Crl, error) {
	ca, err := self.GetCA(pwd)
	if err != nil {
		return nil, err
	}
	verifySign := func(pubkey *ecdsa.PublicKey, msg, sign []byte) (err error) {
		// 证书持有人的签名 >>>>>>>>>>>>>>>>>>>>>>
		if err = verifyECS256Sign(pubkey, msg, sign); err == nil {
			return nil
		}
		// 证书持有人的签名 <<<<<<<<<<<<<<<<<<<<<<

		// CA 签名验证 >>>>>>>>>>>>>>>>>>>>>
		for _, k := range self.keychain.GetAll() {
			caid := k.Subject.CommonName.Pretty()
			capub, _ := alibp2p.ECDSAPubDecode(caid)
			if err = verifyECS256Sign(capub, msg, sign); err == nil {
				return nil
			}
		}
		// CA 签名验证 <<<<<<<<<<<<<<<<<<<<<
		return errors.New("revoke sign verify fail")
	}
	if len(ros) == 1 && ros[0].SerialNumber == nil {
		cert := ros[0].Cert
		revokeSign := ros[0].Sign
		p := Pem(cert)
		certObj, err := p.PaserCert()
		if err != nil {
			return nil, err
		}
		_, err = self.GetKeychain().Verify(certObj)
		if err != nil {
			return nil, err
		}
		nid := certObj.Subject.CommonName
		pub, err := alibp2p.ECDSAPubDecode(nid)
		if err != nil {
			return nil, err
		}
		id := certObj.SerialNumber
		if err = verifySign(pub, id.Bytes(), revokeSign); err != nil {
			return nil, err
		}
		return self.keytool.RevokedCert(ca.Cert, ca.Priv, time.Now(), certObj)
	} else {
		// 当前节点为 CA ，去自己的 pubkey 来验证签名
		nid := ca.Cert.Subject.CommonName
		pub, _ := alibp2p.ECDSAPubDecode(nid)
		sns := make([]*big.Int, 0)
		for _, ro := range ros {
			if err = verifySign(pub, ro.SerialNumber.Bytes(), ro.Sign); err != nil {
				return nil, err
			}
			sns = append(sns, ro.SerialNumber)
		}
		return self.keytool.RevokedCertBySerialNumber(ca.Cert, ca.Priv, time.Now(), sns...)
	}
}

// TODO merge or reset ???
func (self *Alibp2pCAImpl) SetKeychain(keychain certool.Keychain) error {
	if cal, e := keychain.Serialize(); e == nil {
		self.db.Put(CAL, cal)
		self.keychain = keychain
	}
	return nil
}

func (self *Alibp2pCAImpl) GetKeychain() certool.Keychain {
	if self.keychain == nil {
		data, _ := self.db.Get(CAL)
		if kc, err := certool.LoadKeychain(data); err == nil {
			self.keychain = kc
		}
	}
	self.fixKeychain()
	return self.keychain
}

// exclude with CRL
func (self *Alibp2pCAImpl) fixKeychain() {
	crl, err := self.ListCRL()
	if err != nil || len(crl) == 0 {
		return
	}
	sm := make(map[string]struct{})
	for _, r := range crl {
		for _, rid := range r.CertIDs {
			sm[rid] = struct{}{}
		}
	}
	for _, ko := range self.keychain.GetAll() {
		if _, ok := sm[hex.EncodeToString(ko.SerialNumber)]; ok {
			self.UpdateKeychain(ko.Cert, KCA_DEL)
		}
	}
}

func (self *Alibp2pCAImpl) UpdateKeychain(cert Cert, action ...KeychainAction) (err error) {
	var (
		a        = KCA_ADD
		p        = Pem(cert)
		certObj  *x509.Certificate
		keychain = self.GetKeychain()
		storeFn  = func() {
			if err == nil {
				if cal, e := keychain.Serialize(); e == nil {
					fmt.Println("-->", string(cal))
					self.db.Put(CAL, cal)
					self.keychain = keychain
				}
			}
		}
		addFn = func() error {
			defer storeFn()
			// 如果是 RootCA 第一次初始化 keychain 时，是无法使用 keychain.Verify 的
			// 这相当于一次初始化
			if certObj.CheckSignatureFrom(certObj) == nil {
				return keychain.AppendRoot(certObj)
			}
			_, err = keychain.Verify(certObj)
			if err != nil {
				return err
			}
			return keychain.AppendIntermediate(certObj)
		}
		delFn = func() error {
			defer storeFn()
			if certObj.CheckSignatureFrom(certObj) == nil {
				err = errors.New("Cannot remove RootCA")
				return err
			}
			_, err = keychain.Verify(certObj)
			if err != nil {
				return err
			}
			return keychain.Remove(certObj)
		}
	)
	if action != nil {
		a = action[0]
	}
	certObj, err = p.PaserCert()
	if err != nil {
		return err
	}
	defer func() {
		if err == nil {
			self.notify.updateKeychain(cert, a)
		}
	}()
	switch a {
	case KCA_ADD:
		err = addFn()
	default:
		err = delFn()
	}
	return
}

/*
	更新 CRL 属于网络共识层面的功能，验证有效性并保持一致
	-----------------------------------------------
	CRL 的数据结构是 crl = {sign:ca_sign,snl:[certSn,...]}
	所以存储 CRL 时我们要先存储 hash(CRL) = CRL, 再去索引 sn = hash(CRL)
*/
func (self *Alibp2pCAImpl) UpdateCRL(crl Crl) error {
	p := Pem(crl)
	crlObj, err := p.PaserCrl()
	if err != nil {
		return err
	}
	_, err = self.GetKeychain().VerifyCRL(crlObj)
	if err != nil {
		return err
	}
	defer self.notify.updateCRL(crl)
	id := crl.ToID()
	self.db.Put(id.ToBytes(), crl)
	for _, r := range crlObj.TBSCertList.RevokedCertificates {
		self.crldb.Put(r.SerialNumber.Bytes(), id.ToBytes())
	}
	return nil
}

func (self *Alibp2pCAImpl) ListCRL() ([]*CrlSummary, error) {
	it := self.crldb.NewIterator()
	sl := make([]*CrlSummary, 0)
	for it.Next() {
		if kfilter(CRL_TABLE, it.Key()) {
			crlID := it.Value()
			if crlB, err := self.db.Get(crlID); err == nil {
				if cs, err := Crl(crlB).ToSummary(); err == nil {
					sl = append(sl, cs)
				}
			}
		}
	}
	return sl, nil
}

func (self *Alibp2pCAImpl) listCRT() ([]string, error) {
	// 只有 CA 可以使用这个功能
	it := self.crtdb.NewIterator()
	cl := make([]string, 0)
	for it.Next() {
		if kfilter(CRT_TABLE, it.Key()) {
			v := it.Value()
			if self.IsRevokeCert(v) != nil { // 未撤销
				c := hex.EncodeToString(v)
				//fmt.Println("AAAAAAAAAAAAA>", c)
				//p := Pem(v)
				//fmt.Println("$$$$$$$$$$$$>", p.String())
				cl = append(cl, c)
			}
		}
	}
	return cl, nil
}

func (self *Alibp2pCAImpl) IsRevokeCert(cert Cert) error {
	p := Pem(cert)
	certObj, err := p.PaserCert()
	if err != nil {
		return err
	}
	crlid, err := self.crldb.Get(certObj.SerialNumber.Bytes())
	if err != nil {
		return err
	}
	crl, err := self.db.Get(crlid)
	if err != nil {
		return err
	}
	p2 := Pem(crl)
	crlObj, err := p2.PaserCrl()
	if err != nil {
		return err
	}
	_, err = self.GetKeychain().VerifyCRL(crlObj)
	return err
}

func (self *Alibp2pCAImpl) SetCert(uid peer.ID, cert Cert) error {
	p := Pem(cert)
	certObj, err := p.PaserCert()
	if err != nil {
		return err
	}
	cid := certObj.SerialNumber
	self.crtdb.Put(cid.Bytes(), cert)
	self.db.Put([]byte(uid.Pretty()), cid.Bytes())
	log.Println("SetCert", "uid", uid, "cid", cid)
	return nil
}

func (self *Alibp2pCAImpl) GetCert(uid peer.ID) (Cert, error) {
	cid, err := self.db.Get([]byte(uid.Pretty()))
	if err != nil {
		return nil, err
	}
	log.Println("GetCert", "uid", uid, "cid", new(big.Int).SetBytes(cid))
	return self.crtdb.Get(cid)
}

func (self *Alibp2pCAImpl) GetCertByID(id ID) (Cert, error) {
	return self.crtdb.Get(id.ToBytes())
}

func (self *Alibp2pCAImpl) Event() Event {
	return self.notify
}

func (self *Alibp2pCAImpl) Backup(pwd string) ([]byte, error) {
	return EncryptAndBackup(pwd, self.datadir)
}

func (self *Alibp2pCAImpl) Restore(pwd string, data []byte, output string) error {
	return DecryptAndRestore(pwd, data, output)
}
