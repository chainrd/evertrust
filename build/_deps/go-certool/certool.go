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
 * @Time   : 2019/11/21 2:15 下午
 * @Author : liangc
 *************************************************************************/

package certool

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/libp2p/go-libp2p-core/peer"
	uuid "github.com/satori/go.uuid"
	"math/big"
	"time"
)

func makeKid(cert []byte) Kid {
	sha256 := crypto.SHA1.New()
	sha256.Write(cert)
	hash := sha256.Sum(nil)
	return Kid(hex.EncodeToString(hash))
}

func newKeyobj(cert *x509.Certificate) *Keyobj {
	var Country, OrganizationalUnit, Organization, CommonName, email string
	if cert.Subject.Country != nil {
		Country = cert.Subject.Country[0]
	}
	if cert.Subject.OrganizationalUnit != nil {
		OrganizationalUnit = cert.Subject.OrganizationalUnit[0]
	}
	if cert.Subject.Organization != nil {
		Organization = cert.Subject.Organization[0]
	}
	CommonName = cert.Subject.CommonName
	if cert.EmailAddresses != nil && len(cert.EmailAddresses) > 0 {
		email = cert.EmailAddresses[0]
	}
	pid, err := peer.IDB58Decode(CommonName)
	if err != nil {
		//TODO
		panic(err)
	}
	subj := NewSubject(Country, OrganizationalUnit, Organization, pid, email)
	return &Keyobj{
		SerialNumber: cert.SerialNumber.Bytes(),
		Subject:      subj,
		Cert:         cert.Raw,
	}
}

func LoadKeychain(data []byte) (*KeychainImpl, error) {
	kc := new(KeychainImpl)
	if data == nil {
		return kc, nil
	}
	err := json.Unmarshal(data, kc)
	return kc, err
}

func (self *KeychainImpl) GetAll() KeyobjList {
	kl := make([]*Keyobj, 0)
	for _, rca := range self.Roots {
		kl = append(kl, rca)
	}
	for _, ica := range self.Intermediates {
		kl = append(kl, ica)
	}
	return kl
}

// 需要根据最新的 hash 来判断版本
func (self *KeychainImpl) Hash() []byte {
	return self.GetAll().Hash()
}

func (self *KeychainImpl) Verify(cert *x509.Certificate) (chains [][]*x509.Certificate, err error) {
	// 信任链
	opts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
		//DNSName:       cert.DNSNames[0],
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	for _, rca := range self.Roots {
		c, _ := x509.ParseCertificate(rca.Cert)
		opts.Roots.AddCert(c)
	}
	for _, ica := range self.Intermediates {
		c, _ := x509.ParseCertificate(ica.Cert)
		opts.Intermediates.AddCert(c)
	}
	// 验证
	return cert.Verify(opts)
}

func (self *KeychainImpl) VerifyCRL(crl *pkix.CertificateList) (*x509.Certificate, error) {
	for _, rca := range self.Roots {
		c, _ := x509.ParseCertificate(rca.Cert)
		if c.CheckCRLSignature(crl) == nil {
			return c, nil
		}
	}
	for _, ica := range self.Intermediates {
		c, _ := x509.ParseCertificate(ica.Cert)
		if c.CheckCRLSignature(crl) == nil {
			return c, nil
		}
	}
	return nil, errors.New("check signature fail.")
}

func (self *KeychainImpl) Serialize() ([]byte, error) {
	self.RootHash = self.Hash()
	return json.Marshal(self)
}

func (self *KeychainImpl) AppendRoot(cert *x509.Certificate) error {
	if !cert.IsCA {
		return errors.New("Only accept CA")
	}
	err := cert.CheckSignatureFrom(cert)
	if err != nil {
		return err
	}
	kid := makeKid(cert.Raw)
	if self.Roots == nil {
		self.Roots = make(map[Kid]*Keyobj)
	}
	self.Roots[kid] = newKeyobj(cert)
	self.RootHash = self.Hash()
	return nil
}

func (self *KeychainImpl) AppendIntermediate(cert *x509.Certificate) error {
	if !cert.IsCA {
		return errors.New("Only accept CA")
	}
	kid := makeKid(cert.Raw)
	if self.Intermediates == nil {
		self.Intermediates = make(map[Kid]*Keyobj)
	}
	self.Intermediates[kid] = newKeyobj(cert)
	self.RootHash = self.Hash()
	return nil
}

func (self *KeychainImpl) Remove(cert *x509.Certificate) error {
	kid := makeKid(cert.Raw)
	delete(self.Roots, kid)
	delete(self.Intermediates, kid)
	return nil
}

func NewUser(subj *Subject, pub crypto.PublicKey, csr *x509.CertificateRequest, isCA bool, expire int) *User {
	return &User{
		Subj:   subj,
		Pub:    pub,
		Csr:    csr,
		IsCA:   isCA,
		Expire: expire,
	}
}

func NewCA(priv *ecdsa.PrivateKey, cert *x509.Certificate) *CA {
	return &CA{priv, cert}
}

func NewSubject(country, orgUnit, org string, nodeid peer.ID, email string) *Subject {
	return &Subject{
		Country:            country,
		OrganizationalUnit: orgUnit,
		Organization:       org,
		CommonName:         nodeid,
		EmailAddress:       email,
	}
}

func ToSubject(subj pkix.Name) *Subject {
	ret := new(Subject)
	pid, err := peer.IDB58Decode(subj.CommonName)
	if err != nil {
		//TODO
		panic(err)
	}
	ret.CommonName = pid
	if subj.Country != nil {
		ret.Country = subj.Country[0]
	}
	if subj.OrganizationalUnit != nil {
		ret.OrganizationalUnit = subj.OrganizationalUnit[0]
	}
	if subj.Organization != nil {
		ret.Organization = subj.Organization[0]
	}
	return ret
}

func (subject *Subject) tox() pkix.Name {
	if subject == nil {
		return pkix.Name{}
	}
	return pkix.Name{
		Country:            []string{subject.Country},            // 国家地区
		OrganizationalUnit: []string{subject.OrganizationalUnit}, // 组织单位
		Organization:       []string{subject.Organization},       // 组织
		CommonName:         subject.CommonName.Pretty(),          // IDB58 编码的 ECS256 Pubkey
	}
}

// 提取 x509 pem 私钥
func (self *ECCKeytool) ParsePriv(buf, pwd []byte) (*ecdsa.PrivateKey, error) {
	p, _ := pem.Decode(buf)
	data, err := x509.DecryptPEMBlock(p, []byte(pwd))
	if err != nil {
		return nil, err
	}
	priv, err := x509.ParseECPrivateKey(data)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// 提取证书，csr 和 cert 都可以提取
func (self *ECCKeytool) ParseCert(buf []byte) (interface{}, error) {
	p, _ := pem.Decode(buf)
	switch p.Type {
	case self.csrTitle:
		csr, err := x509.ParseCertificateRequest(p.Bytes)
		if err != nil {
			return nil, err
		}
		return csr, nil
	case self.certTitle:
		cert, err := x509.ParseCertificate(p.Bytes)
		if err != nil {
			return nil, err
		}
		return cert, nil
	}
	return nil, errors.New("cert format error")
}

func NewKeytool() Keytool {
	return &ECCKeytool{
		pubTitle:  TITLE_PUB,
		keyTitle:  TITLE_KEY,
		csrTitle:  TITLE_CSR,
		certTitle: TITLE_CRT,
		agl:       x509.PEMCipherAES128,
		caKeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageCRLSign |
			x509.KeyUsageDataEncipherment |
			x509.KeyUsageDigitalSignature, // 证书签名，撤销签名，数据加密，数字签名
		userKeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDataEncipherment,
	}
}

// 创建一个 ECC P256 私钥，用于生成证书
func (self *ECCKeytool) GenKey(pwd string) (privRaw, pubRaw []byte) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bpriv, _ := x509.MarshalECPrivateKey(priv)
	pemblock, _ := x509.EncryptPEMBlock(rand.Reader, self.keyTitle, bpriv, []byte(pwd), self.agl)
	buf := new(bytes.Buffer)
	pem.Encode(buf, pemblock)
	privRaw = buf.Bytes()
	pubRaw = self.exportRawPubkey(priv.Public())
	return
}

// 用 ECC P256 私钥创建一个证书请求文件 CERTIFICATE REQUEST
// 可用于向 CA 申请证书
func (self *ECCKeytool) GenCsr(subject *Subject, key *ecdsa.PrivateKey) (csrRaw []byte, err error) {
	// 生成 PEM 证书
	if key == nil {
		return nil, errors.New("pub not be nil")
	}
	// 生成 CSR
	csrt := &x509.CertificateRequest{Subject: subject.tox()}
	if subject != nil && subject.EmailAddress != "" {
		csrt.EmailAddresses = []string{subject.EmailAddress}
	}
	csr, _ := x509.CreateCertificateRequest(rand.Reader, csrt, key)
	csrPem := &pem.Block{Type: self.csrTitle, Headers: make(map[string]string), Bytes: csr}
	buf := new(bytes.Buffer)
	pem.Encode(buf, csrPem)
	csrRaw = make([]byte, buf.Len())
	copy(csrRaw, buf.Bytes())
	return
}

/* 生成证书

使用 根证书和根密钥签发证书，可以签发给 pub 或者 csr
*/
func (self *ECCKeytool) GenCert(ca *CA, user *User) (certRaw []byte, err error) {
	id := new(big.Int).SetBytes(uuid.NewV4().Bytes())
	emails := make([]string, 0)
	subject := user.Subj
	subj := subject.tox()
	if subject != nil && subject.EmailAddress != "" {
		emails = append(emails, subject.EmailAddress)
	}
	if user.Csr != nil {
		if err = user.Csr.CheckSignature(); err != nil {
			return
		}
		user.Pub = user.Csr.PublicKey
		subj = user.Csr.Subject
		emails = user.Csr.EmailAddresses

		certPem := &pem.Block{Type: TITLE_CSR, Headers: make(map[string]string), Bytes: user.Csr.Raw}
		buf := new(bytes.Buffer)
		pem.Encode(buf, certPem)
		sha256 := crypto.SHA1.New()
		sha256.Write(buf.Bytes())
		idBytes := sha256.Sum(nil)
		id = new(big.Int).SetBytes(idBytes)

	} else if user.Pub == nil && user.Csr == nil {
		user.Pub = ca.Priv.Public() // 如果 user 没传公钥，标示要做自签名
	}

	// 生成 CRT
	template := &x509.Certificate{
		Subject:        subj,
		SerialNumber:   id,                                                                // 序列号
		NotBefore:      time.Now(),                                                        // 在此之前无效
		NotAfter:       time.Now().Add(time.Duration(user.Expire) * 365 * 24 * time.Hour), // 在此之后无效
		EmailAddresses: emails,
	}

	if user.IsCA {
		template.IsCA, template.BasicConstraintsValid = user.IsCA, user.IsCA
		template.KeyUsage = self.caKeyUsage
		if ca.Priv.Public() == user.Pub {
			ca.Cert = template // RCA 是自签名
		}
	} else {
		template.KeyUsage = self.userKeyUsage
	}

	cert, _ := x509.CreateCertificate(rand.Reader, template, ca.Cert, user.Pub, ca.Priv)
	certPem := &pem.Block{Type: self.certTitle, Headers: make(map[string]string), Bytes: cert}
	buf := new(bytes.Buffer)
	pem.Encode(buf, certPem)
	certRaw = make([]byte, buf.Len())
	copy(certRaw, buf.Bytes())
	return
}

//撤销证书
func (self *ECCKeytool) RevokedCert(rca *x509.Certificate, rkey *ecdsa.PrivateKey, expiry time.Time, certs ...*x509.Certificate) ([]byte, error) {
	rclist := make([]pkix.RevokedCertificate, 0)
	for _, r := range certs {
		rclist = append(rclist, pkix.RevokedCertificate{
			SerialNumber:   r.SerialNumber,
			RevocationTime: time.Now(),
			Extensions:     nil,
		})
	}
	if len(rclist) == 0 {
		return nil, errors.New("notfound revoke task")
	}
	crlB, err := rca.CreateCRL(rand.Reader, rkey, rclist, time.Now(), expiry)
	return crlB, err
}

func (self *ECCKeytool) RevokedCertBySerialNumber(rca *x509.Certificate, rkey *ecdsa.PrivateKey, expiry time.Time, serialNumbers ...*big.Int) ([]byte, error) {
	rclist := make([]pkix.RevokedCertificate, 0)
	for _, r := range serialNumbers {
		rclist = append(rclist, pkix.RevokedCertificate{
			SerialNumber:   r,
			RevocationTime: time.Now(),
			Extensions:     nil,
		})
	}
	if len(rclist) == 0 {
		return nil, errors.New("notfound revoke task")
	}
	crlB, err := rca.CreateCRL(rand.Reader, rkey, rclist, time.Now(), expiry)
	return crlB, err
}

func (self *ECCKeytool) exportRawPubkey(pubkey crypto.PublicKey) []byte {
	pubBuf, _ := x509.MarshalPKIXPublicKey(pubkey)
	b := &pem.Block{}
	b.Headers = make(map[string]string)
	b.Type = self.pubTitle
	b.Bytes = pubBuf
	buf := new(bytes.Buffer)
	pem.Encode(buf, b)
	return buf.Bytes()
}

func VerifyECS256Sign(pub *ecdsa.PublicKey, hash, sign []byte) error {
	if len(sign) != 64 {
		return errors.New("error_sign")
	}
	r, s := new(big.Int).SetBytes(sign[:32]), new(big.Int).SetBytes(sign[32:])
	if !ecdsa.Verify(pub, hash, r, s) {
		return errors.New("verify_fail")
	}
	return nil
}
