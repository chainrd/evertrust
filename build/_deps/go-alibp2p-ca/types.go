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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/cc14514/go-alibp2p-ca/ldb"
	"github.com/cc14514/go-certool"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type Alibp2pCAImpl struct {
	db, crtdb, csrdb, rejdb, crldb ldb.Database
	keytool                        certool.Keytool
	keychain                       certool.Keychain
	notify                         *Notify
	datadir                        string
}

type Notify struct {
	updateCRLFn      []func(Crl)
	updateKeychainFn []func(Cert, KeychainAction)
}

func NewNotify() *Notify {
	n := &Notify{
		updateCRLFn:      make([]func(Crl), 0),
		updateKeychainFn: make([]func(c Cert, a KeychainAction), 0),
	}
	return n
}

func (self *Notify) OnUpdateKeychain(fn func(c Cert, a KeychainAction)) {
	self.updateKeychainFn = append(self.updateKeychainFn, fn)
}

func (self *Notify) updateCRL(crl Crl) {
	if self.updateCRLFn != nil {
		for _, fn := range self.updateCRLFn {
			go fn(crl)
		}
	}
}

func (self *Notify) updateKeychain(c Cert, a KeychainAction) {
	if self.updateCRLFn != nil {
		for _, fn := range self.updateKeychainFn {
			go fn(c, a)
		}
	}
}

func (self *Notify) OnUpdateCRL(fn func(Crl)) {
	self.updateCRLFn = append(self.updateCRLFn, fn)
}

type (
	ID             string
	PemType        string
	Csr            []byte
	Cert           []byte
	Crl            []byte
	KeychainAction string
	CrlSummary     struct {
		Creater string   `json:"creater"`
		CertIDs []string `json:"certIds"`
		RawHex  string   `json:"raw"`
	}
	Pem     []byte
	Key     []byte
	Summary struct {
		Id                  ID
		Type                PemType
		IsCA                bool
		NotBefore, NotAfter string
		Subject             *certool.Subject
	}
	CSR_STATE string
)

const (
	CSR_STATE_REJECT   CSR_STATE = "REJECT"   // 拒绝
	CSR_STATE_NORMAL   CSR_STATE = "NORMAL"   // 待处理
	CSR_STATE_PASSED   CSR_STATE = "PASSED"   // 通过
	CSR_STATE_NOTFOUND CSR_STATE = "NOTFOUND" // 不存在
)

const (
	PT_CSR PemType = "CSR"
	PT_CRT PemType = "CRT"
	PT_CRL PemType = "CRL"
)

const (
	KCA_ADD KeychainAction = "ADD"
	KCA_DEL KeychainAction = "DEL"
)

func newSubjectFn(subject pkix.Name, emails []string) *certool.Subject {
	subj := certool.ToSubject(subject)
	if emails != nil {
		subj.EmailAddress = emails[0]
	}
	return subj
}

func (self *Summary) AsJson() []byte {
	j, _ := json.Marshal(self)
	return j
}

func (self *CrlSummary) AsJson() []byte {
	j, _ := json.Marshal(self)
	return j
}

func (self ID) ToBytes() []byte {
	b, _ := hex.DecodeString(self.String())
	return b
}

func BytesToID(b []byte) ID    { return ID(hex.EncodeToString(b)) }
func (self ID) String() string { return string(self) }

func (self Crl) ToSummary() (*CrlSummary, error) {
	p := Pem(self)
	crlObj, err := p.PaserCrl()
	if err != nil {
		return nil, err
	}
	certIDs := make([]string, 0)
	for _, obj := range crlObj.TBSCertList.RevokedCertificates {
		certIDs = append(certIDs, hex.EncodeToString(obj.SerialNumber.Bytes()))
	}

	return &CrlSummary{
		Creater: crlObj.TBSCertList.Issuer.String(),
		CertIDs: certIDs,
		RawHex:  hex.EncodeToString(self),
	}, nil
}
func (self Crl) ToID() ID {
	sha256 := crypto.SHA1.New()
	sha256.Write(self)
	return BytesToID(sha256.Sum(nil))
}

func (self Csr) ToID() ID {
	sha256 := crypto.SHA1.New()
	sha256.Write(self)
	return BytesToID(sha256.Sum(nil))
}

func ToCert(cert *x509.Certificate) (Cert, error) {
	certPem := &pem.Block{Type: certool.TITLE_CRT, Headers: make(map[string]string), Bytes: cert.Raw}
	buf := new(bytes.Buffer)
	err := pem.Encode(buf, certPem)
	return buf.Bytes(), err
}

func (self Cert) Hex() string { return hex.EncodeToString(self) }

func (self Csr) String() string  { return string(self) }
func (self Cert) String() string { return string(self) }
func (self Key) String() string  { return string(self) }

func LoadPem(fp string) (Pem, error) {
	return ioutil.ReadFile(fp)
}

func (self Pem) String() string { return string(self) }
func (self Pem) Bytes() []byte  { return self }

func (self Pem) WriteTo(fp string) error {
	d, _ := path.Split(fp)
	err := os.MkdirAll(d, 0755)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(fp, self, 0755)
}

func (self Pem) PaserKey(pwd string) (*ecdsa.PrivateKey, error) {
	data := self
	for {
		b, r := pem.Decode(data)
		if b == nil {
			return nil, errors.New("error pem format")
		}
		switch b.Type {
		case certool.TITLE_KEY:
			buf, err := x509.DecryptPEMBlock(b, []byte(pwd))
			if err != nil {
				return nil, err
			}
			return x509.ParseECPrivateKey(buf)
		default:
			data = r
		}
	}
	return nil, errors.New("error pem data")
}

func (self Pem) PaserCert() (*x509.Certificate, error) {
	data := self
	for data != nil && len(data) > 0 {
		b, r := pem.Decode(data)
		if b == nil {
			return nil, errors.New("error pem format")
		}
		switch b.Type {
		case certool.TITLE_CRT:
			return x509.ParseCertificate(b.Bytes)
		default:
			data = r
		}
	}
	return nil, errors.New("error pem data")
}

func (self Pem) PaserCsr() (*x509.CertificateRequest, error) {
	data := self
	for {
		b, r := pem.Decode(data)
		if b == nil {
			return nil, errors.New("error pem format")
		}
		switch b.Type {
		case certool.TITLE_CSR:
			return x509.ParseCertificateRequest(b.Bytes)
		default:
			data = r
		}
	}
	return nil, errors.New("error pem data")
}

func (self Pem) PaserCrl() (*pkix.CertificateList, error) {
	crlObj, err := x509.ParseCRL(self)
	if err != nil {
		return nil, err
	}
	return crlObj, nil
}

func (self Pem) ToSummary() *Summary {
	var s = new(Summary)
	if crt, err := self.PaserCert(); err == nil {
		s.Subject = newSubjectFn(crt.Subject, crt.EmailAddresses)
		s.Type = PT_CRT
		s.IsCA = crt.IsCA
		s.Id = BytesToID(crt.SerialNumber.Bytes())
		s.NotBefore = crt.NotBefore.Format("2006-01-02 15:04:05")
		s.NotAfter = crt.NotAfter.Format("2006-01-02 15:04:05")
		return s
	}
	if csr, err := self.PaserCsr(); err == nil {
		s.Subject = newSubjectFn(csr.Subject, csr.EmailAddresses)
		s.Type = PT_CSR
		s.Id = Csr(self).ToID()
	}
	return s
}

func verifyECS256Sign(pub *ecdsa.PublicKey, hash, sign []byte) error {
	return certool.VerifyECS256Sign(pub, hash, sign)
}

func EncryptAES(src []byte, key []byte) []byte {
	if key == nil || len(key) == 0 {
		key = []byte{0xff}
	}
	var (
		padding = func(src []byte, blocksize int) []byte {
			padnum := blocksize - len(src)%blocksize
			pad := bytes.Repeat([]byte{byte(padnum)}, padnum)
			return append(src, pad...)
		}
		sha256 = crypto.SHA256.New()
	)
	sha256.Write(key)
	key = sha256.Sum(nil)
	block, _ := aes.NewCipher(key)
	src = padding(src, block.BlockSize())
	iv := key[:block.BlockSize()]
	blockmode := cipher.NewCBCEncrypter(block, iv)
	blockmode.CryptBlocks(src, src)
	return src
}

func DecryptAES(src []byte, key []byte) []byte {
	if key == nil || len(key) == 0 {
		key = []byte{0xff}
	}
	var (
		unpadding = func(src []byte) []byte {
			n := len(src)
			unpadnum := int(src[n-1])
			return src[:n-unpadnum]
		}
		sha256 = crypto.SHA256.New()
	)
	sha256.Write(key)
	key = sha256.Sum(nil)
	block, _ := aes.NewCipher(key)
	iv := key[:block.BlockSize()]
	blockmode := cipher.NewCBCDecrypter(block, iv)
	blockmode.CryptBlocks(src, src)
	src = unpadding(src)
	return src
}

func DecryptAndRestore(pwd string, data []byte, outpath string) error {
	db := DecryptAES(data, []byte(pwd))
	gr, err := gzip.NewReader(bytes.NewReader(db))
	if err != nil {
		return errors.New("passwd or back-up file fail")
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
		err = os.MkdirAll(outpath, 0755)
		if err != nil {
			return err
		}
		fp := path.Join(outpath, hdr.Name)
		if hdr.FileInfo().IsDir() {
			fmt.Println(err, fp, hdr.FileInfo().IsDir())
			os.MkdirAll(fp, 0755)
			continue
		}

		file, err := os.Create(fp)
		if err != nil {
			return err
		}
		io.Copy(file, tr)
	}
	return nil
}

func EncryptAndBackup(pwd string, fpath string) ([]byte, error) {
	var (
		buf       = new(bytes.Buffer)
		gzwriter  = gzip.NewWriter(buf)
		tarwriter = tar.NewWriter(gzwriter)
		fileFn    = func(directory string, filesource string, sfileInfo os.FileInfo, tarwriter *tar.Writer) error {
			sfile, err := os.Open(filesource)
			if err != nil {
				panic(err)
				return err
			}
			defer sfile.Close()
			header, err := tar.FileInfoHeader(sfileInfo, "")
			if err != nil {
				fmt.Println(err)
				return err
			}
			header.Name = directory
			err = tarwriter.WriteHeader(header)
			if err != nil {
				fmt.Println(err)
				return err
			}
			if _, err = io.Copy(tarwriter, sfile); err != nil {
				fmt.Println(err)
				panic(err)
				return err
			}
			return nil
		}

		dirFn = func(directory string, tarwriter *tar.Writer) error {
			var baseFolder = filepath.Base(directory)
			return filepath.Walk(directory, func(targetpath string, file os.FileInfo, err error) error {
				if file == nil {
					panic(err)
					return err
				}
				if file.IsDir() {
					header, err := tar.FileInfoHeader(file, "")
					if err != nil {
						return err
					}
					header.Name = filepath.Join(baseFolder, strings.TrimPrefix(targetpath, directory))
					if err = tarwriter.WriteHeader(header); err != nil {
						return err
					}
					os.Mkdir(strings.TrimPrefix(baseFolder, file.Name()), os.ModeDir)
					return nil
				} else {
					var fileFolder = filepath.Join(baseFolder, strings.TrimPrefix(targetpath, directory))
					return fileFn(fileFolder, targetpath, file, tarwriter)
				}
			})
		}
		fi, err = os.Stat(fpath)
	)
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		dirFn(fpath, tarwriter)
	} else {
		fileFn("", fpath, fi, tarwriter)
	}
	err = tarwriter.Close()
	if err != nil {
		return nil, err
	}
	err = gzwriter.Close()
	if err != nil {
		return nil, err
	}
	return EncryptAES(buf.Bytes(), []byte(pwd)), nil
}

func PrintCert(certB Cert) {
	p := Pem(certB)
	cert, _ := p.PaserCert()

	fmt.Println("-------------------------------------------------------------------------------------")
	fmt.Println(" 证书摘要")
	fmt.Println("-------------------------------------------------------------------------------------")
	fmt.Println()
	fmt.Println("证书ID", hex.EncodeToString(cert.SerialNumber.Bytes()))
	fmt.Println("节点ID", cert.Subject.CommonName)
	fmt.Println("地区", cert.Subject.Country)
	fmt.Println("单位", cert.Subject.OrganizationalUnit)
	fmt.Println("组织", cert.Subject.Organization)
	fmt.Println("邮箱", cert.EmailAddresses)
	//fmt.Println("在此之前无效", cert.NotBefore)
	fmt.Println("有效期", cert.NotAfter)
	fmt.Println("签名算法", cert.SignatureAlgorithm.String())
	fmt.Println("是否根证书", cert.IsCA)
	fmt.Println()
	fmt.Println()
	fmt.Println("-------------------------------------------------------------------------------------")
	fmt.Println(" 公钥信息")
	fmt.Println("-------------------------------------------------------------------------------------")
	fmt.Println()
	fmt.Println("签名算法", cert.PublicKeyAlgorithm.String())
	pubkey := cert.PublicKey.(*ecdsa.PublicKey)
	pubkeyBuf := elliptic.Marshal(pubkey.Curve, pubkey.X, pubkey.Y)
	fmt.Println("公钥", hex.EncodeToString(pubkeyBuf))
	fmt.Println("签名", hex.EncodeToString(cert.Signature))
	fmt.Println()
	fmt.Println()
	fmt.Println("-------------------------------------------------------------------------------------")
	fmt.Println(" CA 摘要")
	fmt.Println("-------------------------------------------------------------------------------------")
	fmt.Println()
	fmt.Println("节点ID", cert.Issuer.CommonName)
	fmt.Println("地区", cert.Issuer.Country)
	fmt.Println("单位", cert.Issuer.OrganizationalUnit)
	fmt.Println("组织", cert.Issuer.Organization)
	fmt.Println()
	fmt.Println()
	fmt.Println("-------------------------------------------------------------------------------------")
	fmt.Println(" 证书原文")
	fmt.Println("-------------------------------------------------------------------------------------")
	fmt.Println()
	fmt.Println(string(certB))
	fmt.Println()
	fmt.Println()
}
