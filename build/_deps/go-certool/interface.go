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
 * @Time   : 2019/11/28 9:35 上午
 * @Author : liangc
 *************************************************************************/

package certool

import (
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

type Keychain interface {
	Verify(cert *x509.Certificate) (chains [][]*x509.Certificate, err error)
	VerifyCRL(crl *pkix.CertificateList) (*x509.Certificate, error)
	Serialize() ([]byte, error)
	AppendRoot(cert *x509.Certificate) error
	AppendIntermediate(cert *x509.Certificate) error
	Remove(cert *x509.Certificate) error
	GetAll() KeyobjList
	Hash() []byte
}

type Keytool interface {
	ParsePriv(buf, pwd []byte) (*ecdsa.PrivateKey, error)
	ParseCert(buf []byte) (interface{}, error)
	GenKey(pwd string) (privRaw, pubRaw []byte)
	GenCsr(subject *Subject, key *ecdsa.PrivateKey) (csrRaw []byte, err error)
	GenCert(ca *CA, user *User) (certRaw []byte, err error)
	RevokedCert(rca *x509.Certificate, rkey *ecdsa.PrivateKey, expiry time.Time, certs ...*x509.Certificate) ([]byte, error)
	RevokedCertBySerialNumber(rca *x509.Certificate, rkey *ecdsa.PrivateKey, expiry time.Time, serialNumbers ...*big.Int) ([]byte, error)
}
