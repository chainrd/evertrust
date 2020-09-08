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
 * @Time   : 2019/11/27 1:46 下午
 * @Author : liangc
 *************************************************************************/

package certool

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"github.com/libp2p/go-libp2p-core/peer"
	"math/big"
	"sort"
)

const (
	TITLE_PUB = "ECC PUBLIC KEY"
	TITLE_KEY = "ECC PRIVATE KEY"
	TITLE_CSR = "CERTIFICATE REQUEST"
	TITLE_CRT = "CERTIFICATE"
)

type (
	Kid     string
	Subject struct {
		//Addr,
		Country,
		OrganizationalUnit,
		Organization,
		EmailAddress string // ECC S256K1 转成的 addr.hex, 例如: 0xeb0cea3a04a19d5533611c499fb735aa79fa1bdb
		CommonName peer.ID
	}

	CA struct {
		Priv *ecdsa.PrivateKey
		Cert *x509.Certificate
	}

	User struct {
		Subj   *Subject
		Pub    crypto.PublicKey         // 和 csr 二选一，csr 优先
		Csr    *x509.CertificateRequest // 和 Pub 二选一，csr 优先
		IsCA   bool                     // 是否签发为 CA 证书
		Expire int                      // 过期时间，单位:年
	}

	Keyobj struct {
		SerialNumber []byte
		Subject      *Subject
		Cert         []byte
	}

	KeychainImpl struct {
		RootHash             []byte // ECS256Sign
		Roots, Intermediates map[Kid]*Keyobj
	}

	ECCKeytool struct {
		pubTitle, keyTitle, csrTitle, certTitle string
		agl                                     x509.PEMCipher
		caKeyUsage, userKeyUsage                x509.KeyUsage
	}
	KeyobjList []*Keyobj
)

func (k KeyobjList) Len() int {
	return len(k)
}

func (k KeyobjList) Less(i, j int) bool {
	ii := new(big.Int).SetBytes(k[i].SerialNumber)
	jj := new(big.Int).SetBytes(k[j].SerialNumber)
	return ii.Cmp(jj) > 0
}

func (k KeyobjList) Swap(i, j int) {
	k[i], k[j] = k[j], k[i]
}

func (kl KeyobjList) Hash() []byte {
	if kl == nil || len(kl) == 0 {
		return nil
	}
	sort.Sort(kl)
	base := make([]byte, 0)
	for _, k := range kl {
		base = append(base, k.SerialNumber...)
	}
	sha256 := crypto.SHA1.New()
	sha256.Write(base)
	return sha256.Sum(nil)
}
