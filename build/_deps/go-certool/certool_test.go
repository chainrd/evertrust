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
 * @Time   : 2019/11/20 3:31 下午
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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/satori/go.uuid"
	"math/big"
	"testing"
	"time"
)

// 一个标准的 CSR 文件, BASE64 编码, PEM 都是这种编码格式
var (
	kt     = NewKeytool()
	csrStr = `-----BEGIN CERTIFICATE REQUEST-----
MIICujCCAaICAQAwdTELMAkGA1UEBhMCY24xCzAJBgNVBAgMAnBuMQswCQYDVQQH
DAJsbjELMAkGA1UECgwCb24xDDAKBgNVBAsMA291bjEQMA4GA1UEAwwHY29tbW9u
bjEfMB0GCSqGSIb3DQEJARYQY2MxNDUxNEBtYWlsLmNvbTCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAO4dKIB7tMXaJNsPwBGR4B54XPKxKBqKK2Z1p/8I
qdlPOc6aobM+PDdvwJNcjaBUV70UcnMDy8AMzsZbadmM56ioHkbPMN0MQR+q2rM8
g6A7/HyC2LH0gtbqXZpcC5KIG+aGf9EQoetT8IBttvfTJtGi5zTJpeUB1OSMzayY
qcJqngVb6v66hCJOziZeSgFkqyYrX1zvzYSw+vwdDiu9p2neTh37rQ3txWZJxrn3
RvfTFn6FRbHqI+zCQyIBTkpNodZacqBIC68A288prutdJ9fQs9mj3OVKTZyWsNAy
Me7l4Nd9QMECmiwTuk+fKrvIMJBHNZK9BTN0qTt4Te9MXnsCAwEAAaAAMA0GCSqG
SIb3DQEBCwUAA4IBAQA8JzLyED8dFPomPlE8WzyUlNEk8vxPo2fcnDedzPzZG/kf
nEUmxLb1GLPnC2c5LlUtD6pwc61CID+P6qs1pBIsBsqJ+S0PAwUE9XQ68N+iIOPA
6OZC/1xlqylWaikN2JbWk5obLDE7NhZ2zg6Jg5NpfTgBT/IHiYXlDL80nxS7VpJT
shqzsqLVPGk93dKdzRrNT1Yk01vyoY9Yu5UDGxvrOVs5TUas2jUQRLkQviGQA73F
3imKv92yQN9Hsa0q3T1U3SqUP4rT2teCZnk8ovoInTjIkeTCggUhxCUTMWLpjVBA
QoSDnmDQgX0eT6jJAX87NLX3n0FEc96pFNpkMnEI
-----END CERTIFICATE REQUEST-----
`

	rKey = `-----BEGIN ECC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,d6a62848820ded279a1a378fbefaf7fd
        
gFUBWsrklx5ZiNoyGSP/1VL6kUteOAoeEaANv0NjfsoFLdx8Gcv3iHjTes+bn+dy
Nkasx7j+9OGS0MT05HcNU7rl8GOYUjj0SJgJGZyghqAnwL5nOCjhmY/RnnHJQfmT
n5C1nVW/M0SFUrPAcPmCFaDl2tPqySMMdvIIkWeLDNI=
-----END ECC PRIVATE KEY-----
`

	rCrt = `-----BEGIN CERTIFICATE-----
MIIBvDCCAWOgAwIBAgIQe1E2nSDgTHvulhe9X/keETAKBggqhkjOPQQDAjBOMQww
CgYDVQQLEwNwZHgxPjA8BgNVBAMTNTE2VWl1MkhBa3pmU3V2aU51UjdlejlCTWtZ
dzk4WVdOanlCTk5tU0xObm9YMlhBRGZaR3FQMB4XDTE5MTIxMDA0MDIwNloXDTIw
MTIwOTA0MDIwNlowTjEMMAoGA1UECxMDcGR4MT4wPAYDVQQDEzUxNlVpdTJIQWt6
ZlN1dmlOdVI3ZXo5Qk1rWXc5OFlXTmp5Qk5ObVNMTm5vWDJYQURmWkdxUDBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABMZulPEPymhI/Dccgxf4m0ceEkR0nScjsOuw
8WhtQRRFgivQnFjc8I/w2IOOoMWkdrkKe/OJKtnVMewVJs87HbqjIzAhMA4GA1Ud
DwEB/wQEAwIBFjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIGof
UEDJqoqKTJ8q6tbObl/DpmPUaCDcu27187EjGknvAiAq0ZAuZLREA4/5iSThIoEj
WwxdEf0HaeDNgiRNqYcSBw==
-----END CERTIFICATE-----
`

	iKey = `-----BEGIN ECC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,ec01478108f7c79c36c2d2fc108af276

hV64jxJBOZtOnQqIxDs3DooF7Wy7EqRPgcgNWMr//FjptC6x9ruYat9AqWeBvNt5
LPtJ9UfSTqVKcRYPCggvOsKHBD1F9lAT4EfY85J5XF+7neK5l1IGk/jzVIAQv0I9
tX5AZ6ERF5Pi3Jlur/NLpy5GTBJor5pkPzgUCuOPElU=
-----END ECC PRIVATE KEY-----
`

	iCrt = `-----BEGIN CERTIFICATE-----
MIIBwzCCAWmgAwIBAgIRAOYp9r3Qi9vKxYRGLSE9ZzIwCgYIKoZIzj0EAwIwTjEM
MAoGA1UECxMDcGR4MT4wPAYDVQQDEzUxNlVpdTJIQWt6ZlN1dmlOdVI3ZXo5Qk1r
WXc5OFlXTmp5Qk5ObVNMTm5vWDJYQURmWkdxUDAeFw0xOTEyMTAwNDAzNTVaFw0y
MDEyMDkwNDAzNTVaMFMxETAPBgNVBAoTCGljYTEucGR4MT4wPAYDVQQDEzUxNlVp
dTJIQW05bzM3WXdCclVFTHUycXAzaUhiOHhNQ3B3SGp3UTQxM3NCUDlLZFN6TFZq
RTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOXOmBaFuuHG8k0O8kdb2skvE2qP
qniolWeRFQkIAY2RfZ5m+DV7hfPr9pY3sgZWEzBpb5HwWuiT77xL0KQFk9CjIzAh
MA4GA1UdDwEB/wQEAwIBFjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gA
MEUCIQCH+k1X357V4R4938Mxj7E/eds3Cbq4/Nx3rOAGl/5VjQIgaTTerB6256jW
CFciagpJAN9ukkVTW3yKMEIRFLMJIe4=
-----END CERTIFICATE-----
`

	cas = `{
        	"RootHash": "SJekUuKNfEOSZDEStCNeRAiOeW0=",
        	"Roots": {
        		"b80c90dee84b828ab646c4d7b5d13f547799b6b8": {
        			"SerialNumber": "e1E2nSDgTHvulhe9X/keEQ==",
        			"Subject": {
        				"Country": "",
        				"OrganizationalUnit": "CRD",
        				"Organization": "",
        				"EmailAddress": "",
        				"CommonName": "16Uiu2HAkzfSuviNuR7ez9BMkYw98YWNjyBNNmSLNnoX2XADfZGqP"
        			},
        			"Cert": "MIIBvDCCAWOgAwIBAgIQe1E2nSDgTHvulhe9X/keETAKBggqhkjOPQQDAjBOMQwwCgYDVQQLEwNwZHgxPjA8BgNVBAMTNTE2VWl1MkhBa3pmU3V2aU51UjdlejlCTWtZdzk4WVdOanlCTk5tU0xObm9YMlhBRGZaR3FQMB4XDTE5MTIxMDA0MDIwNloXDTIwMTIwOTA0MDIwNlowTjEMMAoGA1UECxMDcGR4MT4wPAYDVQQDEzUxNlVpdTJIQWt6ZlN1dmlOdVI3ZXo5Qk1rWXc5OFlXTmp5Qk5ObVNMTm5vWDJYQURmWkdxUDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMZulPEPymhI/Dccgxf4m0ceEkR0nScjsOuw8WhtQRRFgivQnFjc8I/w2IOOoMWkdrkKe/OJKtnVMewVJs87HbqjIzAhMA4GA1UdDwEB/wQEAwIBFjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIGofUEDJqoqKTJ8q6tbObl/DpmPUaCDcu27187EjGknvAiAq0ZAuZLREA4/5iSThIoEjWwxdEf0HaeDNgiRNqYcSBw=="
        		}
        	},
        	"Intermediates": {
        		"c57fbf4794e2ab6f5d27dfa1841e24a2d3cb847f": {
        			"SerialNumber": "5in2vdCL28rFhEYtIT1nMg==",
        			"Subject": {
        				"Country": "",
        				"OrganizationalUnit": "",
        				"Organization": "ica1.CRD",
        				"EmailAddress": "",
        				"CommonName": "16Uiu2HAm9o37YwBrUELu2qp3iHb8xMCpwHjwQ413sBP9KdSzLVjE"
        			},
        			"Cert": "MIIBwzCCAWmgAwIBAgIRAOYp9r3Qi9vKxYRGLSE9ZzIwCgYIKoZIzj0EAwIwTjEMMAoGA1UECxMDcGR4MT4wPAYDVQQDEzUxNlVpdTJIQWt6ZlN1dmlOdVI3ZXo5Qk1rWXc5OFlXTmp5Qk5ObVNMTm5vWDJYQURmWkdxUDAeFw0xOTEyMTAwNDAzNTVaFw0yMDEyMDkwNDAzNTVaMFMxETAPBgNVBAoTCGljYTEucGR4MT4wPAYDVQQDEzUxNlVpdTJIQW05bzM3WXdCclVFTHUycXAzaUhiOHhNQ3B3SGp3UTQxM3NCUDlLZFN6TFZqRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOXOmBaFuuHG8k0O8kdb2skvE2qPqniolWeRFQkIAY2RfZ5m+DV7hfPr9pY3sgZWEzBpb5HwWuiT77xL0KQFk9CjIzAhMA4GA1UdDwEB/wQEAwIBFjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCH+k1X357V4R4938Mxj7E/eds3Cbq4/Nx3rOAGl/5VjQIgaTTerB6256jWCFciagpJAN9ukkVTW3yKMEIRFLMJIe4="
        		}
        	}
        }`

	testCert = `
-----BEGIN CERTIFICATE-----
MIIB2jCCAX+gAwIBAgIRAKxZlfHFeAsh5/SJqTkc5WcwCgYIKoZIzj0EAwIwTDEL
MAkGA1UEBhMCQ04xHjAcBgNVBAoTFXBkeCB1dG9waWEgYmxvY2tjaGFpbjEMMAoG
A1UECxMDcGR4MQ8wDQYDVQQDEwZ1dG9waWEwHhcNMTkxMTIyMTExMTEwWhcNMjkx
MTE5MTExMTEwWjBFMQswCQYDVQQGEwJDTjEPMA0GA1UEChMGdXRpcGlhMRAwDgYD
VQQLEwdwZHguY29tMRMwEQYDVQQDEwpoZWxsb3dvcmxkMFkwEwYHKoZIzj0CAQYI
KoZIzj0DAQcDQgAEQc20CqH6WfIMK01n7lP+oVdM8C+skmYKwE34VAW7hf8dMo8C
lNJKPWlWPM1Kzi0vcpjMGUIV1Yzt5kcH+M0kXaNJMEcwDgYDVR0PAQH/BAQDAgSw
MDUGA1UdEQQuMCyCKjB4ZWIwY2VhM2EwNGExOWQ1NTMzNjExYzQ5OWZiNzM1YWE3
OWZhMWJkYjAKBggqhkjOPQQDAgNJADBGAiEA6j6zRVzc32XSrb64osSd/aQ2tHor
PRwcFWmgl7jlDAkCIQCEkoLOluGydsETRgubVmviWl8haXsGdFfXtJsu4QdJgw==
-----END CERTIFICATE-----
`
)

func ca(k, c string) (priv *ecdsa.PrivateKey, crt *x509.Certificate) {
	rootPem, _ := pem.Decode([]byte(k))
	privBuf, _ := x509.DecryptPEMBlock(rootPem, pwd)
	priv, _ = x509.ParseECPrivateKey(privBuf)
	rootCrtPem, _ := pem.Decode([]byte(c))
	crt, _ = x509.ParseCertificate(rootCrtPem.Bytes)

	txt := base64.StdEncoding.EncodeToString(rootCrtPem.Bytes)
	fmt.Println("cert-txt :", txt)
	return
}

func TestCa(t *testing.T) {
	ca(rKey, rCrt)
	ca(iKey, iCrt)
}

func TestCsrDecodeAndEncode(t *testing.T) {
	// 解析 base64 编码的 csr
	pemBlock, _ := pem.Decode([]byte(csrStr))
	csr, _ := x509.ParseCertificateRequest(pemBlock.Bytes)
	t.Log(csr.Subject)
	t.Log(len(csr.Raw), len(pemBlock.Bytes))

	// 序列化 csr
	pemBlock.Type = "CERTIFICATE REQUEST"
	pemBlock.Headers = make(map[string]string)
	buf := new(bytes.Buffer)
	err := pem.Encode(buf, pemBlock)
	t.Log(err)
	t.Log(buf.String())

	// 断言
	t.Log(csrStr == buf.String())
}

var pwd = []byte("123456")

// 根证书
func TestRCA(t *testing.T) {
	// 生成 ECDSA 密钥
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bpriv, _ := x509.MarshalECPrivateKey(priv)

	// 生成 PEM 证书
	pemBlock, _ := x509.EncryptPEMBlock(rand.Reader, "ECC PRIVATE KEY", bpriv, pwd, x509.PEMCipherAES128)
	buf := new(bytes.Buffer)
	pem.Encode(buf, pemBlock)
	t.Log(buf.String())

	// 生成 CRT
	var serialBytes [16]byte
	rand.Read(serialBytes[:])
	ca := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serialBytes[:]),
		Subject: pkix.Name{
			OrganizationalUnit: []string{"CRD"},
			CommonName:         "16Uiu2HAkzfSuviNuR7ez9BMkYw98YWNjyBNNmSLNnoX2XADfZGqP",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDataEncipherment,
		BasicConstraintsValid: true,
		IsCA: true,
	}
	cert, _ := x509.CreateCertificate(rand.Reader, ca, ca, priv.Public(), priv)
	certPem := &pem.Block{Type: "CERTIFICATE", Headers: make(map[string]string), Bytes: cert}
	buf = new(bytes.Buffer)
	pem.Encode(buf, certPem)
	t.Log(buf.String())

}

// 中间证书
func TestICA(t *testing.T) {
	// 生成 ECDSA 密钥
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bpriv, _ := x509.MarshalECPrivateKey(priv)

	// 生成 PEM 证书
	pemBlock, _ := x509.EncryptPEMBlock(rand.Reader, "ECC PRIVATE KEY", bpriv, pwd, x509.PEMCipherAES128)
	buf := new(bytes.Buffer)
	pem.Encode(buf, pemBlock)
	fmt.Println(buf.String())

	// 生成 CSR
	/*
		csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName:   "ica1.CRD",
				Organization: []string{"ica1.CRD"},
			},
			SignatureAlgorithm: x509.ECDSAWithSHA256,
			EmailAddresses:     []string{"cc14514@icloud.com"},
		}, priv)

		csr, _ := x509.ParseCertificateRequest(csrBytes)

		csrPem := &pem.Block{Type: "CERTIFICATE REQUEST", Headers: make(map[string]string), Bytes: csr.Raw}
		buf = new(bytes.Buffer)
		pem.Encode(buf, csrPem)

		fmt.Println(buf.String())
	*/

	// 生成 CRT
	var serialBytes [16]byte
	rand.Read(serialBytes[:])
	template := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(serialBytes[:]),
		Subject: pkix.Name{
			CommonName:   "16Uiu2HAm9o37YwBrUELu2qp3iHb8xMCpwHjwQ413sBP9KdSzLVjE",
			Organization: []string{"ica1.CRD"},
		},

		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDataEncipherment,
		BasicConstraintsValid: true,
		IsCA: true,
	}
	rk, rca := ca(rKey, rCrt)
	cert, _ := x509.CreateCertificate(rand.Reader, template, rca, priv.Public(), rk)
	certPem := &pem.Block{Type: "CERTIFICATE", Headers: make(map[string]string), Bytes: cert}
	buf = new(bytes.Buffer)
	pem.Encode(buf, certPem)
	fmt.Println(buf.String())

	myCert, err := x509.ParseCertificate(cert)
	err = myCert.CheckSignatureFrom(rca)
	t.Log(err, myCert.PublicKeyAlgorithm, rca.PublicKeyAlgorithm)
}

// 签发证书
func TestCrt(t *testing.T) {
	// 生成 ECDSA 密钥
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bpriv, _ := x509.MarshalECPrivateKey(priv)

	// 生成 PEM
	pemBlock, _ := x509.EncryptPEMBlock(rand.Reader, "ECC PRIVATE KEY", bpriv, pwd, x509.PEMCipherAES128)
	buf := new(bytes.Buffer)
	pem.Encode(buf, pemBlock)

	t.Log(buf.String())

	// 生成 CSR
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "16Uiu2HAm7Kuq3xsiyw2yxxbz5Fstqjoq2AzTYe3zL6k9LD35GY24",
			Organization: []string{"org1.CRD.com"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		EmailAddresses:     []string{"cc14514@icloud.com"},
	}, priv)

	csr, _ := x509.ParseCertificateRequest(csrBytes)
	t.Log("Email =", csr.EmailAddresses)

	csrPem := &pem.Block{Type: "CERTIFICATE REQUEST", Headers: make(map[string]string), Bytes: csr.Raw}
	buf = new(bytes.Buffer)
	pem.Encode(buf, csrPem)

	t.Log(buf.String())

	// 生成 CRT
	var serialBytes [16]byte
	rand.Read(serialBytes[:])
	template := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serialBytes[:]),
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageDataEncipherment,
		BasicConstraintsValid: false,
		IsCA:           false,
		EmailAddresses: csr.EmailAddresses,
	}
	_, rca := ca(rKey, rCrt)
	ik, ica := ca(iKey, iCrt)
	cert, _ := x509.CreateCertificate(rand.Reader, template, ica, csr.PublicKey, ik)
	certPem := &pem.Block{Type: "CERTIFICATE", Headers: make(map[string]string), Bytes: cert}
	buf = new(bytes.Buffer)
	pem.Encode(buf, certPem)
	t.Log(buf.String())

	// Test Revoke

	//certStr := base64.StdEncoding.EncodeToString(cert)

	// ====================================== 验证 ===================================

	// 验证
	myCert, err := x509.ParseCertificate(cert)
	err = myCert.CheckSignatureFrom(ica)
	t.Log(err, myCert.PublicKeyAlgorithm, rca.PublicKeyAlgorithm, ica.PublicKeyAlgorithm, myCert.DNSNames)

	// 信任链验证

	// 信任链
	opts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
		CurrentTime:   time.Now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	opts.Roots.AppendCertsFromPEM([]byte(rCrt))
	opts.Intermediates.AppendCertsFromPEM([]byte(iCrt))

	// 验证
	ccs, err := myCert.Verify(opts)
	t.Log("verify-result", err, ccs)
	for i, cs := range ccs {
		for j, c := range cs {
			t.Log(i, j, c.Subject, "==============", c.EmailAddresses)
		}
	}

}

func TestDecode(t *testing.T) {
	/*
		-----BEGIN CERTIFICATE-----
		MIIBeTCCASCgAwIBAgIRAMLvgOkOP/ju+94lraH+2J0wCgYIKoZIzj0EAwIwJjER
		MA8GA1UEChMIaWNhMS5wZHgxETAPBgNVBAMTCGljYTEucGR4MB4XDTE5MTEyMTA1
		NDcxNFoXDTIwMTEyMDA1NDcxNFowQzEVMBMGA1UEChMMb3JnMS5wZHguY29tMRYw
		FAYDVQQDEw1zMjU2azEtcHVia2V5MRIwEAYDVQQFEwlzMjU2azEtaWQwWTATBgcq
		hkjOPQIBBggqhkjOPQMBBwNCAATbdWFVA/toU4b+4GsEp4wyXpjnkPEZ5n0y3Ee5
		zgb/rtlFTr0kffH7O4Msrywd+RFddT4lAwB5dUVsaG85IHk0oxIwEDAOBgNVHQ8B
		Af8EBAMCBJAwCgYIKoZIzj0EAwIDRwAwRAIgGjI3+t9B1rFb2nlcLv/EnfGmGYW+
		9l/5MDlRL3lS4Q4CICGafkYV4uIDTQEgJ0LT9AtyYgyJ5LO0sPeAbRnn/qtD
		-----END CERTIFICATE-----
	*/
	certStr := "MIIBeTCCASCgAwIBAgIRAMLvgOkOP/ju+94lraH+2J0wCgYIKoZIzj0EAwIwJjERMA8GA1UEChMIaWNhMS5wZHgxETAPBgNVBAMTCGljYTEucGR4MB4XDTE5MTEyMTA1NDcxNFoXDTIwMTEyMDA1NDcxNFowQzEVMBMGA1UEChMMb3JnMS5wZHguY29tMRYwFAYDVQQDEw1zMjU2azEtcHVia2V5MRIwEAYDVQQFEwlzMjU2azEtaWQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATbdWFVA/toU4b+4GsEp4wyXpjnkPEZ5n0y3Ee5zgb/rtlFTr0kffH7O4Msrywd+RFddT4lAwB5dUVsaG85IHk0oxIwEDAOBgNVHQ8BAf8EBAMCBJAwCgYIKoZIzj0EAwIDRwAwRAIgGjI3+t9B1rFb2nlcLv/EnfGmGYW+9l/5MDlRL3lS4Q4CICGafkYV4uIDTQEgJ0LT9AtyYgyJ5LO0sPeAbRnn/qtD"
	certBytes, _ := base64.StdEncoding.DecodeString(certStr)
	cert, _ := x509.ParseCertificate(certBytes)
	_, ica := ca(iKey, iCrt)
	t.Log(cert.CheckSignatureFrom(ica))
}

func TestKey(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubBuf, err := x509.MarshalPKIXPublicKey(priv.Public())
	t.Log(err, pubBuf)
	b := &pem.Block{}
	b.Headers = make(map[string]string)
	b.Type = "ECC PUBLIC KEY"
	b.Bytes = pubBuf
	t.Log(b)
	//x509.ParsePKIXPublicKey()
	buf := new(bytes.Buffer)
	pem.Encode(buf, b)
	t.Log(buf.String())

	pubBytes := buf.Bytes()
	pb, r := pem.Decode(pubBytes)
	t.Log(pb, r)

	pub2, _ := x509.ParsePKIXPublicKey(pb.Bytes)
	t.Log(priv.Public())
	t.Log(pub2.(crypto.PublicKey))
}

func TestLoadKeychain(t *testing.T) {
	kc, err := LoadKeychain([]byte(cas))
	t.Log("load", err, kc)
	ic, _ := kt.ParseCert([]byte(iCrt))
	rc, _ := kt.ParseCert([]byte(rCrt))
	err = kc.AppendIntermediate(ic.(*x509.Certificate))
	t.Log(err)
	err = kc.AppendRoot(rc.(*x509.Certificate))
	t.Log(err)
	data, err := kc.Serialize()
	var out bytes.Buffer
	json.Indent(&out, data, "", "\t")
	t.Log(out.String())
	c, err := kc.Verify(ic.(*x509.Certificate))
	t.Log("verifyed", err, c)
	t.Log("hash", kc.Hash())

}

func TestCRL(t *testing.T) {
	kc, _ := LoadKeychain(nil)
	ic, _ := kt.ParseCert([]byte(iCrt))
	rc, _ := kt.ParseCert([]byte(rCrt))
	kc.AppendIntermediate(ic.(*x509.Certificate))
	kc.AppendRoot(rc.(*x509.Certificate))
	rca, _ := kt.ParseCert([]byte(rCrt))
	rkey, _ := kt.ParsePriv([]byte(rKey), pwd)
	ca := rca.(*x509.Certificate)
	tCrt, _ := kt.ParseCert([]byte(testCert))
	crl, err := kt.RevokedCert(ca, rkey, time.Now(), tCrt.(*x509.Certificate))
	t.Log("crl", err, crl)
	crlObj, _ := x509.ParseCRL(crl)
	err = kc.VerifyCRL(crlObj)
	t.Log("verify", err)
}

func TestRandID(t *testing.T) {
	t.Log(new(big.Int).SetBytes(uuid.NewV4().Bytes()))
	id, err := peer.IDB58Decode("16Uiu2HAkzfSuviNuR7ez9BMkYw98YWNjyBNNmSLNnoX2XADfZGqP")
	t.Log(err, id.Pretty())
}

func TestFoobar(t *testing.T) {
	fmt.Println("")
	fmt.Print("Hello world.")
}
