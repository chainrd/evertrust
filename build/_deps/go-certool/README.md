# go-certool

>这个库主要设计目标是用来在去中心网络中开发 CA 功能，
密钥使用 ECC 算法，不推荐也不支持 RSA 密钥；

## 接口 

* Keychain

>用来操作证书信任链，将业务系统中识别的 CA 全部添加到 keychain 对象中，keychain 可以序列化到磁盘上，主要用来验证证书是否合法

```go
type Keychain interface {
	Verify(cert *x509.Certificate) (chains [][]*x509.Certificate, err error)
	VerifyCRL(crl *pkix.CertificateList) error
	Serialize() ([]byte, error)
	AppendRoot(cert *x509.Certificate) error
	AppendIntermediate(cert *x509.Certificate) error
	Remove(cert *x509.Certificate) error
}
```

* Keytool

>用来生成根证书、中间证书、签发证书、撤销证书

```go
type Keytool interface {
	ParsePriv(buf, pwd []byte) (*ecdsa.PrivateKey, error)
	ParseCert(buf []byte) (interface{}, error)
	GenKey(pwd string) (privRaw, pubRaw []byte)
	GenCsr(subject *Subject, key *ecdsa.PrivateKey) (csrRaw []byte, err error)
	GenCert(ca *CA, user *User) (certRaw []byte, err error)
	RevokedCert(rca *x509.Certificate, rkey *ecdsa.PrivateKey, expiry time.Time, revoked ...*x509.Certificate) ([]byte, error)
}
```

## 例子

> 在 cmd/main.go 中提供了使用 certool 开发的 cmd 工具，提供如下功能: 



```bash
$> go build -o certool cmd/main.go
$> ./certool --help

NAME:
   ECC 证书工具

USAGE:
   main [global options] command [command options] [arguments...]

VERSION:
   0.0.1

AUTHOR:
   liangc <cc14514@icloud.com>

COMMANDS:
   gen-rca   创建根证书
   gen-ica   创建中间证书
   gen-cert  签发证书
   gen-key   创建 ECC 私钥
   show      查看证书信息
   verify    查看证书信息
   keychain  操作CA信任链
   help, h   Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --homedir value, -d value  home dir (default: "/tmp")
   --help, -h                 show help
   --version, -v              print the version
```