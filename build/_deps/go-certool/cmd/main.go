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
 * @Time   : 2019/11/21 5:32 下午
 * @Author : liangc
 *************************************************************************/

package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/cc14514/go-certool"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/urfave/cli"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
)

var keytool = certool.NewKeytool()

func main() {
	app := cli.NewApp()
	app.Name = os.Args[0]
	app.Usage = "ECC 证书工具"
	app.Version = "0.0.1"
	app.Author = "liangc"
	app.Email = "cc14514@icloud.com"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "homedir,d",
			Usage: "home dir",
			Value: "/tmp",
		},
	}
	app.Commands = []cli.Command{
		{
			Name:   "gen-rca",
			Usage:  "创建根证书",
			Action: genRCA,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "passwd,p",
					Usage: "私钥的密码",
				},
				cli.StringFlag{
					Name:  "key,k",
					Usage: "私钥, 不传则生成新的私钥",
				},
				cli.StringFlag{
					Name:  "out,o",
					Usage: "证书输出目录，默认会输出 root_ca.cert",
					Value: "./root_ca.cert",
				},
			},
		},
		{
			Name:   "gen-ica",
			Usage:  "创建中间证书",
			Action: genICA,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "passwd,p",
					Usage: "私钥的密码",
				},
				cli.StringFlag{
					Name:  "ipub,i",
					Usage: "公钥, 用来生成中间证书",
				},
				cli.StringFlag{
					Name:  "rca",
					Usage: "根证书",
				},
				cli.StringFlag{
					Name:  "rkey",
					Usage: "根私钥",
				},
				cli.StringFlag{
					Name:  "out,o",
					Usage: "证书输出目录，默认输出 i_ca.cert",
					Value: "./i_ca.cert",
				},
			},
		},
		{
			Name:   "gen-cert",
			Usage:  "签发证书",
			Action: genCert,
			/*
				pubP, csrP, rca = ctx.String("pub"), ctx.String("csr"), ctx.String("rca")
				pwd, rkey, output = ctx.String("passwd"), ctx.String("rkey"), ctx.String("out")
			*/
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "passwd,p",
					Usage: "私钥的密码",
				},
				cli.StringFlag{
					Name:  "csr,r",
					Usage: "要生成证书的请求证书, 跟 pub 二选一",
				},
				cli.StringFlag{
					Name:  "pub,i",
					Usage: "要生成证书的公钥, 跟 csr 二选一",
				},
				cli.StringFlag{
					Name:  "rca",
					Usage: "根证书",
				},
				cli.StringFlag{
					Name:  "rkey",
					Usage: "根私钥",
				},
				cli.StringFlag{
					Name:  "out,o",
					Usage: "证书输出目录，默认输出 ecc.cert",
					Value: "./ecc.cert",
				},
			},
		},

		{
			Name:   "gen-key",
			Usage:  "创建 ECC 私钥",
			Action: genKey,
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "nocsr,n",
					Usage: "顺便生成 csr",
				},
				cli.StringFlag{
					Name:  "passwd,p",
					Usage: "私钥的密码",
				},
				cli.StringFlag{
					Name:  "out,o",
					Usage: "私钥输出目录，会输出 ecc_key 和 ecc_key.pub",
					Value: "./",
				},
			},
		},
		{
			Name:   "show",
			Usage:  "查看证书信息",
			Action: show,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "c",
					Usage: "查看 cert 或 csr 内容",
				},
			},
		},

		{
			Name:   "verify",
			Usage:  "查看证书信息",
			Action: verifyCert,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "keychain,k",
					Usage: "使用 keychain 信任链来验证",
				},
				cli.StringFlag{
					Name:  "p",
					Usage: "使用 parent 证书来验证 cert",
				},
				cli.StringFlag{
					Name:  "c",
					Usage: "被验证的 cert 地址",
				},
			},
		},

		{
			Name:   "keychain",
			Usage:  "操作CA信任链",
			Action: keychain,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "src,s",
					Usage: "keychain.json 文件",
					Value: "./keychain.json",
				},
				cli.StringFlag{
					Name:  "action,a",
					Usage: "动作：add / del / list",
				},
				cli.StringFlag{
					Name:  "cert,c",
					Usage: "CA证书地址，添加到 KeychainImpl 上",
				},
			},
		},
	}

	app.Before = func(ctx *cli.Context) error {
		return nil
	}
	app.Action = func(ctx *cli.Context) error {
		return nil
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Println(err)
	}

}

func keychain(ctx *cli.Context) error {
	var (
		err    error
		kd     []byte
		src    = ctx.String("src")
		certP  = ctx.String("cert")
		action = ctx.String("action")
		listFn = func(kc *certool.KeychainImpl) error {
			data, err := kc.Serialize()
			if err != nil {
				return err
			}
			buf := new(bytes.Buffer)
			err = json.Indent(buf, data, "", "\t")
			if err != nil {
				return err
			}
			fmt.Print(buf.String())
			return nil
		}
		addOrDelFn = func(kc *certool.KeychainImpl, certP string, add bool) error {
			if certP == "" {
				return errors.New("cert not be nil")
			}
			cert, err := loadCert(certP)
			if err != nil {
				return err
			}
			if add {

				if cert.CheckSignatureFrom(cert) == nil {
					kc.AppendRoot(cert)
				} else {
					kc.AppendIntermediate(cert)
				}
			} else {
				kc.Remove(cert)
			}
			return nil
		}
	)
	if src != "" {
		kd, err = ioutil.ReadFile(src)
	}
	kc, err := certool.LoadKeychain(kd)
	if err != nil {
		return err
	}
	defer func() {
		data, err := kc.Serialize()
		if err == nil {
			ioutil.WriteFile(src, data, 0755)
			fmt.Println("success :", src)
		}
	}()
	switch action {
	case "add":
		return addOrDelFn(kc, certP, true)
	case "del":
		return addOrDelFn(kc, certP, false)
	case "list":
		return listFn(kc)
	}
	return nil
}

func loadCert(certpath string) (*x509.Certificate, error) {
	buf, err := ioutil.ReadFile(certpath)
	if err != nil {
		return nil, err
	}
	x, err := keytool.ParseCert(buf)
	if err != nil {
		return nil, err
	}
	cert, ok := x.(*x509.Certificate)
	if ok {
		return cert, nil
	}
	return nil, errors.New("error cert")
}

func loadCsr(certpath string) (*x509.CertificateRequest, error) {
	buf, err := ioutil.ReadFile(certpath)
	if err != nil {
		return nil, err
	}
	x, err := keytool.ParseCert(buf)
	if err != nil {
		return nil, err
	}
	csr, ok := x.(*x509.CertificateRequest)
	if ok {
		return csr, nil
	}
	return nil, errors.New("error cert")
}

func loadPriv(keypath, pwd string) (*ecdsa.PrivateKey, error) {
	buf, err := ioutil.ReadFile(keypath)
	if err != nil {
		return nil, err
	}
	return keytool.ParsePriv(buf, []byte(pwd))
}

func loadPub(pubpath string) (crypto.PublicKey, error) {
	buf, err := ioutil.ReadFile(pubpath)
	if err != nil {
		return nil, err
	}
	pb, _ := pem.Decode(buf)
	pub, _ := x509.ParsePKIXPublicKey(pb.Bytes)
	return pub, nil
}

func show(ctx *cli.Context) error {
	c := ctx.String("c")
	buf, err := ioutil.ReadFile(c)
	if err != nil {
		return err
	}
	x, err := keytool.ParseCert(buf)
	if err != nil {
		return err
	}
	if cert, ok := x.(*x509.Certificate); ok {
		printCert(cert)
	} else if csr, ok := x.(*x509.CertificateRequest); ok {
		printCsr(csr)
	}
	return nil
}

func genKey(ctx *cli.Context) error {
	var output, pwd string
	pwd = ctx.String("passwd")
	output = ctx.String("out")
	if pwd == "" {
		pwd = readarg("设置密码", "")
	}
	if output == "" {
		output = readarg("输出目录")
	}
	privRaw, pubRaw := keytool.GenKey(pwd)
	p1 := path.Join(output, "ecc_key")
	p2 := path.Join(output, "ecc_key.pub")
	err := ioutil.WriteFile(p1, privRaw, 0644)
	err = ioutil.WriteFile(p2, pubRaw, 0644)
	fmt.Println("-------------------------------------------------------------------")
	fmt.Println(" 私钥: " + p1)
	fmt.Println(" 公钥: " + p2)
	fmt.Println("-------------------------------------------------------------------")
	if !ctx.Bool("nocsr") {
		var country, organizationalUnit, organization, commonName, email string
		country = readarg("国家/地区")
		organizationalUnit = readarg("单位名称")
		organization = readarg("组织名称")
		email = readarg("电子邮箱")
		fmt.Println("-------------------------------------------------------------------")
		fmt.Println(" 签名主体为 '钱包/节点' 地址, ECS256 公钥的 IDB58 编码")
		fmt.Println(" 例如 : 16Uiu2HAkzfSuviNuR7ez9BMkYw98YWNjyBNNmSLNnoX2XADfZGqP")
		fmt.Println("-------------------------------------------------------------------")
		commonName = readarg("节点ID(IDB58格式)")
		key, _ := loadPriv(p1, pwd)
		pid, err := peer.IDB58Decode(commonName)
		if err != nil {
			panic(err)
		}
		subj := certool.NewSubject(country, organizationalUnit, organization, pid, email)
		csrRaw, err := keytool.GenCsr(subj, key)
		if err != nil {
			return err
		}
		p3 := path.Join(output, "ecc_key.csr")
		ioutil.WriteFile(p3, csrRaw, 0644)
		fmt.Println(" CSR: " + p3)
	}
	return err
}

func readarg(title string, opt ...interface{}) string {
	for {
		fmt.Print(title, ": ")
		ir := bufio.NewReader(os.Stdin)
		if cmd, err := ir.ReadString('\n'); err == nil && strings.Trim(cmd, " ") != "\n" {
			cmd = strings.Trim(cmd, " ")
			cmd = cmd[:len([]byte(cmd))-1]
			return cmd
		}
		if opt != nil {
			break
		}
		fmt.Println()
		fmt.Println(title + " 不能为空")
	}
	return ""
}

func genRCA(ctx *cli.Context) error {
	var (
		err                                                          error
		priv                                                         *ecdsa.PrivateKey
		output, key, pwd                                             string
		country, organizationalUnit, organization, commonName, email string
		expire                                                       = 1
	)
	pwd, key = ctx.String("passwd"), ctx.String("key")
	output = ctx.String("out")

	if key == "" {
		return errors.New("privkey can not nil")
	}

	priv, err = loadPriv(key, pwd)
	if err != nil {
		return err
	}

	country = readarg("国家/地区")
	organization = readarg("组织名称")
	organizationalUnit = readarg("单位名称")
	commonName = readarg("节点ID(IDB58格式)")
	email = readarg("电子邮箱")
	expire, err = strconv.Atoi(readarg("有效期(单位:年)"))
	if err != nil {
		return err
	}

	ca := certool.NewCA(priv, nil)
	pid, err := peer.IDB58Decode(commonName)
	if err != nil {
		panic(err)
	}
	subj := certool.NewSubject(country, organizationalUnit, organization, pid, email)
	user := certool.NewUser(subj, priv.Public(), nil, true, expire)
	cert, err := keytool.GenCert(ca, user)
	if err != nil {
		return err
	}
	fmt.Println("############ 根证书-创建成功 ##############\r\n")
	ioutil.WriteFile(output, cert, 0644)
	fmt.Println(" 证书: " + output)
	fmt.Println()
	return nil
}

func genICA(ctx *cli.Context) error {
	var (
		err                                                          error
		rootPriv                                                     *ecdsa.PrivateKey
		pub                                                          crypto.PublicKey
		output, rca, rkey, ipub, pwd                                 string
		country, organizationalUnit, organization, commonName, email string
		expire                                                       = 1
	)
	ipub, rca = ctx.String("ipub"), ctx.String("rca")
	pwd, rkey, output = ctx.String("passwd"), ctx.String("rkey"), ctx.String("out")

	if rkey == "" || rca == "" {
		return errors.New("rkey 、rca 必填")
	}

	rootCert, err := loadCert(rca)
	if err != nil {
		return err
	}

	rootPriv, err = loadPriv(rkey, pwd)
	if err != nil {
		return err
	}
	if ipub == "" {
		return errors.New("pub not be nil")
	}
	pub, err = loadPub(ipub)
	if err != nil {
		return err
	}

	country = readarg("国家/地区")
	organization = readarg("组织名称")
	organizationalUnit = readarg("单位名称")
	commonName = readarg("节点ID(IDB58格式)")
	email = readarg("电子邮箱")
	expire, err = strconv.Atoi(readarg("有效期(单位:年)"))
	if err != nil {
		return err
	}

	fmt.Println("############ 中间证书-创建成功 ##############\r\n")

	ca := certool.NewCA(rootPriv, rootCert)
	pid, err := peer.IDB58Decode(commonName)
	if err != nil {
		panic(err)
	}
	subj := certool.NewSubject(country, organizationalUnit, organization, pid, email)
	user := certool.NewUser(subj, pub, nil, true, expire)
	cert, err := keytool.GenCert(ca, user)
	if err != nil {
		return err
	}
	ioutil.WriteFile(output, cert, 0644)
	fmt.Println(" 证书: " + output)
	fmt.Println()
	return nil
}

// 签发证书
func genCert(ctx *cli.Context) error {
	var (
		err                                                          error
		rootPriv                                                     *ecdsa.PrivateKey
		pub                                                          crypto.PublicKey
		csr                                                          *x509.CertificateRequest
		output, rca, rkey, csrP, pubP, pwd                           string
		country, organizationalUnit, organization, commonName, email string
		expire                                                       = 1
	)
	pubP, csrP, rca = ctx.String("pub"), ctx.String("csr"), ctx.String("rca")
	pwd, rkey, output = ctx.String("passwd"), ctx.String("rkey"), ctx.String("out")

	if rkey == "" || rca == "" {
		return errors.New("rkey 、rca 必填")
	}

	rootCert, err := loadCert(rca)
	if err != nil {
		return err
	}

	rootPriv, err = loadPriv(rkey, pwd)
	if err != nil {
		return err
	}
	if pubP != "" {
		pub, err = loadPub(pubP)
		if err != nil {
			return err
		}
		country = readarg("国家/地区")
		organization = readarg("组织名称")
		organizationalUnit = readarg("单位名称")
		email = readarg("电子邮箱")
		fmt.Println("-------------------------------------------------------------------")
		fmt.Println(" 签名主体为 '钱包/节点' 地址, ECS256 公钥的 IDB58 编码")
		fmt.Println(" 例如 : 16Uiu2HAkzfSuviNuR7ez9BMkYw98YWNjyBNNmSLNnoX2XADfZGqP")
		fmt.Println("-------------------------------------------------------------------")
		commonName = readarg("节点ID(IDB58格式)")
	} else if csrP != "" {
		csr, err = loadCsr(csrP)
		if err != nil {
			return err
		}
	} else {
		return errors.New("pub / csr 二选一")
	}
	expire, err = strconv.Atoi(readarg("有效期(单位:年)"))
	if err != nil {
		return err
	}

	fmt.Println("############ 证书-创建成功 ##############\r\n")

	ca := certool.NewCA(rootPriv, rootCert)
	pid, err := peer.IDB58Decode(commonName)
	if err != nil {
		panic(err)
	}
	subj := certool.NewSubject(country, organizationalUnit, organization, pid, email)
	user := certool.NewUser(subj, pub, csr, false, expire)
	cert, err := keytool.GenCert(ca, user)
	ioutil.WriteFile(output, cert, 0644)
	fmt.Println(" 证书: " + output)
	fmt.Println()
	return nil
}

func verifyCert(ctx *cli.Context) error {
	parentP, certP := ctx.String("p"), ctx.String("c")
	keychainP := ctx.String("keychain")
	c, err := loadCert(certP)
	if err != nil {
		return err
	}
	if keychainP == "" {
		p, err := loadCert(parentP)
		if err != nil {
			return err
		}
		err = c.CheckSignatureFrom(p)
		if err != nil {
			fmt.Println("验证失败 : ", err)
		} else {
			fmt.Println("验证成功")
		}
	} else {
		kd, err := ioutil.ReadFile(keychainP)
		if err != nil {
			return err
		}
		kc, err := certool.LoadKeychain(kd)
		if err != nil {
			return err
		}
		chain, err := kc.Verify(c)
		if err != nil {
			return err
		}
		fmt.Println("验证通过")
		fmt.Println(chain)
	}
	return nil
}

func printCert(cert *x509.Certificate) {
	fmt.Println("######## 证书原文 ##########")
	certPem := &pem.Block{Type: "CERTIFICATE", Headers: make(map[string]string), Bytes: cert.Raw}
	buf := new(bytes.Buffer)
	pem.Encode(buf, certPem)
	fmt.Println(buf.String())

	fmt.Println("######## 主题名称 ##########")
	fmt.Println("国家地区", cert.Subject.Country)
	fmt.Println("组织单位", cert.Subject.OrganizationalUnit)
	fmt.Println("组织", cert.Subject.Organization)
	fmt.Println("电子邮箱", cert.EmailAddresses)
	fmt.Println("签名主体", cert.Subject.CommonName)
	fmt.Println()
	fmt.Println("######## 签发者名称 ########")
	fmt.Println("国家地区", cert.Issuer.Country)
	fmt.Println("组织单位", cert.Issuer.OrganizationalUnit)
	fmt.Println("组织", cert.Issuer.Organization)
	fmt.Println("常用名", cert.Issuer.CommonName)
	fmt.Println("序列号", cert.SerialNumber)
	fmt.Println("签名算法", cert.SignatureAlgorithm.String())
	fmt.Println("在此之前无效", cert.NotBefore)
	fmt.Println("在此之后无效", cert.NotAfter)
	fmt.Println()

	fmt.Println("######## 公共密钥 ##########")
	fmt.Println("签名算法", cert.PublicKeyAlgorithm.String())
	pubkey := cert.PublicKey.(*ecdsa.PublicKey)
	pubkeyBuf := elliptic.Marshal(pubkey.Curve, pubkey.X, pubkey.Y)
	fmt.Println("公共密钥", hex.EncodeToString(pubkeyBuf))
	fmt.Println("签名", hex.EncodeToString(cert.Signature))
	fmt.Println("根证书", cert.IsCA)
	fmt.Println()
}

func printCsr(csr *x509.CertificateRequest) {
	fmt.Println("######## CSR 原文 ##########")
	certPem := &pem.Block{Type: "CERTIFICATE REQUEST", Headers: make(map[string]string), Bytes: csr.Raw}
	buf := new(bytes.Buffer)
	pem.Encode(buf, certPem)
	fmt.Println(buf.String())

	fmt.Println("######## 主题名称 ##########")
	fmt.Println("国家地区", csr.Subject.Country)
	fmt.Println("组织单位", csr.Subject.OrganizationalUnit)
	fmt.Println("组织", csr.Subject.Organization)
	fmt.Println("电子邮箱", csr.EmailAddresses)
	fmt.Println("签名主体", csr.Subject.CommonName)
	fmt.Println()

	fmt.Println("######## 公共密钥 ##########")
	fmt.Println("签名算法", csr.PublicKeyAlgorithm.String())
	pubkey := csr.PublicKey.(*ecdsa.PublicKey)
	pubkeyBuf := elliptic.Marshal(pubkey.Curve, pubkey.X, pubkey.Y)
	fmt.Println("公共密钥", hex.EncodeToString(pubkeyBuf))
	fmt.Println("签名", hex.EncodeToString(csr.Signature))
	fmt.Println()
}
