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
 * @Time   : 2019/11/28 11:59 上午
 * @Author : liangc
 *************************************************************************/

package ca

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/cc14514/go-alibp2p-ca/ldb"
	"github.com/cc14514/go-certool"
	"github.com/libp2p/go-libp2p-core/peer"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"testing"
)

var (
	datadir   = "/tmp/alibp2pca"
	alibp2pCA = NewAlibp2pCA(datadir)
	pwd       = "123456"
	fp        = path.Join(datadir, "rca.pem")
	nid, _    = peer.IDB58Decode("16Uiu2HAkzfSuviNuR7ez9BMkYw98YWNjyBNNmSLNnoX2XADfZGqP")
)

func initdb() {
	err := os.RemoveAll(datadir)
	fmt.Println("rmdir :", datadir, err)
	alibp2pCA = NewAlibp2pCA(datadir)
}

func TestAlibp2pCAImpl_GenRootCA(t *testing.T) {
	initdb()
	subj := certool.NewSubject(
		"CN",
		"rca.evertrust.ltd",
		"evertrust.ltd",
		nid,
		"cc14514@icloud.com")
	err := alibp2pCA.GenRootCA(pwd, subj)
	t.Log(err)
}

func TestAlibp2pCAImpl_GetCA(t *testing.T) {
	rca, err := alibp2pCA.GetCA(pwd)
	if err != nil {
		t.Error(err)
	}
	var s = new(Summary)
	s.Subject = newSubjectFn(rca.Cert.Subject, rca.Cert.EmailAddresses)
	s.Id = BytesToID(rca.Cert.SerialNumber.Bytes())
	s.IsCA = true
	s.Type = PT_CRT
	printJson(t, s.AsJson())
	t.Log(new(big.Int).SetBytes(s.Id.ToBytes()))
}

func TestAlibp2pCAImpl_ExportRootCA(t *testing.T) {
	p, err := alibp2pCA.ExportRootCA(pwd)
	if err != nil {
		t.Error(err)
	}
	crt, err := p.PaserCert()
	t.Log(err, crt.Subject, crt.EmailAddresses)
	key, err := p.PaserKey(pwd)
	t.Log(err, key)
	err = p.WriteTo(fp)
	t.Log(err)

}

func TestAlibp2pCAImpl_ImportRootCA(t *testing.T) {
	datadir = "/tmp/alibp2pca2"
	alibp2pCA = NewAlibp2pCA(datadir)
	p, err := LoadPem(fp)
	t.Log(err, len(p))
	err = alibp2pCA.ImportRootCA(pwd, p)
	t.Log(err)
	rca, err := alibp2pCA.GetCA(pwd)
	if err != nil {
		t.Error(err)
	}
	t.Log(rca.Cert.Subject, rca.Cert.EmailAddresses)
}

func TestAlibp2pCAImpl_GenCertByCsr(t *testing.T) {
	subj := certool.NewSubject(
		"CN",
		"ica1.evertrust.ltd",
		"evertrust.ltd",
		nid,
		"liangc@icloud.com")
	key, csr := alibp2pCA.GenKey(pwd, subj)
	t.Log(key)
	t.Log(csr)
	crt, err := alibp2pCA.GenCertByCsr(pwd, csr, true, 10)
	t.Log("GenCertByCsr-err", err)

	csrP := Pem(csr)
	csrObj, _ := csrP.PaserCsr()
	crtP := Pem(crt)
	crtObj, err := crtP.PaserCert()
	t.Log("Cert-err", err)
	t.Log("RCA:", crtObj.Issuer)
	t.Log("ICA-CSR", csrObj.Subject)
	t.Log("ICA:", crtObj.Subject)
}

func TestAlibp2pCAImpl_ListCert(t *testing.T) {
	sl := alibp2pCA.ListCert()
	for _, s := range sl {
		printJson(t, s.AsJson())
	}
}

func TestAlibp2pCAImpl_CsrHandler(t *testing.T) {
	subj := certool.NewSubject(
		"CN",
		"test.evertrust.ltd",
		"evertrust.ltd",
		nid,
		"test@icloud.com")
	_, csr := alibp2pCA.GenKey(pwd, subj)
	id, err := alibp2pCA.CsrHandler(csr)
	t.Log(err, id)
}

func TestAlibp2pCAImpl_ListCsr(t *testing.T) {
	sl := alibp2pCA.ListCsr()
	for _, s := range sl {
		printJson(t, s.AsJson())
	}
}

func TestAlibp2pCAImpl_AcceptCsr(t *testing.T) {
	sl := alibp2pCA.ListCsr()
	for _, s := range sl {
		crt, err := alibp2pCA.AcceptCsr(s.Id, 3, pwd)
		t.Log(err, crt)
	}
}

func TestAlibp2pCAImpl_RejectCsr(t *testing.T) {
	id := ID("08ba104b8886e32d0859e9f639a360160074c95f")
	csr, err := alibp2pCA.RejectCsr(id, "邮箱格式不对")
	t.Log(err, csr)
}

func TestAlibp2pCAImpl_CsrStatus(t *testing.T) {
	id := ID("08ba104b8886e32d0859e9f639a360160074c95f")
	s, err := alibp2pCA.CsrStatus(id)
	t.Log(err, s)
}

func TestAlibp2pCAImpl_UpdateKeychain(t *testing.T) {
	rca, _ := alibp2pCA.GetCA(pwd)
	crt, _ := ToCert(rca.Cert)
	err := alibp2pCA.UpdateKeychain(crt)
	t.Log("update-keychain", err)
}

func TestAlibp2pCAImpl_GetKeychain(t *testing.T) {
	kc := alibp2pCA.GetKeychain()
	j, err := kc.Serialize()
	t.Log(err, string(j))
}

func TestAlibp2pCAImpl_RevokeCert(t *testing.T) {
	rca, _ := alibp2pCA.GetCA(pwd)
	crt, _ := ToCert(rca.Cert)
	alibp2pCA.UpdateKeychain(crt)

	subj := certool.NewSubject(
		"CN",
		"ica1.evertrust.ltd",
		"evertrust.ltd",
		nid,
		"liangc@icloud.com")
	_, csr := alibp2pCA.GenKey(pwd, subj)

	crt2, _ := alibp2pCA.GenCertByCsr(pwd, csr, true, 10)
	crl, _ := alibp2pCA.RevokeCert(pwd, crt2)

	err := alibp2pCA.UpdateCRL(crl)
	t.Log("UpdateCRL", err, crl)
	err = alibp2pCA.IsRevokeCert(crt2)
	t.Log("IsRevoke", err)

}

func TestAlibp2pCAImpl_ListCRL(t *testing.T) {
	crls, _ := alibp2pCA.ListCRL()
	for _, crl := range crls {
		printJson(t, crl.AsJson())
	}
}

func printJson(t *testing.T, b []byte) {
	buf := new(bytes.Buffer)
	json.Indent(buf, b, "", "\t")
	t.Log(buf.String())
}

func TestFoobar(t *testing.T) {
	a := "6c6f636b2c3078313635454144646163643864363337613938303534363838466438433636653138343635413933452c30783536626337356532643633313030303030"
	b, err := hex.DecodeString(a)
	t.Log(err, string(b))
}

func TestAlibp2pCAImpl_Backup(t *testing.T) {
	bak, err := alibp2pCA.Backup(pwd)
	t.Log(err, len(bak))
	ioutil.WriteFile("/tmp/cadb.bak", bak, 0755)

	err = os.RemoveAll("/tmp/foobar")
	t.Log(err)
	err = alibp2pCA.Restore(pwd, bak, "/tmp/foobar")
	t.Log(err)
	db, err := ldb.NewLDBDatabase("/tmp/foobar/cadb", 100, 100)
	it := db.NewIterator()
	t.Log(err, it, db)
	for it.Next() {
		t.Log(string(it.Key()), len(it.Value()))
	}
}
