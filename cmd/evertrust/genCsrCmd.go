package main

import (
	"fmt"
	"gopkg.in/urfave/cli.v1"
	"io/ioutil"
	"os/exec"
	"CRD-chain/accounts/keystore"
	"CRD-chain/cmd/utils"
	"CRD-chain/crypto"
	"strings"
)

var genCsrCommand = cli.Command{
	Action:    utils.MigrateFlags(genCsr),
	Name:      "gencsr",
	Usage:     "generate csr file associated with mine account",
	ArgsUsage: "./evertrust genCsr --keystoreFile [keystore file path] --password [password file path]",
	Category:  "evertrust COMMANDS",
	Description: `./evertrust gencsr --keystorefile <keystore file> --password <password file> --days <valid time> --subj <eg:/C=CN/ST=Beijing/L=Haidian/O=CRD/OU=CRD/CN=CA-Localhost>

will generate node.csr in current dir`,
	Flags: GencsrFlags,
}

func genCsr(ctx *cli.Context) (err error) {
	keystoreFile := ctx.String(utils.EvertrustKeystoreFileFlag.Name)
	passwdFile := ctx.String(utils.PasswordFileFlag.Name)
	days := ctx.Int(utils.EvertrustCsrDaysFlag.Name)
	subj := ctx.String(utils.EvertrustCsrSubjFlag.Name)

	keystoreBuf, err := ioutil.ReadFile(keystoreFile)
	if err != nil {
		fmt.Printf("read keystore file fail: [%s]%v", keystoreFile, err)
		return
	}

	passwdBuf, err := ioutil.ReadFile(passwdFile)
	if err != nil {
		fmt.Printf("read passwd file fail: %v", err)
		return
	}

	key, err := keystore.DecryptKey(keystoreBuf, strings.Replace(string(passwdBuf), "\n", "", -1))
	if err != nil {
		fmt.Printf("decrypt key fail: %v", err)
		return
	}

	//a preString : 30740201010420
	preString := "30740201010420"
	//a midString : a00706052b8104000aa144034200 (identifies secp256k1)
	midString := "a00706052b8104000aa144034200"

	privKey := fmt.Sprintf("%x", crypto.FromECDSA(key.PrivateKey))

	pubKeyObj := key.PrivateKey.PublicKey
	//the pubKey   : (65 bytes as 130 hexits)
	pubKey := fmt.Sprintf("%x", crypto.FromECDSAPub(&pubKeyObj))

	pemFile := "./node.pem"
	cmdPem := fmt.Sprintf("echo %s %s %s %s | xxd -r -p | openssl ec -inform d > %s", preString, privKey, midString, pubKey, pemFile)
	result, err := exec.Command("/bin/bash", "-c", cmdPem).CombinedOutput()
	if err != nil {
		fmt.Printf("generate pem fail: %v \nreson: %s", err, result)
		return
	}

	if subj == "" {
		subj = "/miner=" + pubKey
	}

	csrFile := "./node.csr"
	cmdCsr := fmt.Sprintf(`openssl req -new -days %d -key %s -out %s -subj "%s"`, days, pemFile, csrFile, subj)
	fmt.Println("cmdCsr:", cmdCsr)
	result, err = exec.Command("/bin/bash", "-c", cmdCsr).CombinedOutput()
	if err != nil {
		fmt.Printf("generate node csr fail: %v \nreason: %s", err, result)
		return
	}

	fmt.Println("has generated node.csr file in current file")

	return
}
