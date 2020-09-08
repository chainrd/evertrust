package conf

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"CRD-chain/log"
	"strings"
	"time"

	"github.com/spf13/viper"
	"CRD-chain/core/state"
)

var BaapHome = os.Getenv("CRD_BAAP_HOME")
var DbPath = BaapHome + ""

var ChainId *big.Int

var GetStateDB func() (*state.StateDB, error)

var NoLimitCC = map[string][]byte{
	"baap-deploy:v1.0":    {0},
	"baap-stream:v1.0":    {0},
	"baap-payment:v1.0":   {0},
	"baap-chainiaas:v1.0": {0},
	"baap-trusttree:v1.0": {0},
}

const (
	MaxResultSize  = 100
	Space          = "\x00"
	HisKeyTemplate = "%s-baap-his"
	RangeKey       = "baap-range"
)

const (
	SetETH     = "set"
	SetCRD     = "setCRD"
	GetETH     = "get"
	GetCRD     = "getCRD"
	ETHKeyFlag = "1"
	CRDKeyFlag = "2"
)

const (
	TxEstimateGas = "estimateGas"
)

var (
	ApplyTime = time.Millisecond * 4000
)

//noinspection ALL
const (
	//evertrust-filled TX meta data, readable by chaincode
	BaapEngineID = "baap-stack-id"
	BaapDst      = "baap-dst"
	BaapSender   = "baap-sender"
	BaapSpbk     = "baap-sender-pubk"
	BaapTxid     = "baap-txid"
	BaapTxType   = "baap-tx-type"

	BaapEnable               = "evertrust.baap.enable"
	BaapSandboxPolicy        = "evertrust.baap.sandbox.policy"
	BaapConfPath             = "/conf/baap.properties"
	BaapCertPath             = "/conf/client.crt"
	BaapCaPath               = "/conf/root.crt"
	BaapSandboxPolicyDefault = "PUBLIC-MOST-RESTRICTED"
	StreamKey                = "evertrust.baap.stream"
)

const (
	SandboxCCPolicyFile  = "cc-profile"
	SandboxJrePolicyFile = "jre.policy"
	SandboxPolicyDIR     = "/conf/sandbox-policy/"
	SandboxStateKeyNum   = "state.key.num"
	SandboxStateHisNum   = "state.his.num"
	SandboxStateSize     = "state.size"
	SandboxCPU           = "cpu"
	SandboxMemory        = "memory"
	SandboxNet           = "net"
	SandboxHdd           = "hdd"
)

var BaapViper = viper.New()
var CCViper = viper.New()

var NetWorkId int

var SandboxCCPolicyPath string
//var SandboxJrePolicyPath string

const (
	Exec  = "exec"
	Init  = "init"
	Query = "query"
)

func InitConf() {
	//fi, err := os.Open(BaapHome + BaapConfPath)
	//if err != nil {
	//	panic(err)
	//}
	//defer fi.Close()
	//// baap enable
	//BaapViper.SetConfigType("properties")
	//BaapViper.ReadConfig(bufio.NewReader(fi))
	//log.Info("BaapEnable", "enable", BaapViper.GetBool(BaapEnable))

	// baap sandbox
	sandboxPolicy := BaapViper.GetString(BaapSandboxPolicy)
	if sandboxPolicy == "" {
		sandboxPolicy = BaapSandboxPolicyDefault
	}

	SandboxCCPolicyPath = BaapHome + SandboxPolicyDIR + sandboxPolicy + "/" + SandboxCCPolicyFile
	//SandboxJrePolicyPath = BaapHome + SandboxPolicyDIR + sandboxPolicy + "/" + SandboxJrePolicyFile

	var reader io.Reader
	fi, err := os.Open(SandboxCCPolicyPath)
	if err != nil {
		log.Warn("os open file fail, use default", "err", err, "SandboxCCPolicyPath", SandboxCCPolicyPath)
		//default conf
		ccProfile :=
			`{
				"state.key.num": -1,
				"state.his.num" : -1,
				"state.size": "-1b",
				"cpu": "5%",
				"memory": "64m",
				"net": [
					"127.0.0.1:9052",
					"127.0.0.1:8052"
				],
				"hdd": [
				]
			}`
		reader = strings.NewReader(ccProfile)
	}else {
		reader = bufio.NewReader(fi)
	}
	defer fi.Close()
	CCViper.SetConfigType("json")
	CCViper.ReadConfig(reader)

	log.Info("SandboxStateKeyNum", "num", CCViper.GetInt(SandboxStateKeyNum))

	//pool := x509.NewCertPool()
	//addTrust(pool, BaapHome+BaapCaPath)
}

func addTrust(pool *x509.CertPool, path string) {
	aCrt, err := ioutil.ReadFile(path)
	if err != nil {
		panic(fmt.Sprintf("ReadFile err: %s", err.Error()))
	}
	pool.AppendCertsFromPEM(aCrt)
}
