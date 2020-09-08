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
 *************************************************************************/
package iaasconn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"CRD-chain/common"
	"CRD-chain/common/hexutil"
	core_types "CRD-chain/core/types"
	"CRD-chain/crypto"
	"CRD-chain/log"
	"CRD-chain/p2p/discover"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/evertrust"
	"CRD-chain/evertrust/types"
	"time"
)

type CommitExtra struct {
	NewBlockHeight *hexutil.Big `json:"newBlockHeight"`

	AcceptedBlocks []common.Hash `json:"acceptedBlocks"`

	Evidences []types.CondensedEvidence `json:"evidences"`

	// Changes on consensus nodes
	MinerAdditions []common.Address `json:"minerAdditions"`
	MinerDeletions []common.Address `json:"minerDeletions"`

	// Change on observatory nodes
	NodeAdditions []common.Address `json:"nodeAdditions"`
	NodeDeletions []common.Address `json:"nodeDeletions"`

	Quorum             []string `json:"quorum"`
	CNum               uint64   `json:"cNum"`
	Island             bool     `json:"island"`
	Rank               uint64   `json:"rank"`
	IslandAssertionSum uint64   `json:"assertionSum"`
}
type BlockExtra struct {
	NodeID discover.NodeID `json:"nodeID"`

	Rank uint32 `json:"rank"`

	CNumber *hexutil.Big `json:"cNumber"`

	Signature []byte `json:"signature"`

	IP   net.IP `json:"ip"`
	Port uint16 `json:"port"`

	// For extension only
	CommitExtra CommitExtra `json:"commitExtra"`
}
type Header struct {
	ParentHash  common.Hash           `json:"parentHash"       gencodec:"required"`
	UncleHash   common.Hash           `json:"sha3Uncles"       gencodec:"required"`
	Coinbase    common.Address        `json:"miner"            gencodec:"required"`
	Root        common.Hash           `json:"stateRoot"        gencodec:"required"`
	TxHash      common.Hash           `json:"transactionsRoot" gencodec:"required"`
	ReceiptHash common.Hash           `json:"receiptsRoot"     gencodec:"required"`
	Bloom       core_types.Bloom      `json:"logsBloom"        gencodec:"required"`
	Difficulty  *hexutil.Big          `json:"difficulty"       gencodec:"required"`
	Number      *hexutil.Big          `json:"number"           gencodec:"required"`
	GasLimit    hexutil.Uint64        `json:"gasLimit"         gencodec:"required"`
	GasUsed     hexutil.Uint64        `json:"gasUsed"          gencodec:"required"`
	Time        *hexutil.Big          `json:"timestamp"        gencodec:"required"`
	Extra       BlockExtra            `json:"blockExtra"       gencodec:"required"`
	MixDigest   common.Hash           `json:"mixHash"          gencodec:"required"`
	Nonce       core_types.BlockNonce `json:"nonce"            gencodec:"required"`
}
type Block struct {
	Header       *Header                 `json:"header"`
	Uncles       []*Header               `json:"uncles"`
	Transactions core_types.Transactions `json:"transactions"`
}

func SendToIaas(commitBlock *core_types.Block, privK *ecdsa.PrivateKey) {
	log.Info("iaas server is:", "server", evertrust.Config.String("iaas"))
	buffer := bytes.NewBuffer(nil)
	err := commitBlock.EncodeRLP(buffer)
	if err != nil {
		log.Error("commit block encode rlp", "err", err)
		return
	}

	req, err := http.NewRequest(
		"POST",
		evertrust.Config.String("iaas")+"/rest/chain/block",
		buffer,
	)
	if err != nil {
		log.Error("newRequest err", "err", err)
		return
	}
	chainId := conf.ChainId.String()
	cBlockN := commitBlock.Number().String()

	req.Header.Set("X-EVERTRUST-CHAIN-ID", chainId)
	req.Header.Set("X-EVERTRUST-CBLOCK-NO", cBlockN)

	pubKeyObj := privK.PublicKey
	pubK := fmt.Sprintf("%x", crypto.FromECDSAPub(&pubKeyObj))
	req.Header.Set("X-EVERTRUST-MINER-PUBK", pubK)

	cbhash := commitBlock.Hash().String()

	digest := chainId + cBlockN + pubK + cbhash

	sig, err := crypto.Sign(crypto.Keccak256([]byte(digest)), privK)
	if err != nil {
		log.Error("sign error", "err", err)
		return
	}
	req.Header.Set("X-EVERTRUST-SIGNATURE", common.Bytes2Hex(sig))

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	client.Timeout = time.Millisecond * 1500
	resp, err := client.Do(req)
	if err != nil {
		log.Warn("client do", "err", err)
		return
	}
	defer resp.Body.Close()

	respBuffer, _ := ioutil.ReadAll(resp.Body)
	log.Info("send to iaas resp", "resp", string(respBuffer), "status", resp.Status)

}

func GetNodeFromIaas(chainID string) (host []string, err error) {
	iaasServer := evertrust.Config.String("iaas")
	log.Info("get Node From Iaas", "iaas", iaasServer)
	if iaasServer == "" {
		return nil, errors.New("iaas not config")
	}
	client := &http.Client{Timeout: time.Millisecond * 1500}
	resp, err := client.Get(iaasServer + "/rest/chain/hosts?chainId=" + chainID)
	if err != nil {
		return nil, fmt.Errorf("resp error:%v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read resp body error:%v", err)
	}
	log.Info("get node from iaas resp", "status", resp.Status)

	type Data struct {
		Hosts     []string `json:"hosts"`
		UnityCert string   `json:"unityCert"`
		Salt      string   `json:"salt"`
		Timestamp string   `json:"timestamp"`
		Signature string   `json:"signature"`
	}
	type RspBody struct {
		Status int               `json:""`
		Meta   map[string]string `json:"meta"`
		Data   Data              `json:"data"`
	}
	var result RspBody
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("body unmarshal error:%v", err)
	}

	l := len(result.Data.Hosts)
	if l == 0 {
		return nil, errors.New("data hosts empty")
	}

	//验证签名
	//check publicKey
	toPub := core_types.GenPubKeyFromIAASCert(result.Data.UnityCert)
	if toPub == nil {
		return nil, errors.New("gen pub key from cert fail")
	}
	//pubkey := crypto.CompressPubkey(toPub)
	certPubkey := crypto.FromECDSAPub(toPub)

	//digest hash
	hostStr := ""
	for _, v := range result.Data.Hosts {
		hostStr += v
	}
	digest := hostStr + result.Data.UnityCert + result.Data.Salt + result.Data.Timestamp
	digestHash := crypto.Keccak256([]byte(digest))
	//sig
	sig := result.Data.Signature
	sigBuf, err := base64.URLEncoding.DecodeString(sig)
	if err != nil {
		log.Error("sig decode", "err", err)
		return
	}

	sigPubkey, err := crypto.Ecrecover(digestHash, sigBuf)
	if err != nil {
		log.Error("ec recover pubkey", "err", err)
		return
	}
	if bytes.Compare(certPubkey, sigPubkey) != 0 {
		return nil, errors.New("cert pubkey != sig pubkey")
	}

	//验证证书
	if !core_types.CheckIAASCert(result.Data.UnityCert, "tcadmHosts.crt") {
		return nil, fmt.Errorf("check IAAS cert fail")
	}

	rand.Shuffle(l, func(i, j int) {
		result.Data.Hosts[i], result.Data.Hosts[j] = result.Data.Hosts[j], result.Data.Hosts[i]
	})
	if l <= 10 {
		return result.Data.Hosts, nil
	} else {
		return result.Data.Hosts[0:10], nil
	}

}
