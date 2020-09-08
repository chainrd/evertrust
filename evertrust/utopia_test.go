package evertrust

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"CRD-chain/crypto"
	"CRD-chain/evertrust/utils"
	"testing"
)

func TestParseData(t *testing.T) {
	//data:nil pass
	//str := "abc_123_a1b2c3" pass
	//flag := ExtensionFlag
	//payloadStr := "abc123" // to nil pass
	type Obj struct {
		Name string `json:"name"`
	}
	obj := Obj{Name:"tonysu"}
	payloadBefore, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("json marshal:%v", err)
	}
	payloadStr := hex.EncodeToString(payloadBefore)
	t.Logf("obj hex:%v", payloadStr)

	metaBefore := utils.Meta{"name":[]byte("tonysu"), "version":[]byte("1.2"), "desc":[]byte("12423545"),"ddd":[]byte("ddd")}

	//assemble
	data, err := AssemblePayload(payloadBefore, metaBefore)
	if err != nil {
		t.Fatalf("assemble payload:%v", err)
	}

	//split
	payload, meta, err := ParseData(data)
	if err != nil {
		t.Fatalf("parse data:%v", err)
	}

	if !bytes.Equal(payloadBefore, payload) {
		t.Fatalf("payload parse fail")
	}
	if !bytes.Equal(meta["name"], metaBefore["name"]) ||
		!bytes.Equal(meta["version"], metaBefore["version"]) ||
		!bytes.Equal(meta["jwt"], metaBefore["jwt"]) {

		t.Fatalf("meta parse fail")
	}

	data2, err := AssemblePayload(payload, meta)
	if err != nil {
		t.Fatalf("assemble2 payload:%v", err)
	}

	if !bytes.Equal(crypto.Keccak256(data), crypto.Keccak256(data2)) {
		t.Fatalf("data != data2")
	}
}

func TestGetTrustNodeFromIaas(t *testing.T)  {

	iaas, _, _ := GetTrustNodeFromIaas("739", "", "")
	fmt.Println(iaas)

}