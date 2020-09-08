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
package CRDcc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/CRDcc/protos"
	"CRD-chain/CRDcc/util"

	"github.com/golang/protobuf/proto"
	gpb "github.com/golang/protobuf/ptypes/timestamp"
	"CRD-chain/common"
	"CRD-chain/log"
)

type CRDData interface {
	// Open(string) *leveldb.DB
	GetRaw(string, string) []byte
	PutRaw(string, string, []byte)
	DelRaw(string, string)
	GetRawRange(string, string, string) ([]*protos.KV, string)
	GetRawHis(string, string, int) ([]*protos.KeyModification, int)
	GetRawNum(namespace string) int
}

type CRDDataSupport struct {
	stateFunc func(fcn string, key string, value []byte) []byte
}

type ExecReslt struct {
	ChaincodeMsg *protos.ChaincodeMessage
	Err          string
}

func (self *CRDDataSupport) Duplicate(txid string) (execResult ExecReslt, duplicate bool) {
	result := self.GetRaw("executedTx", txid)
	log.Info("get raw result", "result", result)
	if len(result) == 0 {
		return
	}
	err := json.Unmarshal(result, &execResult)
	if err != nil {
		log.Error("unmarshal error", "err", err)
		return
	}

	duplicate = true
	return
}

func (self *CRDDataSupport) PutRaw(namespace, key string, value []byte, txid string, timestamp *gpb.Timestamp) {
	putRaw(self, key, value)

	updateRange(namespace, key, self, false)
	updateHis(namespace, key, self, txid, value, timestamp, false)
}

func putRaw(support *CRDDataSupport, key string, value []byte) {
	support.stateFunc(conf.SetETH, key, []byte(value))
	support.stateFunc(conf.SetCRD, key, []byte(value))
}

func (self *CRDDataSupport) GetRaw(namespace, key string) []byte {
	value := getRaw(self, namespace, key)
	return value
}

func getRaw(support *CRDDataSupport, namespace, key string) []byte {
	if support.stateFunc != nil {
		hash := support.stateFunc(conf.GetETH, key, nil)
		value := support.stateFunc(conf.GetCRD, key, nil)

		if (common.BytesToHash(hash) == common.Hash{}) && len(value) == 0 {
			return []byte{}
		}

		valueHash := util.EthHash(value)

		if !bytes.Equal(valueHash.Bytes(), hash) {
			log.Error(fmt.Sprintf("!!!!! Error %s bad hash (%s %s) !", key, common.BytesToHash(hash).Hex(), valueHash.Hex()))
			return []byte{}
		}
		return value
	} else {
		stateDB, err := conf.GetStateDB()
		if err != nil {
			log.Error("!!!!! Get StateDB error")
			return []byte{}
		}
		keyHash1 := util.EthHash([]byte(key + conf.ETHKeyFlag))
		hash := stateDB.GetState(util.EthAddress(namespace), keyHash1)

		keyHash2 := util.EthHash([]byte(key + conf.CRDKeyFlag))
		value := stateDB.GetCRDState(util.EthAddress(namespace), keyHash2)

		if (hash == common.Hash{}) && len(value) == 0 {
			return []byte{}
		}

		valueHash := util.EthHash(value)

		if !bytes.Equal(valueHash.Bytes(), hash.Bytes()) {
			log.Error(fmt.Sprintf("!!!!! Error %s bad hash (%s %s) !", key, hash.Hex(), valueHash.Hex()))
			return []byte{}
		}
		return value
	}
}

func (self *CRDDataSupport) DelRaw(namespace, key string, txid string, timestamp *gpb.Timestamp) {
	log.Info(fmt.Sprintf("!!!!! DelRaw enter %s %s", namespace, key))
	raw := getRaw(self, namespace, key)

	del(self, key)
	updateRange(namespace, key, self, true)

	if raw == nil || len(raw) == 0 {
		log.Info("delete the key but not in the stateDB, so will not update his!")
		return
	}
	updateHis(namespace, key, self, txid, raw, timestamp, true)

}

func del(support *CRDDataSupport, key string) {
	support.stateFunc(conf.SetETH, key, common.Hash{}.Bytes())
	support.stateFunc(conf.SetCRD, key, []byte{})
}

func updateHis(namespace, key string, self *CRDDataSupport, txid string, value []byte, timestamp *gpb.Timestamp, isDelete bool) {

	hisKey := fmt.Sprintf(conf.HisKeyTemplate, key)
	raw := getRaw(self, namespace, hisKey)

	his := bytes.Split(raw, []byte(conf.Space))

	if len(his) == 1 && len(his[0]) == 0 {
		his = [][]byte{}
	}

	modify := &protos.KeyModification{TxId: txid, Value: value, Timestamp: timestamp, IsDelete: isDelete}
	modifyBytes, err := proto.Marshal(modify)
	if err != nil {
		log.Error(err.Error())
		return
	}

	num := conf.CCViper.GetInt(conf.SandboxStateHisNum)
	if num == -1 || len(his) < num {
		his = append(his, modifyBytes)
	} else {
		//log.Info("no walk this way")
		his = append(his[len(his)-num+1:], modifyBytes)
	}

	putRaw(self, hisKey, bytes.Join(his, []byte(conf.Space)))

}

func updateRange(namespace, key string, self *CRDDataSupport, isDelete bool) {
	keyBytes := []byte(key)

	raw := getRaw(self, namespace, conf.RangeKey)

	if isDelete {
		raw := bytes.Replace(raw, append(keyBytes, []byte(conf.Space)...), nil, -1)
		putRaw(self, conf.RangeKey, raw)
	} else {
		if bytes.Contains(raw, keyBytes) {
			//log.Warn(fmt.Sprintf("!!!!! %s already in the range value", key))
			return
		}

		r := bytes.Split(raw, []byte(conf.Space))
		if len(r) == 1 && len(r[0]) == 0 {
			r = [][]byte{}
		}

		num := conf.CCViper.GetInt(conf.SandboxStateKeyNum)
		if num == -1 || len(r) < num {
			r = append(r, keyBytes)
		} else {
			//log.Info("no walk this way")
			r = append(r[len(r)-num+1:], keyBytes)
		}

		putRaw(self, conf.RangeKey, bytes.Join(r, []byte(conf.Space)))
	}

}

func (self *CRDDataSupport) GetRawRange(namespace, start, end string) ([]*protos.KV, string) {
	log.Info(fmt.Sprintf("!!!!! GetRawRange enter %s %s %s", namespace, start, end))

	startBytes := []byte(start)
	endBytes := []byte(end)

	raw := getRaw(self, namespace, conf.RangeKey)

	all := bytes.Split(raw, []byte(conf.Space))

	if len(all) == 1 && len(all[0]) == 0 {
		log.Info("!!!!! spilt but not found GetRawRange")
		return nil, ""
	}

	var result []*protos.KV
//log.Debug("bbbbbbbbbbbbbbbbbbbbbbbbb", "all len", len(all))
	find := false
	for _, key := range all {
		//log.Debug("ccccccccccccccccccc", "key", string(key))
		if len(result) >= conf.MaxResultSize {
			return result, string(key)
		}

		if bytes.Equal(key, startBytes) || find {
			result = append(result,
				&protos.KV{Namespace: namespace,
					Key:   string(key),
					Value: getRaw(self, namespace, string(key)),
				},
			)
			//log.Debug("aaaaaaaaaaaaaaaaaaaaaaaaaa", "key", string(key), "v", string(getRaw(self, namespace, string(key))))
			find = true
		}

		if bytes.Equal(key, endBytes) {
			return result, ""
		}
	}

	return result, ""
}

func (self *CRDDataSupport) GetRawHis(namespace, key string, index int) ([]*protos.KeyModification, int) {
	log.Info(fmt.Sprintf("!!!!! GetRawHis enter %s %s %d", namespace, key, index))

	hisKey := fmt.Sprintf(conf.HisKeyTemplate, key)

	raw := getRaw(self, namespace, hisKey)

	his := bytes.Split(raw, []byte(conf.Space))

	if len(his) == 1 && len(his[0]) == 0 {
		log.Info("!!!!! spilt but not found GetRawHis")
		return nil, -1
	}

	hasMore := -1
	//log.Info("qqqqqqqqqqqqq", "MaxResultSize", conf.MaxResultSize, "SandboxStateHisNum", conf.SandboxStateHisNum)
	stateHisNum := conf.CCViper.GetInt(conf.SandboxStateHisNum)
	if stateHisNum == -1 || conf.MaxResultSize < stateHisNum {
		//log.Info("<<<<<<<<<<<<<<<<<<<<<", "index", index, "MaxResultSize", conf.MaxResultSize)
		// 分页最大值 小于 沙箱限制，需要考虑分页
		if index+conf.MaxResultSize < len(his) {
			his = his[index : index+conf.MaxResultSize]
			hasMore = index + conf.MaxResultSize
			//log.Info("ttttttttttttttttttttt", "his", his, "hisMore", hasMore)
		} else {
			his = his[index:]
		}
	} else {
		//log.Info(">====================")
		his = his[index:]
	}

	var res []*protos.KeyModification

	for _, b := range his {
		message := &protos.KeyModification{}
		err := proto.Unmarshal(b, message)
		if err != nil {
			return res, hasMore
		}
		//log.Info("eeeeeeeeeeeeeeee", "value", string(message.Value))
		res = append(res, message)
	}

	return res, hasMore
}

func (self *CRDDataSupport) GetRawNum(namespace string) int {
	raw := getRaw(self, namespace, conf.RangeKey)

	all := bytes.Split(raw, []byte(conf.Space))

	if len(all) == 1 && len(all[0]) == 0 {
		log.Info("!!!!! spilt but not found GetRawNum")
		return 0
	}

	return len(all)
}
