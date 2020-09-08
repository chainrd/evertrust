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

package vm

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/go-interpreter/wagon/exec"
	"github.com/go-interpreter/wagon/wasm"
	"golang.org/x/crypto/ed25519"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/core/rawdb"
	"CRD-chain/crypto"
	"CRD-chain/ethdb"
	"CRD-chain/log"
	"CRD-chain/params"
	"CRD-chain/rlp"
	"CRD-chain/evertrust"
	"CRD-chain/evertrust/utils"
	"sync"
	"sync/atomic"
	"time"
)

var eeiFunctionList = []string{
	"useGas",
	"getAddress",
	"getExternalBalance",
	"getBlockHash",
	"call",
	"callDataCopy",
	"getCallDataSize",
	"callCode",
	"callDelegate",
	"callStatic",
	"storageStore",
	"storageLoad",
	"getCaller",
	"getCallValue",
	"codeCopy",
	"getCodeSize",
	"getBlockCoinbase",
	"create",
	"getBlockDifficulty",
	"externalCodeCopy",
	"getExternalCodeSize",
	"getGasLeft",
	"getBlockGasLimit",
	"getTxGasPrice",
	"log",
	"getBlockNumber",
	"getTxOrigin",
	"finish",
	"revert",
	"getReturnDataSize",
	"returnDataCopy",
	"selfDestruct",
	"getBlockTimestamp",
	// add by liangc : 扩展 ewasm 存储功能 >>>>
	"storageStore2",
	"storageLoad2",
	// add by liangc : 扩展 ewasm 存储功能 <<<<
}

var debugFunctionList = []string{
	"printMemHex",
	"printStorageHex",
}

// ModuleResolver matches all EEI functions to native go functions
func ModuleResolver(interpreter *EWASMInterpreter, name string) (*wasm.Module, error) {
	if name == "debug" {
		debugModule := wasm.NewModule()
		debugModule.Types = eeiTypes
		debugModule.FunctionIndexSpace = getDebugFuncs(interpreter)
		entries := make(map[string]wasm.ExportEntry)
		for idx, name := range debugFunctionList {
			entries[name] = wasm.ExportEntry{
				FieldStr: name,
				Kind:     wasm.ExternalFunction,
				Index:    uint32(idx),
			}
		}
		debugModule.Export = &wasm.SectionExports{
			Entries: entries,
		}
		return debugModule, nil
	}

	if name != "ethereum" {
		return nil, fmt.Errorf("Unknown module name: %s", name)
	}

	m := wasm.NewModule()
	m.Types = eeiTypes
	m.FunctionIndexSpace = eeiFuncs(interpreter)

	entries := make(map[string]wasm.ExportEntry)

	for idx, name := range eeiFunctionList {
		entries[name] = wasm.ExportEntry{
			FieldStr: name,
			Kind:     wasm.ExternalFunction,
			Index:    uint32(idx),
		}
	}

	m.Export = &wasm.SectionExports{
		Entries: entries,
	}

	return m, nil
}

func WrappedModuleResolver(in *EWASMInterpreter) wasm.ResolveFunc {
	return func(name string) (*wasm.Module, error) {
		return ModuleResolver(in, name)
	}
}

type (
	ewasmFuns struct {
		dblock     *sync.Mutex
		spub       [32]byte
		magic      [4]byte
		chaindb    ethdb.Database
		codedb     ethdb.Database
		synchronis *int32
		once       *sync.Once
		stop       chan struct{}
		auditTask  chan []byte
	}
	auditTask struct {
		Key                 *big.Int
		Txhash              common.Hash
		Status, BlockNumber *big.Int
	}
)

var (
	EwasmFuncs = &ewasmFuns{
		dblock: new(sync.Mutex),
		spub: [32]byte{78, 213, 66, 231, 2, 216, 32, 136,
			71, 233, 64, 132, 125, 45, 77, 101,
			222, 209, 181, 20, 212, 62, 181, 43,
			190, 87, 231, 13, 194, 112, 244, 183},
		magic:  [4]byte{0, 80, 68, 88},
		codedb: ethdb.NewMemDatabase(),
		once:   new(sync.Once),
		stop:   make(chan struct{}),
	}
	taskNumKey = crypto.Keccak256([]byte("task-num"))
	taskPreKey = crypto.Keccak256([]byte("task-pre"))
	auditLimit = int64(20)
)

func (f *ewasmFuns) Shutdown() {
	log.Debug("ewasmFuncs-shutdown")
	if f.codedb != nil {
		f.codedb.Close()
	}
	close(f.stop)
}

func (f *ewasmFuns) DelCode(key []byte) {
	err := f.codedb.Delete(key)
	if err != nil {
		log.Error("DelCode", "key", hex.EncodeToString(key), "err", err)
	}
	log.Debug("DelCode", "synchronis", atomic.LoadInt32(f.synchronis), "key", hex.EncodeToString(key))
}

func (f *ewasmFuns) GetCode(key []byte) (val []byte, ok bool) {
	ok = true
	var v interface{}
	v, err := f.codedb.Get(key)
	if err != nil {
		return nil, false
	}
	val = v.([]byte)
	log.Debug("GetCode", "synchronis", atomic.LoadInt32(f.synchronis), "key", hex.EncodeToString(key), "ok", ok)
	return
}

// codekey -> finalkey -> final
func (f *ewasmFuns) PutCode(key, val []byte) {
	err := f.codedb.Put(key, val)
	if err != nil {
		log.Error("PutCode", "key", hex.EncodeToString(key), "val.len", len(val), "err", err)
	}
	log.Debug("PutCode", "synchronis", atomic.LoadInt32(f.synchronis), "key", hex.EncodeToString(key), "val.len", len(val))
}

func (f *ewasmFuns) IsFinalcode(finalcode []byte) bool {
	if len(finalcode) < 72 || !f.IsWASM(finalcode) {
		return false
	}
	tail := finalcode[len(finalcode)-8:]
	if bytes.Equal(append(f.magic[:], params.CRDTEwasm), tail[:5]) {
		return true
	}
	log.Debug("IsFinalcode-error", "synchronis", atomic.LoadInt32(f.synchronis), "last8", finalcode[len(finalcode)-8:], "want-last5", append(f.magic[:], params.CRDTEwasm))
	return false
}

// finalcode == {code,final,[4]byte,[1]byte,[3]byte}
// [4]byte 魔术字节
// [1]byte 封包类型
// [3]byte final 的字节长度
func (f *ewasmFuns) SplitTxdata(finalcode []byte) (code, final []byte, err error) {
	if len(finalcode) < 73 {
		return nil, nil, errors.New("error format of ewasm finalcode ")
	}
	tail := finalcode[len(finalcode)-8:]
	l := new(big.Int).SetBytes(tail[5:]).Int64()
	size := len(finalcode)
	code = finalcode[:size-int(l)-8]
	final = finalcode[size-int(l)-8 : size-8]
	_, err = f.ValidateCode(final)
	if err != nil {
		return nil, nil, err
	}
	log.Info("SplitTxdata", "synchronis", atomic.LoadInt32(f.synchronis), "code", len(code), "final", len(final), "finalcode", len(finalcode), "last8", finalcode[len(finalcode)-8:])
	return code, final, nil
}

// finalcode == {code,final,[4]byte,[1]byte,[3]byte}
// [4]byte 魔术字节
// [1]byte 封包类型
// [3]byte final 的字节长度
func (f *ewasmFuns) JoinTxdata(code, final []byte) ([]byte, error) {
	if f.IsFinalcode(code) || f.IsFinalcode(final) {
		return nil, errors.New("reject join")
	}
	_, err := f.ValidateCode(final)
	if err != nil {
		return nil, err
	}
	finallen := int64(len(final))
	if finallen > 16777215 {
		return nil, errors.New("ewasm code too long")
	}
	i24 := big.NewInt(finallen)
	finalcode := make([]byte, 0)
	finalcode = append(finalcode, code[:]...)
	finalcode = append(finalcode, final[:]...)
	finalcode = append(finalcode, f.magic[:]...)
	finalcode = append(finalcode, params.CRDTEwasm)
	b24 := i24.Bytes()
	bl := 3 - len(b24)
	if bl > 0 {
		r := make([]byte, bl)
		b24 = append(r[:], b24[:]...)
	}
	finalcode = append(finalcode, b24[:]...)
	log.Info("JoinTxdata", "synchronis", atomic.LoadInt32(f.synchronis), "code", len(code), "final", len(final), "finalcode", len(finalcode), "last8", finalcode[len(finalcode)-8:])
	return finalcode, nil
}

func (f *ewasmFuns) ValidateCode(code []byte) ([]byte, error) {
	if len(code) > 64 && f.IsWASM(code) {
		var (
			sig = code[len(code)-64:]
			msg = code[:len(code)-64]
		)
		ret := ed25519.Verify(f.spub[:], msg, sig)
		//fmt.Println(ret, code)
		if ret {
			return msg, nil
		}
	}
	return nil, errors.New("bad ewasm code")
}

func (f *ewasmFuns) IsWASM(code []byte) bool {
	data := f.jwtfilter(code)
	if len(data) < 41 || string(data[:4]) != "\000asm" {
		return false
	}
	return true
}

// 适配 JWT 和 META 数据
func (f *ewasmFuns) jwtfilter(code []byte) []byte {
	if p, e := evertrust.ParseData2(code); e == nil {
		return p
	}
	return code
}

func (f *ewasmFuns) Sentinel(code []byte) ([]byte, error) {
	code = f.jwtfilter(code)
	var (
		err     error
		mainSig *wasm.FunctionSig
		evm     = NewEVM(Context{}, nil, params.TestChainConfig, Config{})
		in      = &EWASMInterpreter{
			StateDB:  evm.StateDB,
			evm:      evm,
			gasTable: evm.chainConfig.GasTable(evm.BlockNumber),
		}
		meteringa = common.HexToAddress(sentinelContractAddress)
		meteringf = AccountRef(common.HexToAddress("0x110"))
		meteringt = AccountRef(meteringa)
	)
	in.meteringModule, err = wasm.ReadModule(bytes.NewReader(meteringCode), WrappedModuleResolver(in))
	if err != nil {
		log.Error("sentinel execute fail 0", "err", err)
		return nil, err
	}

	in.meteringStartIndex = int64(in.meteringModule.Export.Entries["main"].Index)
	mainSig = in.meteringModule.FunctionIndexSpace[in.meteringStartIndex].Sig
	if len(mainSig.ParamTypes) != 0 || len(mainSig.ReturnTypes) != 0 {
		log.Error("sentinel execute fail 1", "err", err)
		return nil, err
	}

	in.contract = NewContract(meteringf, meteringt, new(big.Int), 9999999999)
	in.contract.SetCallCode(&meteringa, crypto.Keccak256Hash(meteringCode), meteringCode)
	vm, err := exec.NewVM(in.meteringModule)
	if err != nil {
		log.Error("sentinel execute fail 2", "err", err)
		return nil, err
	}
	vm.RecoverPanic = true
	in.vm = vm
	in.contract.Input = code
	start := time.Now()
	final, err := in.vm.ExecCode(in.meteringStartIndex)
	if err != nil {
		log.Error("sentinel execute fail 3", "err", err)
		return nil, err
	}
	if final == nil {
		final = in.returnData
	}
	_, err = f.ValidateCode(final.([]byte))
	log.Info("Sentinel", "timeused", time.Since(start), "code", len(code), "final", len(final.([]byte)))
	return final.([]byte), err
}

// 当 save == nil 时获取最新的可用 num，否则保存 save
func (f *ewasmFuns) newTask(k []byte, save *big.Int) *big.Int {
	n := big.NewInt(0)
	if f.codedb == nil {
		fmt.Println("TEST")
		return n
	}
	if save != nil {
		if err := f.codedb.Put(k, save.Bytes()); err != nil {
			panic(err)
		}
		return save
	}
	if buf, err := f.codedb.Get(k); err == nil {
		n = new(big.Int).SetBytes(buf)
	}
	return n
}

func (f *ewasmFuns) processAuditTask(atask *auditTask) {
	tx, _, num, _ := rawdb.ReadTransaction(f.chaindb, atask.Txhash)
	if tx == nil {
		return
	}
	atask.BlockNumber = big.NewInt(int64(num))
	code := tx.Data()
	//codekey := crypto.Keccak256(code)
	codekey := f.GenCodekey(code)
	final, ok := f.GetCode(codekey)
	if ok && len(final) == 32 {
		final, ok = f.GetCode(final)
	}
	log.Debug("processAuditTask-start", "num", num, "code", len(code), "final", len(final), "codekey", common.BytesToHash(codekey).Hex())
	if atask.Key != nil && ok {
		if _final, err := f.Sentinel(code); err == nil {
			log.Debug("processAuditTask", "sentinel", len(_final))
			if _, err = f.ValidateCode(_final); err == nil {
				log.Debug("processAuditTask", "validateCode", len(_final))
				if bytes.Equal(crypto.Keccak256(final), crypto.Keccak256(_final)) {
					log.Debug("processAuditTask", "audit-result", "ok")
					atask.Status = big.NewInt(1)
				}
			}
		}
	}
	finalstatekey := crypto.Keccak256(final, []byte("status"))
	finalstateval, err := rlp.EncodeToBytes(atask)
	if err != nil {
		// 不接受异常
		panic(err)
	}
	err = f.codedb.Put(finalstatekey, finalstateval)
	log.Debug("processAuditTask-success", "finalstatekey", finalstatekey, "hex", common.BytesToHash(finalstatekey).Hex(), "atask", atask)
	if err != nil {
		// 不接受异常
		panic(err)
	}
	if atask.Key != nil {
		f.newTask(taskPreKey, atask.Key)
	}
}

func (f *ewasmFuns) auditLoop() {
	if f.codedb == nil {
		fmt.Println("TEST")
		return
	}
	log.Info("ewasmFuns-auditLoop-start")
	preNum := f.newTask(taskPreKey, nil)
	lastNum := f.newTask(taskNumKey, nil)
	cap := lastNum.Int64() - preNum.Int64() + 100
	f.auditTask = make(chan []byte, cap)
	log.Debug("ewasmFuns-auditLoop-params", "preNum", preNum, "lastNum", lastNum, "taskCap", cap)
	for i := preNum.Int64(); i < lastNum.Int64(); i++ {
		if i == 0 {
			continue
		}
		k := big.NewInt(i)
		f.auditTask <- k.Bytes()
		log.Debug("ewasmFuncs-auditLoop-reload-task", "tk", k)
	}
	for {
		select {
		case <-f.stop:
			return
		case tk := <-f.auditTask:
			// TODO 并行处理
			tv, _ := f.codedb.Get(tk)
			task := new(auditTask)
			err := rlp.DecodeBytes(tv, task)
			if err == nil {
				log.Info("ewasmFuns-auditLoop-task", "err", err, "tk", tk, "tv", tv, "task", task)
				// 先生成任务数据，再去更新
				go f.processAuditTask(task)
			}
		}
	}
}

func (f *ewasmFuns) GenAuditTask(txhash common.Hash) {
	if atomic.LoadInt32(f.synchronis) == 1 {
		// 正在同步，跳过验证，没有任务，直接生成结果
		log.Debug("ewasmFuns-GenAuditTask-skip : default success", "synchronis", atomic.LoadInt32(f.synchronis), "tx", txhash.Hex())
		atask := &auditTask{
			Status: big.NewInt(1),
			Txhash: txhash,
		}
		f.processAuditTask(atask)
		return
	}
	var (
		err        error
		tk         *big.Int
		atask      auditTask
		ataskBytes []byte
	)
	f.dblock.Lock()
	defer func() {
		if err == nil {
			log.Debug("GenAuditTask-success", "key", tk, "txhash", txhash.Hex())
			// commit task
			f.auditTask <- f.newTask(taskNumKey, tk).Bytes()
		}
		f.dblock.Unlock()
	}()
	// task-num
	tk = new(big.Int).Add(f.newTask(taskNumKey, nil), big.NewInt(1))
	atask = auditTask{tk, txhash, big.NewInt(0), nil}
	// 这个方法出现的异常不可恢复,panic
	ataskBytes, err = rlp.EncodeToBytes(&atask)
	log.Debug("Ataskbytes", "err", err, "task", ataskBytes)
	if err != nil {
		panic(err)
	}
	err = f.codedb.Put(tk.Bytes(), ataskBytes)
	if err != nil {
		panic(err)
	}
}

func (f *ewasmFuns) getFinalStatus(final []byte) (*auditTask, error) {
	finalstatekey := crypto.Keccak256(final, []byte("status"))
	buf, err := f.codedb.Get(finalstatekey)
	//log.Debug("ewasmFuns-getFinalStatus", "err", err, "finalstatekey", finalstatekey, "hex", common.BytesToHash(finalstatekey).Hex())
	if err != nil {
		return nil, err
	}
	atask := new(auditTask)
	err = rlp.DecodeBytes(buf, atask)
	if err != nil {
		return nil, err
	}
	return atask, nil
}

func (f *ewasmFuns) VerifyStatus(currentBlockNumber *big.Int, final []byte) error {

	atask, err := f.getFinalStatus(final)
	if err != nil {
		log.Debug("VerifyStatus-getFinalStatus-error", "err", err)
		return err
	}
	/* 同步时默认审核通过，不影响验证逻辑
	if atomic.LoadInt32(f.synchronis) == 1 {
		// 正在同步，跳过验证
		log.Debug("ewasmFuns-verifyStatus-skip", "synchronis", atomic.LoadInt32(f.synchronis))
		return nil
	}*/
	//log.Debug("VerifyStatus-ready", "status", atask.Status, "num", atask.BlockNumber, "current", currentBlockNumber)
	if atask.Status != nil && atask.Status.Int64() == 1 &&
		atask.BlockNumber != nil && (new(big.Int).Add(atask.BlockNumber, big.NewInt(auditLimit))).Cmp(currentBlockNumber) < 0 {
		//log.Debug("VerifyStatus-success")
		return nil
	}
	log.Debug("VerifyStatus-fail")
	return fmt.Errorf("VerifyStatus-fail : status=%d , num=%d , current=%d", atask.Status, atask.BlockNumber, currentBlockNumber)
}

func (f *ewasmFuns) GenCodekey(code []byte) []byte {
	code, _, err := evertrust.ParseData(code)
	if err != nil {
		panic(err)
	}
	return crypto.Keccak256(code)
}

func (f *ewasmFuns) Init(chaindb, codedb ethdb.Database, synchronis *int32) {
	f.once.Do(func() {
		log.Debug("ewasmFuncs-init")
		f.chaindb = chaindb
		f.codedb = codedb
		f.synchronis = synchronis
		go EwasmFuncs.auditLoop()
	})
}

func init() {
	utils.EwasmToolImpl = EwasmFuncs
}
