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
 * @Time   : 2019/9/18 11:30 上午
 * @Author : liangc
 *************************************************************************/

package utils

import (
	"CRD-chain/common"
	"CRD-chain/ethdb"
)

// 处理 ewasm 合约部署逻辑
// 抽象成接口是为在 core types 中避免循环引用
type EwasmTool interface {
	SplitTxdata(finalcode []byte) (code, final []byte, err error)
	JoinTxdata(code, final []byte) ([]byte, error)
	ValidateCode(code []byte) ([]byte, error)
	IsWASM(code []byte) bool
	Sentinel(code []byte) ([]byte, error)

	IsFinalcode(finalcode []byte) bool
	DelCode(key []byte)
	GetCode(key []byte) ([]byte, bool)
	GenCodekey(code []byte) []byte
	PutCode(key, val []byte)
	Init(chaindb, codedb ethdb.Database, synchronis *int32)
	GenAuditTask(txhash common.Hash)
	Shutdown()
}

var EwasmToolImpl EwasmTool
