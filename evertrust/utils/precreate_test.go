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
 * @Time   : 2019-08-06 15:30
 * @Author : liangc
 *************************************************************************/
package utils

import (
	"CRD-chain/common"
	"testing"
)

func TestPrecreate_Get(t *testing.T) {
	k := common.HexToHash("0x")
	v := &PrecreateResponse{Gas: 10000}
	Precreate.Put(k, v)
	r1 := Precreate.Det(k)
	t.Log(k, v)
	t.Log("1", r1)
	r2 := Precreate.Det(k)
	t.Log("2", r2, r1)
}
