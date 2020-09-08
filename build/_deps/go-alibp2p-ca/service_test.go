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
 * @Time   : 2019/12/3 5:16 下午
 * @Author : liangc
 *************************************************************************/

package ca

import (
	"encoding/json"
	"github.com/cc14514/go-lightrpc/rpcserver"
	"testing"
)

func TestSuccess(t *testing.T) {
	success := new(rpcserver.Success)
	success.Error("1000", "hello world")
	buf, _ := json.Marshal(success)

	s := rpcserver.SuccessFromBytes(buf)

	res := s.Entity.(map[string]interface{})
	t.Log(res["reason"])

}
