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
 * @Time   : 2020/1/14 5:05 下午
 * @Author : liangc
 *************************************************************************/

package alibp2p

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestAddCounter(t *testing.T) {
	s := `
{
  "alibp2p-counter": {
    "bw": {
      "total-in": "643197",
      "total-out": "5696915",
      "rate-in": "20.28",
      "rate-out": "596.35"
    },
    "rw": {
      "total-in": "100219",
      "total-out": "20147",
      "avg-in": "3.17",
      "avg-out": "0.63"
    },
    "msg": {
      "total-in": "9",
      "total-out": "20084",
      "avg-in": "0.00",
      "avg-out": "0.63"
    }
  }
}`
	m := make(map[string]interface{})
	err := json.Unmarshal([]byte(s), &m)
	t.Log(err, m)
	b, err := json.Marshal(m)
	t.Log(err, string(b)[1:])
	h := fmt.Sprintf(`"%s"`, "helloworld")
	t.Log(h)

	now := "now"
	ss := `{"a":123"}`
	bb := []byte(fmt.Sprintf("{\"time\":\"%s\",%s", now, ss[1:]))
	cc := []byte(fmt.Sprintf(`{"time":"%s",{"details":%s}}`, now, `["a","b"]`))
	t.Log(bb)
	t.Log(string(bb))
	t.Log(cc)
	t.Log(string(cc))
}

func TestPool(t *testing.T) {
	var asc AStreamCache
	t.Log(asc.has("hello"))
}
