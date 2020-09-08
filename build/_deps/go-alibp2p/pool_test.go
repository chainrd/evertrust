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
 * @Time   : 2020/3/27 10:43 上午
 * @Author : liangc
 *************************************************************************/

package alibp2p

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestFoobar(t *testing.T) {
	t.Log("check compile")
}

func TChain(c interface{}, v interface{}) bool {
	cv := reflect.ValueOf(c)
	fmt.Println(cv.IsNil(), cv.IsValid(), cv.IsZero())
	defer fmt.Println(cv.IsNil(), cv.IsValid(), cv.IsZero())
	vv := reflect.ValueOf(v)

	ok := cv.TrySend(vv)
	fmt.Println("cv", ok)
	fmt.Println("cv close")
	return ok
}

func TestTChan(t *testing.T) {
	c1 := make(chan int)
	go func() {
		n := <-c1
		fmt.Println("recv:", n)
	}()
	<-time.After(1 * time.Second)
	err := TChain(c1, 10)
	fmt.Println(err)

	<-time.After(1 * time.Second)
}
