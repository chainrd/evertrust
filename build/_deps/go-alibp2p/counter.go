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
 * @Time   : 2020/1/14 4:51 下午
 * @Author : liangcfdghsgs
 *************************************************************************/

package alibp2p

import (
	"fmt"
	"time"
)

func startCounter(srv *Service) {
	go func() {
		for {
			select {
			case <-srv.ctx.Done():
			case <-time.After(300 * time.Second):
				fmt.Println("alibp2p-counter =", string(srv.Report()))
			}
		}
	}()
}
