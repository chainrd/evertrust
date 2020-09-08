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
 * @Time   : 2020/4/15 11:03 上午
 * @Author : liangc
 *************************************************************************/

package service

var (
	history = []string{
		"0.0.1-beta",
		"0.0.2-beta",
		"0.0.3-beta",
		"0.0.4-beta",
		"0.0.5-dev",
		"0.0.6-beta",
	}
	changelog = map[string]string{
		"0.0.1-beta": `
第一个基础版，包含了 PC 和 Mobile 端;
`, "0.0.2-beta": `
1、提升入网速度；
2、提供更多 Admin API 给 Mobile 端，包括 myid / conns / config / fnodes / report ；
3、适配 IOS 端的 web3 SDK，他发来的 request 是数组，需要修正为字典；
`, "0.0.3-beta": `
1、适配 IOS 的输入输出，均为数组，按顺序执行执行 request 并按顺序返回结果;
2、调整 dial timeout ，在 findprovides 时缩短，执行完再还原，否则影响组网;
`, "0.0.4-beta": `
1、为 PC 端提供 keystore 目录；
2、为 config 提供 AsMap 函数；
3、在 admin_config 接口中提供 keystore 目录信息(仅PC端)
`, "0.0.5-beta": `
增加 AccountService 提供 keystore 功能, 包括 create / delete / list / signtx
`, "0.0.6-beta": `
签名交易时适配字符串原文和16进制字符串;
`,
	}
)

func Version() string {
	return history[len(history)-1]
}
