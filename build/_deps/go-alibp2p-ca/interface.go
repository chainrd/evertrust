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
 * @Time   : 2019/11/28 9:35 上午
 * @Author : liangc
 *************************************************************************/

package ca

import (
	"crypto/ecdsa"
	"github.com/cc14514/go-certool"
	"github.com/libp2p/go-libp2p-core/peer"
	"math/big"
)

type (
	RevokeObj struct {
		SerialNumber *big.Int
		Cert         Cert
		Sign         []byte
	}
	// 去中心 CA 模块入口
	Alibp2pCAService interface {
		// 如果是 CA 角色，需要先解锁私钥以便执行签名
		UnlockCAKey(pwd string) error
		// 对 CSR 进行签发
		AcceptCsr(id ID, expire int) (Cert, error)

		// 启动服务
		Start() error
		// 检查一个节点是否在线，通常是用 Client 端来 Ping CA 节点
		Ping(*ecdsa.PublicKey) (PingMsg, error)
		// 获取被认可的 CA 列表，可以跟网络中的其他节点索取，如果 参数为 nil 则是获取本地已保存的
		GetCAL(*ecdsa.PublicKey) (certool.Keychain, error)
		// 向 CA 提交 CSR 请求，第一个参数使用 CA 在网络中的节点地址公钥
		SendCsr(*ecdsa.PublicKey, Csr) (ID, error)
		/*
			向 CA 提交 CSR 状态查询请求，第一个参数使用 CA 在网络中的节点地址公钥
			------------------------------------------------------------
				CSR_STATE_REJECT   CSR_STATE = "REJECT"   // 拒绝
				CSR_STATE_NORMAL   CSR_STATE = "NORMAL"   // 待处理
				CSR_STATE_PASSED   CSR_STATE = "PASSED"   // 通过
				CSR_STATE_NOTFOUND CSR_STATE = "NOTFOUND" // 不存在
		*/
		CsrStatus(*ecdsa.PublicKey, ID) (CSR_STATE, error)

		// 当 CSR 状态为 CSR_STATE_PASSED 时，就可以用 ID 跟 CA 获取 CRT 了，标示已经得到授权
		GetCert(*ecdsa.PublicKey, ID) (Cert, error)

		// 申请撤销, 立即生效, 由在线的 CA 执行

		RevokeCert(nodeid *ecdsa.PublicKey, ros ...RevokeObj) (Crl, error)

		// 向指定节点同步撤销列表
		GetCRLs(*ecdsa.PublicKey) ([]Crl, error)

		// 这个功能只对 CA 开放，获取本地证书库中全部有效的证书
		// 主要是为执行撤销时使用
		GetCERTs() ([]Cert, error)

		GetAlibp2pCA() Alibp2pCA
	}

	Alibp2pCA interface {
		SetCert(peer.ID, Cert) error
		GetCert(peer.ID) (Cert, error)
		GetCertByID(ID) (Cert, error)
		// 创建 RCA 直接存入磁盘,注意 RCA 在同一个实例上只能存在一份
		// 创建 RCA 的前提是拥有一个 S256 私钥，作为节点身份，并把 S256 公钥放入 subj.CommonName
		GenRootCA(pwd string, subj *certool.Subject) error
		// 获取 RCA/ICA 信息
		GetCA(pwd string) (*certool.CA, error)
		// 导出 RCA/ICA : key 和 crt 混合在一起，需要妥善保存
		ExportRootCA(pwd string) (Pem, error)
		// 导入 RCA/ICA : key 和 crt 混合在一起
		ImportRootCA(pwd string, data Pem) error
		// 生成私钥，如果 subj != nil 则顺便生成 csr
		GenKey(pwd string, subj *certool.Subject) (Key, Csr)
		// 根据 Csr 主动签发证书，通常用来生成 ICA
		GenCertByCsr(pwd string, csr Csr, isCA bool, expire int) (Cert, error)
		// 已签发的证书列表
		ListCert() []*Summary
		// 接受证书请求
		CsrHandler(csr Csr) (ID, error)
		// 如果 error != nil, 则标示拒绝了
		CsrStatus(id ID) (CSR_STATE, error)
		// 待签发证书请求列表
		ListCsr() []*Summary
		// 接受Csr，过期时间 expire 单位为 年
		AcceptCsr(id ID, expire int, rootKeyPwd string) (Cert, error)
		// 不接受证书请求，并拒绝签发
		RejectCsr(id ID, reason string) (Csr, error)
		// 主动撤销已签发的证书
		RevokeCert(pwd string, certs ...Cert) (Crl, error)

		/*
			接收用户发起的撤销请求,用户需要对证书进行签名
			这里只对撤销进行签名，但是并不对撤销结果进行广播，需要额外的处理逻辑
			----------------------------------------------------------
			撤销签名规则：
				证书中的 CommonName 存放了证书所有者的 ECS256 pubkey 的 hex ,
				想要撤销时需要使用 ECS256 privateKey 对证书 SerialNumber 进行签名，
				合并签名结果 revokeSign = append(R,S)

				方法实现时需要对以上规则进行校验
		*/
		RevokeService(pwd string, ros ...RevokeObj) (Crl, error)

		/*
			更新 keychain 的触发条件是创建 CA 服务时放入 RootCA ，
			每当有新的 ICA 收到更新的广播时再来更新 ICA
			更新 keychain 属于网络共识层面的功能，不需要做过多的验证，保持一致即可
			// TODO 这里有一个问题是，能否撤销一个 ICA，如何撤销 ICA
		*/
		UpdateKeychain(cert Cert, action ...KeychainAction) error

		GetKeychain() certool.Keychain
		SetKeychain(certool.Keychain) error
		/*
			更新 CRL 属于网络共识层面的功能，验证有效性并保持一致
			-----------------------------------------------
			CRL 的数据结构是 crl = {sign:ca_sign,snl:[certSn,...]}
			所以存储 CRL 时我们要先存储 hash(CRL) = CRL, 再去索引 sn = hash(CRL)
		*/
		UpdateCRL(crl Crl) error
		ListCRL() ([]*CrlSummary, error)

		// 这个功能只对 CA 开放，获取本地证书库中全部有效的证书
		// 主要是为执行撤销时使用
		listCRT() ([]string, error)

		// 检查一个证书是否被撤销, err == nil 为被撤销， err != nil 为未撤销
		IsRevokeCert(cert Cert) error

		Event() Event

		Backup(pwd string) ([]byte, error)

		Restore(pwd string, db []byte, outdir string) error
	}

	// 可以在此处定义事件，并指定事件回调函数
	Event interface {
		OnUpdateCRL(fn func(Crl))
		OnUpdateKeychain(fn func(Cert, KeychainAction))
	}
)
