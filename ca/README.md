# CRD SurePKI 

## 名词解释

|名词|解释|
|:----|:----|
|PKI|Public Key Infrastructure 公钥基础设施，一个典型的PKI系统包括PKI策略、软硬件系统、证书机构CA、注册机构RA、证书发布系统和PKI应用等。|
|CA|Certificate Authority证书颁发机构,即颁发数字证书的机构。是负责发放和管理数字证书的机构|
|RootCA / RCA|Root Certificate Authority持有根证书的证书颁发机构|
|ICA|Intermediate Certificate Authority 持有中间证书的证书办法机构，中间证书由根证书签发|
|CSR|Certificate Signing Request 证书签发请求|
|CAL|Certificate Authority Lists 证书办法机构列表，包括根证书和中间证书|
|CRL|Certificate revocation Lists 证书废除列表，又称证书黑名单|
|Bootnode|网络中任何一个节点都可以充当 Bootnode 角色，相当于一个介绍人，介绍一个新的节点进入网络|
|genesis|创世区块，每个链都有其独一无二的创世区块|
|peer|在CRD Utipia 的网络中节点间的关系分两种，一种是连接关系，一种是 peer 关系，当节点提供正确的 networkid 后即可确定连接关系，想升级为peer关系需要提供额外的握手条件|

## 前言

* 在联盟链中需要的并非传统 CA 公共服务，是否允许谁进入联盟链网络通常是由联盟的相关管理机构决定的，
传统 CA 公共服务的授权并不具备此信任基础，因此我们看到很多联盟链的方案中，CA 被设计成一个私有的独立的中心化服务，
区块链节点使用数字证书鉴权并与 PKI 体系兼容，但需要依赖外部的 CA 服务；

* 为了最大程度的简化 CA 的开发、部署与维护，以及最大程度保留系统的去中心化自制和安全与稳定性，
在 CRD evertrust 协议栈上将会提供去中心化 CA 服务。

* 本章将概述CRD evertrust 网络层为联盟链提供的更加优雅的 CRD SurePKI 解决方案。


## 现状

![图1](https://git.lug.ustc.edu.cn/cc14514/statics/raw/master/evertrust/images/ca/8.jpg)

>图1 是目前在联盟链中流行的 CA 服务架构，搭建联盟链时需要额外部署一套 中心化CA服务，
用户想加入联盟链网络需要先将证书请求发送到认证中心，如果联盟比较大，有多级认证体系时，
可能需要搭建多个这样的中心服务，增加了部署和维护成本，而且需要联盟链节点与链外数据源进行交互，
增加了不确定性和安全性问题；
>
>搭建和使用一套系统是十分复杂的工作，需要专门的技术人员进行操作和维护，为了确保服务的稳定与可靠需要额外付出很多代价；

## 目标

![图2](https://git.lug.ustc.edu.cn/cc14514/statics/raw/master/evertrust/images/ca/7.jpg)

>CRD SurePKI的目标是将提供一套更加简单和稳定的解决方案，将 CA 服务设计为标准模块嵌入在节点中，
提供此服务的 RCA/ICA 节点与联盟中的其他节点属于对等关系，即所有节点都可以申请成为 CA 节点，
为其组织内的普通节点提供证书的授权服务，上图中可以看到绿色的节点是符合规则的可以提供 CA 服务的角色，
其信息会被放入 CAL 被同步到每一个对等节点中，此时的 CAL = [RCA, ICA1, ICA2]，CAL的准确性和一致性由区块链来保证；
>
>当一个新的节点想要加入网络时，他可以任意找到一个节点作为 Bootnode 来进入网络并且获取 CAL ，
遍历 CAL 信息找到其组织对应的 CA 并提出入网申请，在得到证书后即可与网络中的节点进行握手并升级为 peer 关系，
之后便可同步账本使用区块链服务；

## 约定

__为完成 “目标” 我们需遵循如下约定，来使用数字证书和CRD SurePKI服务：__

* 联盟链只接受两级证书信任链，即一级RCA和第二级ICA；
* 二级中间证书不能再签发下一级中间证书，只能用于签发用户证书；
* 启动联盟链的第一个节点之前，要先生成根证书，并将根证书放入 genesis 区块中
* 用来生成证书的密钥使用 ECC 算法生成，并使用 P256 曲线
* 证书的 Subject.CommonName 需要填写正确的 ECC S256K1 公钥信息
* 证书模块会维护两个列表，CAL / CRL 分别代表合法的 CA 证书和已撤销的证书列表

## 治理规则

>在网络中一些持有 CA 私钥的节点可以提供 CA 服务，在创世节点中可以指定初始的 RootCA 集合，
如果想在 RootCA 集合中增加 RCA 角色节点，则需要全部 RCA 节点进行投票，
每一个 ICA 节点负责签发其组织内的 CSR，在网络中增加 ICA 角色时，也需要全部的 RCA 节点进行投票；

![图3](https://git.lug.ustc.edu.cn/cc14514/statics/raw/master/evertrust/images/ca/6.jpg)

>图3 描述了上述规则，其中 RootCA 集合成员 root2 分管 “组织r2” ，
org1.ica 和 org2.ica 是被 RootCA 投票产生的两个二级 CA 角色，分别管理 “组织org1” 和 “组织 org2”。
>
>如果联盟初始状态没有那么复杂的组织关系，可以弃用投票规则，只需要在 genesis 中指定单根证书即可，
当组织演化为有必要使用多个 RCA 时，只需要当前的 RCA 向 CAL 中添加新的 RCA 成员即可，
再次委任新 CA 时因为 RCA 数量大于 1 ，即会激活投票规则。

* 注：图中的连线表示的是节点证书与 CA 之间的关系，并非连接关系；

## 入网用例

![图4](https://git.lug.ustc.edu.cn/cc14514/statics/raw/master/evertrust/images/ca/5.jpg)

>图4 中概述了新节点 org1.x（黄色） 节点想要加入联盟链网络的基本交互过程，
我们假设此过程开始前节点已经完成了 “图2” 中描述的 “加入网络” 的步骤

1. getCAL : 随机选择对等节点 r2.CRD 获取 CAL ，此时 CAL = [root1, root2, rootN, org1.ica, org2.ica]，
当前节点属于组织 org1, 所以此处选择节点 org1.ica 提供服务；
2. sendCSR : 向目标 CA (org1.ica) 节点发送 CSR 申请证书；
3. getCRT : 收到审核通过的通知后，即可获取 CRT 证书；
4. Handshake : 得到合法的证书后去和其他节点进行握手，正式加入联盟。

## 功能描述

### 授权CA证书

> 根证书的持有人可以签发下一级的CA证书，可以主动制作证书也可以由节点提出申请，下图的交互描述了节点 D 主动申请成为 ICA 的过程

![图5](https://git.lug.ustc.edu.cn/cc14514/statics/raw/master/evertrust/images/ca/1.jpg)

1. 节点 D 使用 evertrust 节点提供的工具生成私钥和相应的 CSR;
2. 将 ICA.csr 发送给R (RCA) 进行申请，节点 R 的地址是通过 RCA 证书获取的;
3. 节点 R 收到 ICA.csr 后生成一个待处理的任务，需要人工参与审核，如果审核通过则签发 ICA.crt ，如果节点D在线则发送给节点D，
否则等待节点D拉取证书；
4. 节点 D 得到正确的 ICA 证书后，需要向全网广播自己的 ICA 身份，通过 Assert 块进行广播，可以重复广播，
直到同步到的 CAL 列表中包含自己为止；
5. 节点 B 此时为 M0 打块节点，将节点 D 广播过来的身份升级信息随 Commit 块广播到全网；
6. 每个收到新的 Commit 块的节点，都向自己的 CAL 列表中增加节点 D.

## 签发用户证书

>节点启动时，只要使用了正确的 genesis 和 bootnode 就可以加入到联盟链的网络中，
但是不能和 peer 进行握手，因为还没有得到正确的证书，需要完成下图描述的签发过程，才可以正式以 peer 身份加入网络

![图6](https://git.lug.ustc.edu.cn/cc14514/statics/raw/master/evertrust/images/ca/2.jpg)

1. 节点 A 启动时，节点发现 A 没有入网证书即生成 CSR 备用；
2. 通过 bootnode 接入网络，并随机找到了节点 C 去获取网络中最新的 CAL 列表;
3. 操作节点 A 的用户根据 CAL 列表的信息选择了向 ICA 节点 E 申请证书；
4. 节点 E 收到 A 的 CSR 后生成一个待处理的任务，需人工参与审核，审核通过则将 crt 发送给节点 A，或等待A来拉取;
5. 节点 E 将新签发的证书信息上报给 RootCA 节点 R.

## 撤销证书

>撤销证书的约定是根证书有权撤销所有证书，包括中间证书，中间证书只能撤销自己签发的用户证书；
更常见的撤销请求是由用户主动发起，例如将节点私钥丢失或者需要变更时，旧的证书则可进行撤销操作
>
>无论如何撤销的结果都是由CA节点以Assert的方式通知给打块节点，并随commit块同步到每个节点；
下图演示了RCA节点R撤销节点X的用户证书的过程：

![图7](https://git.lug.ustc.edu.cn/cc14514/statics/raw/master/evertrust/images/ca/3.jpg)

1. 节点 R 可管理全网的证书，假设 X 节点用户证书需要撤回，则 R 节点签发一个 CRL 请求，并以 Assert 方式发送给节点 B;
2. 节点 B 此时为 M0 打块节点，将节点 R 广播过来的撤销信息随 Commit 块广播到全网；
3. 每个收到新的 Commit 块的节点，都向自己的 CRL 列表中增加节点 X.
4. 每个节点更新完自己的 CRL 后都重新检查一遍自己的连接中是否有节点存在于 CRL 中，此时节点 C 发现 X 和自己处于 peer 关系，
则主动解除 peer 关系.

## 架构说明

![图8](https://git.lug.ustc.edu.cn/cc14514/statics/raw/master/evertrust/images/ca/9.jpg)

>架构图摘取了与 CRD SurePKI 相关的模块进行描述，该模块被设计成可插拔式的独立模块，
依赖于底层的 alibp2p 网络，同时为 p2p 模块提供服务，数据层使用了独立的 CaDB 数据库进行必要的持久化操作.

## 接口设计

![图9](https://git.lug.ustc.edu.cn/cc14514/statics/raw/master/evertrust/images/ca/10.png)

三个接口之间依赖关系如图所示，集成应用时主要使用 `Alibp2pCAService` 进行节点间交互

### Alibp2pCAService

>此接口主要用来实现节点间的交互，

```go
// 去中心 CRD SurePKI 服务入口
type Alibp2pCAService interface {

	// 启动服务
	Start() error

	// 如果是 CA 角色，需要先解锁私钥以便执行签发任务
	UnlockCAKey(pwd string) error

	// 对 CSR 进行签发
	AcceptCsr(id ID, expire int) (Cert, error)

	// 检查一个节点是否在线，通常是用 Client 端来 Ping CA 节点
	Ping(*ecdsa.PublicKey) (PingMsg, error)

	// 获取被认可的 CA 列表，可以跟网络中的其他节点索取，如果 参数为 nil 则是获取本地已保存的
	GetCAL(*ecdsa.PublicKey) (certool.Keychain, error)

	// 向 CA 提交 CSR 请求，第一个参数使用 CA 在网络中的节点地址公钥
	SendCsr(*ecdsa.PublicKey, Csr) (ID, error)

	/*
		向 CA 提交 CSR 状态查询请求，第一个参数使用 CA 在网络中的节点地址公钥
        你的 CSR 发给哪个 CA 就要到哪个 CA 进行查询
		------------------------------------------------------------
			CSR_STATE_REJECT   CSR_STATE = "REJECT"   // 拒绝
			CSR_STATE_NORMAL   CSR_STATE = "NORMAL"   // 待处理
			CSR_STATE_PASSED   CSR_STATE = "PASSED"   // 通过
			CSR_STATE_NOTFOUND CSR_STATE = "NOTFOUND" // 不存在
	*/
	CsrStatus(*ecdsa.PublicKey, ID) (CSR_STATE, error)

	// 当 CSR 状态为 CSR_STATE_PASSED 时，就可以用 ID 跟 CA 获取 CRT 了
	GetCert(*ecdsa.PublicKey, ID) (Cert, error)

	// 申请撤销, 立即生效, 由在线的 CA 执行
	RvokeCert(nodeid *ecdsa.PublicKey, cert Cert, sign []byte) (Crl, error)

	// 在指定的节点上下载撤销列表，新用户接入网络时可以使用此接口获取 CRL 
	GetCRLs(*ecdsa.PublicKey) ([]Crl, error)
    
    // 非交互性 API，本地接口 
	GetAlibp2pCA() Alibp2pCA
}
```

### Alibp2pCA

>提供关于密钥和证书的本地操作API，以实现证书的生成、签发、撤销等原子功能功能，CRD SuperPKI 的服务可以通过组合不同的功能来进行实现 

```go
type Alibp2pCA interface {
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
	RvokeCert(pwd string, certs ...Cert) (Crl, error)

	/*
		接收用户发起的撤销请求,用户需要对证书进行签名
		这里只对撤销进行签名，但是并不对撤销结果进行广播，需要额外的处理逻辑
		----------------------------------------------------------
		撤销签名规则：
			证书中的 CommonName 存放了证书所有者的 ECS256 pubkey 的 hex ,
			想要撤销时需要使用 ECS256 privateKey 对证书 SerialNumber 进行签名，
			合并签名结果 rvokeSign = append(R,S)

			方法实现时需要对以上规则进行校验
	*/
	RvokeService(pwd string, cert Cert, rvokeSign []byte) (Crl, error)

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

	// 检查一个证书是否被撤销, err == nil 为被撤销， err != nil 为未撤销
	IsRvokeCert(cert Cert) error

	Event() Event
}
```

### Event 

>为 `Alibp2pCA` 定义的事件接口，可以注册事件用来得到 CRL 和 CAL 的变更通知 

```go
// 可以在此处定义事件，并指定事件回调函数
type Event interface {
	OnUpdateCRL(fn func(Crl))
	OnUpdateKeychain(fn func(Cert, KeychainAction))
}
```

