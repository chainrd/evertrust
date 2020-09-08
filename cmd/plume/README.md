## Plume 使用手册

### 编译

>进入 `CRD-chain` 执行 `make plume` 即可将轻节点编译到 `build/bin/plume`

```
$> make plume
......

$> build/bin/plume --help
NAME:
   Plume - A new cli application

USAGE:
   plume [global options] command [command options] [arguments...]

VERSION:
   v0.0.1-beta

DESCRIPTION:
   Light Node for CRD evertrust Blockchain

AUTHOR:
   cc14514@icloud.com

COMMANDS:
     attach   attach to console
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --bootnodes value, -b value  节点的 URL 集合, 多个节点时用 ',' 分隔
   --networkid value, -n value  网络id，必须与全节点保持一致 (default: 111)
   --rpcport value, -p value    http 协议的 rpc 接口 (default: 18545)
   --port value                 节点端口，默认使用随机端口 (default: 0)
   --trusts value, -t value     信任节点的 ID 集合，如自己公司部署的全节点, 多个节点时用 ',' 分隔, 注意区别于 bootnodes 这里只是 ID 的集合
   --homedir value, -d value    数据目录 (default: "{$HOME}/.plume")
   --relay, -r                  turn on relay serve of current node
   --inbound, -i                enable inbound , may be just for bridge node
   --verbosity value            Logging verbosity: 0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=detail (default: 3)
   --help, -h                   show help
   --version, -v                print the version
```

### 启动

>启动轻节点至少应当设置 `bootnode` 和 `networkid`，此时默认的 `rpcport` 为 `18545`（给 web3 API 使用），
>轻节点的 `p2p` 端口不对外提供服务，所以使用随机端口，

```
$> build/bin/plume -b /ip4/10.0.0.116/mux/5978:11112/ipfs/16Uiu2HAm39zRzVr5JK6P1WCba7ew8L5CBT4r5e3wcZ8V2zQRvWSM -n 555

---- service config ---->
bootnodes : [/ip4/10.0.0.116/mux/5978:11112/ipfs/16Uiu2HAm39zRzVr5JK6P1WCba7ew8L5CBT4r5e3wcZ8V2zQRvWSM]
trusts : []
networkid : 555
port : 0
rpcport : 18545
enable relay : false
enable inbound : false
home dir : /Users/liangc/.plume
---- service config ----<

INFO [04-07|11:14:11.052|CRD-chain/p2p/alibp2p.go:520] alibp2p::alibp2p-loglevel =>             env=3 ret=3
11:14:11.054  INFO    alibp2p: [0] listen on /ip4/127.0.0.1/tcp/58139/ipfs/16Uiu2HAmP2XdiFRWg7XKLe7i18wPPkU9vefWSSwntUHfCLzomx3f impl.go:130
11:14:11.055  INFO    alibp2p: [1] listen on /ip4/10.0.0.76/tcp/58139/ipfs/16Uiu2HAmP2XdiFRWg7XKLe7i18wPPkU9vefWSSwntUHfCLzomx3f impl.go:130
......

```

### Web3 API

endpoint : http://localhost:18545

>轻节点启动后可以直接使用 web3 兼容的 SDK 设置 endpoint ，
>即可使用 evertrust 链的功能，但并不是所有 API 都可以通过 Plume 访问，
>这里需要满足 `白名单-黑名单` 的约束,白名单中开放了 `eth` 模块的全部 `API`,
>又通过黑名单限制了 `accounts,sendTransaction,sign,signTransaction,sendIBANTransaction`
>这组 API ，具体如下： 

```go
whitelist := map[string]string{
	"eth":    "*",
	"txpool": "*",
	"web3":   "*",
	"rpc":    "modules",
}
blacklist := map[string]string{
	"eth": "accounts,sendTransaction,sign,signTransaction,sendIBANTransaction",
}
```

### 本地节点管理 API

endpoint : http://localhost:18545/admin

>轻节点对本地提供了 `JSONRPC` 接口来使用 `Admin API`, 包含下列功能:

* Config 查看当前节点配置
* Myid 获取当前节点信息
* Conns 获取当前网络连接信息
* Findpeer [id] 查找 id 对应的 addr 信息
* Connect [id/url] 连接一个 id 或 url
* Findproviders [limit] 获取已经 advertise 的 fullnode 列表, limit 为可选参数
* Fnodes 查看当前的 fnodes 集合提供服务的节点信息
* Report 查看网络资源使用情况

>在 PC 端可以直接通过 `attach` 子命令登陆到 `local admin console` 来使用 `Admin API`, 
>或者直接用 `console` 子命令启动节点；

#### admin 模块

##### 节点配置信息 (config)

* request

```json
{"id":"1e55d0d2-a47b-457e-94ad-f99e6b3b2474","method":"admin_config"}
```

* response
```json
{
  "result": {
    "bootnodes": [
      "/ip4/10.0.0.116/mux/5978:11112/ipfs/16Uiu2HAm39zRzVr5JK6P1WCba7ew8L5CBT4r5e3wcZ8V2zQRvWSM"
    ],
    "networkid": 555,
    "rpcport": 18545,
    "homedir": "/Users/liangc/.plume"
  },
  "Id": "1e55d0d2-a47b-457e-94ad-f99e6b3b2474"
}
```

##### 节点ID (myid)

* request

```json
{"id":"f386f6fb-53b4-4d69-b6dd-e77a8c0520eb","method":"admin_myid"}
```

* response

```json
{
  "result": {
    "Id": "16Uiu2HAmP2XdiFRWg7XKLe7i18wPPkU9vefWSSwntUHfCLzomx3f",
    "addrs": [
      "/ip4/127.0.0.1/tcp/60463",
      "/ip4/10.0.0.76/tcp/60463"
    ]
  },
  "id": "f386f6fb-53b4-4d69-b6dd-e77a8c0520eb"
}
```
##### 连接信息 (conns)

* request

```json
{"id":"33faf61e-8962-4906-8acd-04bc73f19eb2","method":"admin_conns"}
```

* response

```json
{
  "result": {
    "TimeUsed": "602.009µs",
    "Total": 10,
    "Direct": [
      {
        "ID": "16Uiu2HAmAtCTfawR2qUML68qgUMKkR6xEZL9LHN8P656LwYd77rw",
        "Addrs": [
          "/ipfs/16Uiu2HAmAtCTfawR2qUML68qgUMKkR6xEZL9LHN8P656LwYd77rw",
          "/ip4/127.0.0.1/tcp/11112",
          "/ip4/127.0.0.1/mux/5978:11112",
          "/ip4/10.0.0.125/tcp/11112",
          "/ip4/172.17.0.1/tcp/11112",
          "/ip4/10.0.0.125/mux/5978:11112",
          "/ip4/172.17.0.1/mux/5978:11112"
        ],
        "Inbound": false
      }
    ],
    "Relay": {}
  },
  "id": "33faf61e-8962-4906-8acd-04bc73f19eb2"
}
```

##### 查找节点 (findpeer) 

* request

```json
{
  "id": "a8165440-f298-4d9a-9bca-8a58bbb5f213",
  "method": "admin_findpeer",
  "params": [
    "16Uiu2HAmAtCTfawR2qUML68qgUMKkR6xEZL9LHN8P656LwYd77rw"
  ]
}
```

* response

```json
{
  "result": {
    "Id": "16Uiu2HAmAtCTfawR2qUML68qgUMKkR6xEZL9LHN8P656LwYd77rw",
    "addrs": [
      "/ip4/172.17.0.1/mux/5978:11112",
      "/ipfs/16Uiu2HAmAtCTfawR2qUML68qgUMKkR6xEZL9LHN8P656LwYd77rw",
      "/ip4/127.0.0.1/tcp/11112",
      "/ip4/127.0.0.1/mux/5978:11112",
      "/ip4/10.0.0.125/tcp/11112",
      "/ip4/172.17.0.1/tcp/11112",
      "/ip4/10.0.0.125/mux/5978:11112"
    ]
  },
  "id": "a8165440-f298-4d9a-9bca-8a58bbb5f213"
}
```

##### 连接节点 (connect)

* request

```json
{
  "id": "2d350811-e91a-498d-b114-905bdf879289",
  "method": "admin_connect",
  "params": [
    "16Uiu2HAmAtCTfawR2qUML68qgUMKkR6xEZL9LHN8P656LwYd77rw"
  ]
}
```

* response

```json
{"result":"success","id":"2d350811-e91a-498d-b114-905bdf879289"}
```

##### 提供服务的全节点 (findproviders) 

* request

```json
{
  "id": "392fc699-3ccc-40f9-ac1f-b02c6eaeb86c",
  "method": "admin_findproviders",
  "params": [
    "3"
  ]
}
```

* response

```json
{
  "result": {
    "nodes": [
      "16Uiu2HAkuxQ291PQfGFLuPH4EB2mJLtEW6Tak7sQwJui9SLciejG",
      "16Uiu2HAm8JtrYV4cq94PYh3tzMhDFtMBv3CuLSGNmiVpv7V1awUA",
      "16Uiu2HAmC53oXbgnsW4a6JniiUU7avhLkSjCBboLFFvyBp4Lzeev"
    ],
    "total": 3
  },
  "id": "392fc699-3ccc-40f9-ac1f-b02c6eaeb86c"
}
```

##### 考核通过的全节点 (fnodes)

* request

```json
{"id":"85b3518b-515a-409a-9127-72f3556d6f9e","method":"admin_fnodes"}
```

* response

```json
{
  "result": {
    "nodes": [
      {
        "Id": "16Uiu2HAkwFoCfMgXLLbHWkA4mwQtTLs4d43DtWLjxj1cZsX2eGWo",
        "Ttl": 15702150
      },
      {
        "Id": "16Uiu2HAkuxQ291PQfGFLuPH4EB2mJLtEW6Tak7sQwJui9SLciejG",
        "Ttl": 15912172
      },
      {
        "Id": "16Uiu2HAm39zRzVr5JK6P1WCba7ew8L5CBT4r5e3wcZ8V2zQRvWSM",
        "Ttl": 26164640
      },
      {
        "Id": "16Uiu2HAmLwEpfEeehAfpkJpS5PuYGr5Y7mQjY17632aS92FkjjJ3",
        "Ttl": 26319503
      },
      {
        "Id": "16Uiu2HAm91nQQDzcRLXoojbeyrnrjodaDemv7xafFPsmZKTnrW9P",
        "Ttl": 26404734
      }
    ],
    "trusts": null
  },
  "id": "85b3518b-515a-409a-9127-72f3556d6f9e"
}
```

##### report 

* request

```json
{"id":"8a01d377-cd31-40e0-b95d-4aed9981b437","method":"admin_report"}
```

* response

```json
{
  "result": {
    "detail": {
      "bw": {
        "rate-in": "59.50",
        "rate-out": "2595.63",
        "total-in": "604734",
        "total-out": "455671"
      },
      "msg": {
        "avg-in": "0.00",
        "avg-out": "0.00",
        "total-in": "0",
        "total-out": "62"
      },
      "rw": {
        "avg-in": "1.43",
        "avg-out": "1.43",
        "total-in": "1377",
        "total-out": "679"
      }
    },
    "time": "2020-04-07 15:21:31"
  },
  "id": "8a01d377-cd31-40e0-b95d-4aed9981b437"
}
```

#### account 模块

##### create 

* request

```json
{"id":"fafd1147-9a58-41b0-99df-c627cff4b9cf","method":"account_create","params":["123456"]}
```

* response

```json
{
  "id": "fafd1147-9a58-41b0-99df-c627cff4b9cf",
  "result": "0x60b86F6318CdBCD38B087e4076B151c994F143a2"
}
```

##### delete

* request

```json
{
  "id": "1698e2ad-43c0-43bb-9e1f-486a9e2f07cc",
  "method": "account_delete",
  "params": [
    "0x60b86F6318CdBCD38B087e4076B151c994F143a2",
    "123456"
  ]
}
```

* response

```json
{"result":"success","id":"1698e2ad-43c0-43bb-9e1f-486a9e2f07cc"}
```

##### list

* request

```json
{"id":"aa17863a-a5ff-4737-a4e4-cb8af8c3da7a","method":"account_list"}
```

* response

```json
{
  "id": "61b55a11-f1bc-4699-b007-3dd98b33cee3",
  "result": [
    "0x3BB3EC9eFCc1F3f9E4dAd75f51dB875993aa484F",
    "0xE481dA82D47fb4372dE27Dc3Be94F148051e1b1a",
    "0x60b86F6318CdBCD38B087e4076B151c994F143a2"
  ]
}
```

##### signtx

* request

```json
{
  "id": "991ad27e-34e1-4f18-8a90-29a1db31ed22",
  "method": "account_signtx",
  "params": [
    {
      "from": "0x3BB3EC9eFCc1F3f9E4dAd75f51dB875993aa484F",
      "to": "0xe481da82d47fb4372de27dc3be94f148051e1b1a",
      "value": "2000000000000000000",
      "gas": "21000",
      "gasprice": "18000000000",
      "nonce": "1",
      "input": "0x",
      "chainid": "739",
      "passwd": "123456"
    }
  ]
}
```

* response

```json
{
  "result": "0xf85f010b0194e481da82d47fb4372de27dc3be94f148051e1b1a6580820102a00ae1d0521fcec7668a30cc59f4775707751b44ad07658e58c2d17bfcac714c2da03a5be3c6e890b34548fda59ecbf7661227570c18931e00d6ddc03f051b8cadcb",
  "id": "991ad27e-34e1-4f18-8a90-29a1db31ed22"
}
```

### Console

>在 `PC` 端使用 `plume` 时可以通过 `attach` 子命令登陆到一个已经启动的节点控制台，并执行 `Admin API`

```
$> build/bin/plume attach
----------------------------------
 Plume Console, Rpcport 18545
----------------------------------

$> help
-------------------------------------------------------------------------
# 当前 shell 支持以下指令
-------------------------------------------------------------------------
config 查看当前节点配置
myid 获取当前节点信息
conns 获取当前网络连接信息
findpeer [id] 查找 id 对应的 addr 信息
connect [id/url] 连接一个 id 或 url
findproviders [limit] 获取已经 advertise 的 fullnode 列表, limit 为可选参数
fnodes 查看当前的 fnodes 集合提供服务的节点信息
report 查看网络资源使用情况

exit 退出 shell

$> myid
{
	"Id": "16Uiu2HAmP2XdiFRWg7XKLe7i18wPPkU9vefWSSwntUHfCLzomx3f",
	"addrs": [
		"/ip4/127.0.0.1/tcp/60463",
		"/ip4/10.0.0.76/tcp/60463"
	]
}
```

### 移动端

* 在移动端使用 `Plume` 节点时要为 `App` 分配网络权限

>静态库提供了 `Admin API` ，遵循 `JSONRPC2.0` 规范，如果返回的错误消息 `error.code = -1` 则表示为一个系统错误，
>本地节点发生故障，如下消息为异常消息的统一处理模版：
```json
{
   "id": "foo",
   "error": {
     "code": "-1",
     "message": "error detail"
   }
 }
```
#### IOS 

编译环境:

* Xcode : Version 11.4 (11E146)
* Golang : go1.14.1 darwin/amd64 
* gomobile : version +4c31acb Sun Mar 29 12:56:38 2020 +0000 (android,ios);

>在 `CRD-chain` 目录执行 `make plume-ios` 会在 `build/bin/` 目录得到静态库 `plume.framework`;
>将其导入 `IOS App` 即可, 下面给出了 `Swift` 调用 `Plume` 的 `demo`  

```swift
import UIKit
import Plume

class ViewController: UIViewController {

    var web: web3!
    let port = 12345
    let contractAddress = "合约地址"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        startPlume()
        setWeb3()
    }
    
    //启动轻节点
    private func startPlume() {
        guard let path = NSSearchPathForDirectoriesInDomains(FileManager.SearchPathDirectory.documentDirectory, FileManager.SearchPathDomainMask.userDomainMask, true).first else{
            return
        }

        let bootnodes = "/ip4/10.0.0.252/mux/5978:30200/ipfs/16Uiu2HAm39zRzVr5JK6P1WCba7ew8L5CBT4r5e3wcZ8V2zQRvWSM"
        let trusts = ""
        let networkid = 739
        PlumeStart(bootnodes, trusts, path, Int64(networkid), port)
    }
    ......
}
```

### Android

编译环境:

* Golang : go1.14.1 darwin/amd64 
* gomobile : version +4c31acb Sun Mar 29 12:56:38 2020 +0000 (android,ios);
* Android SDK Platform-Tools : v29.0.6
* Android NDK : r21

>在 `CRD-chain` 目录执行 `make plume-android` 会在 `build/bin/` 目录得到静态库 `plume.aar`;
>将其导入 `Android App` 即可, 下面给出了 `Java` 调用 `Plume` 的 `demo`  

__导入 plume.aar：__

1. 在 `app/build.gradle` 中增加 `repositories`, 与  `dependencies` 同级

```
repositories {
    flatDir(
            dirs: 'libs'
    )
}
```

2. 在 `app/build.gradle` 的 `dependencies` 的 `fileTree` 属性中增加 `*.aar`

```
implementation fileTree(dir: 'libs', include: ['*.jar','*.aar'])
```

3. 将 `plume.aar` 复制到 `app/libs` 目录中

__启动__

>建议将 Plume 启动在 Application 或者 Service 级别, 并定时检查状态以便重启；

```
import plume.Plume;
......
    String bootnodes = "/ip4/10.0.0.76/tcp/10000/ipfs/16Uiu2HAm39zRzVr5JK6P1WCba7ew8L5CBT4r5e3wcZ8V2zQRvWSM";
    String trusts = "";
    long networkid = 111;
    long rpcport = 28545;
    String homedir = getFilesDir().getAbsolutePath().toString();
    Plume.start(bootnodes, trusts, homedir, networkid, rpcport);
......
```
