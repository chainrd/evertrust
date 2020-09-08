#ERC20 Exange 设计

## 原型目标

>实现去中心化 ERC20 代币在 evertrust 上自由交换，为此 evertrust 应提供如下功能：

* 提供 ERC20 合约注册表，在合约部署时系统自动拦截 ERC20 合约并将地址信息填入注册表，并对外提供获取注册表信息功能；

* 提供挂单功能，ASK / BID 分别对应卖单和买单，挂单时价格以交易区价格为基准，例如在 A 交易区的 B/A 交易对，挂 “ASK单” 价格为 600B/200A 时,
表示要卖出 600B 换回 200A，挂 “BID单” 价格为 100A/300B 时，表示要用 100A 的价格买入 300B, 关于挂单价格我们不能使用小数，因为在去中心化
合约中完成交易，合约并不支持浮点数，所以我们要以明确的兑换比例来表示价格; 

* 提供按 “交易对” 归类检索挂单列表功能。例如：假设当前存在 A、B、C、D 四个交易区，想要查看 A 交易区时，提供 B/A 、C/A、D/A 三组交易对，
进而可以通过交易对 B/A 来检索当前 B/A 的 ASK/BID 列表；

* 提供自动撮合功能，当某组 ASK / BID 符合撮合条件时，生成撮合任务，并在下一个区块中进行撮合交易，撮合交易需要由系统自动完成，
买卖双方不用再次参与确认；



## 内置合约

### 结构定义

>内置合约结构初步设计如下图,合约内部的数据大概分成3个部分，
其中“ERC20交易对”并非复制的冗余数据，而是对 “ERC20注册表” 数据的加工和引用，图中例举了挂单与生成注册表的简单示例：

![1](https://git.lug.ustc.edu.cn/cc14514/statics/raw/master/evertrust/images/pointsexange/1.png)


* ERC20 注册表 : 部署 ERC20 合约 D 到 evertrust 时系统将自动添加 D 的合约地址到注册表，此步骤无需用户参与；

* Ledger 充值账本 : 当用户将 erc20 points 转给 pointsexange 地址时，触发充值账本的记账功能，可以通过 balanceOf 查询余额;

* ERC20 交易对 : 当这册表的合约数量大于等于2以后，就可以加工成交易对，注册表中的每个合约都可以单独成为一个交易区，跟其他合约的交换称作交易对，
例如想要进入 A 区 A 和 B 的交易对则需要选择 “A 区”-> “B/A 交易对”；

* 挂单列表 : 上图中通过 BID / ASK 接口的调用分别在挂单列表 “BID A->B” 和 “ASK B->A” 中产生了两条挂单数据，顺序是 BID 
在前，ASK 在后，所以可以看到编号为 1 的 “触发撮合” 并不会产生撮合任务，而编号为 2 的 “触发撮合” 会产生两笔撮合任务，分别对应 BID 列表按价格
倒序的前两条数据；

* 触发撮合 : 此处的触发撮合是产生撮合任务，当区块的打包人发现有撮合任务需要执行时，才会具体的触发撮合流程；



### 接口定义

#### 关于充值

>pointsexange 合约使用类似交易所的模式，需要用户主动向 `address = 0x1504e9D3741b8a5449A42953AF4137079108Eb00` 的地址进行一次 
`erc20` 的 `transfer` 操作表示充值，例如：假设 `A` 是 `erc20` 合约，`U1` 用户发起 
`A.transfer("0x1504e9D3741b8a5449A42953AF4137079108Eb00",amount)` ，
这个请求会触发 `pointsexange` 合约中生成账本数据 `U1:{A:amount}`.


#### 接口与事件

> 接口符合 web3 的 ABI 规范，可以抽象成 solidity contract，并可以直接使用

代码：

```
contract exange {

    /*
    列出当前链上符合 ERC20 接口规范的合约地址列表, 开发者可以根据列表来生成交易对
    例如：
        pointslist 返回 [A,B,C,D]
        以 A 为交易区，我们可以展示 B/A 、C/A、D/A 三个交易对

        后面的接口参数中，我们会用 `address region` 表示交易区，`address target` 表示交易目标，
        交易对 `B/A` 等价于 `{region:A , target:B}`
    */
    function pointsList() public view returns (address[] memory);

    /*
    根据 ERC20 合约地址，获取摘要信息，可以用在展示交易区和交易对时使用
    */
    function pointsInfo(address) public view returns (string memory name, string memory symbol, uint256 totalSupply, uint8 decimals);

    /*
    挂买单
    参数说明：
        region : 交易区 erc20 合约地址
        target : 交易目标 erc20 合约地址
        regionAmount : 想要用 regionAmount 个 region points 换取 targetAmount 个 target points
        targetAmount : 想要用 regionAmount 个 region points 换取 targetAmount 个 target points

        由于合约不能直接处理浮点数，所以这里的兑换价格需要开发者自行计算,
        在精度相等时 price = regionAmount / targetAmount，否则需要先除精度
    */
    function bid(address region, address target, uint256 regionAmount, uint256 targetAmount) public payable;

    /*
    挂卖单
    参数说明：
        region : 交易区 erc20 合约地址
        target : 交易目标 erc20 合约地址
        regionAmount : 想要用 targetAmount 个 target points 换取 regionAmount 个 region points
        targetAmount : 想要用 targetAmount 个 target points 换取 regionAmount 个 region points
    */
    function ask(address region, address target, uint256 regionAmount, uint256 targetAmount) public payable;

    /*
    撤销订单(ask/bid)
        订单在达到 final 状态之前均可以撤销，撤销后状态变为 final 即不再参与撮合
    */
    function cancel(uint256 id) public payable;

    /*
    查询余额，根据 erc20 合约地址查询在 pointsexange 中的余额，
    余额是通过向 pointsexange 合约地址充值 region 对应的 points 得来的
    例如：
        用户 U 持有 A 资产，则 U 去执行 A.transfer(pointsexange.address,amount) 成功后，
        用户 U 再去执行 pointsexange.balanceOf(A) 时将会得到 (A.name,A,symbol,amount,decimals) 元组
    */
    function balanceOf(address region) public view returns (string memory name, string memory symbol, uint256 balance, uint8 decimals);

    /*
    余额提现，只要 balanceOf 能查询出来的余额都可以提现
    还以用户 U 和资产 A 来举例，提现操作相当于 A.transfer(U,pointsexange.balanceOf(A).balance)
    */
    function withdrawal(address region, uint256 amount) public payable;

    /*
    查询挂单列表，在指定的交易对上进行查询，只返回订单 ID 列表，
    注意不要修改列表顺序，列表已经按价格进行排序，ask 单是升序，bid 单是降序
    参数：
        orderType : 订单类型，可选值为 "bid" / "ask" 分别表示 买单 / 卖单
        region : 交易区 erc20 合约地址
        target : 交易目标 erc20 合约地址
    */
    function orderlist(string memory orderType, address region, address target) public view returns (uint256[] memory);

    /*
    获取订单详情
    详情包含了挂单时的全部信息，同时还包含了订单的当前状态，
    其中 regionComplete / targetComplete 是当前已经撮合成的数量
    isFinal == true 时表示订单为最终转改，不再参与撮合
    两种情况会让订单变为最终状态，一是撮合完成，二是撤单
    */
    function orderinfo(uint256 id) public view returns (
        string memory orderType,
        address region, address target,
        uint256 regionAmount, uint256 targetAmount,
        uint256 regionComplete, uint256 targetComplete,
        uint8 regionDecimals, uint8 targetDecimals,
        bool isFinal,
        address owner
    );
    /*
    查询我挂过的订单 (bid & ask)
    参数：
        addrs : 是一个数组，其长度必须是 1 或 3,
                是 1 时 addrs = [owner] 表示查询 owner 的全部挂单信息
                是 3 时 addrs = [owner,region,target] 表示查询 owner 在 target/region 交易区的挂单信息
        pageNum : 分页检索时用来表示页号，每页20条信息；
                TODO 目前没有实现分页，传 1 即可返回全部信息
    */
    function ownerOrder(address[] memory addrs, uint256 pageNum) public view returns (uint256[] memory);

    /*
    此事件记录订单状态变化，在撮合时触发，无论是否为最终状态都会触发
    记录被撮合的订单变化信息，主要包括如下属性
            ( orderid, owner, region, rc, regionAmount, target, tc, targetAmount )
      分别对应：
            ( 订单id, 订单创建人, 交易区, 操作(加/减), 交易区资产数量, 目标资产, 操作(加/减), 目标资产数量 )
      例如：
            (111,"0x1","0xA",+1,100,"0xB",-1,200)
            表示 111 这个订单成交信息为 A 资产增加 100, B 资产减少 200
            从这个资产变化甚至可以看出 111 是一个 ask 单，本次撮合卖出了 200B 收获了 100A
    */
    event Combination(uint256 indexed orderid, address indexed owner,
        address region, int8 rc, uint256 regionAmount,
        address target, int8 tc, uint256 targetAmount
    );
    // 此事件在挂买单成功时触发，用来通知 dapp 有新的买单产生
    event Bid(address indexed owner, uint256 indexed orderid);
    // 此事件在挂卖单成功时触发，用来通知 dapp 有新的卖单产生
    event Ask(address indexed owner, uint256 indexed orderid);
}
```

ABI：
```json
[{"constant":false,"inputs":[{"name":"region","type":"address"},{"name":"target","type":"address"},{"name":"regionAmount","type":"uint256"},{"name":"targetAmount","type":"uint256"}],"name":"ask","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":false,"inputs":[{"name":"region","type":"address"},{"name":"target","type":"address"},{"name":"regionAmount","type":"uint256"},{"name":"targetAmount","type":"uint256"}],"name":"bid","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":false,"inputs":[{"name":"id","type":"uint256"}],"name":"cancel","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"constant":false,"inputs":[{"name":"region","type":"address"},{"name":"amount","type":"uint256"}],"name":"withdrawal","outputs":[],"payable":true,"stateMutability":"payable","type":"function"},{"anonymous":false,"inputs":[{"indexed":true,"name":"orderid","type":"uint256"},{"indexed":true,"name":"owner","type":"address"},{"indexed":false,"name":"region","type":"address"},{"indexed":false,"name":"rc","type":"int8"},{"indexed":false,"name":"regionAmount","type":"uint256"},{"indexed":false,"name":"target","type":"address"},{"indexed":false,"name":"tc","type":"int8"},{"indexed":false,"name":"targetAmount","type":"uint256"}],"name":"Combination","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"owner","type":"address"},{"indexed":true,"name":"orderid","type":"uint256"}],"name":"Bid","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"name":"owner","type":"address"},{"indexed":true,"name":"orderid","type":"uint256"}],"name":"Ask","type":"event"},{"constant":true,"inputs":[{"name":"region","type":"address"}],"name":"balanceOf","outputs":[{"name":"name","type":"string"},{"name":"symbol","type":"string"},{"name":"balance","type":"uint256"},{"name":"decimals","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"id","type":"uint256"}],"name":"orderinfo","outputs":[{"name":"orderType","type":"string"},{"name":"region","type":"address"},{"name":"target","type":"address"},{"name":"regionAmount","type":"uint256"},{"name":"targetAmount","type":"uint256"},{"name":"regionComplete","type":"uint256"},{"name":"targetComplete","type":"uint256"},{"name":"regionDecimals","type":"uint8"},{"name":"targetDecimals","type":"uint8"},{"name":"isFinal","type":"bool"},{"name":"owner","type":"address"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"orderType","type":"string"},{"name":"region","type":"address"},{"name":"target","type":"address"}],"name":"orderlist","outputs":[{"name":"","type":"uint256[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"addrs","type":"address[]"},{"name":"pageNum","type":"uint256"}],"name":"ownerOrder","outputs":[{"name":"","type":"uint256[]"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[{"name":"","type":"address"}],"name":"pointsInfo","outputs":[{"name":"name","type":"string"},{"name":"symbol","type":"string"},{"name":"totalSupply","type":"uint256"},{"name":"decimals","type":"uint8"}],"payable":false,"stateMutability":"view","type":"function"},{"constant":true,"inputs":[],"name":"pointsList","outputs":[{"name":"","type":"address[]"}],"payable":false,"stateMutability":"view","type":"function"}]
```

### 数据存储

> 数据事物统一，全部使用 StateDB 进行存储，主要涉及了 ERC20合约索引、订单、订单索引、用户账本 信息

#### ERC20合约索引

合约地址装入数组并 rlp 序列化存储在固定的 key 中，如 : 

```
key = hash("REG-IDX")
val = rlp([address1, address2, ..., addressN])
```

#### 订单信息

订单 id 的生成规则如下 :

```
id = keccak256(owner,nonce,"-ID")
```

订单对象的存储直接用 id 作为 key

```
key = order.id 
val = rlp(order)
```

#### 订单索引

订单索引中只记录 `订单id`，我们的 `订单id` 用 `big.Int` 来表示，存储时是 `[32]byte` 类型

orderlist 方法使用的索引

```
key = hash(keccak256(target,region,orderType))
val = rlp([[32]byte, [32]byte, ..., [32]byte])
```

ownerOrder 方法使用的索引有两种：

1: owner 的订单

```
key = hash(keccak256("OWNER-IDX",owner))
val = rlp([[32]byte, [32]byte, ..., [32]byte])
```

2: owner 不同交易对的订单 

```
key = hash(keccak256("OWNER-IDX",owner,region,target))
val = rlp([[32]byte, [32]byte, ..., [32]byte])
```

#### 用户账本

账本数据的生成是由 `from_addr` 用户在 `erc20addr` 中操作 `transfer` 向 `0x123` 转账时产生的

```
key = hash(keccak256("BALANCE",erc20addr,from_addr))
val = big.Int
```



## 撮合规则

> 撮合在挂单的同时会自动触发，可以由 ASK / BID 单分别触发，并实时结算，具体撮合逻辑按照下面规则执行


![2](https://git.lug.ustc.edu.cn/cc14514/statics/raw/master/evertrust/images/pointsexange/4.png)

* 由 `ASK` 单触发撮合时，会过滤 `BIDList` 以便筛选出满足撮合条件的数据,筛选条件是 `BID.Price >= ASK.Price`


![3](https://git.lug.ustc.edu.cn/cc14514/statics/raw/master/evertrust/images/pointsexange/5.png)

* 由 `BID` 单触发撮合时，会过滤 `ASKList` 以便筛选出满足撮合条件的数据,筛选条件同样是 `BID.Price >= ASK.Price`


整个的撮合原则是价高者得，按高价成交，例如

买单挂 `BID={A:100,B:100}` 相当于价格 `P = 1.0`  

卖单挂 `ASK={A:100,B:200}` 相当于价格 `P = 0.5` 

那么此时的撮合结果就是 

    BID={A:100,B:100}{RA:0,RB:100} 
    ASK={A:100,B:200}{RA:100,RB:100}
    
我们看到 `ASK` 目标是要卖 `200B` 换取 `100A`，但是按照 `BID`(买单触发撮合) 的出价撮合完成时，`ASK` 得到了 `100A` 同时还剩余 `100B`