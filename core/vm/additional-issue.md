出块奖励的增发和减少

在genesis.json中进行配置：

```json
"config": {
        "evertrust": {
               "isIncrease":true,
               "totalReward": "200000000000000000000"
        }
}
```
isIncrease说明：true允许人为增发 false不允许人为增发
totalReward说明：增发打块奖励的总额。可以是整数字符串，也可以是0x开头的十六进制字符串

增发交易：
to：0xf4b2CE0084F155FBbE9ccc0bA6289F8db9348566
from:必须为第一个挖矿账户地址。在genesis.json中的extraData配置中
payload为：

````code
type AddData struct {
    Amount *big.Int `json:"amount"`
}
````

json marshal 后的结果。
其中 Amount为正时表示增加，为负时表示减少。例如：

````json
{"amount": 500000000000}
````

````json
{"amount": -500000000000}
````
当交易执行成功，打块奖励账户：common.HexToAddress("123456789")会增加或减少。

