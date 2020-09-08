# 存款预编译合约

用户向公账户转账，转账成功后，公账户再自动发起存款交易，在链上给用户增加本币。
公账户默认是多个用户投票后设定的，如果为空，就从genesi.json中的publicAccount获取。

```json 
{
	"evertrust": {
		"epoch": 30000,
		"noRewards": false,
		"cfd": 10,
		"numMasters": 2,
		"blockDelay": 5000,
		"pointsChain": [],
		"nohypothecation": false,
		"voterAddrs": ["0x251b3740A02A1C5cF5FfCdF60D42ED2a8398DdC8",
			"0x8000d109DAef5C81799bC01D4d82B0589dEEDb33",
			"0x1cEb7edECEA8d481aA315B9a51B65c4DeF9B3dC6",
			"0xc0925eDE3d2ff6Dd3f4041965F45BfC74957a23F"
		],
		"publicAccount": "0x251b3740A02A1C5cF5FfCdF60D42ED2a8398DdC8",
		"minerRewardAccount": "0x251b3740a02a1c5cf5ffcdf60d42ed2a8398ddc8"
	}
}
```

## 充值交易 

交易的payload数据结构：

```struct
type CashInData struct 
{
	BankReceipt string `json:"bank_receipt"` //银行收据
	Amount *big.Int `json:"amount"` //充值钱数
	To common.Address `json:"to"` //给谁充值
}
```

交易的to为把字符串"cash-in" sha3后的地址，生成方法为：

```function
func Keccak256ToAddress(ccName string) common.Address {
	hash := sha3.NewKeccak256()

	var buf []byte
	hash.Write([]byte(ccName))
	buf = hash.Sum(buf)

	return common.BytesToAddress(buf)
}
```

交易的value设置为空。

## 交易记录

交易执行成功后，会给指定的用户增加本币。并会记录该次的存款信息，记录内容为：

```struct
type CashInRecord struct {
	BankReceipt string         `json:"bank_receipt"` // 银行收据
	Amount      *big.Int       `json:"amount"` // 充值数
	To          common.Address `json:"to"` // 充值给谁
	PublicAccount common.Address `json:"public_account"` // 公账户地址
	txHash common.Hash `json:"tx_hash"` // 充值时间
}
```

同时记录所有用户累次的存款总量。