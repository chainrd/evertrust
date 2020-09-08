# 提现预编译合约

*用户从链上提现，需要发送提现交易，提现交易执行成功后，公账户自动打款给用户。*

## 提现交易 

交易to为把字符串"cash-out" sha3后的地址，生成方法为：

```function
func Keccak256ToAddress(ccName string) common.Address {
	hash := sha3.NewKeccak256()

	var buf []byte
	hash.Write([]byte(ccName))
	buf = hash.Sum(buf)

	return common.BytesToAddress(buf)
}
```

交易的value置为提现数

## 交易记录

交易执行成功后，会扣除该用户提现数量的本币。并且记录该用户的提现信息，记录内容为：

```struct
type CashOutRecord struct {
	Amount    *big.Int       `json:"amount"` // 提现数
	From      common.Address `json:"to"` // 提现用户
	TxHash common.Hash `json:"tx_hash"` // 提现时间
}
```

同时记录所有用户累次的提现总数
