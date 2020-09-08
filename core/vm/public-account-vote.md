# 公账户投票合约

投票合约的nonce作为投票轮数，投票完成后nonce加1。
有权限的用户进行投票，当投给某个公账户地址的人数达到有权限投票总人数的2/3时，该公账户地址被记录到链上，只有该公账户地址发送的存款交易才有效。

有权限投票的账户地址设置在genesis.json中的voterAddrs：

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
		"voterAddrs": [
		    "0x251b3740A02A1C5cF5FfCdF60D42ED2a8398DdC8",
			"0x8000d109DAef5C81799bC01D4d82B0589dEEDb33",
			"0x1cEb7edECEA8d481aA315B9a51B65c4DeF9B3dC6",
			"0xc0925eDE3d2ff6Dd3f4041965F45BfC74957a23F"
		],
		"publicAccount": "0x251b3740A02A1C5cF5FfCdF60D42ED2a8398DdC8",
		"minerRewardAccount": "0x251b3740a02a1c5cf5ffcdf60d42ed2a8398ddc8"
	}
}
```

## 投票交易 

交易的payload数据结构：

```struct
type VoteData struct 
{
	Nonce uint64 `json:"nonce"` //投票合约的nonce
	PublicAccount common.Address `json:"public_account"` //要投的公账户地址
}
```

交易的to为把字符串"public-account-vote" sha3后的地址，生成方法为：

```function
func Keccak256ToAddress(ccName string) common.Address {
	hash := sha3.NewKeccak256()

	var buf []byte
	hash.Write([]byte(ccName))
	buf = hash.Sum(buf)

	return common.BytesToAddress(buf)
}
```

交易的value置为空