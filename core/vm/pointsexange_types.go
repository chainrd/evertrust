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
 * @Time   : 2019-08-10 12:52
 * @Author : liangc
 * @Doc    : contracts/pointsexange/README.md
 *************************************************************************/

package vm

import (
	"fmt"
	"math/big"
	"CRD-chain/accounts/abi"
	"CRD-chain/common"
	pointsexangelib "CRD-chain/contracts/pointsexange/lib"
	"CRD-chain/crypto"
	"CRD-chain/log"
	"CRD-chain/params"
	"CRD-chain/rlp"
	"sort"
	"strconv"
	"strings"
)

const points_EXANGE_ABI = `
[
  {
    "constant": false,
    "inputs": [
      {
        "name": "region",
        "type": "address"
      },
      {
        "name": "target",
        "type": "address"
      },
      {
        "name": "regionAmount",
        "type": "uint256"
      },
      {
        "name": "targetAmount",
        "type": "uint256"
      }
    ],
    "name": "ask",
    "outputs": [],
    "payable": true,
    "stateMutability": "payable",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "region",
        "type": "address"
      },
      {
        "name": "target",
        "type": "address"
      },
      {
        "name": "regionAmount",
        "type": "uint256"
      },
      {
        "name": "targetAmount",
        "type": "uint256"
      }
    ],
    "name": "bid",
    "outputs": [],
    "payable": true,
    "stateMutability": "payable",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "id",
        "type": "uint256"
      }
    ],
    "name": "cancel",
    "outputs": [],
    "payable": true,
    "stateMutability": "payable",
    "type": "function"
  },
  {
    "constant": false,
    "inputs": [
      {
        "name": "region",
        "type": "address"
      },
      {
        "name": "amount",
        "type": "uint256"
      }
    ],
    "name": "withdrawal",
    "outputs": [],
    "payable": true,
    "stateMutability": "payable",
    "type": "function"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "orderid",
        "type": "uint256"
      },
      {
        "indexed": true,
        "name": "owner",
        "type": "address"
      },
      {
        "indexed": false,
        "name": "region",
        "type": "address"
      },
      {
        "indexed": false,
        "name": "rc",
        "type": "int8"
      },
      {
        "indexed": false,
        "name": "regionAmount",
        "type": "uint256"
      },
      {
        "indexed": false,
        "name": "target",
        "type": "address"
      },
      {
        "indexed": false,
        "name": "tc",
        "type": "int8"
      },
      {
        "indexed": false,
        "name": "targetAmount",
        "type": "uint256"
      }
    ],
    "name": "Combination",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "owner",
        "type": "address"
      },
      {
        "indexed": true,
        "name": "orderid",
        "type": "uint256"
      }
    ],
    "name": "Bid",
    "type": "event"
  },
  {
    "anonymous": false,
    "inputs": [
      {
        "indexed": true,
        "name": "owner",
        "type": "address"
      },
      {
        "indexed": true,
        "name": "orderid",
        "type": "uint256"
      }
    ],
    "name": "Ask",
    "type": "event"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "region",
        "type": "address"
      }
    ],
    "name": "balanceOf",
    "outputs": [
      {
        "name": "name",
        "type": "string"
      },
      {
        "name": "symbol",
        "type": "string"
      },
      {
        "name": "balance",
        "type": "uint256"
      },
      {
        "name": "decimals",
        "type": "uint8"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "id",
        "type": "uint256"
      }
    ],
    "name": "orderinfo",
    "outputs": [
      {
        "name": "orderType",
        "type": "string"
      },
      {
        "name": "region",
        "type": "address"
      },
      {
        "name": "target",
        "type": "address"
      },
      {
        "name": "regionAmount",
        "type": "uint256"
      },
      {
        "name": "targetAmount",
        "type": "uint256"
      },
      {
        "name": "regionComplete",
        "type": "uint256"
      },
      {
        "name": "targetComplete",
        "type": "uint256"
      },
      {
        "name": "regionDecimals",
        "type": "uint8"
      },
      {
        "name": "targetDecimals",
        "type": "uint8"
      },
      {
        "name": "isFinal",
        "type": "bool"
      },
      {
        "name": "owner",
        "type": "address"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "orderType",
        "type": "string"
      },
      {
        "name": "region",
        "type": "address"
      },
      {
        "name": "target",
        "type": "address"
      }
    ],
    "name": "orderlist",
    "outputs": [
      {
        "name": "",
        "type": "uint256[]"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "addrs",
        "type": "address[]"
      },
      {
        "name": "pageNum",
        "type": "uint256"
      }
    ],
    "name": "ownerOrder",
    "outputs": [
      {
        "name": "",
        "type": "uint256[]"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [
      {
        "name": "",
        "type": "address"
      }
    ],
    "name": "pointsInfo",
    "outputs": [
      {
        "name": "name",
        "type": "string"
      },
      {
        "name": "symbol",
        "type": "string"
      },
      {
        "name": "totalSupply",
        "type": "uint256"
      },
      {
        "name": "decimals",
        "type": "uint8"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  },
  {
    "constant": true,
    "inputs": [],
    "name": "pointsList",
    "outputs": [
      {
        "name": "",
        "type": "address[]"
      }
    ],
    "payable": false,
    "stateMutability": "view",
    "type": "function"
  }
]
`

const (
	ASK OrderType = iota
	BID
)

const (
	TTA_CREATE       TTA = iota
	TTA_TRANSFER         //erc20.transfer
	TTA_TRANSFERFROM     //erc20.transferFrom
)

var (
	pointsExagenAddress = params.PointsExagenAddress
	PointsExange        = newpointsexange()
	_abi, _             = abi.JSON(strings.NewReader(points_EXANGE_ABI))

	//REGISTER_PREFIX = []byte("points_EXANGE_REG")
	tab_reg_idx = common.BytesToHash([]byte("REG-IDX"))
	// TODO 这个多余了，不会有重复的 address
	tab_reg_key = func(addr common.Address) common.Hash {
		return common.BytesToHash(crypto.Keccak256([]byte("REG"), addr.Bytes()))
	}
	// 充值记录的 key , BALANCE + ERC20points + FROM
	tab_ledger_key = func(erc20points, from common.Address) common.Hash {
		return common.BytesToHash(crypto.Keccak256([]byte("BALANCE"), erc20points.Bytes(), from.Bytes()))
	}
	tab_owner_idx = func(owner, region, target common.Address) (allKey common.Hash, regionKey common.Hash) {
		prefix := []byte("OWNER-IDX")
		allKey = common.BytesToHash(crypto.Keccak256(prefix, owner.Bytes()))
		if region != common.HexToAddress("0x") && target != common.HexToAddress("0x") {
			regionKey = common.BytesToHash(crypto.Keccak256(prefix, owner.Bytes(), region.Bytes(), target.Bytes()))
		}
		return
	}

	eip20abi, _   = abi.JSON(strings.NewReader(pointsexangelib.EIP20InterfaceABI))
	transferInput = func(addr common.Address, amount *big.Int) ([]byte, error) {
		//EIP20InterfaceABI
		m, _ := eip20abi.Methods["transfer"]
		data, err := m.Inputs.Pack(addr, amount)
		if err != nil {
			return nil, err
		}
		return append(m.Id(), data[:]...), nil
	}

	// 处理浮点数时使用
	commonfactorForDiv = func(x, y, m, n *big.Int, xmd, ynd uint8) (fixedMul *big.Int) {
		min := func(x, y *big.Int) *big.Int {
			r := x
			if x.Cmp(y) > 0 {
				r = y
			}
			return r
		}
		fn := func(_f, a *big.Int, d uint8) *big.Int {
			base := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(d)), nil)
			f := new(big.Int).SetBytes(_f.Bytes())
			for {
				r := new(big.Int).Mul(f, a)
				if r.Cmp(base) > 0 {
					break
				}
				f = new(big.Int).Mul(big.NewInt(10), f)
			}
			return f
		}
		fix := func(f, x, y, m, n *big.Int, xmd, ynd uint8) *big.Int {
			a := min(x, m)
			ra := fn(f, a, xmd)
			b := min(y, n)
			rb := fn(f, b, ynd)
			if ra.Cmp(rb) < 0 {
				return rb
			}
			return ra
		}
		f := commonfactor(x, y, m, n, xmd, ynd)
		rf := fix(f, x, y, m, n, xmd, ynd)
		if rf.Cmp(big.NewInt(1000)) < 0 {
			rf = big.NewInt(1000)
		}
		return rf
	}
	commonfactor = func(x, y, m, n *big.Int, xmd, ynd uint8) (fixedMul *big.Int) {
		var (
			sx = fmt.Sprintf("%d", x)
			sy = fmt.Sprintf("%d", y)
			sm = fmt.Sprintf("%d", m)
			sn = fmt.Sprintf("%d", n)
			// 每个数字的位数, 如果比对应的位数小，就需要做位数修正了
			fix = func(n string, d uint8) int {
				for j := len(n) - 1; j >= 0; j-- {
					if n[j] != '0' {
						cf := int(d) - len(n) + j + 1
						if cf > 0 {
							//fmt.Println("commonfactor", n, "d=", d, "len(n)=", len(n), "j=", j, "cf=", cf)
							return cf
						}
					}
				}
				return 0
			}
		)
		var (
			// 计算方式：从右往左找第一个不是0的值，记住后面0的位数，找到最小的值，然后补位直到精度范围内没有非0为止
			lx = fix(sx, xmd)
			lm = fix(sm, xmd)
			ly = fix(sy, ynd)
			ln = fix(sn, ynd)
		)
		fixedMul = big.NewInt(1)
		// 是否需要修正
		t := []int{lx, lm, ly, ln}
		sort.Sort(decimalsList(t))
		fixedMul = new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(t[0])), nil)
		//fmt.Println("lx", lx, "lm", lm, "ly", ly, "ln", ln, "xmd", xmd, "ynd", ynd, "fixedMul", fixedMul)
		return
	}
	_test_order_id = int64(0) //just for test
)

type IpointsExmage interface {
	PrecompiledContract
	// 无 ABI 描述，不对外开放，erc20 部署时被调用
	Erc20Trigger(action TTA, args TTAArgs)
}

type OrderType byte
type OrderIndex []*big.Int
type OrderList []*orderImpl

// 把符合撮合条件的子集返回去
func (o OrderList) filter(t *orderImpl) OrderList {
	if o == nil || len(o) == 0 {
		return o
	}
	if t.getType() == o[0].getType() {
		panic("Order type can not different in same OrderList")
	}
	for i, item := range o {
		// ask <= bid 时可以撮合,找到 ask 来做比较,当条件相反时截断
		switch t.getType() {
		case ASK:
			if t.compare(item) < 0 {
				return o[:i]
			}
			break
		case BID:
			if item.compare(t) < 0 {
				return o[:i]
			}
			break
		}
	}
	return o[:]
}

func (o OrderList) Len() int {
	return len(o)
}

func (o OrderList) Less(i, j int) bool {
	if o[i].getType() != o[j].getType() {
		panic("Order type can not different in same OrderList")
	}
	// bid 降序排列
	// ask 升序排列
	switch o[i].getType() {
	case ASK:
		return o[i].compare(o[j]) > 0
	default:
		return o[i].compare(o[j]) < 0
	}
}

func (o OrderList) Swap(i, j int) {
	o[i], o[j] = o[j], o[i]
}

//fixDecimals
type decimalsList []int

func (self decimalsList) Len() int {
	return len(self)
}

func (self decimalsList) Less(i, j int) bool {
	return self[i] > self[j]
}

func (self decimalsList) Swap(i, j int) {
	self[i], self[j] = self[j], self[i]
}

// pointsexange trigger action
type TTA int

type TTAArgs struct {
	Addr, From, To common.Address
	Amount         *big.Int
	State          StateDB
}

func (a TTAArgs) AppendAddr(address common.Address) TTAArgs {
	a.Addr = address
	return a
}
func (a TTAArgs) AppendFrom(address common.Address) TTAArgs {
	a.From = address
	return a
}
func (a TTAArgs) AppendTo(address common.Address) TTAArgs {
	a.To = address
	return a
}
func (a TTAArgs) AppendAmount(n *big.Int) TTAArgs {
	a.Amount = n
	return a
}

type orderImpl struct {
	Id                             *big.Int
	Owner, Region, Target          common.Address
	RegionAmount, TargetAmount     *big.Int  // 表示挂单价格
	RRegionAmount, RTargetAmount   *big.Int  // 表示成交数量
	OrderType                      OrderType // Region/RegionAmount Target/TargetAmount 对应，通过 OrderType 来区分类型，进行校验
	RegionDecimals, TargetDecimals uint8
	Final                          bool // final = true 时，此单将被移出索引列表，并且不能再撤销了
	BlockNumber                    *big.Int
}

func (self *orderImpl) equal(o *orderImpl) bool {
	return self.String() == o.String()
}
func (self *orderImpl) snapshot() *orderImpl {
	return &orderImpl{new(big.Int).SetBytes(self.Id.Bytes()),
		self.Owner, self.Region, self.Target,
		new(big.Int).SetBytes(self.RegionAmount.Bytes()), new(big.Int).SetBytes(self.TargetAmount.Bytes()),
		new(big.Int).SetBytes(self.RRegionAmount.Bytes()), new(big.Int).SetBytes(self.RTargetAmount.Bytes()),
		self.OrderType,
		self.RegionDecimals, self.TargetDecimals,
		self.Final,
		new(big.Int).SetBytes(self.BlockNumber.Bytes()),
	}
}

//ASK1.RA = ASK1.RA + ASK1.RB * BID2.P
func (self *orderImpl) rTargetMulPrice(price float64) *big.Int {
	var ten = big.NewInt(10)
	fn := commonfactor(self.RegionAmount, self.TargetAmount, self.RegionAmount, self.TargetAmount, self.RegionDecimals, self.TargetDecimals)
	rbase := new(big.Int).Exp(ten, big.NewInt(int64(self.RegionDecimals)), nil)
	tbase := new(big.Int).Exp(ten, big.NewInt(int64(self.TargetDecimals)), nil)

	r := new(big.Int).Div(new(big.Int).Mul(fn, self.RRegionAmount), rbase).Int64()
	t := new(big.Int).Div(new(big.Int).Mul(fn, self.RTargetAmount), tbase).Int64()

	ret := float64(r) + float64(t)*price
	ret = ret / float64(fn.Int64())

	d := self.RegionDecimals
	ff := fmt.Sprintf("%.12f", ret)
	nn := strings.Split(ff, ".")
	n0, _ := strconv.ParseInt(nn[0], 10, 64)
	n1, _ := strconv.ParseInt(nn[1], 10, 64)
	dd := int(d) - len(nn[1])
	if dd < 0 {
		dd = int(d)
		nn[1] = nn[1][:d]
	}

	base0 := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(d)), nil)
	base1 := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(dd)), nil)
	// n0 * (10**d) + n1 * (10**(d-len(n1)))
	r0 := new(big.Int).Mul(big.NewInt(n0), base0)
	r1 := new(big.Int).Mul(big.NewInt(n1), base1)
	rr := new(big.Int).Add(r0, r1)
	return rr
}

//ASK1.RA = ASK1.RA + ASK1.RB * BID2.P
func (ask *orderImpl) askRA_add_askRB_mul_bidPrice_for_RA(bid *orderImpl) *big.Int {
	log.Trace("--------------- askRA_add_askRB_mul_bidPrice_for_RA -------------")
	var ten = big.NewInt(10)
	fn := commonfactor(ask.RegionAmount, ask.TargetAmount, bid.RegionAmount, bid.TargetAmount, ask.RegionDecimals, ask.TargetDecimals)
	rbase := new(big.Int).Exp(ten, big.NewInt(int64(ask.RegionDecimals)), nil)
	tbase := new(big.Int).Exp(ten, big.NewInt(int64(ask.TargetDecimals)), nil)

	aRA := new(big.Int).Div(new(big.Int).Mul(fn, ask.RRegionAmount), rbase).Int64()
	aRB := new(big.Int).Div(new(big.Int).Mul(fn, ask.RTargetAmount), tbase).Int64()

	//bRA := new(big.Int).Div(new(big.Int).Mul(fn, bid.RRegionAmount), rbase).Int64()
	//bRB := new(big.Int).Div(new(big.Int).Mul(fn, bid.RTargetAmount), tbase).Int64()

	log.Trace("askRA_add_askRB_mul_bidPrice_for_RA", "fn", fn, "base", tbase)
	ret := float64(aRA) + float64(aRB)*bid.price()
	log.Trace("askRA_add_askRB_mul_bidPrice_for_RA", "exp", fmt.Sprint(aRA, "+", aRB, "*", bid.price(), "=", ret))

	// f(x) = (ret * fn * tbase) / (fn*fn)
	a := new(big.Int).Mul(big.NewInt(int64(ret*float64(fn.Int64()))), rbase)
	b := new(big.Int).Div(a, new(big.Int).Mul(fn, fn))
	return b
}

//BID2.RA = BID2.RA - ASK1.RB * BID2.P
func (bid *orderImpl) bidRA_sub_askRB_mul_bidPrice_for_RA(ask *orderImpl) *big.Int {
	log.Trace("--------------- bidRA_add_askRB_mul_bidPrice_for_RA -------------")
	var ten = big.NewInt(10)
	fn := commonfactor(ask.RegionAmount, ask.TargetAmount, ask.RegionAmount, ask.TargetAmount, ask.RegionDecimals, ask.TargetDecimals)
	bidfn := commonfactor(bid.RegionAmount, bid.TargetAmount, bid.RegionAmount, bid.TargetAmount, bid.RegionDecimals, bid.TargetDecimals)
	if bidfn.Cmp(fn) > 0 {
		fn = bidfn
	}
	rbase := new(big.Int).Exp(ten, big.NewInt(int64(ask.RegionDecimals)), nil)
	tbase := new(big.Int).Exp(ten, big.NewInt(int64(ask.TargetDecimals)), nil)

	//aRA := new(big.Int).Div(new(big.Int).Mul(fn, ask.RRegionAmount), rbase).Int64()
	aRB := new(big.Int).Div(new(big.Int).Mul(fn, ask.RTargetAmount), tbase).Int64()

	bRA := new(big.Int).Div(new(big.Int).Mul(fn, bid.RRegionAmount), rbase).Int64()
	//bRB := new(big.Int).Div(new(big.Int).Mul(fn, bid.RTargetAmount), tbase).Int64()

	log.Trace("bidRA_sub_askRB_mul_bidPrice_for_RA", "fn", fn, "base", tbase)
	ret := float64(bRA) - float64(aRB)*bid.price()
	log.Trace("bidRA_sub_askRB_mul_bidPrice_for_RA", "exp", fmt.Sprint(bRA, "-", aRB, "*", bid.price(), "=", ret))
	// f(x) = (ret * fn * tbase) / (fn*fn)
	a := new(big.Int).Mul(big.NewInt(int64(ret*float64(fn.Int64()))), rbase)
	b := new(big.Int).Div(a, new(big.Int).Mul(fn, fn))
	return b
}

// ask.RB = ask.RB - bid.RA/bid.P
func (ask *orderImpl) askRB_sub_bidRA_div_bidPrice_for_RB(bid *orderImpl) *big.Int {
	log.Trace("--------------- askRB_sub_bidRA_div_bidPrice_for_RB -------------")
	var ten = big.NewInt(10)
	fn := commonfactorForDiv(ask.RegionAmount, ask.TargetAmount, bid.RegionAmount, bid.TargetAmount, ask.RegionDecimals, ask.TargetDecimals)
	rbase := new(big.Int).Exp(ten, big.NewInt(int64(ask.RegionDecimals)), nil)
	tbase := new(big.Int).Exp(ten, big.NewInt(int64(ask.TargetDecimals)), nil)

	//aRA := new(big.Int).Div(new(big.Int).Mul(fn, ask.RRegionAmount), rbase).Int64()
	aRB := new(big.Int).Div(new(big.Int).Mul(fn, ask.RTargetAmount), tbase).Int64()

	bRA := new(big.Int).Div(new(big.Int).Mul(fn, bid.RRegionAmount), rbase).Int64()
	//bRB := new(big.Int).Div(new(big.Int).Mul(fn, bid.RTargetAmount), tbase).Int64()

	log.Trace("askRB_sub_bidRA_div_bidPrice_for_RB", "fn", fn, "tbase", tbase, "rbase", rbase, "bid.RB", bid.RRegionAmount, "bRA = bid.RB / rbase * fn =", bRA)
	ret := float64(aRB) - float64(bRA)/bid.price()
	// f(x) = (ret * fn * tbase) / (fn*fn)
	a := new(big.Int).Mul(big.NewInt(int64(ret*float64(fn.Int64()))), tbase)
	b := new(big.Int).Div(a, new(big.Int).Mul(fn, fn))
	log.Trace("askRB_sub_bidRA_div_bidPrice_for_RB", "exp", fmt.Sprint(aRB, "-", bRA, "/", bid.price(), "=", ret, " ==>", b))
	return b
}

// bid.RB = bid.RB + bid.RA/bid.P
func (bid *orderImpl) bidRB_add_bidRA_div_bidPrice_for_RB() *big.Int {
	log.Trace("--------------- bidRB_add_bidRA_div_bidPrice_for_RB -------------")
	var ten = big.NewInt(10)
	fn := commonfactorForDiv(bid.RegionAmount, bid.TargetAmount, bid.RegionAmount, bid.TargetAmount, bid.RegionDecimals, bid.TargetDecimals)

	rbase := new(big.Int).Exp(ten, big.NewInt(int64(bid.RegionDecimals)), nil)
	tbase := new(big.Int).Exp(ten, big.NewInt(int64(bid.TargetDecimals)), nil)

	//aRA := new(big.Int).Div(new(big.Int).Mul(fn, ask.RRegionAmount), rbase).Int64()
	//aRB := new(big.Int).Div(new(big.Int).Mul(fn, ask.RTargetAmount), tbase).Int64()

	bRA := new(big.Int).Div(new(big.Int).Mul(fn, bid.RRegionAmount), rbase).Int64()
	bRB := new(big.Int).Div(new(big.Int).Mul(fn, bid.RTargetAmount), tbase).Int64()

	log.Trace("bidRB_add_bidRA_div_bidPrice_for_RB", "fn", fn, "base", tbase)

	ret := float64(bRB) + float64(bRA)/bid.price()
	log.Trace("bidRB_add_bidRA_div_bidPrice_for_RB", "exp", fmt.Sprint(bid, ":", bRB, "+", bRA, "/", bid.price(), "=", ret))
	// f(x) = (ret * fn * tbase) / (fn*fn)
	a := new(big.Int).Mul(big.NewInt(int64(ret*float64(fn.Int64()))), tbase)
	b := new(big.Int).Div(a, new(big.Int).Mul(fn, fn))
	return b
}

//ask.RB = ask.RB - bid.RA / ask.P
/*
P = A/B => B = A/P
*/
func (bid *orderImpl) askRB_sub_bidRA_div_askPrice_for_RB(ask *orderImpl) *big.Int {
	log.Trace("--------------- askRB_sub_bidRA_div_askPrice_for_RB -------------")
	var ten = big.NewInt(10)
	fn := commonfactorForDiv(ask.RegionAmount, ask.TargetAmount, bid.RegionAmount, bid.TargetAmount, ask.RegionDecimals, ask.TargetDecimals)

	rbase := new(big.Int).Exp(ten, big.NewInt(int64(bid.RegionDecimals)), nil)
	tbase := new(big.Int).Exp(ten, big.NewInt(int64(bid.TargetDecimals)), nil)

	//aRA := new(big.Int).Div(new(big.Int).Mul(fn, ask.RRegionAmount), rbase).Int64()
	aRB := new(big.Int).Div(new(big.Int).Mul(fn, ask.RTargetAmount), tbase).Int64()

	bRA := new(big.Int).Div(new(big.Int).Mul(fn, bid.RRegionAmount), rbase).Int64()
	//bRB := new(big.Int).Div(new(big.Int).Mul(fn, bid.RTargetAmount), tbase).Int64()

	log.Trace("askRB_sub_bidRA_div_askPrice_for_RB", "fn", fn, "base", tbase)

	ret := float64(aRB) - float64(bRA)/ask.price()
	log.Trace("askRB_sub_bidRA_div_askPrice_for_RB", "exp", fmt.Sprint(aRB, "-", bRA, "/", bid.price(), "=", ret))
	// f(x) = (ret * fn * tbase) / (fn*fn)
	a := new(big.Int).Mul(big.NewInt(int64(ret*float64(fn.Int64()))), tbase)
	b := new(big.Int).Div(a, new(big.Int).Mul(fn, fn))
	return b
}

// bid.RB = bid.RA / ask.P
func (bid *orderImpl) bidRA_div_askPrice_for_RB(ask *orderImpl) *big.Int {
	log.Trace("--------------- bidRA_div_askPrice_for_RB -------------")
	var ten = big.NewInt(10)
	fn := commonfactorForDiv(ask.RegionAmount, ask.TargetAmount, bid.RegionAmount, bid.TargetAmount, ask.RegionDecimals, ask.TargetDecimals)

	rbase := new(big.Int).Exp(ten, big.NewInt(int64(bid.RegionDecimals)), nil)
	tbase := new(big.Int).Exp(ten, big.NewInt(int64(bid.TargetDecimals)), nil)

	//aRA := new(big.Int).Div(new(big.Int).Mul(fn, ask.RRegionAmount), rbase).Int64()
	//aRB := new(big.Int).Div(new(big.Int).Mul(fn, ask.RTargetAmount), tbase).Int64()

	bRA := new(big.Int).Div(new(big.Int).Mul(fn, bid.RRegionAmount), rbase).Int64()
	//bRB := new(big.Int).Div(new(big.Int).Mul(fn, bid.RTargetAmount), tbase).Int64()

	log.Trace("bidRA_div_askPrice_for_RB", "fn", fn, "base", tbase)

	ret := float64(bRA) / ask.price()
	log.Trace("bidRA_div_askPrice_for_RB", "exp", fmt.Sprint(bRA, "/", bid.price(), "=", ret))
	// f(x) = (ret * fn * tbase) / (fn*fn)
	a := new(big.Int).Mul(big.NewInt(int64(ret*float64(fn.Int64()))), tbase)
	b := new(big.Int).Div(a, new(big.Int).Mul(fn, fn))
	return b
}

// ask.RB * ask.P
// bid.RA = bid.RA - ask.RB * ask.P
/*
P = A/B => A = P*B
*/
func (ask *orderImpl) askRB_mut_askPrice_for_RA() *big.Int {
	var ten = big.NewInt(10)
	fn := commonfactor(ask.RegionAmount, ask.TargetAmount, ask.RegionAmount, ask.TargetAmount, ask.RegionDecimals, ask.TargetDecimals)
	rbase := new(big.Int).Exp(ten, big.NewInt(int64(ask.RegionDecimals)), nil)
	tbase := new(big.Int).Exp(ten, big.NewInt(int64(ask.TargetDecimals)), nil)

	aRA := new(big.Int).Div(new(big.Int).Mul(fn, ask.RRegionAmount), rbase).Int64()
	aRB := new(big.Int).Div(new(big.Int).Mul(fn, ask.RTargetAmount), tbase).Int64()
	log.Trace("askRB_mut_askPrice_for_RA", "aRA", aRA, "aRB", aRB, "rbase", rbase, "tbase", tbase, "fn", fn, "ask.RB", ask.RTargetAmount)
	ret := float64(aRB) * ask.price()

	log.Trace("askRB_mut_askPrice_for_RA", "ret", ret, "want", ask.RegionAmount)
	//a := new(big.Int).Mul(big.NewInt(int64(ret)), rbase)
	//b := new(big.Int).Div(a, fn)

	// f(x) = (ret * fn * tbase) / (fn*fn)
	a := new(big.Int).Mul(big.NewInt(int64(ret*float64(fn.Int64()))), rbase)
	b := new(big.Int).Div(a, new(big.Int).Mul(fn, fn))
	return b
}

func (self *orderImpl) price() float64 {
	var ten = big.NewInt(10)
	fn := commonfactor(self.RegionAmount, self.TargetAmount, self.RegionAmount, self.TargetAmount, self.RegionDecimals, self.TargetDecimals)
	rbase := new(big.Int).Exp(ten, big.NewInt(int64(self.RegionDecimals)), nil)
	tbase := new(big.Int).Exp(ten, big.NewInt(int64(self.TargetDecimals)), nil)
	r := new(big.Int).Div(new(big.Int).Mul(fn, self.RegionAmount), rbase).Int64()
	t := new(big.Int).Div(new(big.Int).Mul(fn, self.TargetAmount), tbase).Int64()
	//fmt.Println("::: price :::>", "fn=", fn, "A=", self.RegionAmount, "B=", self.TargetAmount, "AD=", rbase, "BD=", tbase, "r=", r, "t=", t)
	n := float64(r) / float64(t)
	n2, _ := strconv.ParseFloat(fmt.Sprintf("%.12f", n), 64)
	return n2
}

func (self *orderImpl) rlpEncode() ([]byte, error) {
	return rlp.EncodeToBytes(self)
}

func (self *orderImpl) rlpDecode(buff []byte) error {
	return rlp.DecodeBytes(buff, self)
}

func (self *orderImpl) getType() OrderType {
	return self.OrderType
}

func (self *orderImpl) String() string {
	t := "ASK"
	if self.OrderType == BID {
		t = "BID"
	}
	s := fmt.Sprintf("[%v_%v={A:%d,B:%d}(P=%.9f){RA:%d,RB:%d}(Final:%v)]", t, self.Id, self.RegionAmount, self.TargetAmount, self.price(), self.RRegionAmount, self.RTargetAmount, self.Final)
	return s
}

func (self *orderImpl) getRegionAmount() *big.Int {
	return self.RegionAmount
}

func (self *orderImpl) getTargetAmount() *big.Int {
	return self.TargetAmount
}

// hash(Target,Region,type)
func (self *orderImpl) indexKey(t OrderType) common.Hash {
	return common.BytesToHash(crypto.Keccak256(self.Target.Bytes(), self.Region.Bytes(), []byte{byte(t)}))
}

func (self *orderImpl) indexVal() *big.Int {
	return self.Id
}

/*
--------------------------------------------------
A 区 B/A 交易对价格以 A 为准，则有 Pa 卖单价，Pb 买单价：

Pa : xA==yB => 1A == y/x(B)
Pb : mA==nB => 1A == n/m(B)

Pa = y / x
Pb = n / m

比较 Pa 与 Pb 的大小

P = (y*m - x*n) / x*m

已知 x,y,m,n 均大于 0, 则判断正负时忽略分母，
可推出 P >= 0 则 Pa >= Pb , P <= 0 则 Pa <= Pb
--------------------------------------------------
*/
func (self *orderImpl) compare(o *orderImpl) (r int) {
	// 此处需要处理精度，要用具体数值除以精度，得到的结果再进行比较，否则精度不同时，会出现错误数据
	var x, y, m, n = self.getRegionAmount(), self.getTargetAmount(), o.getRegionAmount(), o.getTargetAmount()
	// 处理浮点数情况，例如 金额 小于 精度 时的情况
	if self.RegionDecimals != self.TargetDecimals {
		fn := commonfactor(x, y, m, n, self.RegionDecimals, self.TargetDecimals)
		b10 := big.NewInt(10)
		xmd, ynd := self.RegionDecimals, self.TargetDecimals
		x = new(big.Int).Div(new(big.Int).Mul(fn, x), new(big.Int).Exp(b10, big.NewInt(int64(xmd)), nil))
		y = new(big.Int).Div(new(big.Int).Mul(fn, y), new(big.Int).Exp(b10, big.NewInt(int64(ynd)), nil))
		m = new(big.Int).Div(new(big.Int).Mul(fn, m), new(big.Int).Exp(b10, big.NewInt(int64(xmd)), nil))
		n = new(big.Int).Div(new(big.Int).Mul(fn, n), new(big.Int).Exp(b10, big.NewInt(int64(ynd)), nil))
	}
	ym := new(big.Int).Mul(y, m)
	xn := new(big.Int).Mul(x, n)
	r = ym.Cmp(xn)
	return
}

func newAskOrder(db StateDB, owner, region, target common.Address, regionAmount, targetAmount *big.Int, rdecimals, tdecimals uint8, blockNumber *big.Int) *orderImpl {
	ask := newOrder(db, ASK, owner, region, target, regionAmount, targetAmount, rdecimals, tdecimals, blockNumber)
	ask.RRegionAmount = big.NewInt(0)
	ask.RTargetAmount = new(big.Int).SetBytes(targetAmount.Bytes())
	return ask
}

func newBidOrder(db StateDB, owner, region, target common.Address, regionAmount, targetAmount *big.Int, rdecimals, tdecimals uint8, blockNumber *big.Int) *orderImpl {
	bid := newOrder(db, BID, owner, region, target, regionAmount, targetAmount, rdecimals, tdecimals, blockNumber)
	bid.RRegionAmount = new(big.Int).SetBytes(regionAmount.Bytes())
	bid.RTargetAmount = big.NewInt(0)
	return bid
}

func newOrder(db StateDB, t OrderType, owner, region, target common.Address, regionAmount, targetAmount *big.Int, rdecimals, tdecimals uint8, blockNumber *big.Int) *orderImpl {
	id := new(big.Int)
	if db != nil {
		id = id.SetBytes(crypto.Keccak256(owner.Bytes(), big.NewInt(int64(db.GetNonce(owner))).Bytes()[:], []byte("-ID")))
	} else {
		//FOR TEST
		_test_order_id++
		id = big.NewInt(_test_order_id)
	}
	return &orderImpl{
		Id:             id,
		OrderType:      t,
		Owner:          owner,
		Region:         region,
		Target:         target,
		RegionAmount:   regionAmount,
		TargetAmount:   targetAmount,
		RegionDecimals: rdecimals,
		TargetDecimals: tdecimals,
		BlockNumber:    blockNumber,
	}
}
