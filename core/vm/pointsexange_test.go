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
 * @Time   : 2019-08-06 16:50
 * @Author : liangc
 *************************************************************************/

package vm

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"CRD-chain/accounts/abi"
	"CRD-chain/common"
	"CRD-chain/crypto"
	"CRD-chain/rlp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestABI(t *testing.T) {
	a, _ := abi.JSON(strings.NewReader(points_EXANGE_ABI))
	pointsaddr := common.HexToAddress("0x48dea7f532f7b2839143244e7af0d7433f16701a")
	data, err := a.Pack("pointsAppend", pointsaddr)
	t.Log("pack", err, hex.EncodeToString(data))
	var _pointsaddr common.Address
	err = a.UnpackInput(&_pointsaddr, "pointsAppend", data[4:])
	t.Log("unpackInput", err, _pointsaddr.Hex())
	m, err := a.MethodById(data[:4])
	t.Log(err, m)

	pointsListBuff, _ := a.Pack("pointsList")
	t.Log(pointsListBuff)
	t.Log(hex.EncodeToString(pointsListBuff))

	data, err = a.PackOutput("pointsInfo", "Hello", "HLT", big.NewInt(123123), uint8(18))
	t.Log("pointsInfo output", err, hex.EncodeToString(data))
}

func TestShowABI(t *testing.T) {
	a, _ := abi.JSON(strings.NewReader(points_EXANGE_ABI))
	for _, m := range a.Methods {
		t.Log(m)
	}

	for _, e := range a.Events {
		t.Log(e.Name, e)
		switch e.Name {
		case "Bid", "Ask":
			owner := common.HexToAddress("0xf")
			id := big.NewInt(1)
			buf, err := e.Inputs.Pack(owner, id)
			t.Log(e.Name, err, owner, id, len(buf), buf)
		default:
			id := big.NewInt(1)
			owner := common.HexToAddress("0xf")
			region := common.HexToAddress("0xff")
			target := common.HexToAddress("0xfff")

			buf, err := e.Inputs.Pack(id, owner, region, int8(-1), big.NewInt(888), target, int8(+1), big.NewInt(999))
			t.Log(e.Name, err, owner, id, len(buf), buf)
		}
	}

	//0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
	//event Transfer(address indexed _from, address indexed _to, uint _value);
	sig := []byte("Transfer(address,address,uint256)")
	sigbuf := crypto.Keccak256(sig)
	t.Log(hex.EncodeToString(sigbuf))

	//0xd025af3c283935511f884c83da0d18eb1895cfb7aca5659b459d93ada7d2969e
	/*
		event Combination(uint256 indexed orderid,address indexed owner,
			address region,int8 rc,uint256 regionAmount,
			address target,int8 tc,uint256 targetAmount
		);*/
	sig = []byte("Combination(uint256,address,address,int8,uint256,address,int8,uint256)")
	sigbuf = crypto.Keccak256(sig)
	t.Log(hex.EncodeToString(sigbuf))
}

func TestShowEvents(t *testing.T) {
	/*
		event Combination(uint256 indexed orderid,address indexed owner,
			address region,int8 rc,uint256 regionAmount,
			address target,int8 tc,uint256 targetAmount
		);
		event Bid(address indexed owner,uint256 indexed orderid);
		event Ask(address indexed owner,uint256 indexed orderid);
	*/
	a, _ := abi.JSON(strings.NewReader(points_EXANGE_ABI))
	var sig, sigbuf []byte
	for _, e := range a.Events {
		switch e.Name {
		case "Ask":
			sig = []byte("Ask(address,uint256)")
		case "Bid":
			sig = []byte("Bid(address,uint256)")
		default:
			sig = []byte("Combination(uint256,address,address,int8,uint256,address,int8,uint256)")
		}
		sigbuf = crypto.Keccak256(sig)
		t.Log(e.Name, hex.EncodeToString(sigbuf))
	}
	data, err := a.Events["Combination"].Inputs.Pack(-1, big.NewInt(1000000))
	t.Log(err, data)
}

func TestBidABI(t *testing.T) {
	a, _ := abi.JSON(strings.NewReader(points_EXANGE_ABI))
	var (
		region       = common.HexToAddress("0xA")
		target       = common.HexToAddress("0xB")
		regionAmount = big.NewInt(100)
		targetAmount = big.NewInt(200)
	)
	buf, err := a.Pack("bid", region, target, regionAmount, targetAmount)
	t.Log(err, buf)
	var (
		_r  = new(common.Address)
		_t  = new(common.Address)
		_ra = new(big.Int)
		_ta = new(big.Int)
	)
	var v = []interface{}{_r, _t, &_ra, &_ta}
	err = a.UnpackInput(&v, "bid", buf[4:])
	t.Log(err, _r.Hex(), _t.Hex(), _ra, _ta)
}

func TestBidlistABI(t *testing.T) {
	a, _ := abi.JSON(strings.NewReader(points_EXANGE_ABI))
	v := []*big.Int{
		new(big.Int).SetBytes(common.HexToHash("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa").Bytes()),
		new(big.Int).SetBytes(common.HexToHash("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffb").Bytes()),
		new(big.Int).SetBytes(common.HexToHash("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc").Bytes()),
	}
	buf, err := a.PackOutput("bidlist", v)
	t.Log("bidlist packoutput", err, buf)

	id := new(big.Int)
	err = a.UnpackInput(&id, "orderinfo", common.HexToHash("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa").Bytes())
	t.Log(err, id)

}

func TestAddr(t *testing.T) {
	list := []common.Address{{1}, {2}, {3}, {4}, {5}}
	t.Log(list)
	buff, err := rlp.EncodeToBytes(list)
	t.Log(err, buff)
	var rlist = make([]common.Address, 0)
	err = rlp.DecodeBytes(buff, &rlist)
	t.Log(err, rlist)
}

func TestBigIntRlp(t *testing.T) {
	v := []*big.Int{big.NewInt(100), big.NewInt(200), big.NewInt(300)}
	buff, err := rlp.EncodeToBytes(v)
	t.Log(err, v, buff)
	var _v = make([]*big.Int, 0)
	err = rlp.DecodeBytes(buff, &_v)
	t.Log(err, _v)
}

func TestContract_Address(t *testing.T) {
	t.Log(pointsexagenAddress.Hex())
}

var (
	region      = common.HexToAddress("0xA")
	target      = common.HexToAddress("0xB")
	owner       = common.HexToAddress("0x")
	blockNumber = big.NewInt(100)

	bid1 = newBidOrder(nil, owner, region, target, big.NewInt(1*100), big.NewInt(3*100), 18, 18, blockNumber)
	bid2 = newBidOrder(nil, owner, region, target, big.NewInt(1*100), big.NewInt(2*100), 18, 18, blockNumber)
	bid3 = newBidOrder(nil, owner, region, target, big.NewInt(1*100), big.NewInt(1*100), 18, 18, blockNumber)

	// 卖单 balanceOf(Target) >= TargetAmount
	ask1 = newAskOrder(nil, owner, region, target, big.NewInt(1*100), big.NewInt(4*100), 18, 18, blockNumber)
	ask2 = newAskOrder(nil, owner, region, target, big.NewInt(2*100), big.NewInt(10*100), 18, 18, blockNumber)
	ask3 = newAskOrder(nil, owner, region, target, big.NewInt(1*100), big.NewInt(6*100), 18, 18, blockNumber)

	te = new(Pointsexange)
)

/*
A 区 B/A 交易对挂单撮合建模演算

设:
	ASK 卖单价格 Pa 为 xB == yA
	BID 买单价格 Pb 为 mB == nA

则有如下方程

	Pa = xB / yA
	Pb = mB / nA

推出
	P = ((x*n)B - (y*m)B) / (y*n)A

	P >= 0 则 Pa >= Pb
	P <= 0 则 Pa <= Pb

验证公式
*/
func TestOrderList(t *testing.T) {
	t.Log(region.Hex(), target.Hex())
	var bidlist OrderList = []*orderImpl{bid1, bid2, bid3}
	var asklist OrderList = []*orderImpl{ask1, ask2, ask3}

	sort.Sort(bidlist)
	sort.Sort(asklist)
	for i, ask := range asklist {
		t.Log(i, "ask", ": ", ask.getRegionAmount(), "/", ask.getTargetAmount(), ": ", float64(ask.getRegionAmount().Int64())/float64(ask.getTargetAmount().Int64()))
	}
	t.Log("----------")
	for i, bid := range bidlist {
		t.Log(i, "bid", ": ", bid.getRegionAmount(), "/", bid.getTargetAmount(), ": ", float64(bid.getRegionAmount().Int64())/float64(bid.getTargetAmount().Int64()))
	}

	// 生成新订单时，筛选撮合数据
	t.Log("ask 触发撮合 ----------")

	ask4 := newAskOrder(nil, owner, region, target, big.NewInt(1*100), big.NewInt(2*100), 18, 18, blockNumber)
	te = new(Pointsexange)
	combinationList := bidlist.filter(ask4)
	t.Log(ask4)
	for i, combination := range combinationList {
		t.Log(i, "ask->bid", ": ", combination.getRegionAmount(), "/", combination.getTargetAmount(), ": ", float64(combination.getRegionAmount().Int64())/float64(combination.getTargetAmount().Int64()))
	}

	t.Log("bid 触发撮合 ----------")
	bid4 := newBidOrder(nil, owner, region, target, big.NewInt(2*100), big.NewInt(10*100), 18, 18, blockNumber)
	te = new(Pointsexange)
	combinationList = asklist.filter(bid4)
	t.Log(bid4)
	for i, combination := range combinationList {
		t.Log(i, "bid->ask ", ": ", combination.getRegionAmount(), "/", combination.getTargetAmount(), ": ", float64(combination.getRegionAmount().Int64())/float64(combination.getTargetAmount().Int64()))
	}

	t.Log("bid 无效的撮合 ---------")
	bid5 := newBidOrder(nil, owner, region, target, big.NewInt(1*100), big.NewInt(3*100), 18, 18, blockNumber)
	te = new(Pointsexange)
	combinationList = asklist.filter(bid5)
	t.Log(bid5)
	for i, combination := range combinationList {
		t.Log(i, "bid->ask ", ": ", combination.getRegionAmount(), "/", combination.getTargetAmount(), ": ", float64(combination.getRegionAmount().Int64())/float64(combination.getTargetAmount().Int64()))
	}

	t.Log("rlp orderlist ---------")

	askbuf, _ := rlp.EncodeToBytes(asklist)
	askhex := hex.EncodeToString(askbuf)
	t.Log(len(askbuf), askbuf)
	t.Log(askhex)
}

/* TODO :
BID_106199498897560767742943200246010469758822637423373576834951423571815346485249=
{A:15674904000000000,B:5880000000000000}(P=2.665800000){RA:5674904000000000,RB:6000000000000000}(Final:false)

ASK_39533454969761314316384891845403321274392730437392166126620487830073053765362=
{A:3000000000000000,B:3000000000000000}(P=1.000000000){RA:0,RB:3000000000000000}(Final:false)

---- combinationAsk -----------------------------------------
## bid = {A:15674904,B:5880000}(P=2.665800000){RA:5674904,RB:6000000}(Final:false)
## ask = {A:3000000,B:3000000}(P=1.000000000){RA:0,RB:3000000}(Final:false)
# ---- a ----
ask.RB >= bid.RA/bid.P
ask.RB = ask.RB - bid.RA/bid.P // *
ask.RA = ask.RA + bid.RA

bid.RB = bid.RB + bid.RA/bid.P // *
bid.RA = 0
-------------------------------------------------------------
## bid = {A:15674904,B:5880000}(P=2.665800000){RA:10674904,RB:6000000}(Final:false)
## ask = {A:3000000,B:3000000}(P=1.000000000){RA:0,RB:3000000}(Final:false)
# ---- b ----
ask.RB < bid.RA/bid.P
bid.RB = bid.RB + ask.RB
ask.RA = ask.RA + ask.RB * bid.P
bid.RA = bid.RA - ask.RB * bid.P
ask.RB = 0

---- combinationBid -----------------------------------------
## ask = {A:10,B:40}(P=0.25){RA:0,RB:40}(Final:false)
## bid = {A:10,B:20}(P=0.5){RA:10,RB:0}(Final:false)
# ---- a ----
bid.RA >= ask.RB * ask.P
bid.RA = bid.RA - ask.RB * ask.P  	=> bid = {A:10,B:20}(P=0.5){RA:0,RB:0}
bid.RB = bid.RB + ask.RB 			=> bid = {A:10,B:20}(P=0.5){RA:0,RB:40}(Final:true)

ask.RB = 0							=> ask = {A:10,B:40}(P=0.25){RA:0,RB:0}
ask.RA = ask.RA 					=> ask = {A:10,B:40}(P=0.25){RA:10,RB:0}(Final:true)

-------------------------------------------------------------
## ask = {A:10,B:40}(P=0.25){RA:0,RB:40}(Final:false)
## bid = {A:5,B:10}(P=0.5){RA:5,RB:0}(Final:false)
# ---- b ----
bid.RA < ask.RB * ask.P
ask.RA = ask.RA + bid.RA				=> ask = {A:10,B:40}(P=0.25){RA:5,RB:40}
ask.RB = ask.RB - bid.RA / ask.P		=> ask = {A:10,B:40}(P=0.25){RA:5,RB:20}
bid.RB = bid.RB + bid.RA / ask.P		=> bid = {A:5,B:10}(P=0.5){RA:5,RB:20}
bid.RA = 0 								=> bid = {A:5,B:10}(P=0.5){RA:0,RB:20}(Final:true)
*/

func TestAskRB_sub_bidRA_div_askPrice_for_RB(t *testing.T) {
	// ask.RB = ask.RB - bid.RA / ask.P	=> ask = {A:10,B:40}(P=0.25){RA:5,RB:20}
	ask := newAskOrder(nil, owner, region, target, big.NewInt(10), big.NewInt(40), 18, 18, blockNumber)
	bid := newBidOrder(nil, owner, region, target, big.NewInt(5), big.NewInt(10), 18, 18, blockNumber)
	ask.RRegionAmount = big.NewInt(5)
	ask.RTargetAmount = bid.askRB_sub_bidRA_div_askPrice_for_RB(ask)
	t.Log("ask", ask)
	// bid.RB = bid.RA / ask.P			=> bid = {A:5,B:10}(P=0.5){RA:5,RB:20}
	bid.RTargetAmount = bid.bidRA_div_askPrice_for_RB(ask)
	bid.RRegionAmount = big.NewInt(0)
	bid.Final = true
	t.Log("bid", bid)
}

func TestAskRB_mut_askPrice(t *testing.T) {
	ask := newAskOrder(nil, owner, region, target, big.NewInt(2000), big.NewInt(4000), 15, 15, blockNumber)
	ask.RRegionAmount = big.NewInt(2000)
	r := ask.askRB_mut_askPrice_for_RA()
	t.Log("p", ask.price())
	t.Log("r", r)
}

func TestCombinationAsk_askRB_sub_bidRA_div_bidPrice_for_RB(t *testing.T) {
	/*
		[]bidlist= [
		    [BID_2={A:100,B:200}(P=0.500000000){RA:50,RB:100}(Final:false)]
		]
		第二次 ASK 触发撮合
		    [ASK_8={A:100,B:200}(P=0.500000000){RA:0,RB:200}(Final:false)]

		期望得到 => [ASK_8={A:100,B:200}(P=0.500000000){RA:50,RB:100}(Final:false)]
	*/
	bidOrder := newBidOrder(nil, owner, region, target, big.NewInt(1000000000000000000), big.NewInt(2000000000000000000), 18, 18, blockNumber)
	bidOrder.RRegionAmount = big.NewInt(500000000000000000)
	bidOrder.RTargetAmount = big.NewInt(1000000000000000000)
	ask1 := newAskOrder(nil, owner, region, target, big.NewInt(1000000000000000000), big.NewInt(2000000000000000000), 18, 18, blockNumber)
	//ask.RB = ask.RB - bid.RA/bid.P
	aRB := ask1.askRB_sub_bidRA_div_bidPrice_for_RB(bidOrder)
	t.Log("ask.RB = ", ask1.RTargetAmount, "-", bidOrder.RRegionAmount, "/", bidOrder.price())
	t.Log("ret", aRB)

	//bRB := bidOrder.bidRB_add_bidRA_div_bidPrice_for_RB()
	//t.Logf("bRB = %d", bRB)
}

func TestCombinationAsk_a(t *testing.T) {
	bidOrder := newBidOrder(nil, owner, region, target, big.NewInt(500), big.NewInt(1000), 3, 4, blockNumber)
	bidOrder.RRegionAmount = big.NewInt(100)
	bidOrder.RTargetAmount = big.NewInt(1000)
	ask1 := newAskOrder(nil, owner, region, target, big.NewInt(400), big.NewInt(1000), 3, 4, blockNumber)
	//ask.RB = ask.RB - bid.RA/bid.P
	aRB := ask1.askRB_sub_bidRA_div_bidPrice_for_RB(bidOrder)
	t.Log("ask.RB = ", ask1.RTargetAmount, "-", bidOrder.RRegionAmount, "/", bidOrder.price())
	t.Log("ret(800)", aRB)

	bRB := bidOrder.bidRB_add_bidRA_div_bidPrice_for_RB()
	t.Logf("bRB = %d", bRB)
}

func TestCombinationAsk2(t *testing.T) {
	bidOrder := newBidOrder(nil, owner, region, target, big.NewInt(15674904000000000), big.NewInt(5880000000000000), 15, 15, blockNumber)
	bidOrder.RRegionAmount = big.NewInt(5674904000000000)
	bidOrder.RTargetAmount = big.NewInt(6000000000000000)
	var bidlist1 OrderList = []*orderImpl{bidOrder}
	sort.Sort(bidlist1)
	ask1 := newAskOrder(nil, owner, region, target, big.NewInt(3000000000000000), big.NewInt(3000000000000000), 15, 15, blockNumber)
	te = new(Pointsexange)
	bidlist2 := bidlist1.filter(ask1)
	t.Log("[]bidlist =", bidlist2)

	t.Log("第一次 ASK 触发撮合", ask1)
	completeMap1, _ := te.combinationAsk(nil, ask1, bidlist2)
	t.Log("completeMap1", completeMap1)
	for i := 0; i < len(bidlist2); i++ {
		bid := bidlist2[i]
		if _, ok := completeMap1[common.BytesToHash(bid.Id.Bytes())]; ok {
			bidlist2 = append(bidlist2[:i], bidlist2[i+1:]...)
		}
	}
	t.Log("撮合结果 : ask1 =", ask1, "[]bidlist=", bidlist2)
}

/*
[ASK={A:50000000000000000,B:10000000000000000000}(P=0.500000000){RA:0,RB:10000000000000000000}(Final:false)]
[
	[BID={A:80000000000000000,B:2000000000000000000}(P=4.000000000){RA:20000000000000000,RB:2000000000000000000}(Final:false)]
	[BID={A:60000000000000000,B:3000000000000000000}(P=2.000000000){RA:60000000000000000,RB:0}(Final:false)]
]
-------error result---------
[ASK={A:50000000000000000,B:10000000000000000000}(P=0.500000000){RA:80000000000000000,RB:6000000000000000000}(Final:false)]
[BID={A:80000000000000000,B:2000000000000000000}(P=4.000000000){RA:0,RB:2000000000000000000}(Final:true)]
[BID={A:60000000000000000,B:3000000000000000000}(P=2.000000000){RA:0,RB:3000000000000000000}(Final:true)]
*/
func s2i(n string) *big.Int {
	r, _ := new(big.Int).SetString(n, 10)
	return r
}
func TestCombinationAsk3(t *testing.T) {
	bidOrder := newBidOrder(nil, owner, region, target, s2i("80000000000000000"), s2i("2000000000000000000"), 16, 18, blockNumber)
	bidOrder.RRegionAmount = s2i("20000000000000000")
	bidOrder.RTargetAmount = s2i("2000000000000000000")
	bidOrder2 := newBidOrder(nil, owner, region, target, s2i("60000000000000000"), s2i("3000000000000000000"), 16, 18, blockNumber)
	var bidlist1 OrderList = []*orderImpl{bidOrder, bidOrder2}
	sort.Sort(bidlist1)
	ask1 := newAskOrder(nil, owner, region, target, s2i("50000000000000000"), s2i("10000000000000000000"), 16, 18, blockNumber)
	te = new(Pointsexange)
	bidlist2 := bidlist1.filter(ask1)
	t.Log("[]bidlist =", bidlist2)

	t.Log("ASK 触发撮合", ask1)
	completeMap1, _ := te.combinationAsk(nil, ask1, bidlist2)
	t.Log("completeMap1", completeMap1)
	for i := 0; i < len(bidlist2); i++ {
		bid := bidlist2[i]
		if _, ok := completeMap1[common.BytesToHash(bid.Id.Bytes())]; ok {
			bidlist2 = append(bidlist2[:i], bidlist2[i+1:]...)
		}
	}
	t.Log("撮合结果 : ask1 =", ask1, "[]bidlist=", bidlist2)
}

func TestCombinationAsk(t *testing.T) {
	var bidlist1 OrderList = []*orderImpl{bid1, bid2, bid3}
	sort.Sort(bidlist1)
	ask1 := newAskOrder(nil, owner, region, target, big.NewInt(1*100), big.NewInt(2*100), 18, 18, blockNumber)
	te = new(Pointsexange)
	bidlist2 := bidlist1.filter(ask1)
	t.Log("[]bidlist =", bidlist2)

	t.Log("第一次 ASK 触发撮合", ask1)
	completeMap1, err := te.combinationAsk(nil, ask1, bidlist2)
	t.Log(err, "completeMap1", completeMap1)
	for i := 0; i < len(bidlist2); i++ {
		bid := bidlist2[i]
		if _, ok := completeMap1[common.BytesToHash(bid.Id.Bytes())]; ok {
			bidlist2 = append(bidlist2[:i], bidlist2[i+1:]...)
		}
	}

	t.Log("第一次撮合结果 : ask1 =", ask1, "[]bidlist=", bidlist2)
	ask2 := newAskOrder(nil, owner, region, target, big.NewInt(1*100), big.NewInt(2*100), 18, 18, blockNumber)
	te = new(Pointsexange)
	t.Log("第二次 ASK 触发撮合", ask2)
	completeMap2, err := te.combinationAsk(nil, ask2, bidlist2)
	t.Log(err, "completeMap2", completeMap2)
	for i := 0; i < len(bidlist2); i++ {
		bid := bidlist2[i]
		if _, ok := completeMap1[common.BytesToHash(bid.Id.Bytes())]; ok {
			bidlist2 = append(bidlist2[:i], bidlist2[i+1:]...)
		}
	}
	t.Log("第二次撮合结果 : ask2 =", ask2, "[]bidlist=", bidlist2)
}

func TestCombinationBid(t *testing.T) {
	var asklist OrderList = []*orderImpl{ask1, ask2, ask3}
	sort.Sort(asklist)
	bid1 := newBidOrder(nil, owner, region, target, big.NewInt(200), big.NewInt(1000), 18, 18, blockNumber)
	te = new(Pointsexange)

	asklist2 := asklist.filter(bid1)

	t.Log("[]asklist =", asklist2)

	t.Log("第一次 BID 触发撮合", bid1)

	completeMap1, err := te.combinationBid(nil, bid1, asklist2)
	t.Log(err, "completeMap1", completeMap1)
	for i := 0; i < len(asklist2); i++ {
		ask := asklist2[i]
		if _, ok := completeMap1[common.BytesToHash(ask.Id.Bytes())]; ok {
			asklist2 = append(asklist2[:i], asklist2[i+1:]...)
		}
	}

	t.Log("第一次撮合结果 : bid1 =", bid1, "[]asklist=", asklist2)
	bid2 := newBidOrder(nil, owner, region, target, big.NewInt(200), big.NewInt(1000), 18, 18, blockNumber)
	te = new(Pointsexange)
	t.Log("第二次 BID 触发撮合", bid2)
	completeMap2, err := te.combinationBid(nil, bid2, asklist2)
	t.Log(err, "completeMap2", completeMap2)
	for i := 0; i < len(asklist2); i++ {
		ask := asklist2[i]
		if _, ok := completeMap1[common.BytesToHash(ask.Id.Bytes())]; ok {
			asklist2 = append(asklist2[:i], asklist2[i+1:]...)
		}
	}
	t.Log("第二次撮合结果 : bid2 =", bid2, "[]asklist=", asklist2)

}

/* TODO
BID={A:4480000000000000,B:5600000000000000}(P=0.800000000){RA:4480000000000000,RB:0}(Final:false)
[
    [ASK_1={A:50000000000000000,B:100000000000000000}(P=0.500000000){RA:123000000000000000,RB:2000000000000000}(Final:false)]
    [ASK_2={A:17000000000000000,B:34000000000000000}(P=0.500000000){RA:0,RB:34000000000000000}(Final:false)]
]
*/
func TestCombinationBid2(t *testing.T) {
	ask1 := newAskOrder(nil, owner, region, target, big.NewInt(50000000000000000), big.NewInt(100000000000000000), 15, 15, blockNumber)
	ask1.RRegionAmount = big.NewInt(123000000000000000)
	ask1.RTargetAmount = big.NewInt(2000000000000000)
	ask2 := newAskOrder(nil, owner, region, target, big.NewInt(17000000000000000), big.NewInt(34000000000000000), 15, 15, blockNumber)
	var asklist OrderList = []*orderImpl{ask1, ask2}
	sort.Sort(asklist)

	bid1 := newBidOrder(nil, owner, region, target, big.NewInt(4480000000000000), big.NewInt(5600000000000000), 15, 15, blockNumber)
	te = new(Pointsexange)

	asklist2 := asklist.filter(bid1)

	t.Log("[]asklist =", asklist2)

	t.Log("第一次 BID 触发撮合", bid1)

	completeMap1, err := te.combinationBid(nil, bid1, asklist2)
	t.Log(err, "completeMap1", completeMap1)
	for i := 0; i < len(asklist2); i++ {
		ask := asklist2[i]
		if _, ok := completeMap1[common.BytesToHash(ask.Id.Bytes())]; ok {
			asklist2 = append(asklist2[:i], asklist2[i+1:]...)
		}
	}
	t.Log("撮合结果 : bid1 =", bid1, "[]asklist=", asklist2)
}

func TestOrderFilter(t *testing.T) {
	/*
		开始撮合

		ask [ASK_0={A:100000000000000000000,B:200000000000000000000}(P=0.50){RA:0,RB:200000000000000000000}(Final:false)]

		bidlist = [
			[BID_1={A:100000000000000000000,B:100000000000000000000}(P=1.00){RA:100000000000000000000,RB:0}(Final:false)]
			[BID_2={A:100000000000000000000,B:200000000000000000000}(P=0.50){RA:100000000000000000000,RB:0}(Final:false)]
		]
	*/
	b1 := newBidOrder(nil, owner, region, target, big.NewInt(100), big.NewInt(100), 18, 18, blockNumber)
	te = new(Pointsexange)
	b2 := newBidOrder(nil, owner, region, target, big.NewInt(100), big.NewInt(200), 18, 18, blockNumber)
	te = new(Pointsexange)
	var bidlist OrderList = []*orderImpl{b1, b2}

	a1 := newAskOrder(nil, owner, region, target, big.NewInt(300), big.NewInt(200), 18, 18, blockNumber)
	te = new(Pointsexange)
	sort.Sort(bidlist)
	t.Log(a1, bidlist)
	bidlist2 := bidlist.filter(a1)
	t.Log(bidlist2)
}

func TestDecimals(t *testing.T) {
	var (
		rd, td           = 3, 8
		b1               = newBidOrder(nil, owner, region, target, big.NewInt(100000), big.NewInt(80000000000), uint8(rd), uint8(td), blockNumber)
		b2               = newBidOrder(nil, owner, region, target, big.NewInt(100000), big.NewInt(50000000000), uint8(rd), uint8(td), blockNumber)
		b3               = newBidOrder(nil, owner, region, target, big.NewInt(100000), big.NewInt(90000000000), uint8(rd), uint8(td), blockNumber)
		bl     OrderList = []*orderImpl{b1, b2, b3}
		a1               = newAskOrder(nil, owner, region, target, big.NewInt(10000), big.NewInt(5000000000), uint8(rd), uint8(td), blockNumber)
	)
	t.Log(bl)
	sort.Sort(bl)
	t.Log(bl)

	d := 18
	_big := new(big.Int).Exp(big.NewInt(10), big.NewInt(17), nil)
	s := fmt.Sprintf("%d", _big)
	t.Log(d, len(s)-1, s)

	fn := commonfactor(b1.RegionAmount, b1.TargetAmount, b2.RegionAmount, b2.TargetAmount, b1.RegionDecimals, b1.TargetDecimals)
	t.Log(b1)
	t.Log(b2)
	t.Log(fn)

	m, e := te.combinationAsk(nil, a1, bl)
	t.Log(e, m)

}

func Test_commonfactor(t *testing.T) {
	b1 := newBidOrder(nil, owner, region, target, big.NewInt(18), big.NewInt(32), uint8(3), uint8(3), blockNumber)
	fn := commonfactor(b1.RegionAmount, b1.TargetAmount, b1.RegionAmount, b1.TargetAmount, b1.RegionDecimals, b1.TargetDecimals)
	t.Log(fn)
}

func TestDecimals2(t *testing.T) {
	d := 18
	ff := "0.00000000123456"
	t.Log(ff)

	nn := strings.Split(ff, ".")
	n0, err := strconv.ParseInt(nn[0], 10, 64)
	t.Log(err, "n0", n0)
	n1, err := strconv.ParseInt(nn[1], 10, 64)
	dd := d - len(nn[1])
	if dd < 0 {
		dd = d
		nn[1] = nn[1][:d]
	}

	base0 := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(d)), nil)
	base1 := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(dd)), nil)
	t.Log(err, "n1", n1, base0, base1)
	// n0 * (10**d) + n1 * (10**(d-len(n1)))
	r0 := new(big.Int).Mul(big.NewInt(n0), base0)
	r1 := new(big.Int).Mul(big.NewInt(n1), base1)
	rr := new(big.Int).Add(r0, r1)
	t.Log(rr)
}

type Foo []common.Hash

func (self Foo) Len() int {
	return len(self)
}

func (self Foo) Less(i, j int) bool {
	return new(big.Int).SetBytes(self[i].Bytes()).Cmp(new(big.Int).SetBytes(self[j].Bytes())) > 0
}

func (self Foo) Swap(i, j int) {
	self[i], self[j] = self[j], self[i]
}

func TestSort(t *testing.T) {
	var arr = []common.Hash{
		common.HexToHash("0x1"),
		common.HexToHash("0x5"),
		common.HexToHash("0x3"),
		common.HexToHash("0x2"),
		common.HexToHash("0x4"),
	}
	t.Log("before :", arr)
	sort.Sort(Foo(arr))
	t.Log("after :", arr)
	var brr = make([][]byte, 0)
	for _, a := range arr {
		brr = append(brr, a.Bytes())
	}
	hash := crypto.Keccak256(brr[:]...)
	t.Log(hex.EncodeToString(hash))
}

func TestDefer(t *testing.T) {
	i := big.NewInt(100000000)
	b := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)
	r := new(big.Int).Mul(i, b)
	//[0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 82 183 210 220 200 12 210 228 0 0 0]
	t.Log(r, r.Bytes())

	tex := common.HexToAddress("0x123").Hash()
	t.Log(tex.Bytes())
}
