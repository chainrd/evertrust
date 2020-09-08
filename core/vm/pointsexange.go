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
 * @Time   : 2019-08-06 15:30
 * @Author : liangc
 * @Doc    : contracts/pointsexange/README.md
 *************************************************************************/

package vm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"CRD-chain/accounts/abi/bind"
	"CRD-chain/common"
	"CRD-chain/contracts/erc20points"
	pointsexangelib "CRD-chain/contracts/pointsexange/lib"
	"CRD-chain/core/types"
	"CRD-chain/log"
	"CRD-chain/params"
	"CRD-chain/CRDcc/util"
	"CRD-chain/rlp"
	"sort"
	"strings"
	"sync"
)

type Pointsexange struct {
	ctx     context.Context
	backend bind.ContractBackend
	once    *sync.Once
}

func newpointsexange() IpointsExmage {
	return &Pointsexange{
		ctx:  context.Background(),
		once: new(sync.Once),
	}
}

func (self *Pointsexange) init() {
	self.once.Do(func() {
		var ubi = make(chan interface{})
		params.EvertrustBackendInstanceCh <- ubi
		self.backend = (<-ubi).(bind.ContractBackend)
	})
}

// 为了保证事物一致性，这里必须同步执行，不能异步处理
func (self *Pointsexange) Erc20Trigger(action TTA, args TTAArgs) {
	switch action {
	case TTA_CREATE:
		self.appendReg(args.State, args.Addr)
	case TTA_TRANSFER, TTA_TRANSFERFROM:
		if args.To == pointsExagenAddress {
			self.addBalanceLedger(args.State, args.Addr, args.From, args.Amount)
		}
	}
}

func (self *Pointsexange) RequiredGas(input []byte) uint64 {
	self.init()
	if input != nil && len(input) > 0 {
		method, err := _abi.MethodById(input[:4])
		log.Trace("pointsexange-RequiredGas ::> ", "err", err, "input", input, "method", method)
		return 100
	}
	return 100
}

// dispatch
func (self *Pointsexange) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	self.init()
	if input == nil || len(input) < 4 {
		//log.Trace("pointsexange-Run ::> empty_input")
		return nil, nil
	}
	method, err := _abi.MethodById(input[:4])
	//TODO dev&debug
	defer func() {
		if err != nil {
			log.Error("[pointsexange.run-error]", "err", err)
		}
	}()
	//log.Trace("pointsexange-Run ::> err=", err, "input=", input, " ; method=", method)
	if err != nil {
		return nil, err
	}
	// TODO 可以用 反射 来优化 ...
	switch method.Name {
	case "bid":
		//function bid(region address, target address, regionAmount uint256, targetAmount uint256) returns()
		var (
			_r  = new(common.Address)
			_t  = new(common.Address)
			_ra = new(big.Int)
			_ta = new(big.Int)
		)
		var v = []interface{}{_r, _t, &_ra, &_ta}
		if err = _abi.UnpackInput(&v, method.Name, input[4:]); err != nil {
			return nil, err
		}
		log.Trace("----> bid", "r", _r, "t", _t, "ra", _ra, "ta", _ta)
		if err = self.bid(ctx, *_r, *_t, _ra, _ta); err != nil {
			return nil, err
		}

	case "ask":
		//function ask(region address, target address, regionAmount uint256, targetAmount uint256) returns()
		var (
			_r  = new(common.Address)
			_t  = new(common.Address)
			_ra = new(big.Int)
			_ta = new(big.Int)
		)
		var v = []interface{}{_r, _t, &_ra, &_ta}
		if err = _abi.UnpackInput(&v, method.Name, input[4:]); err != nil {
			return nil, err
		}
		log.Trace("----> ask", "r", _r, "t", _t, "ra", _ra, "ta", _ta)
		if err = self.ask(ctx, *_r, *_t, _ra, _ta); err != nil {
			return nil, err
		}
	case "ownerOrder":
		//function ownerOrder(address[] memory addrs,uint256 pageNum) public view returns(uint256[] memory);
		var (
			addrs   = make([]common.Address, 0)
			pageNum = new(big.Int)
		)
		v := []interface{}{&addrs, &pageNum}
		err := _abi.UnpackInput(&v, method.Name, input[4:])
		log.Trace("ownerOrder -->", "err", err, "addrs", addrs, "pageNum", pageNum)
		list, err := self.fetchOwnerOrder(ctx, addrs, pageNum)
		log.Trace("fetchOwnerOrder -> ", err, list)
		if err != nil {
			log.Error("ownerOrder", "err", err, "list", list)
		}
		data, err := _abi.PackOutput(method.Name, list)
		log.Trace("<-- ownerOrder", "err", err, "data-len", len(data))
		return data, err

	case "orderlist":
		// function orderlist(string orderType) constant returns(uint256[])
		var (
			t              = ""
			region, target common.Address
			ot             OrderType
		)
		v := []interface{}{&t, &region, &target}
		if err = _abi.UnpackInput(&v, method.Name, input[4:]); err != nil {
			return nil, err
		}
		log.Trace("----> orderlist", "input", input, "t", t)
		switch strings.ToUpper(t) {
		case "ASK":
			ot = ASK
			break
		case "BID":
			ot = BID
			break
		default:
			return nil, errors.New("error_order_type: 'ASK' / 'BID'")
		}
		list, err := self.orderlist(ctx, ot, region, target)
		if err != nil {
			log.Error("orderlist", "err", err, "list", list)
		}
		data, err := _abi.PackOutput(method.Name, list)
		log.Trace("<- orderlist :", "err", err, "data-len", len(data))
		return data, err
	case "cancel":
		// function cancel(uint256 id) public ;
		var id = new(big.Int)
		if err := _abi.UnpackInput(&id, method.Name, input[4:]); err != nil {
			return nil, err
		}
		log.Trace("cancel -->", "id", id)
		err = self.cancel(ctx, id)
		log.Trace("<-- cancel", "id", id, "err", err)
		return nil, err
	case "withdrawal":
		// function withdrawal(address region,uint256 amount) public payable;
		var (
			region common.Address
			amount = new(big.Int)
		)
		v := []interface{}{&region, &amount}
		if err := _abi.UnpackInput(&v, method.Name, input[4:]); err != nil {
			return nil, err
		}
		log.Trace("withdrawal ->", "points", region.Hex(), "amount", amount)
		err = self.withdrawal(ctx, region, amount)
		log.Trace("<- withdrawal", "points", region.Hex(), "amount", amount, "err", err)
		return nil, err
	case "orderinfo":
		/*
		   function orderinfo(uint256 id) public view returns(
		       string memory orderType,
		       address region,address target,
		       uint256 regionAmount,uint256 targetAmount,
		       uint256 regionComplete, uint256 targetComplete,
		       uint8 regionDecimals, uint8 targetDecimals,
		       bool isFinal, address owner
		   );
		*/
		var (
			id        = new(big.Int)
			orderType = "bid"
		)
		if err := _abi.UnpackInput(&id, method.Name, input[4:]); err != nil {
			return nil, err
		}
		order, err := self.orderinfo(ctx, id)
		if err != nil {
			return nil, err
		}
		if order.OrderType == ASK {
			orderType = "ask"
		}
		// TODO : 获取详情时，不应该提供订单 owner 这个属性，测试时提供
		data, err := _abi.PackOutput(method.Name, orderType,
			order.Region, order.Target,
			order.RegionAmount, order.TargetAmount,
			order.RRegionAmount, order.RTargetAmount,
			order.RegionDecimals, order.TargetDecimals,
			order.Final, order.Owner,
		)
		log.Trace("<- orderinfo", "err", err, "order", order)
		return data, err
	case "balanceOf":
		//function balanceOf(Region address) constant returns(name string, symbol string, balance uint256, decimals uint8)
		var pointsaddr common.Address
		if err := _abi.UnpackInput(&pointsaddr, method.Name, input[4:]); err != nil {
			return nil, err
		}
		name, symbol, balance, decimals, err := self.balanceOf(ctx, pointsaddr)
		if err != nil {
			return nil, err
		}
		data, err := _abi.PackOutput(method.Name, name, symbol, balance, decimals)
		log.Trace("balanceOf -> result :", "err", err, "data", data)
		return data, err
	case "pointsInfo":
		//function pointsInfo( address) constant returns(name string, symbol string, totalSupply uint256, decimals uint8)
		var pointsaddr common.Address
		if err := _abi.UnpackInput(&pointsaddr, method.Name, input[4:]); err != nil {
			return nil, err
		}
		name, symbol, totalSupply, decimals, err := self.pointsInfo(ctx, pointsaddr)
		if err != nil {
			return nil, err
		}
		data, err := _abi.PackOutput(method.Name, name, symbol, totalSupply, decimals)
		log.Trace("pointsInfo -> result :", "err", err, "data", data)
		return data, err
	case "pointsList":
		ret := self.pointsList(ctx)
		data, err := _abi.PackOutput(method.Name, ret)
		log.Trace("pointsList -> result :", "err", err, "data", data)
		return data, err
		//case "pointsAppend": // TODO 仅仅开发和测试时使用
		//	var pointsaddr common.Address
		//	if err := _abi.UnpackInput(&pointsaddr, method.Name, input[4:]); err != nil {
		//		return nil, err
		//	}
		//	self.pointsAppend(ctx, pointsaddr)

	}
	return nil, nil
}

func (self *Pointsexange) validateOrder(ctx *PrecompiledContractContext, t OrderType, region, target common.Address, ra, ta *big.Int) error {
	var (
		// 挂买单需要检查 region 账本余额大于 ra
		//_n, _s, _rb, _rd, _re = self.balanceOf(ctx, region)
		_n, _s, _rb, _, _re = self.balanceOf(ctx, region)
		_, _, _tb, _td, _te = self.balanceOf(ctx, target)
	)
	log.Trace("validateOrder : check balance ", "td", _td, "re", _re, "n", _n, "s", _s, "rb", _rb, "ra", ra)
	if _re != nil {
		return _re
	}
	if _te != nil {
		return _te
	}

	// 卖单 target 余额要大于 targetAmount，买单 region 余额要大于 regionAmount >>>>>>>>
	switch t {
	case ASK:
		if _tb.Cmp(ta) < 0 {
			return errors.New("ask_balance_too_low")
		}
	case BID:
		if _rb.Cmp(ra) < 0 {
			return errors.New("bid_balance_too_low")
		}
	}
	// 卖单 target 余额要大于 targetAmount，买单 region 余额要大于 regionAmount <<<<<<<<
	/*
		// 最低不能低于 1 ，即必须满足 amount / decimals >= 1 >>>>>>>>
		br := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(_rd)), nil)
		if ra.Cmp(br) < 0 {
			return errors.New("region_amount_too_low")
		}
		bt := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(_td)), nil)
		if ta.Cmp(bt) < 0 {
			return errors.New("target_amount_too_low")
		}
		// 最低不能低于 1 ，即必须满足 amount / decimals >= 1 <<<<<<<<
	*/
	return nil
}

/*
function orderinfo(uint256 id) public view returns(
    string memory orderType,
    address region,address target,
    uint256 regionAmount,uint256 targetAmount,
    uint256 regionComplete, uint256 targetComplete,
    uint8 regionDecimals, uint8 targetDecimals
);
*/
// bidlist 与 asklist 放的都是 order.id 集合, 获取到 id 集合后要调用 orderinfo 来获取详情
func (self *Pointsexange) orderinfo(ctx *PrecompiledContractContext, id *big.Int) (*orderImpl, error) {
	var (
		order     = orderImpl{}
		buff, err = self.getKeyState(ctx.Evm.StateDB, id.Bytes())
	)
	if err != nil {
		return nil, err
	}
	if buff != nil && len(buff) > 0 {
		err = rlp.DecodeBytes(buff, &order)
	}
	return &order, err
}

func (self *Pointsexange) cancel(ctx *PrecompiledContractContext, id *big.Int) error {
	order, err := self.orderinfo(ctx, id)
	if err != nil {
		return err
	}
	if ctx.Contract.CallerAddress != order.Owner {
		return errors.New("fail_signature")
	}
	if order.Final {
		return nil
	}
	order.Final = true
	orderval, err := order.rlpEncode()
	if err != nil {
		return err
	}
	self.setKeyState(ctx.Evm.StateDB, id.Bytes(), orderval)
	var (
		indexBid    OrderIndex = make([]*big.Int, 0)
		indexAsk    OrderIndex = make([]*big.Int, 0)
		indexBidKey            = order.indexKey(BID)
		indexAskKey            = order.indexKey(ASK)
		cleanIndex             = func(key common.Hash, oidx OrderIndex) error {
			for i := 0; i < len(oidx); i++ {
				if oidx[i].Cmp(id) == 0 {
					oidx = append(oidx[:i], oidx[i+1:]...)
					oidxVal, err := rlp.EncodeToBytes(oidx)
					if err != nil {
						return err
					}
					self.setKeyState(ctx.Evm.StateDB, key.Bytes(), oidxVal)
					return nil
				}
			}
			return errors.New("cancel_error_index_notfound")
		}
	)
	switch order.OrderType {
	case ASK:
		// >>>>>>>>>>>>>>>>>>
		self.addBalanceLedger(ctx.Evm.StateDB, order.Target, order.Owner, order.RTargetAmount)
		log.Trace("Cancel-ASK", "order", order, "+RB", order.RTargetAmount)
		// >>>>>>>>>>>>>>>>>>
		indexAskBuf, err := self.getKeyState(ctx.Evm.StateDB, indexAskKey.Bytes())
		if err != nil {
			return err
		}
		err = rlp.DecodeBytes(indexAskBuf, &indexAsk)
		if err != nil {
			return err
		}
		return cleanIndex(indexAskKey, indexAsk)
	case BID:
		// >>>>>>>>>>>>>>>>>>
		self.addBalanceLedger(ctx.Evm.StateDB, order.Region, order.Owner, order.RRegionAmount)
		log.Trace("Cancel-BID", "order", order, "+RA", order.RRegionAmount)
		// >>>>>>>>>>>>>>>>>>
		indexBidBuf, err := self.getKeyState(ctx.Evm.StateDB, indexBidKey.Bytes())
		if err != nil {
			return err
		}
		err = rlp.DecodeBytes(indexBidBuf, &indexBid)
		if err != nil {
			return err
		}
		return cleanIndex(indexBidKey, indexBid)
	}
	return nil
}

//function bid(Region address, Target address, RegionAmount uint256, TargetAmount uint256) returns()
func (self *Pointsexange) bid(ctx *PrecompiledContractContext, region, target common.Address, ra, ta *big.Int) error {
	if err := self.validateOrder(ctx, BID, region, target, ra, ta); err != nil {
		return err
	}
	var (
		db = ctx.Evm.StateDB
		// 挂买单需要检查 region 账本余额大于 ra
		_, _, _rb, _rd, _ = self.balanceOf(ctx, region)
		_, _, _, _td, _   = self.balanceOf(ctx, target)
		bid               = newBidOrder(db, ctx.Contract.CallerAddress, region, target, ra, ta, _rd, _td, ctx.Evm.BlockNumber)
		// 通过 indexAsk 拿出 askOrderList 并进行 filter ，得到可以撮合的集合
		indexBid OrderIndex = make([]*big.Int, 0)
		// 卖单id 索引 : [ ask.id, ask.id, ... ]
		indexAsk OrderIndex = make([]*big.Int, 0)
		// 卖单列表
		askOrderlist OrderList = make([]*orderImpl, 0)
		// 买单索引Key
		indexBidKey = bid.indexKey(BID)
		// 卖单索引Key
		indexAskKey = bid.indexKey(ASK)
	)

	// indexAskKey = [ ask.id, ask.id, ... ]
	indexAskBuf, err := self.getKeyState(db, indexAskKey.Bytes())
	log.Trace("检查通过准备撮合 bid :", "bid", bid, "err", err, "indexAskBuf-len", len(indexAskBuf))
	if err == nil && len(indexAskBuf) > 0 {
		err = rlp.DecodeBytes(indexAskBuf, &indexAsk)
		log.Trace("还原 indexAsk : ", "err", err, "indexAsk", indexAsk)
		for i, askKey := range indexAsk {
			// ask order
			askBuf, err := self.getKeyState(db, askKey.Bytes())
			order := new(orderImpl)
			if err != nil {
				log.Trace("getKeyState error", "err", err, "askKey", askKey, "buf", askBuf)
				return err
			}
			err = rlp.DecodeBytes(askBuf, &order)
			log.Trace("bid->ask 从索引还原 asklist ", "i", i, "err", err, "id", askKey, "ask", order)
			if err != nil {
				return err
			}
			askOrderlist = append(askOrderlist, order)
		}
		// 排序卖单列表
		sort.Sort(askOrderlist)
		// 执行撮合，bid 为指针，撮合过程中会改变对象属性值，并顺带清理 askOrderlist
		askOrderlist = askOrderlist.filter(bid)
		dirty, err := self.combinationBid(ctx, bid, askOrderlist)
		if err != nil {
			return err
		}
		// 把撮合完成的 ask 单做清除处理
		if dirty != nil && len(dirty) > 0 {
			for i := 0; i < len(indexAsk); i++ {
				askKey := indexAsk[i]
				if _ask, ok := dirty[common.BytesToHash(askKey.Bytes())]; ok {
					if _ask.Final {
						log.Trace("bid : EVENT_DEL_ASKLIST", "ask", _ask)
						log.Trace("ask 索引变化 : EVENT_DEL_ASKLIST", "ask", _ask)
						indexAsk = append(indexAsk[:i], indexAsk[i+1:]...)
						i--
						// 删除订单前，要完成转账，ASK 单需要把 RRegionAmount 增加到 Region 对应的余额中
						// 如果是实时结算，这个地方的逻辑就错了 :: 19-08-16 : 已经改成实时结算 >>>>
						// self.addBalanceLedger(db, _ask.Region, _ask.Owner, _ask.RRegionAmount)
						// 如果是实时结算，这个地方的逻辑就错了 :: 19-08-16 : 已经改成实时结算 <<<<
					}
					_askBytes, err := _ask.rlpEncode()
					if err != nil {
						return err
					}
					// 刷新 ask 值
					self.setKeyState(db, _ask.Id.Bytes(), _askBytes)
				}
			}
			// 在 indexAsk 中删除处理完成的索引信息
			indexAskVal, err := rlp.EncodeToBytes(indexAsk)
			if err != nil {
				return err
			}
			// TODO :: 订单只要删掉索引就可以了吧？？？数据需要清除吗？
			// TODO :: 订单只要删掉索引就可以了吧？？？数据需要清除吗？
			self.setKeyState(db, indexAskKey.Bytes(), indexAskVal)
		}
	}
	// 如果撮合完了, bid.RRegionAmount > 0 则将撮合结果写入数据库
	log.Trace("撮合完毕", "bid", bid)
	if !bid.Final {
		log.Trace("写入 bid 单索引 到 indexBid 中，存放 bid.Id >>>>", "bid", bid)
		// 写入 bid 单索引 到 indexBid 中，存放 bid.Id >>>>
		if indexBidBuf, err := self.getKeyState(db, indexBidKey.Bytes()); err == nil && len(indexBidBuf) > 0 {
			rlp.DecodeBytes(indexBidBuf, &indexBid)
		}
		indexBid = append(indexBid, bid.Id)
		indexBidVal, err := rlp.EncodeToBytes(indexBid)
		if err != nil {
			return err
		}
		self.setKeyState(db, indexBidKey.Bytes(), indexBidVal)
		// 写入 bid 单索引 到 indexBid 中，存放 bid.Id <<<<
		log.Trace("写入 bid 单索引 到 indexBid 中，存放 bid.Id <<<<", "indexBidKey", indexBidKey.Hex(), "indexBid-len", len(indexBid))
		//} else {
		// 如果是实时结算，这个地方的逻辑就错了 :: 19-08-16 : 已经改成实时结算 >>>>
		// log.Trace("bid 结算 target : 买单撮合成功需要结算 :", "target :", bid.Target.Hex(), ", add :", bid.RTargetAmount)
		// self.addBalanceLedger(db, target, ctx.Contract.CallerAddress, bid.RTargetAmount)
		// 如果是实时结算，这个地方的逻辑就错了 :: 19-08-16 : 已经改成实时结算 <<<<
	}
	log.Trace("写入 bid 到 statedb 中, key = bid.Id , val = bid.rlp >>>>", "bidid", bid.Id, "bid", bid)
	// 写入 bid 到 statedb 中, key = bid.Id , val = bid.rlp >>>>
	bidBytes, err := bid.rlpEncode()
	if err != nil {
		return err
	}
	// TODO 给订单的 owner 创建索引，并且应该扩展为分区存储，索引最好不要无限增长
	// 将 bid 单写入 statedb , 每次 bid 都会产生新的 bid 订单
	err = self.setKeyState(db, bid.Id.Bytes(), bidBytes)
	if err != nil {
		return err
	}
	self.eventBid(ctx, bid.Owner, bid.Id)
	self.addOwnerOrder(ctx, bid)
	// 写入 bid 到 statedb 中, key = bid.Id , val = bid.rlp <<<<
	log.Trace("写入 bid 到 statedb 中, key = bid.Id , val = bid.rlp <<<<", "bidid", bid.Id)
	// 除非事物没有成功，否则要扣除余额
	log.Trace("bid 账户余额调整:", "region", region.Hex(), "result", new(big.Int).Sub(_rb, ra), "rb", _rb, "ra", ra)
	return self.subBalanceLedger(db, region, ctx.Contract.CallerAddress, ra)
	//return self.setBalanceLedger(db, region, ctx.Contract.CallerAddress, new(big.Int).Sub(_rb, ra))
}

func (self *Pointsexange) ask(ctx *PrecompiledContractContext, region, target common.Address, ra, ta *big.Int) error {
	if err := self.validateOrder(ctx, ASK, region, target, ra, ta); err != nil {
		return err
	}
	var (
		db = ctx.Evm.StateDB
		// 挂买单需要检查 region 账本余额大于 ra
		_, _, _, _rd, _   = self.balanceOf(ctx, region)
		_, _, _tb, _td, _ = self.balanceOf(ctx, target)
		ask               = newAskOrder(db, ctx.Contract.CallerAddress, region, target, ra, ta, _rd, _td, ctx.Evm.BlockNumber)
		// 通过 indexAsk 拿出 askOrderList 并进行 filter ，得到可以撮合的集合
		indexBid OrderIndex = make([]*big.Int, 0)
		// 卖单id 索引 : [ ask.id, ask.id, ... ]
		indexAsk OrderIndex = make([]*big.Int, 0)
		// 卖单列表
		bidOrderlist OrderList = make([]*orderImpl, 0)
		// 买单索引Key
		indexBidKey = ask.indexKey(BID)
		// 卖单索引Key
		indexAskKey = ask.indexKey(ASK)
	)

	indexBidBuf, err := self.getKeyState(db, indexBidKey.Bytes())
	log.Trace("检查通过准备撮合", "ask", ask, "err", err, "indexBidBuf-len", indexBidBuf)
	// indexBidKey = [ bid.id, bid.id, ... ]
	if err == nil && len(indexBidBuf) > 0 {
		rlp.DecodeBytes(indexBidBuf, &indexBid)
		for i, bidKey := range indexBid {
			// ask order
			bidBuf, err := self.getKeyState(db, bidKey.Bytes())
			if err != nil {
				return err
			}
			order := new(orderImpl)
			err = rlp.DecodeBytes(bidBuf, &order)
			log.Trace("ask->bid 从索引还原 bidlist ", "i", i, "err", err, "id", bidKey, "bid", order)
			if err != nil {
				return err
			}
			bidOrderlist = append(bidOrderlist, order)
		}
		// 排序卖单列表
		log.Trace("bidlist 排序前", "bidOrderList", bidOrderlist)
		sort.Sort(bidOrderlist)
		log.Trace("bidlist 排序后", "bidOrderList", bidOrderlist)
		// 执行撮合，bid 为指针，撮合过程中会改变对象属性值，并顺带清理 askOrderlist
		log.Trace("开始撮合", "ask", ask, "bidlist", bidOrderlist)
		bidOrderlist = bidOrderlist.filter(ask)
		log.Trace("bidlist 过滤后", "bidOrderlist", bidOrderlist)
		dirty, err := self.combinationAsk(ctx, ask, bidOrderlist)
		if err != nil {
			return err
		}
		log.Trace("结束撮合", "ask", ask, "err", err, "dirty", dirty)
		// 把撮合完成的 ask 单做清除处理
		if dirty != nil && len(dirty) > 0 {
			log.Trace("清除撮合完的 ask", "dirty", dirty, "indexBid", indexBid)
			for i := 0; i < len(indexBid); i++ {
				bidKey := indexBid[i]
				_bid, ok := dirty[common.BytesToHash(bidKey.Bytes())]
				log.Trace("foreach indexBid : ", "bidKey", bidKey, "ok", ok, "bid", _bid)
				if ok {
					// TODO EVENT_DEL_BIDLIST(BID) : 订单处理日志处理方案需要确定 ?????
					// TODO EVENT_DEL_BIDLIST(BID) : 订单处理日志处理方案需要确定 ?????
					if _bid.Final {
						// 如果是 final 了就要删除索引
						indexBid = append(indexBid[:i], indexBid[i+1:]...)
						i--
						fmt.Printf("bid 索引变化 : EVENT_DEL_BIDLIST(%v)\n", _bid)
						// 删除订单前，要完成转账，BID 单需要把 RTargetAmount 增加到 Target 对应的余额中
						// 如果是实时结算，这个地方的逻辑就错了 :: 19-08-16 : 已经改成实时结算 >>>>
						// self.addBalanceLedger(db, _bid.Target, _bid.Owner, _bid.RTargetAmount)
						// 如果是实时结算，这个地方的逻辑就错了 :: 19-08-16 : 已经改成实时结算 <<<<
					}
					_bidBytes, err := _bid.rlpEncode()
					if err != nil {
						return err
					}
					// 刷新 bid 值
					self.setKeyState(db, _bid.Id.Bytes(), _bidBytes)
				}
			}
			// 在 indexAsk 中删除处理完成的索引信息
			indexBidVal, err := rlp.EncodeToBytes(indexBid)
			if err != nil {
				return err
			}
			// TODO :: 订单只要删掉索引就可以了吧？？？数据需要清除吗？
			// TODO :: 订单只要删掉索引就可以了吧？？？数据需要清除吗？
			self.setKeyState(db, indexBidKey.Bytes(), indexBidVal)
		}
	}
	log.Trace("撮合完毕", "ask", ask)

	// 如果撮合完了, ask.RTargetAmount > 0 则将撮合结果写入数据库
	if !ask.Final {
		log.Trace("写入 ask 单索引 到 indexAsk 中，存放 ask.Id >>>>", "ask", ask)
		// 写入 ask 单索引 到 indexAsk 中，存放 ask.Id >>>>
		if indexAskBuf, err := self.getKeyState(db, indexAskKey.Bytes()); err == nil && len(indexAskBuf) > 0 {
			rlp.DecodeBytes(indexAskBuf, &indexAsk)
		}
		indexAsk = append(indexAsk, ask.Id)
		indexAskVal, err := rlp.EncodeToBytes(indexAsk)
		if err != nil {
			return err
		}
		self.setKeyState(db, indexAskKey.Bytes(), indexAskVal)
		// 写入 ask 单索引 到 indexAsk 中，存放 ask.Id <<<<
		log.Trace("写入 ask 单索引 到 indexAsk 中，存放 ask.Id <<<<", "indexAsKey", indexAskKey.Hex(), "indexAsk-len", len(indexAsk))
		//} else {
		// 结算 region : 卖单撮合成功需要结算
		// 如果是实时结算，这个地方的逻辑就错了 :: 19-08-16 : 已经改成实时结算 >>>>
		// log.Trace("ask 结算 region : 卖单撮合成功需要结算 :", "region :", ask.Region.Hex(), ", add :", ask.RRegionAmount)
		// self.addBalanceLedger(db, region, ctx.Contract.CallerAddress, ask.RRegionAmount)
		// 如果是实时结算，这个地方的逻辑就错了 :: 19-08-16 : 已经改成实时结算 <<<<
	}
	log.Trace("写入 ask 到 statedb 中, key = ask.Id , val = ask.rlp >>>>", "askId", ask.Id, "ask", ask)
	// 写入 ask 到 statedb 中, key = ask.Id , val = ask.rlp >>>>
	askBytes, err := ask.rlpEncode()
	if err != nil {
		return err
	}
	self.eventAsk(ctx, ask.Owner, ask.Id)
	self.addOwnerOrder(ctx, ask)
	// TODO 给订单的 owner 创建索引，并且应该扩展为分区存储，索引最好不要无限增长
	// 将 ask 单写入 statedb , 每次 ask 都会产生新的 ask 订单
	err = self.setKeyState(db, ask.Id.Bytes(), askBytes)
	// 写入 ask 到 statedb 中, key = ask.Id , val = ask.rlp <<<<
	log.Trace("写入 ask 到 statedb 中, key = ask.Id , val = ask.rlp <<<<", "askId", ask.Id)
	// 除非事物没有成功，否则要扣除余额，无论撮合有没有成功，余额都应该放到订单中
	log.Trace("ask 账户余额调整:", "target", target.Hex(), "result", new(big.Int).Sub(_tb, ta), "tb", _tb, "ta", ta)
	return self.subBalanceLedger(db, target, ctx.Contract.CallerAddress, ta)
	//return self.setBalanceLedger(db, target, ctx.Contract.CallerAddress, new(big.Int).Sub(_tb, ta))

}

// 查询我的充值信息，erc20addr 对应充值的币种
//function balanceOf(Region address) constant returns(name string, symbol string, balance uint256, decimals uint8)
func (self *Pointsexange) balanceOf(ctx *PrecompiledContractContext, erc20addr common.Address) (name string, symbol string, balance *big.Int, decimals uint8, err error) {
	key := tab_ledger_key(erc20addr, ctx.Contract.CallerAddress)
	balanceBuff, err := self.getKeyState(ctx.Evm.StateDB, key.Bytes())
	balance = big.NewInt(0)
	if err == nil {
		balance = new(big.Int).SetBytes(balanceBuff)
	}
	log.Trace("[[ BalanceOf ]] ", "erc20addr", erc20addr.Hex(), "caller", ctx.Contract.CallerAddress.Hex(), "key", key.Hex(), "balance", balance)
	name, symbol, _, decimals, err = self.pointsInfo(ctx, erc20addr)
	return
}

func (self *Pointsexange) pointsInfo(ctx *PrecompiledContractContext, addr common.Address) (name string, symbol string, totalSupply *big.Int, decimals uint8, err error) {
	log.Trace("--> pointsInfo : ", "caller", ctx.Contract.CallerAddress.Hex(), "addr", addr.Hex())
	erc20, err := self.erc20caller(addr)
	if err != nil {
		return
	}
	opts := &bind.CallOpts{Context: self.ctx}
	name, err = erc20.Name(opts)
	if err != nil {
		return
	}
	symbol, err = erc20.Symbol(opts)
	if err != nil {
		return
	}
	totalSupply, err = erc20.TotalSupply(opts)
	if err != nil {
		return
	}
	decimals, err = erc20.Decimals(opts)
	return
}

// function withdrawal(address region,uint256 amount) public payable;
func (self *Pointsexange) withdrawal(ctx *PrecompiledContractContext, pointsaddr common.Address, amount *big.Int) error {
	_, _, b, _, err := self.balanceOf(ctx, pointsaddr)
	if err != nil {
		return err
	}
	if b.Cmp(amount) < 0 {
		return errors.New("balance can not less than amount")
	}
	gas := new(big.Int).Exp(big.NewInt(10), big.NewInt(15), nil)
	sender := ctx.Contract.Address()
	contract := NewContract(AccountRef(sender), AccountRef(pointsaddr), new(big.Int), gas.Uint64())
	contract.SetCallCode(&pointsaddr, ctx.Evm.StateDB.GetCodeHash(pointsaddr), ctx.Evm.StateDB.GetCode(pointsaddr))
	input, err := transferInput(ctx.Contract.Caller(), amount)
	log.Trace("Withdrawal", "err", err, "input", hex.EncodeToString(input))
	if err != nil {
		return err
	}
	_, err = ctx.Evm.interpreter.Run(contract, input, false)
	log.Trace("Withdrawal : 2", "err", err)
	if err != nil {
		return err
	}
	return self.subBalanceLedger(ctx.Evm.StateDB, pointsaddr, ctx.Contract.Caller(), amount)
}

/*func (self *pointsexange) pointsAppend(ctx *PrecompiledContractContext, pointsaddr common.Address) error {
	// validity pointsaddr is a erc20 contract
	code := ctx.Evm.StateDB.GetCode(pointsaddr)
	if !utils.ERC20Trait.IsERC20(code) {
		log.Trace("❌ pointsAppend-Fail : not a erc20 contract : ", pointsaddr.Hex())
		return nil
	}
	self.appendReg(ctx.Evm.StateDB, pointsaddr)
	log.Trace("🏦 pointsAppend-Success : collector erc20 contract : ", pointsaddr.Hex())
	return nil
}*/

func (self *Pointsexange) pointsList(ctx *PrecompiledContractContext) []common.Address {
	ret := make([]common.Address, 0)
	buff, err := self.getKeyState(ctx.Evm.StateDB, tab_reg_idx.Bytes())
	if err == nil && len(buff) > 0 {
		rlp.DecodeBytes(buff, &ret)
	}
	return ret
}

func (self *Pointsexange) orderlist(ctx *PrecompiledContractContext, t OrderType, region, target common.Address) ([]*big.Int, error) {
	var (
		index OrderIndex = make([]*big.Int, 0)
		order            = new(orderImpl)
	)
	order.Region, order.Target = region, target
	indexKey := order.indexKey(t)
	buff, err := self.getKeyState(ctx.Evm.StateDB, indexKey.Bytes())
	if err != nil {
		return nil, err
	}
	if buff != nil && len(buff) > 0 {
		err = rlp.DecodeBytes(buff, &index)
	}
	return index, err
}

/*
func (self *pointsexange) setBalanceLedger(db StateDB, erc20points, owner common.Address, balance *big.Int) error {
	if !db.Exist(pointsexagenAddress) {
		db.CreateAccount(pointsexagenAddress)
		// TODO must be EIP158
		db.SetNonce(pointsexagenAddress, 1)
	}
	ledgerKey := tab_ledger_key(erc20points, owner)
	return self.setKeyState(db, ledgerKey.Bytes(), balance.Bytes())
}
*/

// 拦截到 erc20.transfer 时触发执行，用来生成抵押账本
// FROM = { ERC20points : AMOUNT }
func (self *Pointsexange) addBalanceLedger(db StateDB, erc20points, from common.Address, amount *big.Int) error {
	if !db.Exist(pointsExagenAddress) {
		db.CreateAccount(pointsExagenAddress)
		// TODO must be EIP158
		db.SetNonce(pointsExagenAddress, 1)
	}
	ledgerKey := tab_ledger_key(erc20points, from)
	data, err := self.getKeyState(db, ledgerKey.Bytes())
	oldbalance := big.NewInt(0)
	if err == nil {
		oldbalance = new(big.Int).SetBytes(data)
	}
	newbalance := new(big.Int).Add(oldbalance, amount)
	log.Trace("[[ addBalanceLedger ]] : ", "erc20points", erc20points.Hex(), "from", from.Hex(), ", key", ledgerKey.Hex(), "old_val", oldbalance, "new_val", newbalance)
	err = self.setKeyState(db, ledgerKey.Bytes(), newbalance.Bytes())
	if err != nil {
		log.Error("[[ addBalanceLedger-error ]]", "err", err)
	}
	return err
}

func (self *Pointsexange) subBalanceLedger(db StateDB, erc20points, account common.Address, amount *big.Int) error {
	if !db.Exist(pointsExagenAddress) {
		db.CreateAccount(pointsExagenAddress)
		// TODO must be EIP158
		db.SetNonce(pointsExagenAddress, 1)
	}
	ledgerKey := tab_ledger_key(erc20points, account)
	data, err := self.getKeyState(db, ledgerKey.Bytes())
	oldbalance := big.NewInt(0)
	if err == nil {
		oldbalance = new(big.Int).SetBytes(data)
		if amount.Cmp(oldbalance) > 0 {
			return errors.New("sub balance error , amount big than old balance")
		}
		newbalance := new(big.Int).Sub(oldbalance, amount)
		log.Trace("[[ subBalanceLedger ]] : ", "erc20points", erc20points.Hex(), "account", account.Hex(), ", key", ledgerKey.Hex(), "old_val", oldbalance, "new_val", newbalance)
		err = self.setKeyState(db, ledgerKey.Bytes(), newbalance.Bytes())
		if err != nil {
			log.Error("[[ subBalanceLedger-error ]]", "err", err)
		}
	}
	return err
}

// 拦截到 erc20 部署时触发执行
func (self *Pointsexange) appendReg(db StateDB, addr common.Address) error {
	if !db.Exist(pointsExagenAddress) {
		db.CreateAccount(pointsExagenAddress)
		// TODO must be EIP158
		db.SetNonce(pointsExagenAddress, 1)
	}
	code := db.GetCode(addr)
	err := erc20points.Template.VerifyCode(code)
	if err != nil {
		log.Error("pointsexange-appendReg-error-1", "err", err)
		return err
	}
	// 这个只是用来判断索引是否重复添加过，没有其他作用
	// 不过这个地方也是多余的，因为多次部署不会产生相同的 addr
	key := tab_reg_key(addr)
	// 映射
	_, err = self.getKeyState(db, key.Bytes())
	if err != nil {
		// 索引 ：只添加一次
		idxBuff, err := self.getKeyState(db, tab_reg_idx.Bytes())
		var idxList = make([]common.Address, 0)
		if idxBuff != nil && len(idxBuff) > 0 {
			rlp.DecodeBytes(idxBuff, &idxList)
		}
		idxList = append(idxList, addr)
		idxBuff, _ = rlp.EncodeToBytes(idxList)
		err = self.setKeyState(db, tab_reg_idx.Bytes(), idxBuff)
		if err != nil {
			log.Error("pointsexange-appendReg-error-2", "err", err)
			return err
		}
	}
	// 如果有值就去覆盖
	err = self.setKeyState(db, key.Bytes(), addr.Hash().Bytes())
	return err
}

func (self *Pointsexange) setState(db StateDB, key []byte, value []byte) {
	k := util.EthHash(key)
	v := util.EthHash(value)
	db.SetState(pointsExagenAddress, k, v)
}

func (self *Pointsexange) getState(db StateDB, key []byte) common.Hash {
	k := util.EthHash(key)
	hash := db.GetState(pointsExagenAddress, k)
	return hash
}

func (self *Pointsexange) setCRDState(db StateDB, value []byte) {
	keyHash := util.EthHash(value)
	db.SetCRDState(pointsExagenAddress, keyHash, value)
}

func (self *Pointsexange) getCRDState(db StateDB, key common.Hash) []byte {
	return db.GetCRDState(pointsExagenAddress, key)
}

func (self *Pointsexange) setKeyState(db StateDB, key, val []byte) error {
	self.setState(db, key, val)
	self.setCRDState(db, val)
	return nil
}

func (self *Pointsexange) getKeyState(db StateDB, key []byte) ([]byte, error) {
	valueHash := self.getState(db, key)
	if (valueHash == common.Hash{}) {
		return nil, fmt.Errorf("key [%s] not found", common.BytesToHash(key).Hex())
	}
	return self.getCRDState(db, valueHash), nil
}

func (self *Pointsexange) erc20caller(addr common.Address) (*pointsexangelib.EIP20InterfaceCaller, error) {
	return pointsexangelib.NewEIP20InterfaceCaller(addr, self.backend)
}

// TODO 个人订单的设计目标是不分交易区检索，和分交易区检索两种方式，均按照 blockNumber 倒序排列，并且应当分页存储，暂时简化处理先不分页 >>>
// TODO 个人订单的设计目标是不分交易区检索，和分交易区检索两种方式，均按照 blockNumber 倒序排列，并且应当分页存储，暂时简化处理先不分页 >>>
func (self *Pointsexange) addOwnerOrder(ctx *PrecompiledContractContext, order *orderImpl) error {
	var (
		allKey, regionKey = tab_owner_idx(order.Owner, order.Region, order.Target)
		store             = func(key common.Hash, val *big.Int) error {
			var idx OrderIndex = make([]*big.Int, 0)
			buf, err := self.getKeyState(ctx.Evm.StateDB, key.Bytes())
			if err == nil && buf != nil && len(buf) > 0 {
				if err := rlp.DecodeBytes(buf, &idx); err != nil {
					log.Error("addOwnerOrder.store", "err", err)
					return err
				}
			}
			idx = append(idx, order.Id)
			log.Trace("addOwnerOrder ", "idx", idx)
			if buf, err = rlp.EncodeToBytes(idx); err != nil {
				log.Error("addOwnerOrder.store", "err", err)
				return err
			}
			return self.setKeyState(ctx.Evm.StateDB, key.Bytes(), buf)
		}
	)
	log.Trace("addOwnerOrder", "ownerkeys", allKey.Hex(), "regionKey", regionKey.Hex())
	err1 := store(allKey, order.Id)
	log.Trace("store all ->", "err", err1, "ownerkeys", allKey.Hex(), "orderId", order.Id)
	err2 := store(regionKey, order.Id)
	log.Trace("store region ->", "err", err2, "regionKey", regionKey.Hex(), "orderId", order.Id)
	return nil
}

// 检索条件 addrs 最多包含 [owner,region,target] 三个值，至少包含 [owner] 一个值, pageNum 表示页号(暂时无效)
func (self *Pointsexange) fetchOwnerOrder(ctx *PrecompiledContractContext, addrs []common.Address, pageNum *big.Int) (OrderIndex, error) {
	var (
		key   common.Hash
		empty = common.HexToAddress("0x")
		fetch = func(key common.Hash, pn *big.Int) (OrderIndex, error) {
			// pn == pageNum
			buf, err := self.getKeyState(ctx.Evm.StateDB, key.Bytes())
			log.Trace("fetchOwnerOrder", "fetch_key", key.Hex(), "err", err, "buf", buf)
			if err == nil && len(buf) > 0 {
				var list OrderIndex = make([]*big.Int, 0)
				if err = rlp.DecodeBytes(buf, &list); err != nil {
					return nil, err
				}
				return list, nil
			}
			return nil, err
		}
	)
	switch len(addrs) {
	case 1:
		key, _ = tab_owner_idx(addrs[0], empty, empty)
	case 3:
		_, key = tab_owner_idx(addrs[0], addrs[1], addrs[2])
	default:
		return nil, errors.New("error args : addrs , expect format addrs = [owner] / [owner,region,target]")
	}
	return fetch(key, pageNum)
}

// TODO 个人订单的设计目标是不分交易区检索，和分交易区检索两种方式，均按照 blockNumber 倒序排列，并且应当分页存储，暂时简化处理先不分页 <<<
// TODO 个人订单的设计目标是不分交易区检索，和分交易区检索两种方式，均按照 blockNumber 倒序排列，并且应当分页存储，暂时简化处理先不分页 <<<

/* TOPIC-0
   Combination 	:	d025af3c283935511f884c83da0d18eb1895cfb7aca5659b459d93ada7d2969e
   Bid 			:	e684a55f31b79eca403df938249029212a5925ec6be8012e099b45bc1019e5d2
   Ask 			:	32eb218d63024a6bd54a3e6467c1545c355c44c2e1c17940b1a0ed1555ffeffe

e Combination(
	orderid indexed uint256, owner indexed address,
	region address, rc int8, regionAmount uint256,
	target address, tc int8, targetAmount uint256
)
*/
func (self *Pointsexange) eventCombination(ctx *PrecompiledContractContext,
	orderid *big.Int, owner common.Address,
	region common.Address, rc int8, regionAmount *big.Int,
	target common.Address, tc int8, targetAmount *big.Int) error {

	var contractAddr = common.Address{}
	if ctx != nil {
		contractAddr = ctx.Contract.Address()
	}
	topics := make([]common.Hash, 3)
	topics[0] = common.HexToHash("d025af3c283935511f884c83da0d18eb1895cfb7aca5659b459d93ada7d2969e")
	topics[1] = common.BigToHash(orderid)
	topics[2] = owner.Hash()
	data, err := _abi.Events["Combination"].Inputs.Pack(orderid, owner, region, rc, regionAmount, target, tc, targetAmount)
	if err != nil {
		return err
	}

	_log := &types.Log{
		Address: contractAddr,
		Topics:  topics,
		Data:    data[64:],
	}
	logdata, _ := json.Marshal(_log)
	log.Trace("[EventCombination]", "owner", owner.Hex(), "id", orderid, "data.len", len(_log.Data), "log", string(logdata))
	if ctx == nil { // for test
		return nil
	}
	ctx.Evm.StateDB.AddLog(_log)
	return nil
}

// e Bid(owner indexed address, orderid indexed uint256)
func (self *Pointsexange) eventBid(ctx *PrecompiledContractContext, owner common.Address, orderid *big.Int) error {
	log.Trace("[EventBid]", "owner", owner.Hex(), "bid.id", orderid)
	return self.orderevent(ctx, "e684a55f31b79eca403df938249029212a5925ec6be8012e099b45bc1019e5d2", owner, orderid)
}

// e Ask(owner indexed address, orderid indexed uint256)
func (self *Pointsexange) eventAsk(ctx *PrecompiledContractContext, owner common.Address, orderid *big.Int) error {
	log.Trace("[EventAsk]", "owner", owner.Hex(), "ask.id", orderid)
	return self.orderevent(ctx, "32eb218d63024a6bd54a3e6467c1545c355c44c2e1c17940b1a0ed1555ffeffe", owner, orderid)
}

func (self *Pointsexange) orderevent(ctx *PrecompiledContractContext, sig string, owner common.Address, orderid *big.Int) error {
	var contractAddr = common.Address{}
	if ctx != nil {
		contractAddr = ctx.Contract.Address()
	}
	topics := make([]common.Hash, 3)
	topics[0] = common.HexToHash(sig)
	topics[1] = owner.Hash()
	topics[2] = common.BigToHash(orderid)
	_log := &types.Log{
		Address: contractAddr,
		Topics:  topics,
	}
	logdata, _ := json.Marshal(_log)
	log.Trace("orderevent", "log", string(logdata))
	if ctx == nil { // for test
		return nil
	}
	ctx.Evm.StateDB.AddLog(_log)
	return nil
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// 撮合算法描述 : contracts/pointsexange/README.md
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

// 由 ask 触发的撮合，针对当前 bidlist 进行实际撮合
// 返回 bidlist 中已经完成撮合的 订单集合
// TODO : 这里有一个 bug , 如果只返回处理完成的订单数据，那么处理到一半的订单将无法继续处理，
//  	  所以应该把所有处理过的订单全部返回，按照 final 区分状态分别处理
func (self *Pointsexange) combinationAsk(ctx *PrecompiledContractContext, ask1 *orderImpl, bidlist OrderList) (dirty map[common.Hash]*orderImpl, err error) {
	dirty = make(map[common.Hash]*orderImpl)
	if ask1.OrderType != ASK {
		return nil, errors.New("error_order_type")
	}

	// 按照 snapshot 结算
	var (
		askSnapshot     = ask1.snapshot()
		bidlistSnapshot = make([]*orderImpl, 0)
		zero            = big.NewInt(0)
	)
	// 撮合完成就去尝试结算
	defer func() {
		log.Trace("combinationAsk", "askSnapshot", askSnapshot, "askSnapshot.equal(ask1)", askSnapshot.equal(ask1))
		log.Trace("combinationAsk", "bidlistSnapshot", bidlistSnapshot)
		if !askSnapshot.equal(ask1) {
			//TODO 结算
			RA := new(big.Int).Sub(ask1.RRegionAmount, askSnapshot.RRegionAmount)
			RB := new(big.Int).Sub(askSnapshot.RTargetAmount, ask1.RTargetAmount)
			log.Trace("[combinationAsk] ask 结算金额 ", "askSnapshot", askSnapshot, "ask1", ask1, "(+)RA", RA, "(-)RB", RB)
			if RA.Cmp(zero) < 0 || RB.Cmp(zero) < 0 {
				err = fmt.Errorf("[combinationAsk error result] : ask=%s , (+)RA=%d , (-)RB=%d", ask1.String(), RA, RB)
				return
			}
			self.transferLedger(ctx, +1, ask1.Region, ask1.Owner, RA)
			// 挂单时已经扣过了，不能重复扣款
			//self.transferLedger(ctx, -1, ask1.Target, ask1.Owner, RB)
			//combinationEvent(ask.id,owner,region,+1,ra,target,-1,rb)
			self.eventCombination(ctx, ask1.Id, ask1.Owner, ask1.Region, +1, RA, ask1.Target, -1, RB)
		}
		for _, bidSnapshot := range bidlistSnapshot {
			if bid, ok := dirty[common.BytesToHash(bidSnapshot.Id.Bytes())]; ok && !bidSnapshot.equal(bid) {
				//TODO 结算
				RA := new(big.Int).Sub(bidSnapshot.RRegionAmount, bid.RRegionAmount)
				RB := new(big.Int).Sub(bid.RTargetAmount, bidSnapshot.RTargetAmount)
				log.Trace("[combinationAsk] bid 结算金额 :", "bidSnapshot", bidSnapshot, "bid", bid, "(-)RA", RA, "(+)RB", RB)
				if RA.Cmp(zero) < 0 || RB.Cmp(zero) < 0 {
					err = fmt.Errorf("[combinationAsk error result] : bid=%s , (-)RA=%d , (+)RB=%d", bid.String(), RA, RB)
					return
				}
				// 挂单时已经扣过了，不能重复扣款
				//self.transferLedger(ctx, -1, bid.Region, bid.Owner, RA)
				self.transferLedger(ctx, +1, bid.Target, bid.Owner, RB)
				//combinationEvent(bid.id,owner,region,-1,ra,target,+1,rb)
				self.eventCombination(ctx, bid.Id, bid.Owner, bid.Region, -1, RA, bid.Target, +1, RB)
			}
		}
	}()

	for i := 0; i < len(bidlist); i++ {
		bid := bidlist[i]
		bidlistSnapshot = append(bidlistSnapshot, bid.snapshot())
		log.Trace("do combinationAsk ----->", "i", i, "ask1", ask1)
		/* 191218 modify log
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
		*/
		condition := ask1.askRB_sub_bidRA_div_bidPrice_for_RB(bid) // ask.RB - bid.RA/bid.P
		if condition.Cmp(zero) >= 0 {                              // ask.RB >= bid.RA/bid.P
			//ASK1.RB = ASK1.RB - (BID1.B-BID1.RB) // 当 RB > B 时这个条件就错了
			//ask1.RTargetAmount = new(big.Int).Sub(ask1.RTargetAmount, new(big.Int).Sub(bid.TargetAmount, bid.RTargetAmount))
			// ******** ask.RB = ask.RB - bid.RA/bid.P ***********
			ask1.RTargetAmount = condition
			//ASK1.RA = ASK1.RA + BID1.RA
			ask1.RRegionAmount = new(big.Int).Add(ask1.RRegionAmount, bid.RRegionAmount)
			//BID1.RB = BID1.B : // 当 RB > B 时这个条件就错了
			//bid.RTargetAmount.SetBytes(bid.TargetAmount.Bytes())
			// ******** bid.RB = bid.RB + bid.RA/bid.P ***********
			bid.RTargetAmount = bid.bidRB_add_bidRA_div_bidPrice_for_RB()
			//BID1.RA = 0 : bid.RA = 0
			bid.RRegionAmount.SetBytes(zero.Bytes())
		} else { //ASK1.RB < ( BID1.B - BID1.RB )  -->  ask.RB < bid.RA/bid.P
			//BID2.RB = BID2.RB + ASK1.RB
			bid.RTargetAmount = new(big.Int).Add(bid.RTargetAmount, ask1.RTargetAmount)
			//ASK1.RA = ASK1.RA + ASK1.RB * BID2.P
			//ask1rb := ask1.rTargetMulPrice(bid.price()) // ASK1.RB*BID2.P
			//ask1.RRegionAmount = new(big.Int).Add(ask1.RRegionAmount, ask1rb)

			ask1.RRegionAmount = ask1.askRA_add_askRB_mul_bidPrice_for_RA(bid)
			//BID2.RA = BID2.RA - ASK1.RB * BID2.P
			//bid.RRegionAmount = new(big.Int).Sub(bid.RRegionAmount, ask1rb)
			bid.RRegionAmount = bid.bidRA_sub_askRB_mul_bidPrice_for_RA(ask1)
			//ASK1.RB = 0
			ask1.RTargetAmount.SetBytes(zero.Bytes())
		}
		//IF BID2.RA == 0 : DEL BID2
		if bid.RRegionAmount.Cmp(zero) == 0 {
			bid.Final = true
			log.Trace("EVENT 完成撮合 ASK->BIDList :", "bid", bid)
		}
		dirty[common.BytesToHash(bid.Id.Bytes())] = bid
		//IF ASK1.RB == 0 : DEL ASK1
		if ask1.RTargetAmount.Cmp(zero) == 0 {
			ask1.Final = true
			log.Trace("EVENT 撮合 ASK 成功 2 : RETURN", "ask1", ask1, "dirty", dirty)
			return dirty, nil
		}
	}
	return dirty, nil
}

// 由 bid 触发的撮合，针对当前 asklist 进行实际撮合
// 返回 asklist 中已经完成撮合的 订单集合
func (self *Pointsexange) combinationBid(ctx *PrecompiledContractContext, bid1 *orderImpl, asklist OrderList) (dirty map[common.Hash]*orderImpl, err error) {
	dirty = make(map[common.Hash]*orderImpl)
	if bid1.OrderType != BID {
		return nil, errors.New("error_order_type")
	}
	// 按照 snapshot 结算
	var (
		bidSnapshot     = bid1.snapshot()
		asklistSnapshot = make([]*orderImpl, 0)
		zero            = big.NewInt(0)
	)
	defer func() {
		log.Trace("combinationBid", "bidSnapshot", bidSnapshot, "bidSnapshot.equal(bid1)", bidSnapshot.equal(bid1))
		log.Trace("combinationBid", "asklistSnapshot", asklistSnapshot)
		if !bidSnapshot.equal(bid1) {
			//TODO 结算
			RA := new(big.Int).Sub(bidSnapshot.RRegionAmount, bid1.RRegionAmount)
			RB := new(big.Int).Sub(bid1.RTargetAmount, bidSnapshot.RTargetAmount)
			log.Trace("[combinationBid] bid 结算金额 :", "bidSnapshot", bidSnapshot, "bid1", bid1, "(-)RA", RA, "(+)RB", RB)
			if RA.Cmp(zero) < 0 || RB.Cmp(zero) < 0 {
				err = fmt.Errorf("[combinationBid error result] : bid=%s , (-)RA=%d , (+)RB=%d", bid1.String(), RA, RB)
				return
			}
			// 挂单时已经扣过了，不能重复扣款
			// self.transferLedger(ctx, -1, bid1.Region, bid1.Owner, RA)
			self.transferLedger(ctx, +1, bid1.Target, bid1.Owner, RB)
			self.eventCombination(ctx, bid1.Id, bid1.Owner, bid1.Region, -1, RA, bid1.Target, +1, RB)
		}
		for _, askSnapshot := range asklistSnapshot {
			if ask, ok := dirty[common.BytesToHash(askSnapshot.Id.Bytes())]; ok && !askSnapshot.equal(ask) {
				//TODO 结算
				RA := new(big.Int).Sub(ask.RRegionAmount, askSnapshot.RRegionAmount)
				RB := new(big.Int).Sub(askSnapshot.RTargetAmount, ask.RTargetAmount)
				log.Trace("[combinationBid] ask 结算金额 :", "askSnapshot", askSnapshot, "ask", ask, "(+)RA", RA, "(-)RB", RB)
				if RA.Cmp(zero) < 0 || RB.Cmp(zero) < 0 {
					err = fmt.Errorf("[combinationBid error result] : ask=%s , (+)RA=%d , (-)RB=%d", ask.String(), RA, RB)
					return
				}
				self.transferLedger(ctx, +1, ask.Region, ask.Owner, RA)
				// 挂单时已经扣过了，不能重复扣款
				// self.transferLedger(ctx, -1, ask.Target, ask.Owner, RB)
				self.eventCombination(ctx, ask.Id, ask.Owner, ask.Region, +1, RA, ask.Target, -1, RB)
			}
		}
	}()

	for i := 0; i < len(asklist); i++ {
		ask := asklist[i]
		asklistSnapshot = append(asklistSnapshot, ask.snapshot())
		log.Trace("combinationBid", "SNAPSHOT", asklistSnapshot, "bid1", bid1, "i", i)
		/* 191218 modify log
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
		ask.RA = ask.RA + bid.RA
		ask.RB = ask.RB - bid.RA / ask.P	=> ask = {A:10,B:40}(P=0.25){RA:5,RB:20}(Final:false)
		bid.RB = bid.RA / ask.P
		bid.RA = 0 							=> bid = {A:5,B:10}(P=0.5){RA:0,RB:20}(Final:true)
		*/
		condition := ask.askRB_mut_askPrice_for_RA()
		//if bid1.RRegionAmount.Cmp(new(big.Int).Sub(ask.RegionAmount, ask.RRegionAmount)) >= 0 { // BID1.RA >= (ASK1.A - ASK1.RA)
		if bid1.RRegionAmount.Cmp(condition) >= 0 { // bid.RA >= ask.RB * ask.P
			//BID1.RA = BID1.RA - (ASK1.A - ASK1.RA)
			//bid1.RRegionAmount = new(big.Int).Sub(bid1.RRegionAmount, new(big.Int).Sub(ask.RegionAmount, ask.RRegionAmount))
			// XXXX : bid.RA = bid.RA - ask.RB * ask.P  	=> bid = {A:10,B:20}(P=0.5){RA:0,RB:0}
			bid1.RRegionAmount = new(big.Int).Sub(bid1.RRegionAmount, condition)
			//BID1.RB =  BID1.RB + ASK1.RB
			bid1.RTargetAmount = new(big.Int).Add(bid1.RTargetAmount, ask.RTargetAmount)
			// ASK1.RA = ASK1.A
			//ask.RRegionAmount.SetBytes(ask.RegionAmount.Bytes())
			// TODO ASK1.RA = ASK1.RA + ASK1.A
			if ask.RRegionAmount == nil {
				ask.RRegionAmount = big.NewInt(0)
			}
			ask.RRegionAmount = new(big.Int).Add(ask.RRegionAmount, ask.RegionAmount)
			//ASK1.RB = 0
			ask.RTargetAmount.SetBytes(zero.Bytes())

		} else { // BID1.RA < (ASK2.A - ASK2.RA)
			//ASK2.RA = ASK2.RA+BID1.RA
			ask.RRegionAmount = new(big.Int).Add(ask.RRegionAmount, bid1.RRegionAmount)
			/*
				//ASK2.RB = ASK2.RB - (BID1.B-BID1.RB)
				ask.RTargetAmount = new(big.Int).Sub(ask.RTargetAmount, new(big.Int).Sub(bid1.TargetAmount, bid1.RTargetAmount))
				//BID1.RB = BID1.B
				bid1.RTargetAmount.SetBytes(bid1.TargetAmount.Bytes())
			*/
			//XXXX : ask.RB = ask.RB - bid.RA / ask.P
			ask.RTargetAmount = bid1.askRB_sub_bidRA_div_askPrice_for_RB(ask)

			//TODO : bid.RB = bid.RB + bid.RA / ask.P
			log.Trace("combinationBid", "bid1", bid1.String(), "ask", ask)
			bid1.RTargetAmount = new(big.Int).Add(bid1.RTargetAmount, bid1.bidRA_div_askPrice_for_RB(ask))
			log.Trace("combinationBid", "bid1", bid1.String())
			//BID1.RA = 0
			bid1.RRegionAmount.SetBytes(zero.Bytes())
		}
		//IF ASK1.RB == 0 : DEL ASK1
		if ask.RTargetAmount.Cmp(zero) == 0 {
			ask.Final = true
			log.Trace("EVENT 完成撮合 BID->ASKList :", "ask", ask)
		}
		dirty[common.BytesToHash(ask.Id.Bytes())] = ask
		//IF BID1.RA == 0 : DEL BID1
		if bid1.RRegionAmount.Cmp(zero) == 0 {
			bid1.Final = true
			log.Trace("EVENT 撮合 BID 成功 1 : RETURN BID ", "bid1", bid1)
			return dirty, nil
		}
	}
	return
}

// 实时结算
func (self *Pointsexange) transferLedger(ctx *PrecompiledContractContext, action int, erc20, account common.Address, amount *big.Int) {
	if ctx == nil {
		return
	}
	db := ctx.Evm.StateDB
	switch action {
	case +1:
		// erc20 对应的地址要给 order.owner 余额增加 amount
		self.addBalanceLedger(db, erc20, account, amount)
	case -1:
		// erc20 对应的地址要给 order.owner 余额减少 amount
		self.subBalanceLedger(db, erc20, account, amount)
	}
}

// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
// 撮合算法描述 : contracts/pointsexange/README.md
// <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
