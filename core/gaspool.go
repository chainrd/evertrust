// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"fmt"
	"math"
	"CRD-chain/log"
	"sync/atomic"
)

// GasPool tracks the amount of gas available during execution of the transactions
// in a block. The zero value is a pool with zero gas available.
type GasPool uint64

// AddGas makes gas available for execution.
func (gp *GasPool) AddGas(amount uint64) *GasPool {
	old := atomic.LoadUint64((*uint64)(gp))

	for old <= math.MaxUint64-amount && !atomic.CompareAndSwapUint64((*uint64)(gp), old, old+amount) {
		old = atomic.LoadUint64((*uint64)(gp))
	}
	if old > math.MaxUint64-amount{
		panic("gas pool pushed above uint64")
	}

	//*(*uint64)(gp) += amount
	return gp
}

// SubGas deducts the given amount from the pool if enough gas is
// available and returns an error otherwise.
func (gp *GasPool) SubGas(amount uint64) error {
	//log.Info("SubGas对比", "GasPool", uint64(*gp), "花费gas", amount)
	old := atomic.LoadUint64((*uint64)(gp))

	for old >= amount && !atomic.CompareAndSwapUint64((*uint64)(gp), old, old-amount) {
		old = atomic.LoadUint64((*uint64)(gp))
	}

	if old < amount {
		log.Error("SubGas对比", "GasPool", uint64(*gp), "花费gas", amount)
		return ErrGasLimitReached
	}
	//*(*uint64)(gp) -= amount
	return nil
}

// Gas returns the amount of gas remaining in the pool.
func (gp *GasPool) Gas() uint64 {
	return atomic.LoadUint64((*uint64)(gp))
}

func (gp *GasPool) String() string {
	return fmt.Sprintf("%d", gp.Gas())
}
