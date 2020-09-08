// Copyright 2014 The go-ethereum Authors
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

// Package state provides a caching layer atop the Ethereum state trie.
package state

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/crypto"
	"CRD-chain/log"
	"CRD-chain/rlp"
	"CRD-chain/trie"
)

var ErrMStateDBDeadLock = errors.New("deadlock occurred")
var _ IStateDB = &MStateDB{}

// MContext multi-goroutine execution context
type MContext struct {
	// Locked list by running Txs
	lockedAccount map[common.Address]common.Hash
	accountLock   map[common.Address]*sync.Mutex
	txLockQueue   map[common.Hash][]common.Address
	// can be executed and verified in order
	executedTxs []common.Hash

	// main lock to MContext
	mLock  sync.Mutex

	// global state objects
	stateObjects  map[common.Address]*stateObject
	stLock sync.RWMutex

	// lock StateDB Trie
	trieLock sync.RWMutex
}

// MStateDB multi-goroutine executable StateDB
// implements IStateDB interface
type MStateDB struct {
	stdb *StateDB
	ctx  *MContext
}

func NewMStateDB(st *StateDB, num int) ([]*MStateDB, error) {
	if num < 1 {
		return nil, errors.New("NewMStateDB: Invalid multi-goroutine number")
	}

	mctx := &MContext{
		lockedAccount: make(map[common.Address]common.Hash),
		accountLock:   make(map[common.Address]*sync.Mutex),
		txLockQueue:   make(map[common.Hash][]common.Address),
		stateObjects:      make(map[common.Address]*stateObject),
	}

	var mdb []*MStateDB
	for i := 0; i < num; i++ {
		tmp := &MStateDB{stdb: &StateDB{
			db:                st.db,
			trie:              st.trie,
			stateObjects:      make(map[common.Address]*stateObject),
			stateObjectsDirty: make(map[common.Address]struct{}),
			logs:              make(map[common.Hash][]*types.Log),
			preimages:         make(map[common.Hash][]byte),
			journal:           newJournal(),
		},
			ctx: mctx,
		}
		mdb = append(mdb, tmp)
	}

	return mdb, nil
}


func (self *MStateDB) AddLog(log *types.Log) {
	self.stdb.AddLog(log)
}

func (self *MStateDB) GetLogs(hash common.Hash) []*types.Log {
	return self.stdb.GetLogs(hash)
}

func (self *MStateDB) Logs() []*types.Log {
	return self.stdb.Logs()
}

// AddPreimage records a SHA3 preimage seen by the VM.
func (self *MStateDB) AddPreimage(hash common.Hash, preimage []byte) {
	self.stdb.AddPreimage(hash, preimage)
}

// Preimages returns a list of SHA3 preimages that have been submitted.
func (self *MStateDB) Preimages() map[common.Hash][]byte {
	return self.stdb.Preimages()
}

func (self *MStateDB) AddRefund(gas uint64) {
	self.stdb.AddRefund(gas)
}

// Exist reports whether the given account address exists in the state.
// Notably this also returns true for suicided accounts.
func (self *MStateDB) Exist(addr common.Address) bool {
	self.requestAndLock(addr)
	return self.getStateObject(addr) != nil
}

// Empty returns whether the state object is either non-existent
// or empty according to the EIP161 specification (balance = nonce = code = 0)
func (self *MStateDB) Empty(addr common.Address) bool {
	self.requestAndLock(addr)
	so := self.getStateObject(addr)
	return so == nil || so.empty()
}

// example: tx1: A -> B(locked) -> C(locking)
//          tx2: X -> C(locked) -> B/D(locking)
//          tx3: D -> B(locking)
// txLockQueue[tx1]: A B C
//            [tx2]: X C B/D
//            [tx3]: D B
// lockedAccount[A]: tx1
//              [B]: tx1
//              [C]: tx2
//              [D]: tx3
//              [X]: tx2
func (self *MStateDB) _checkDeadLock(lockingAddr common.Address, lockQueue []common.Address, addr common.Address) bool {
	tx := self.ctx.lockedAccount[lockingAddr]
	for tx != self.ctx.lockedAccount[addr] {

		for _, acc := range lockQueue {
			if acc == lockingAddr {
				return true
			}
		}
		//tx1[len(tx1)-1]
		addr = lockingAddr
		tx = self.ctx.lockedAccount[lockingAddr]
		txQueue := self.ctx.txLockQueue[tx]
		if len(txQueue) > 1 {
			lockingAddr = txQueue[len(txQueue)-1]
		} else {
			return false
		}
	}

	return false
}

func (self *MStateDB) requestAndLock(addr common.Address) {
	//not locked by tx, lock it
	self.ctx.mLock.Lock()

	if (self.ctx.lockedAccount[addr] == self.stdb.thash) {
		// this tx holds the account lock, so just return
		self.ctx.mLock.Unlock()
		return

	} else if (self.ctx.lockedAccount[addr] == common.Hash{}) {
		// account is unlocked, lock it
		self.ctx.lockedAccount[addr] = self.stdb.thash
		aLock := &sync.Mutex{}
		aLock.Lock()
		log.Info("lockedaccount", "addr", addr, "lock", aLock)
		self.ctx.accountLock[addr] = aLock
		self.ctx.txLockQueue[self.stdb.thash] = append(self.ctx.txLockQueue[self.stdb.thash], addr)
		self.ctx.mLock.Unlock()

	} else {
		// account locked by other tx(goroutine)
		// check whether deadlock occurs after locking
		tx1 := self.ctx.lockedAccount[addr]
		tx1_LQ := self.ctx.txLockQueue[tx1]
		tx2_LQ := self.ctx.txLockQueue[self.stdb.thash]
		if  len(tx1_LQ)>1 && len(tx2_LQ)>0 && self._checkDeadLock(tx1_LQ[len(tx1_LQ)-1], tx2_LQ, addr) {
			self.ctx.mLock.Unlock()
			log.Debug("deadlock occurred:", "lockedAccount",self.ctx.lockedAccount, "txLockQueue",self.ctx.txLockQueue)
			panic(ErrMStateDBDeadLock)
		}else {
			self.ctx.txLockQueue[self.stdb.thash] = append(self.ctx.txLockQueue[self.stdb.thash], addr)
			aLock := self.ctx.accountLock[addr]
			self.ctx.mLock.Unlock()
			// locking
			aLock.Lock()
			self.ctx.mLock.Lock()
			self.ctx.lockedAccount[addr] = self.stdb.thash

			//if tx1 == self.ctx.lockedAccount[addr] {
			//	self.ctx.lockedAccount[addr] = self.stdb.thash
			//} else {
			//	//deadlock???
			//	log.Info("maybe deadlock", "thash:", self.ctx.lockedAccount[addr])
			//}
			self.ctx.lockedAccount[addr] = self.stdb.thash
			self.ctx.mLock.Unlock()
		}
	}
}

func (self *MStateDB) UnLockAccounts(addTx bool) {
	self.ctx.mLock.Lock()

	accounts := self.ctx.txLockQueue[self.stdb.thash]
	if addTx {
		self.ctx.executedTxs = append(self.ctx.executedTxs, self.stdb.thash)
	}
	var accountLocks []*sync.Mutex
	for _, acc := range accounts {
		al := self.ctx.accountLock[acc]
		accountLocks = append(accountLocks, al)
		//delete(self.ctx.accountLock, acc)
	}
	delete(self.ctx.txLockQueue, self.stdb.thash)
	self.ctx.mLock.Unlock()

	for _, al := range accountLocks {
		al.Unlock()
	}
}

func (self *MStateDB) GetTxs() []common.Hash {
	self.ctx.mLock.Lock()
	defer self.ctx.mLock.Unlock()
	return self.ctx.executedTxs
}

// Retrieve the balance from the given address or 0 if object not found
func (self *MStateDB) GetBalance(addr common.Address) *big.Int {
	self.requestAndLock(addr)
	stateObject := self.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Balance()
	}
	return common.Big0
}

func (self *MStateDB) GetNonce(addr common.Address) uint64 {
	self.requestAndLock(addr)
	stateObject := self.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Nonce()
	}

	return 0
}

func (self *MStateDB) GetCode(addr common.Address) []byte {
	self.requestAndLock(addr)
	stateObject := self.getStateObject(addr)
	if stateObject != nil {
		return stateObject.Code(self.stdb.db)
	}
	return nil
}

func (self *MStateDB) GetCodeSize(addr common.Address) int {
	self.requestAndLock(addr)
	stateObject := self.getStateObject(addr)
	if stateObject == nil {
		return 0
	}
	if stateObject.code != nil {
		return len(stateObject.code)
	}
	size, err := self.stdb.db.ContractCodeSize(stateObject.addrHash, common.BytesToHash(stateObject.CodeHash()))
	if err != nil {
		self.stdb.setError(err)
	}
	return size
}

func (self *MStateDB) GetCodeHash(addr common.Address) common.Hash {
	self.requestAndLock(addr)
	stateObject := self.getStateObject(addr)
	if stateObject == nil {
		return common.Hash{}
	}
	return common.BytesToHash(stateObject.CodeHash())
}

func (self *MStateDB) GetState(addr common.Address, bhash common.Hash) common.Hash {
	self.requestAndLock(addr)
	stateObject := self.getStateObject(addr)
	if stateObject != nil {
		return stateObject.GetState(self.stdb.db, bhash)
	}
	return common.Hash{}
}

func (self *MStateDB) GetCRDState(a common.Address, b common.Hash) []byte {
	self.requestAndLock(a)
	stateObject := self.getStateObject(a)
	if stateObject != nil {
		return stateObject.GetCRDState(self.stdb.db, b)
	}
	return []byte{}
}

// Database retrieves the low level database supporting the lower level trie ops.
func (self *MStateDB) Database() Database {
	return self.stdb.db
}

// StorageTrie returns the storage trie of an account.
// The return value is a copy and is nil for non-existent accounts.
func (self *MStateDB) StorageTrie(addr common.Address) Trie {
	self.requestAndLock(addr)
	stateObject := self.getStateObject(addr)
	if stateObject == nil {
		return nil
	}
	cpy := stateObject.deepCopy(self.stdb)
	return cpy.updateTrie(self.stdb.db)
}

func (self *MStateDB) HasSuicided(addr common.Address) bool {
	self.requestAndLock(addr)
	stateObject := self.getStateObject(addr)
	if stateObject != nil {
		return stateObject.suicided
	}
	return false
}

/*
 * SETTERS
 */

// AddBalance adds amount to the account associated with addr.
func (self *MStateDB) AddBalance(addr common.Address, amount *big.Int) {
	stateObject := self.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.AddBalance(amount)
	}
}

// SubBalance subtracts amount from the account associated with addr.
func (self *MStateDB) SubBalance(addr common.Address, amount *big.Int) {
	stateObject := self.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SubBalance(amount)
	}
}

func (self *MStateDB) SetBalance(addr common.Address, amount *big.Int) {
	stateObject := self.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetBalance(amount)
	}
}

func (self *MStateDB) SetNonce(addr common.Address, nonce uint64) {
	stateObject := self.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetNonce(nonce)
	}
}

func (self *MStateDB) SetCode(addr common.Address, code []byte) {
	stateObject := self.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetCode(crypto.Keccak256Hash(code), code)
	}
}

func (self *MStateDB) SetState(addr common.Address, key, value common.Hash) {
	stateObject := self.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetState(self.stdb.db, key, value)
	}
}

func (self *MStateDB) SetCRDState(addr common.Address, key common.Hash, value []byte) {
	stateObject := self.GetOrNewStateObject(addr)
	if stateObject != nil {
		stateObject.SetCRDState(self.stdb.db, key, value)
	}
}

// Suicide marks the given account as suicided.
// This clears the account balance.
//
// The account's state object is still available until the state is committed,
// getStateObject will return a non-nil account after Suicide.
func (self *MStateDB) Suicide(addr common.Address) bool {
	self.requestAndLock(addr)
	stateObject := self.getStateObject(addr)
	if stateObject == nil {
		return false
	}
	self.stdb.journal.append(suicideChange{
		account:     &addr,
		prev:        stateObject.suicided,
		prevbalance: new(big.Int).Set(stateObject.Balance()),
	})
	stateObject.markSuicided()
	stateObject.data.Balance = new(big.Int)

	return true
}

//
// Setting, updating & deleting state object methods.
//

// updateStateObject writes the given object to the trie.
func (self *MStateDB) updateStateObject(stateObject *stateObject) {
	addr := stateObject.Address()
	data, err := rlp.EncodeToBytes(stateObject)
	if err != nil {
		panic(fmt.Errorf("can't encode object at %x: %v", addr[:], err))
	}
	self.ctx.trieLock.Lock()
	err = self.stdb.trie.TryUpdate(addr[:], data)
	self.ctx.trieLock.Unlock()
	self.stdb.setError(err)
}

// deleteStateObject removes the given object from the state trie.
func (self *MStateDB) deleteStateObject(stateObject *stateObject) {
	stateObject.deleted = true
	addr := stateObject.Address()
	self.ctx.trieLock.Lock()
	err := self.stdb.trie.TryDelete(addr[:])
	self.ctx.trieLock.Unlock()
	self.stdb.setError(err)
}

// Retrieve a state object given by the address. Returns nil if not found.
func (self *MStateDB)  getStateObject(addr common.Address) (stateObject *stateObject) {
	if obj := self.stdb.stateObjects[addr]; obj != nil {
		obj.db = self.stdb
		if obj.deleted {
			return nil
		}
		return obj

	}

	self.ctx.stLock.RLock()
	if obj := self.ctx.stateObjects[addr]; obj != nil {
		self.stdb.stateObjects[addr] = obj
		obj.db = self.stdb
		if obj.deleted {
			self.ctx.stLock.RUnlock()
			return nil
		}
		self.ctx.stLock.RUnlock()
		return obj
	}
	self.ctx.stLock.RUnlock()

	self.ctx.trieLock.RLock()
	// Load the object from the database.
	enc, err := self.stdb.trie.TryGet(addr[:])
	self.ctx.trieLock.RUnlock()
	if len(enc) == 0 {
		self.stdb.setError(err)
		return nil
	}
	var data Account
	if err := rlp.DecodeBytes(enc, &data); err != nil {
		log.Error("Failed to decode state object", "addr", addr, "err", err)
		return nil
	}
	// Insert into the live set.
	obj := newObject(self.stdb, addr, data)
	self.stdb.setStateObject(obj)
	self.setStateObject(obj)
	return obj
}

func (self *MStateDB) setStateObject(object *stateObject) {
	self.ctx.stLock.Lock()
	self.ctx.stateObjects[object.Address()] = object
	self.ctx.stLock.Unlock()
}

// Retrieve a state object or create a new state object if nil.
func (self *MStateDB) GetOrNewStateObject(addr common.Address) *stateObject {
	self.requestAndLock(addr)
	stateObject := self.getStateObject(addr)
	if stateObject == nil || stateObject.deleted {
		stateObject, _ = self.createObject(addr)
	}
	return stateObject
}

// createObject creates a new state object. If there is an existing account with
// the given address, it is overwritten and returned as the second return value.
func (self *MStateDB) createObject(addr common.Address) (newobj, prev *stateObject) {
	prev = self.getStateObject(addr)
	newobj = newObject(self.stdb, addr, Account{})
	newobj.setNonce(0) // sets the object to dirty
	if prev == nil {
		self.stdb.journal.append(createObjectChange{account: &addr})
	} else {
		self.stdb.journal.append(resetObjectChange{prev: prev})
	}
	self.setStateObject(newobj)
	self.stdb.setStateObject(newobj)
	return newobj, prev
}

// CreateAccount explicitly creates a state object. If a state object with the address
// already exists the balance is carried over to the new account.
//
// CreateAccount is called during the EVM CREATE operation. The situation might arise that
// a contract does the following:
//
//   1. sends funds to sha(account ++ (nonce + 1))
//   2. tx_create(sha(account ++ nonce)) (note that this gets the address of 1)
//
// Carrying over the balance ensures that Ether doesn't disappear.
func (self *MStateDB) CreateAccount(addr common.Address) {
	self.requestAndLock(addr)
	new, prev := self.createObject(addr)
	if prev != nil {
		new.setBalance(prev.data.Balance)
	}
}

func (db *MStateDB) ForEachStorage(addr common.Address, cb func(key, value common.Hash) bool) {
	db.requestAndLock(addr)
	so := db.getStateObject(addr)
	if so == nil {
		return
	}

	// When iterating over the storage check the cache first
	for h, value := range so.cachedStorage {
		cb(h, value)
	}

	it := trie.NewIterator(so.getTrie(db.stdb.db).NodeIterator(nil))
	for it.Next() {
		// ignore cached values
		key := common.BytesToHash(db.stdb.trie.GetKey(it.Key))
		if _, ok := so.cachedStorage[key]; !ok {
			cb(key, common.BytesToHash(it.Value))
		}
	}
}

func (db *MStateDB) ForEachCRDStorage(addr common.Address, cb func(key common.Hash, value []byte) bool) {
	db.requestAndLock(addr)
	so := db.getStateObject(addr)
	if so == nil {
		return
	}

	// When iterating over the storage check the cache first
	for h, value := range so.CRDCachedStorage {
		cb(h, value)
	}

	it := trie.NewIterator(so.getTrie(db.stdb.db).NodeIterator(nil))
	for it.Next() {
		// ignore cached values
		key := common.BytesToHash(db.stdb.trie.GetKey(it.Key))
		if _, ok := so.cachedStorage[key]; !ok {
			cb(key, it.Value)
		}
	}
}

// Snapshot returns an identifier for the current revision of the state.
func (self *MStateDB) Snapshot() int {
	return self.stdb.Snapshot()
}

// RevertToSnapshot reverts all state changes made since the given revision.
func (self *MStateDB) RevertToSnapshot(revid int) {
	self.stdb.RevertToSnapshot(revid)
}

// GetRefund returns the current value of the refund counter.
func (self *MStateDB) GetRefund() uint64 {
	return self.stdb.GetRefund()
}

// Finalise finalises the state by removing the self destructed objects
// and clears the journal as well as the refunds.
func (s *MStateDB) Finalise(deleteEmptyObjects bool) {
	for addr := range s.stdb.journal.dirties {
		stateObject, exist := s.stdb.stateObjects[addr]
		if !exist {
			// ripeMD is 'touched' at block 1714175, in tx 0x1237f737031e40bcde4a8b7e717b2d15e3ecadfe49bb1bbc71ee9deb09c6fcf2
			// That tx goes out of gas, and although the notion of 'touched' does not exist there, the
			// touch-event will still be recorded in the journal. Since ripeMD is a special snowflake,
			// it will persist in the journal even though the journal is reverted. In this special circumstance,
			// it may exist in `s.journal.dirties` but not in `s.stateObjects`.
			// Thus, we can safely ignore it here
			continue
		}

		if stateObject.suicided || (deleteEmptyObjects && stateObject.empty()) {
			s.deleteStateObject(stateObject)
		} else {
			stateObject.updateRoot(s.stdb.db)
			s.updateStateObject(stateObject)
		}
		s.stdb.stateObjectsDirty[addr] = struct{}{}
	}
	// Invalidate journal because reverting across transactions is not allowed.
	s.stdb.clearJournalAndRefund()
}


// IntermediateRoot computes the current root hash of the state trie.
// It is called in between transactions to get the root hash that
// goes into transaction receipts.
func (s *MStateDB) IntermediateRoot(deleteEmptyObjects bool) common.Hash {
	s.Finalise(deleteEmptyObjects)
	return s.stdb.trie.Hash()
}

// Prepare sets the current transaction hash and index and block hash which is
// used when the EVM emits new state logs.
func (self *MStateDB) Prepare(thash, bhash common.Hash, ti int) {
	self.stdb.Prepare(thash, bhash, ti)
}

// Commit writes the state to the underlying in-memory trie database.
func (s *MStateDB) Commit(deleteEmptyObjects bool) (root common.Hash, err error) {
	defer s.stdb.clearJournalAndRefund()

	for addr := range s.stdb.journal.dirties {
		s.stdb.stateObjectsDirty[addr] = struct{}{}
	}
	// Commit objects to the trie.
	for addr, stateObject := range s.stdb.stateObjects {
		_, isDirty := s.stdb.stateObjectsDirty[addr]
		switch {
		case stateObject.suicided || (isDirty && deleteEmptyObjects && stateObject.empty()):
			// If the object has been removed, don't bother syncing it
			// and just mark it for deletion in the trie.
			s.deleteStateObject(stateObject)
		case isDirty:
			// Write any contract code associated with the state object
			if stateObject.code != nil && stateObject.dirtyCode {
				s.stdb.db.TrieDB().InsertBlob(common.BytesToHash(stateObject.CodeHash()), stateObject.code)
				stateObject.dirtyCode = false
			}
			// Write any storage changes in the state object to its storage trie.
			if err := stateObject.CommitTrie(s.stdb.db); err != nil {
				return common.Hash{}, err
			}
			// Update the object in the main account trie.
			s.updateStateObject(stateObject)
		}
		delete(s.stdb.stateObjectsDirty, addr)
	}
	// Write trie changes.
	root, err = s.stdb.trie.Commit(func(leaf []byte, parent common.Hash) error {
		var account Account
		if err := rlp.DecodeBytes(leaf, &account); err != nil {
			return nil
		}
		if account.Root != emptyState {
			s.stdb.db.TrieDB().Reference(account.Root, parent)
		}
		code := common.BytesToHash(account.CodeHash)
		if code != emptyCode {
			s.stdb.db.TrieDB().Reference(code, parent)
		}
		return nil
	})
	log.Debug("Trie cache stats after commit", "root", root)
	return root, err
}
