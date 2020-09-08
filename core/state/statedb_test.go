// Copyright 2016 The go-ethereum Authors
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

package state

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"CRD-chain/core/rawdb"
	"CRD-chain/rlp"
	"CRD-chain/trie"
	"reflect"
	"strings"
	"testing"
	"testing/quick"

	"gopkg.in/check.v1"

	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/ethdb"
)

// Tests that updating a state trie does not leak any database writes prior to
// actually committing the state.
func TestUpdateLeaks(t *testing.T) {
	// Create an empty state database
	db := ethdb.NewMemDatabase()
	state, _ := New(common.Hash{}, NewDatabase(db))

	// Update it with some accounts
	for i := byte(0); i < 255; i++ {
		addr := common.BytesToAddress([]byte{i})
		state.AddBalance(addr, big.NewInt(int64(11*i)))
		state.SetNonce(addr, uint64(42*i))
		if i%2 == 0 {
			state.SetState(addr, common.BytesToHash([]byte{i, i, i}), common.BytesToHash([]byte{i, i, i, i}))
		}
		if i%3 == 0 {
			state.SetCode(addr, []byte{i, i, i, i, i})
		}
		state.IntermediateRoot(false)
	}
	// Ensure that no data was leaked into the database
	for _, key := range db.Keys() {
		value, _ := db.Get(key)
		t.Errorf("State leaked into database: %x -> %x", key, value)
	}
}

// Tests that no intermediate state of an object is stored into the database,
// only the one right before the commit.
func TestIntermediateLeaks(t *testing.T) {
	// Create two state databases, one transitioning to the final state, the other final from the beginning
	transDb := ethdb.NewMemDatabase()
	finalDb := ethdb.NewMemDatabase()
	transState, _ := New(common.Hash{}, NewDatabase(transDb))
	finalState, _ := New(common.Hash{}, NewDatabase(finalDb))

	modify := func(state *StateDB, addr common.Address, i, tweak byte) {
		state.SetBalance(addr, big.NewInt(int64(11*i)+int64(tweak)))
		state.SetNonce(addr, uint64(42*i+tweak))
		if i%2 == 0 {
			state.SetState(addr, common.Hash{i, i, i, 0}, common.Hash{})
			state.SetState(addr, common.Hash{i, i, i, tweak}, common.Hash{i, i, i, i, tweak})
		}
		if i%3 == 0 {
			state.SetCode(addr, []byte{i, i, i, i, i, tweak})
		}
	}

	// Modify the transient state.
	for i := byte(0); i < 255; i++ {
		modify(transState, common.Address{byte(i)}, i, 0)
	}
	// Write modifications to trie.
	transState.IntermediateRoot(false)

	// Overwrite all the data with new values in the transient database.
	for i := byte(0); i < 255; i++ {
		modify(transState, common.Address{byte(i)}, i, 99)
		modify(finalState, common.Address{byte(i)}, i, 99)
	}

	// Commit and cross check the databases.
	if _, err := transState.Commit(false); err != nil {
		t.Fatalf("failed to commit transition state: %v", err)
	}
	if _, err := finalState.Commit(false); err != nil {
		t.Fatalf("failed to commit final state: %v", err)
	}
	for _, key := range finalDb.Keys() {
		if _, err := transDb.Get(key); err != nil {
			val, _ := finalDb.Get(key)
			t.Errorf("entry missing from the transition database: %x -> %x", key, val)
		}
	}
	for _, key := range transDb.Keys() {
		if _, err := finalDb.Get(key); err != nil {
			val, _ := transDb.Get(key)
			t.Errorf("extra entry in the transition database: %x -> %x", key, val)
		}
	}
}

// TestCopy tests that copying a statedb object indeed makes the original and
// the copy independent of each other. This test is a regression test against
// https://CRD-chain/pull/15549.
func TestCopy(t *testing.T) {
	// Create a random state test to copy and modify "independently"
	orig, _ := New(common.Hash{}, NewDatabase(ethdb.NewMemDatabase()))

	for i := byte(0); i < 255; i++ {
		obj := orig.GetOrNewStateObject(common.BytesToAddress([]byte{i}))
		obj.AddBalance(big.NewInt(int64(i)))
		orig.updateStateObject(obj)
	}
	orig.Finalise(false)

	// Copy the state, modify both in-memory
	copy := orig.Copy()

	for i := byte(0); i < 255; i++ {
		origObj := orig.GetOrNewStateObject(common.BytesToAddress([]byte{i}))
		copyObj := copy.GetOrNewStateObject(common.BytesToAddress([]byte{i}))

		origObj.AddBalance(big.NewInt(2 * int64(i)))
		copyObj.AddBalance(big.NewInt(3 * int64(i)))

		orig.updateStateObject(origObj)
		copy.updateStateObject(copyObj)
	}
	// Finalise the changes on both concurrently
	done := make(chan struct{})
	go func() {
		orig.Finalise(true)
		close(done)
	}()
	copy.Finalise(true)
	<-done

	// Verify that the two states have been updated independently
	for i := byte(0); i < 255; i++ {
		origObj := orig.GetOrNewStateObject(common.BytesToAddress([]byte{i}))
		copyObj := copy.GetOrNewStateObject(common.BytesToAddress([]byte{i}))

		if want := big.NewInt(3 * int64(i)); origObj.Balance().Cmp(want) != 0 {
			t.Errorf("orig obj %d: balance mismatch: have %v, want %v", i, origObj.Balance(), want)
		}
		if want := big.NewInt(4 * int64(i)); copyObj.Balance().Cmp(want) != 0 {
			t.Errorf("copy obj %d: balance mismatch: have %v, want %v", i, copyObj.Balance(), want)
		}
	}
}

func TestSnapshotRandom(t *testing.T) {
	config := &quick.Config{MaxCount: 1000}
	err := quick.Check((*snapshotTest).run, config)
	if cerr, ok := err.(*quick.CheckError); ok {
		test := cerr.In[0].(*snapshotTest)
		t.Errorf("%v:\n%s", test.err, test)
	} else if err != nil {
		t.Error(err)
	}
}

// A snapshotTest checks that reverting StateDB snapshots properly undoes all changes
// captured by the snapshot. Instances of this test with pseudorandom content are created
// by Generate.
//
// The test works as follows:
//
// A new state is created and all actions are applied to it. Several snapshots are taken
// in between actions. The test then reverts each snapshot. For each snapshot the actions
// leading up to it are replayed on a fresh, empty state. The behaviour of all public
// accessor methods on the reverted state must match the return value of the equivalent
// methods on the replayed state.
type snapshotTest struct {
	addrs     []common.Address // all account addresses
	actions   []testAction     // modifications to the state
	snapshots []int            // actions indexes at which snapshot is taken
	err       error            // failure details are reported through this field
}

type testAction struct {
	name   string
	fn     func(testAction, *StateDB)
	args   []int64
	noAddr bool
}

// newTestAction creates a random action that changes state.
func newTestAction(addr common.Address, r *rand.Rand) testAction {
	actions := []testAction{
		{
			name: "SetBalance",
			fn: func(a testAction, s *StateDB) {
				s.SetBalance(addr, big.NewInt(a.args[0]))
			},
			args: make([]int64, 1),
		},
		{
			name: "AddBalance",
			fn: func(a testAction, s *StateDB) {
				s.AddBalance(addr, big.NewInt(a.args[0]))
			},
			args: make([]int64, 1),
		},
		{
			name: "SetNonce",
			fn: func(a testAction, s *StateDB) {
				s.SetNonce(addr, uint64(a.args[0]))
			},
			args: make([]int64, 1),
		},
		{
			name: "SetState",
			fn: func(a testAction, s *StateDB) {
				var key, val common.Hash
				binary.BigEndian.PutUint16(key[:], uint16(a.args[0]))
				binary.BigEndian.PutUint16(val[:], uint16(a.args[1]))
				s.SetState(addr, key, val)
			},
			args: make([]int64, 2),
		},
		{
			name: "SetCode",
			fn: func(a testAction, s *StateDB) {
				code := make([]byte, 16)
				binary.BigEndian.PutUint64(code, uint64(a.args[0]))
				binary.BigEndian.PutUint64(code[8:], uint64(a.args[1]))
				s.SetCode(addr, code)
			},
			args: make([]int64, 2),
		},
		{
			name: "CreateAccount",
			fn: func(a testAction, s *StateDB) {
				s.CreateAccount(addr)
			},
		},
		{
			name: "Suicide",
			fn: func(a testAction, s *StateDB) {
				s.Suicide(addr)
			},
		},
		{
			name: "AddRefund",
			fn: func(a testAction, s *StateDB) {
				s.AddRefund(uint64(a.args[0]))
			},
			args:   make([]int64, 1),
			noAddr: true,
		},
		{
			name: "AddLog",
			fn: func(a testAction, s *StateDB) {
				data := make([]byte, 2)
				binary.BigEndian.PutUint16(data, uint16(a.args[0]))
				s.AddLog(&types.Log{Address: addr, Data: data})
			},
			args: make([]int64, 1),
		},
	}
	action := actions[r.Intn(len(actions))]
	var nameargs []string
	if !action.noAddr {
		nameargs = append(nameargs, addr.Hex())
	}
	for _, i := range action.args {
		action.args[i] = rand.Int63n(100)
		nameargs = append(nameargs, fmt.Sprint(action.args[i]))
	}
	action.name += strings.Join(nameargs, ", ")
	return action
}

// Generate returns a new snapshot test of the given size. All randomness is
// derived from r.
func (*snapshotTest) Generate(r *rand.Rand, size int) reflect.Value {
	// Generate random actions.
	addrs := make([]common.Address, 50)
	for i := range addrs {
		addrs[i][0] = byte(i)
	}
	actions := make([]testAction, size)
	for i := range actions {
		addr := addrs[r.Intn(len(addrs))]
		actions[i] = newTestAction(addr, r)
	}
	// Generate snapshot indexes.
	nsnapshots := int(math.Sqrt(float64(size)))
	if size > 0 && nsnapshots == 0 {
		nsnapshots = 1
	}
	snapshots := make([]int, nsnapshots)
	snaplen := len(actions) / nsnapshots
	for i := range snapshots {
		// Try to place the snapshots some number of actions apart from each other.
		snapshots[i] = (i * snaplen) + r.Intn(snaplen)
	}
	return reflect.ValueOf(&snapshotTest{addrs, actions, snapshots, nil})
}

func (test *snapshotTest) String() string {
	out := new(bytes.Buffer)
	sindex := 0
	for i, action := range test.actions {
		if len(test.snapshots) > sindex && i == test.snapshots[sindex] {
			fmt.Fprintf(out, "---- snapshot %d ----\n", sindex)
			sindex++
		}
		fmt.Fprintf(out, "%4d: %s\n", i, action.name)
	}
	return out.String()
}

func (test *snapshotTest) run() bool {
	// Run all actions and create snapshots.
	var (
		state, _     = New(common.Hash{}, NewDatabase(ethdb.NewMemDatabase()))
		snapshotRevs = make([]int, len(test.snapshots))
		sindex       = 0
	)
	for i, action := range test.actions {
		if len(test.snapshots) > sindex && i == test.snapshots[sindex] {
			snapshotRevs[sindex] = state.Snapshot()
			sindex++
		}
		action.fn(action, state)
	}
	// Revert all snapshots in reverse order. Each revert must yield a state
	// that is equivalent to fresh state with all actions up the snapshot applied.
	for sindex--; sindex >= 0; sindex-- {
		checkstate, _ := New(common.Hash{}, state.Database())
		for _, action := range test.actions[:test.snapshots[sindex]] {
			action.fn(action, checkstate)
		}
		state.RevertToSnapshot(snapshotRevs[sindex])
		if err := test.checkEqual(state, checkstate); err != nil {
			test.err = fmt.Errorf("state mismatch after revert to snapshot %d\n%v", sindex, err)
			return false
		}
	}
	return true
}

// checkEqual checks that methods of state and checkstate return the same values.
func (test *snapshotTest) checkEqual(state, checkstate *StateDB) error {
	for _, addr := range test.addrs {
		var err error
		checkeq := func(op string, a, b interface{}) bool {
			if err == nil && !reflect.DeepEqual(a, b) {
				err = fmt.Errorf("got %s(%s) == %v, want %v", op, addr.Hex(), a, b)
				return false
			}
			return true
		}
		// Check basic accessor methods.
		checkeq("Exist", state.Exist(addr), checkstate.Exist(addr))
		checkeq("HasSuicided", state.HasSuicided(addr), checkstate.HasSuicided(addr))
		checkeq("GetBalance", state.GetBalance(addr), checkstate.GetBalance(addr))
		checkeq("GetNonce", state.GetNonce(addr), checkstate.GetNonce(addr))
		checkeq("GetCode", state.GetCode(addr), checkstate.GetCode(addr))
		checkeq("GetCodeHash", state.GetCodeHash(addr), checkstate.GetCodeHash(addr))
		checkeq("GetCodeSize", state.GetCodeSize(addr), checkstate.GetCodeSize(addr))
		// Check storage.
		if obj := state.getStateObject(addr); obj != nil {
			state.ForEachStorage(addr, func(key, val common.Hash) bool {
				return checkeq("GetState("+key.Hex()+")", val, checkstate.GetState(addr, key))
			})
			checkstate.ForEachStorage(addr, func(key, checkval common.Hash) bool {
				return checkeq("GetState("+key.Hex()+")", state.GetState(addr, key), checkval)
			})
		}
		if err != nil {
			return err
		}
	}

	if state.GetRefund() != checkstate.GetRefund() {
		return fmt.Errorf("got GetRefund() == %d, want GetRefund() == %d",
			state.GetRefund(), checkstate.GetRefund())
	}
	if !reflect.DeepEqual(state.GetLogs(common.Hash{}), checkstate.GetLogs(common.Hash{})) {
		return fmt.Errorf("got GetLogs(common.Hash{}) == %v, want GetLogs(common.Hash{}) == %v",
			state.GetLogs(common.Hash{}), checkstate.GetLogs(common.Hash{}))
	}
	return nil
}

func (s *StateSuite) TestTouchDelete(c *check.C) {
	s.state.GetOrNewStateObject(common.Address{})
	root, _ := s.state.Commit(false)
	s.state.Reset(root)

	snapshot := s.state.Snapshot()
	s.state.AddBalance(common.Address{}, new(big.Int))

	if len(s.state.journal.dirties) != 1 {
		c.Fatal("expected one dirty state object")
	}
	s.state.RevertToSnapshot(snapshot)
	if len(s.state.journal.dirties) != 0 {
		c.Fatal("expected no dirty state object")
	}
}

// TestCopyOfCopy tests that modified objects are carried over to the copy, and the copy of the copy.
// See https://CRD-chain/pull/15225#issuecomment-380191512
func TestCopyOfCopy(t *testing.T) {
	sdb, _ := New(common.Hash{}, NewDatabase(ethdb.NewMemDatabase()))
	addr := common.HexToAddress("aaaa")
	sdb.SetBalance(addr, big.NewInt(42))

	if got := sdb.Copy().GetBalance(addr).Uint64(); got != 42 {
		t.Fatalf("1st copy fail, expected 42, got %v", got)
	}
	if got := sdb.Copy().Copy().GetBalance(addr).Uint64(); got != 42 {
		t.Fatalf("2nd copy fail, expected 42, got %v", got)
	}
}

func TestStateRoot(t *testing.T) {
	//root0 := "0x83e329196dac98d66d2ebfb8b438cb205f36824c5c78452cd875b695efbab8a8" // 173165
	root0 := "0x427fff24dc90b16fc63c1223bcb127a9be4a34246d8dd1cc1a324808e354d05c"
	key := common.HexToHash(root0)
	ldb, _ := ethdb.NewLDBDatabase("/tmp/ewasm-node/CRD/evertrust/chaindata", 0, 0)
	db := NewDatabase(ldb)
	tr, err := db.OpenTrie(key)
	t.Log(err, tr)

	it := trie.NewIterator(tr.NodeIterator(nil))
	i := 0
	for it.Next() {
		k := common.BytesToHash(it.Key)
		v := tr.GetKey(k.Bytes())

		t.Log(err, k.Hex(), common.BytesToHash(v).Hex())

		i++
	}
	t.Log(i)

}

func TestDB(t *testing.T) {
	ldb, _ := ethdb.NewLDBDatabase("/tmp/ewasm-node/CRD/evertrust/chaindata", 0, 0)
	//ldb, _ := ethdb.NewLDBDatabase("/Users/liangc/Library/Imwallet/imt/chaindata", 0, 0)
	db := NewDatabase(ldb)
	counter := 0
	for i := uint64(173309); i > 1; i-- {
		hash := rawdb.ReadCanonicalHash(ldb, i)
		header := rawdb.ReadHeader(ldb, hash, i)
		if header == nil {
			continue
		}
		root := header.Root
		state, err := New(root, db)
		if err != nil {
			continue
		}
		sval, _ := ldb.Get(hash.Bytes())
		t.Log(counter, "blockNum=", i, "stateval.len=", len(sval), header.Root.Hex())
		it := trie.NewIterator(state.trie.NodeIterator(nil))
		scounter := 0
		for it.Next() {
			var data Account
			rlp.DecodeBytes(it.Value, &data)
			hash := common.BytesToHash(it.Key)
			address := common.BytesToAddress(state.trie.GetKey(it.Key))
			t.Log("\t", scounter, "state -> ", hash.Hex(), address.Hex(), )
			scounter++
		}
		counter++
	}
}

func TestDB2(t *testing.T) {
	ldb, _ := ethdb.NewLDBDatabase("/tmp/ewasm-node/CRD/evertrust/chaindata", 0, 0)
	//ldb, _ := ethdb.NewLDBDatabase("/Users/liangc/Library/Imwallet/imt/chaindata", 0, 0)
	db := NewDatabase(ldb)
	i := uint64(173294)
	hash := rawdb.ReadCanonicalHash(ldb, i)
	header := rawdb.ReadHeader(ldb, hash, i)
	root := header.Root
	state, _ := New(root, db)
	sval, _ := ldb.Get(root.Bytes())
	t.Log(len(sval), sval)
	state.getStateObject(common.HexToAddress("0x47E25b17A5eef0491ceaD57AbDb702BD6f169e6F"))
	it := trie.NewIterator(state.trie.NodeIterator(nil))
	scounter := 0
	for it.Next() {
		var data Account
		rlp.DecodeBytes(it.Value, &data)
		// 迭代 trie 时得到的 key 可以 get 到 address
		// TODO : value 可以反序列化成 Account , 在入库时 stateRoot 对应的值是否为 []Account ???
		// 迭代的时候，返回的 it.Key 为叶子节点的 key, it.Value 为叶子节点对应的 blob，即传入时的 Account 数组中的一员

		// 迭代出来的 key 对应数据库中的 common.Address 账户地址
		// leveldb key = "secure-key-"+it.Key , val = address
		address := common.BytesToAddress(state.trie.GetKey(it.Key))
		t.Log("\t", scounter, "state -> ", address.Hex(), data.Balance)
		scounter++
	}
}

/*
number= 173338 stateRoot= 0x5a9c8a0ba60b894c09e76017777d608666b0eba145c62552a3225f0475c30463
number= 173339 stateRoot= 0xf700fe3b9d66f89ceb177d8405284db9242dbf908a3158214ede36412c3bcb1e
number= 173340 stateRoot= 0x4f3ee97457b91632dc8e1ba89a5c611d318ec39ed1bd533d43bc7bf00217ddaf
number= 173341 stateRoot= 0x469a9be870a7e79843f0d10a2ce28ca62e8281fe87e1b734218b219f2d3bbc1f
number= 173342 stateRoot= 0xc402b8600f04d0ce6deb5e4bafe9f87f6190ecd87fb2b784b27f5c00991db7ae
number= 173343 stateRoot= 0x86426eff60106fde6266a5196aa6b569f7683e0427708630c56e426380187be5
number= 173344 stateRoot= 0xed110e90fa6db4597e5718b9c2b8487235224c3c8ac0766333f8e1194b8e2626
number= 173345 stateRoot= 0xea3a3ce4d4d6270a0543c51881ea69060ea431ea4f5213fd75b1f54e7dc93ed1
number= 173346 stateRoot= 0x4380c7ae004c9e5ed3cdfe1281d4628cec53b195a594158e9be5176639fdac5b
number= 173347 stateRoot= 0x68dafaba26f0bdb88daaf0a9a910432c39d3dda63d962833d3e7fa099201a85e
number= 173348 stateRoot= 0x6ee6841f8474ab29a1e200d718c8961383eb9548b95b154277d666d0ee24e05d
Y number= 173349 stateRoot= 0xaf1830e170c4dbff5afd4a0ecdc262ce42f52e7d943797035a3d5c5179bcb543
Y number= 173350 stateRoot= 0x60edbc87d0948bbba05ab7d6aea7f11a0676ddc8c8d335a1750775b2574a281c
173351 stateRoot= 0x97e85f0ca30dd437960053909eee7ab43c6b8b245c574c36df8483b3cc40236b
173352 stateRoot= 0x72c8aacf273e55ce43b1fcd8cee8d8ca8098a1fbf723c13ba97b4f819c815df6
173353 stateRoot= 0x458373238d10db712a56efe3aa070282f606d66a022f1d625bffea739fadbd34
173354 stateRoot= 0xfcf7db5a502eb07992f4692515f1ab630783540937a497cd43f4d5e2dbc535c2
173355 stateRoot= 0xd1bc5c2d0847861863b1d3052e32915454c219ba877999c0f6263dd708104fb0
173356 stateRoot= 0xe48ffa05cbd2e3d66c3a66f07f5a7bdfb1c32a70d8d798b9a3432c1e0d36e9d5
173357 stateRoot= 0x8477a9ea89579df28483ee31e3c3426cc418499aa87fc9b1f1cba287bde728e7
Y 173358 stateRoot= 0xcd913de25731625774ffbdc56e23adf2e4a82a7b05484cbcb8e50c82608a60b3
Y 173359 stateRoot= 0x64608214e79487611cdaa32437abe1b8ecdc599ae5e217dcb750eb36f69ed4ac
number= 173359 stateRoot= 0x64608214e79487611cdaa32437abe1b8ecdc599ae5e217dcb750eb36f69ed4ac
number= 173360 stateRoot= 0x1cb7585d1e82c491accaaf38c5588e6872a252de2427ae1477f28ac8a087bf7b
number= 173361 stateRoot= 0xa1457b08e975d8fc6ea6d827aba5dd8a851d4391881c05f378cf2c1633dc18ec
number= 173362 stateRoot= 0x1104589a9d0417f5ce8a61005821a90d46622e206f8d74956d88e636ff944ce7
number= 173363 stateRoot= 0xce08a584e5cfccc2d3570e66dc418038efcbed5b21056c5129e73bf96ce2e16b
number= 173364 stateRoot= 0xea9135e6a51d2bc3f4830f8835efba24aba0cf5a8029b18c03c1217a1af5b629
number= 173365 stateRoot= 0xf3b11093b5f44a009e3c06ad8423d1d852fe65c12bc05d5dc8a73e4368dc2aeb
number= 173366 stateRoot= 0x3baac41f0e2cf3a10af682c7c3f4e43f5e1c8f5e0c5eb756c4b48bad1b16ff17
number= 173367 stateRoot= 0x01c7161dde3095aae9bd22b714849753603f47be1c1f565e76d32bf52ca23c64
Y number= 173368 stateRoot= 0x266da4e8e8a6a11ba9895b02bcf986bd7279ba74de2c291515a8ae0a543b5d65
Y number= 173369 stateRoot= 0xea28761d1540a49e645c4659fbd42b9a43fb4e9587c29027adddd7453036a430
*/
func TestDB3(t *testing.T) {
	ldb, _ := ethdb.NewLDBDatabase("/tmp/ewasm-node/CRD/evertrust/chaindata", 0, 0)
	//ldb, _ := ethdb.NewLDBDatabase("/Users/liangc/Library/Imwallet/imt/chaindata", 0, 0)
	db := NewDatabase(ldb)
	counter := 0
	for i := uint64(173404); i > 173338; i-- {
		hash := rawdb.ReadCanonicalHash(ldb, i)
		header := rawdb.ReadHeader(ldb, hash, i)
		if header == nil {
			continue
		}
		root := header.Root
		state, err := New(root, db)
		if err != nil {
			continue
		}
		sval, _ := ldb.Get(hash.Bytes())
		t.Log(counter, "blockNum=", i, "stateval.len=", len(sval), header.Root.Hex())
		it := trie.NewIterator(state.trie.NodeIterator(nil))
		scounter := 0
		for it.Next() {
			var data Account
			rlp.DecodeBytes(it.Value, &data)
			hash := common.BytesToHash(it.Key)
			address := common.BytesToAddress(state.trie.GetKey(it.Key))
			t.Log("\t", scounter, "state -> ", hash.Hex(), address.Hex(), )
			scounter++
		}
		counter++
	}
}
