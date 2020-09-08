package alibp2p

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	lru "github.com/hashicorp/golang-lru"
	pool "github.com/libp2p/go-buffer-pool"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/tendermint/go-amino"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"path"
	"sync"
	"sync/atomic"
	"time"
)

func (f *asyncFn) apply(ctx context.Context) {
	f.fn(ctx, f.args)
}

func NewAsyncRunner(ctx context.Context, min, max int32) *AsyncRunner {
	wg := new(sync.WaitGroup)
	o := &AsyncRunner{
		ctx:     ctx,
		wg:      wg,
		counter: 0,
		min:     min,
		max:     max,
		fnCh:    make(chan *asyncFn),
		closeCh: make(chan struct{}),
		gc:      5 * time.Second,
	}
	wg.Add(1)
	go func() {
		select {
		case <-ctx.Done():
		case <-o.closeCh:
		}
		wg.Done()
	}()
	return o
}

func (a *AsyncRunner) Size() int32 {
	return atomic.LoadInt32(&a.counter)
}

func (a *AsyncRunner) WaitClose() {
	a.close = true
	a.wg.Wait()
}

func (a *AsyncRunner) Wait() {
	a.wg.Wait()
}

func (a *AsyncRunner) spawn(tn int32, fn func(ctx context.Context, args []interface{}), args ...interface{}) {
	a.wg.Add(1)
	go func(tn int32) {
		defer a.wg.Done()
		timer := time.NewTimer(a.gc)
		for {
			select {
			case fn := <-a.fnCh:
				fn.apply(context.WithValue(a.ctx, "tn", tn))
			case <-a.ctx.Done():
				atomic.AddInt32(&a.counter, -1)
				return
			case <-timer.C:
				if func() bool {
					a.Lock()
					defer a.Unlock()
					if c := atomic.LoadInt32(&a.counter); c > a.min || a.close {
						c = atomic.AddInt32(&a.counter, -1)
						//fmt.Println("<--gc--", "tn", tn, a.close, "min", a.min, "counter", c)
						if c == 0 {
							close(a.closeCh)
						}
						return true
					}
					return false
				}() {
					return
				}
			}
			timer.Reset(a.gc)
		}
	}(tn)
}

func (a *AsyncRunner) Apply(fn func(ctx context.Context, args []interface{}), args ...interface{}) {
	select {
	case a.fnCh <- &asyncFn{fn, args}:
	default:
		//if tn := atomic.AddInt32(&a.counter, 1); tn <= a.max {
		a.Lock()
		tn := atomic.LoadInt32(&a.counter) + 1
		if tn <= a.max {
			atomic.AddInt32(&a.counter, 1)
			a.spawn(tn, fn, args)
		}
		a.Unlock()
		a.fnCh <- &asyncFn{fn, args}
	}
}

func NewKeyMutex(timeout time.Duration) *KeyMutex {
	cache, _ := lru.New(1024)
	return &KeyMutex{
		reglock: new(sync.Map),
		timeout: timeout,
		kcache:  cache,
	}
}

func (k *KeyMutex) Regist(namespace string) {
	k.reglock.Store(namespace, make(chan struct{}))
}

func (k *KeyMutex) Lock(namespace, key string) (err error) {
	_, ok := k.reglock.Load(namespace)
	if ok {
		v, ok := k.reglock.LoadOrStore(k.hash(namespace, key), make(chan struct{}, 1))
		log.Debugf("alibp2p-service::KeyMutex-lock:try : %s@%s load=%v", namespace, key, ok)
		t := time.NewTimer(k.timeout)
		defer func() {
			t.Stop()
			if ee := recover(); ee != nil {
				err = fmt.Errorf("take lock fail , lost stream : %s@%s : %v", namespace, key, ee)
			}
		}()
		select {
		case v.(chan struct{}) <- struct{}{}:
			log.Debugf("alibp2p-service::KeyMutex-lock:success : %s@%s", namespace, key)
		case <-t.C:
			log.Debugf("alibp2p-service::KeyMutex-lock:timeout : %s@%s", namespace, key)
			err = fmt.Errorf("take lock timeout : %s@%s", namespace, key)
		}
		return
	}
	return ns_notfound
}

func (k *KeyMutex) Unlock(namespace, key string) (err error) {
	_, ok := k.reglock.Load(namespace)
	if ok {
		v, ok := k.reglock.Load(k.hash(namespace, key))
		log.Debugf("alibp2p-service::KeyMutex-unlock:try %s@%s load=%v", namespace, key, ok)
		if ok {
			t := time.NewTimer(k.timeout)
			defer func() {
				t.Stop()
				if recover() != nil {
					err = fmt.Errorf("release lock fail , lost stream : %s@%s", namespace, key)
				}
			}()
			select {
			case <-v.(chan struct{}):
				log.Debugf("alibp2p-service::KeyMutex-unlock:success : %s@%s", namespace, key)
				return nil
			case <-t.C:
				log.Debugf("alibp2p-service::KeyMutex-unlock:timeout : %s@%s", namespace, key)
				return fmt.Errorf("release lock timeout : %s@%s", namespace, key)
			}
		}
		return
	}
	return ns_notfound
}

// 清除一个旧的锁，会释放一批阻塞的还未超时的 lock 请求，
// 释放以后会在 ns 上产生新的锁,如果 timeout 时间很长，
// 需要提前解除阻塞，可以使用 clean 方法
func (k *KeyMutex) Clean(namespace, key string) {
	if key == "" || namespace == "" {
		return
	}
	if v, ok := k.reglock.Load(k.hash(namespace, key)); ok {
		k.reglock.Delete(k.hash(namespace, key))
		defer func() {
			if r := recover(); r != nil {
				// ignoe
			}
		}()
		close(v.(chan struct{}))
	}
	log.Debugf("alibp2p-service::KeyMutex-cleanlock : %s@%s", namespace, key)
}

func (k *KeyMutex) hash(namespace, key string) string {
	v, ok := k.kcache.Get(namespace + key)
	if ok {
		return v.(string)
	}
	s1 := sha1.New()
	s1.Write([]byte(namespace + key))
	buf := s1.Sum(nil)
	hash := hex.EncodeToString(buf)
	k.kcache.Add(namespace+key, hash)
	return hash
}

// private funcs
var (
	loadid = func(homedir string) (crypto.PrivKey, error) {
		keypath := path.Join(homedir, "p2p.id")
		log.Debug("keypath", keypath)
		buff1, err := ioutil.ReadFile(keypath)
		if err != nil {
			err := os.MkdirAll(homedir, 0755)
			if err != nil {
				panic(err)
			}
			priv, _, err := crypto.GenerateSecp256k1Key(rand.Reader)
			k0 := priv.(*crypto.Secp256k1PrivateKey)
			k1 := (*ecdsa.PrivateKey)(k0)
			arr := [3]*big.Int{k1.X, k1.Y, k1.D}
			buff, _ := json.Marshal(arr)
			s0 := hex.EncodeToString(buff)
			err = ioutil.WriteFile(keypath, []byte(s0), 0755)
			if err != nil {
				panic(err)
			}
			return priv, err
		}
		var arr1 = new([3]*big.Int)
		buff, _ := hex.DecodeString(string(buff1))
		err = json.Unmarshal(buff, arr1)
		if err != nil {
			panic(err)
		}
		priv1 := new(ecdsa.PrivateKey)
		priv1.X, priv1.Y, priv1.D, priv1.Curve = arr1[0], arr1[1], arr1[2], btcec.S256()
		priv2 := (*crypto.Secp256k1PrivateKey)(priv1)
		priv3 := (crypto.PrivKey)(priv2)
		return priv3, err
	}

	connectFn = func(ctx context.Context, ph host.Host, peers []peer.AddrInfo) error {
		if len(peers) < 1 {
			return errors.New("not enough peers to connect")
		}

		errs := make(chan error, len(peers))
		var wg sync.WaitGroup
		for _, p := range peers {
			if ph.ID() == p.ID {
				continue
			}
			wg.Add(1)
			go func(p peer.AddrInfo) {
				defer wg.Done()
				log.Debugf("alibp2p-service::connectFn: from %s connecting to %s : %v", ph.ID().Pretty(), p.ID, p.Addrs)
				// 这里不用重复 addAddrs ， Connect 已经 add 过了
				//ph.Peerstore().AddAddrs(p.ID, p.Addrs, _ttl)
				if err := ph.Connect(ctx, p); err != nil {
					log.Debug("alibp2p-service::connectFn: connect failed", p.ID, err.Error())
					errs <- err
					return
				}
				log.Debug("alibp2p-service::connectFn: connect success :", p.ID.Pretty())
			}(p)
		}
		wg.Wait()
		close(errs)
		count := 0
		var err error
		for err = range errs {
			if err != nil {
				log.Debug("alibp2p-service::connectFn: connect error :", count, err.Error())
				count++
			}
		}
		log.Debug("alibp2p-service::connectFn: connect over :", count)
		if count == len(peers) {
			return fmt.Errorf("failed to connect. %s", err)
		}
		return nil
	}

	convertPeers = func(peers []string) ([]peer.AddrInfo, error) {
		pinfos := make([]peer.AddrInfo, len(peers))
		for i, addr := range peers {
			maddr := ma.StringCast(addr)
			p, err := peer.AddrInfoFromP2pAddr(maddr)
			if err != nil {
				log.Debug(err)
				return nil, err
			}
			pinfos[i] = *p
		}
		return pinfos, nil
	}

	pubkeyToEcdsa = func(pk crypto.PubKey) *ecdsa.PublicKey {
		k0 := pk.(*crypto.Secp256k1PublicKey)
		pubkey := (*ecdsa.PublicKey)(k0)
		return pubkey
	}
	ecdsaToPubkey = func(pk *ecdsa.PublicKey) crypto.PubKey {
		k0 := (*crypto.Secp256k1PublicKey)(pk)
		return k0
	}
	id2pubkey = func(id peer.ID) (crypto.PubKey, error) {
		v, ok := pubkeyCache.Get(id)
		if ok {
			return v.(crypto.PubKey), nil
		}
		k, err := id.ExtractPublicKey()
		if err != nil {
			return nil, err
		}
		pubkeyCache.Add(id, k)
		return k, nil
	}
	randPeers = func(others []peer.AddrInfo, limit int) []peer.AddrInfo {
		_, randk, err := crypto.GenerateRSAKeyPair(1024, rand.Reader)
		if err != nil || randk == nil {
			return nil
		}
		rnBytes, _ := randk.Bytes()
		n := new(big.Int).Mod(new(big.Int).SetBytes(rnBytes), big.NewInt(int64(len(others)))).Int64()
		others = append(others[n:], others[:n]...)
		others = others[:limit]
		return others
	}
)

// public funcs
var (
	ECDSAPubEncode = func(pk *ecdsa.PublicKey) (string, error) {
		id, err := peer.IDFromPublicKey(ecdsaToPubkey(pk))
		return id.Pretty(), err
	}
	ECDSAPubDecode = func(pk string) (*ecdsa.PublicKey, error) {
		id, err := peer.Decode(pk)
		if err != nil {
			return nil, err
		}
		pub, err := id2pubkey(id)
		if err != nil {
			return nil, err
		}
		return pubkeyToEcdsa(pub), nil
	}

	GetBuf = func(size int) []byte {
		return pool.Get(size)
	}
	PutBuf = func(buf []byte) {
		pool.Put(buf)
	}
	Spawn = func(size int, fn func(int)) *sync.WaitGroup {
		wg := new(sync.WaitGroup)
		for i := 0; i < size; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				fn(i)
			}()
		}
		return wg
	}

	FromBytes = func(data []byte, ptr interface{}) error {
		return amino.UnmarshalBinaryLengthPrefixed(data, ptr)
	}
	FromReader = func(rw io.ReadWriter, ptr interface{}, maxSize ...int64) (int64, error) {
		_maxsize := def_maxsize
		if maxSize != nil && len(maxSize) > 0 {
			_maxsize = maxSize[0]
		}
		return amino.UnmarshalBinaryLengthPrefixedReader(rw, ptr, _maxsize)
	}

	ToBytes = func(ptr interface{}) ([]byte, error) {
		return amino.MarshalBinaryLengthPrefixed(ptr)
	}
	ToWriter = func(rw io.ReadWriter, ptr interface{}) (int64, error) {
		return amino.MarshalBinaryLengthPrefixedWriter(rw, ptr)
	}

	MustFromBytes = func(data []byte, ptr interface{}) {
		amino.MustUnmarshalBinaryLengthPrefixed(data, ptr)
	}

	MustToBytes = func(ptr interface{}) []byte {
		return amino.MustMarshalBinaryLengthPrefixed(ptr)
	}
)
