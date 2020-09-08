package alibp2p

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"math/big"
	"sync/atomic"
	"testing"
)

func TestPSK(t *testing.T) {
	n := big.NewInt(100)
	s := sha256.New()
	s.Write(n.Bytes())
	h := s.Sum(nil)
	t.Log(n.Bytes())
	t.Log(len(h), h)
}

func TestID(t *testing.T) {
	peerid, err := peer.Decode("16Uiu2HAmFPq2Tt2TRqAttQHmKiQRcKZ8THmtmQsawAHz84WsHjNr")
	t.Log(err, peerid)
	i := int32(0)

	b := atomic.CompareAndSwapInt32(&i, 0, 5)
	t.Log(b, i)
}

func TestByte(t *testing.T) {
	t.Log([]byte("ping"))
}

func TestNodeid(t *testing.T) {
	peerid := "16Uiu2HAmFPq2Tt2TRqAttQHmKiQRcKZ8THmtmQsawAHz84WsHjNr"
	idBytes := []byte(peerid)
	t.Log(len(idBytes), idBytes)
	id, _ := peer.Decode(peerid)
	pubkey, _ := id.ExtractPublicKey()
	ecdsaPub := pubkeyToEcdsa(pubkey)
	b1, _ := pubkey.Bytes()
	b2 := append(ecdsaPub.X.Bytes(), ecdsaPub.Y.Bytes()...)
	t.Log("b1", len(b1), b1)
	t.Log("b2", len(b2), b2)
	h1 := fmt.Sprintf("%x", b2[:])
	t.Log(len(h1), h1)

}
func TestMaddrs(t *testing.T) {
	url := "/ip4/127.0.0.1/tcp/59464/ipfs/16Uiu2HAm39zRzVr5JK6P1WCba7ew8L5CBT4r5e3wcZ8V2zQRvWSM"
	a, err := convertPeers([]string{url})
	fmt.Println(err, a)
}

func TestRand(t *testing.T) {
	for i := 0; i < 10; i++ {
		var (
			limit = 5
			tasks = []int{1, 2, 3, 4, 5, 6, 7, 8, 9}
			total = len(tasks)
		)
		if total < limit {
			limit = total
		}
		// TODO 随机选出几个进行尝试
		_, randk, _ := crypto.GenerateRSAKeyPair(512, rand.Reader)
		rnBytes, _ := randk.Bytes()
		n := new(big.Int).Mod(new(big.Int).SetBytes(rnBytes), big.NewInt(int64(total))).Int64()
		tasks = append(tasks[n:], tasks[:n]...)
		fmt.Println("-->", total, limit, n, tasks[:limit], tasks[:], len(tasks))
	}
}

func TestCmp(t *testing.T) {
	c := big.NewInt(8)
	i := big.NewInt(1)
	t.Log(c.Cmp(i))
	m := map[interface{}]interface{}{1: 1, 2: 2, 3: 3}
	t.Log(len(m))
}

func TestNotimeout(t *testing.T) {
	t.Log(notimeout == notimeout, notimeout)
}

func TestOptions(t *testing.T) {
	var cfg Config
	opts := FallbackDefaults
	err := cfg.Apply(opts)
	t.Log(err, cfg)
	o, err := cfg.ProtectorOpt()
	t.Log(err, o)
}
