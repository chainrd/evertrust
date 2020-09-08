module github.com/cc14514/go-alibp2p

require (
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/cc14514/go-mux-transport v0.0.3-rc0
	github.com/gogo/protobuf v1.3.1
	github.com/google/uuid v1.1.1
	github.com/hashicorp/golang-lru v0.5.4
	github.com/ipfs/go-cid v0.0.5
	github.com/ipfs/go-ipns v0.0.2
	github.com/ipfs/go-log v1.0.4
	github.com/libp2p/go-buffer-pool v0.0.2
	github.com/libp2p/go-libp2p v0.8.3
	github.com/libp2p/go-libp2p-circuit v0.2.2
	github.com/libp2p/go-libp2p-connmgr v0.2.1
	github.com/libp2p/go-libp2p-core v0.5.3
	github.com/libp2p/go-libp2p-discovery v0.4.0
	github.com/libp2p/go-libp2p-kad-dht v0.7.11
	github.com/libp2p/go-libp2p-mplex v0.2.3
	github.com/libp2p/go-libp2p-peerstore v0.2.3
	github.com/libp2p/go-libp2p-record v0.1.2
	github.com/libp2p/go-libp2p-yamux v0.2.7
	github.com/multiformats/go-multiaddr v0.2.1
	github.com/multiformats/go-multihash v0.0.13
	github.com/tendermint/go-amino v0.0.0-20200130113325-59d50ef176f6
	golang.org/x/xerrors v0.0.0-20190717185122-a985d3407aa7
)

go 1.13

replace github.com/libp2p/go-libp2p-discovery => github.com/cc14514/go-libp2p-discovery v0.0.0-20200509061928-ab91365d125c

replace github.com/libp2p/go-libp2p-kad-dht => github.com/cc14514/go-libp2p-kad-dht v0.0.3-rc1

//replace github.com/libp2p/go-libp2p-kad-dht => ../go-libp2p-kad-dht

replace github.com/libp2p/go-libp2p => github.com/cc14514/go-libp2p v0.0.3-rc4

replace github.com/libp2p/go-libp2p-circuit => github.com/cc14514/go-libp2p-circuit v0.0.3-rc0
