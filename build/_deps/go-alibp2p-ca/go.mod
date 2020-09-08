module github.com/cc14514/go-alibp2p-ca

go 1.13

require (
	github.com/cc14514/go-alibp2p v0.0.0-00010101000000-000000000000
	github.com/cc14514/go-certool v0.0.0-20191210043546-d76c16cd4125
	github.com/cc14514/go-lightrpc v0.0.0-20191009082400-f2eba654f95d
	github.com/libp2p/go-libp2p-core v0.5.3
	github.com/syndtr/goleveldb v1.0.0
)

replace github.com/libp2p/go-libp2p-discovery => github.com/cc14514/go-libp2p-discovery v0.0.0-20200509061928-ab91365d125c

replace github.com/libp2p/go-libp2p-kad-dht => github.com/cc14514/go-libp2p-kad-dht v0.0.3-rc1

replace github.com/libp2p/go-libp2p => github.com/cc14514/go-libp2p v0.0.3-rc4

replace github.com/libp2p/go-libp2p-circuit => github.com/cc14514/go-libp2p-circuit v0.0.3-rc0

replace github.com/cc14514/go-certool => ../go-certool

replace github.com/cc14514/go-alibp2p => ../go-alibp2p
