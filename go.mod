module CRD-chain

go 1.13

require (
	bazil.org/fuse v0.0.0-20200117225306-7b5117fecadc
	contrib.go.opencensus.io/exporter/zipkin v0.1.1 // indirect
	github.com/VictoriaMetrics/fastcache v1.5.7
	github.com/VividCortex/gohistogram v1.0.0 // indirect
	github.com/aristanetworks/goarista v0.0.0-20200224203130-895b4c57c44d
	github.com/bitly/go-simplejson v0.5.1-0.20200325142941-9255fa1e5239
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/cc14514/go-alibp2p v0.0.0-00010101000000-000000000000
	github.com/cc14514/go-cookiekit v0.0.0-20181212102238-6a04bd7258bb
	github.com/cc14514/mdns v0.0.0-20190904051813-5570bdbcd1f5
	github.com/cespare/cp v1.1.1
	github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd // indirect
	github.com/cyberdelia/go-metrics-graphite v0.0.0-20161219230853-39f87cc3b432 // indirect
	github.com/davecgh/go-spew v1.1.1
	github.com/deckarep/golang-set v1.7.1
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/docker v1.13.1
	github.com/edsrzf/mmap-go v1.0.0
	github.com/elastic/gosigar v0.10.5
	github.com/fatih/color v1.9.0
	github.com/fjl/memsize v0.0.0-20190710130421-bcb5799ab5e5
	github.com/go-interpreter/wagon v0.6.0
	github.com/go-stack/stack v1.8.0
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e // indirect
	github.com/golang/protobuf v1.3.3
	github.com/golang/snappy v0.0.1
	github.com/google/uuid v1.1.1
	github.com/hashicorp/golang-lru v0.5.4
	github.com/huin/goupnp v1.0.0
	github.com/jackpal/go-nat-pmp v1.0.2
	github.com/julienschmidt/httprouter v1.2.0
	github.com/karalabe/hid v1.0.0
	github.com/libp2p/go-libp2p-core v0.5.3
	github.com/looplab/fsm v0.1.0
	github.com/mattn/go-colorable v0.1.4
	github.com/mattn/go-sqlite3 v2.0.3+incompatible
	github.com/michaelklishin/rabbit-hole v1.5.0
	github.com/miekg/dns v1.1.27 // indirect
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/multiformats/go-multiaddr v0.2.1
	github.com/naoina/go-stringutil v0.1.0 // indirect
	github.com/naoina/toml v0.1.1
	github.com/olekukonko/tablewriter v0.0.4
	github.com/opentracing/opentracing-go v1.1.0
	github.com/openzipkin/zipkin-go v0.2.2 // indirect
	github.com/pborman/uuid v1.2.0
	github.com/peterh/liner v1.2.0
	github.com/pkg/errors v0.9.1
	github.com/rjeczalik/notify v0.9.2
	github.com/robertkrimen/otto v0.0.0-20191219234010-c382bd3c16ff
	github.com/rs/cors v1.7.0
	github.com/spf13/viper v1.6.2
	github.com/steakknife/bloomfilter v0.0.0-20180922174646-6819c0d2a570
	github.com/steakknife/hamming v0.0.0-20180906055917-c99c65617cd3 // indirect
	github.com/streadway/amqp v0.0.0-20200108173154-1c71cc93ed71
	github.com/stretchr/testify v1.5.1
	github.com/syndtr/goleveldb v1.0.0
	github.com/tjfoc/gmsm v1.3.11
	github.com/uber/jaeger-client-go v2.22.1+incompatible
	github.com/uber/jaeger-lib v2.2.0+incompatible // indirect
	github.com/vrischmann/go-metrics-influxdb v0.1.1
	golang.org/x/crypto v0.0.0-20200221231518-2aa609cf4a9d
	golang.org/x/mobile v0.0.0-20200329125638-4c31acba0007 // indirect
	golang.org/x/net v0.0.0-20200222125558-5a598a2470a0
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/sys v0.0.0-20200223170610-d5e6a3e2c0ae
	golang.org/x/tools v0.0.0-20200225022059-a0ec867d517c
	google.golang.org/grpc v1.27.1
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15
	gopkg.in/karalabe/cookiejar.v2 v2.0.0-20150724131613-8dcd6a7f4951
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce
	gopkg.in/olebedev/go-duktape.v3 v3.0.0-20190709231704-1e4459ed25ff
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
	gopkg.in/src-d/go-git.v4 v4.13.1 // indirect
	gopkg.in/urfave/cli.v1 v1.20.0
)

replace github.com/cc14514/go-alibp2p => ./build/_deps/go-alibp2p

replace github.com/cc14514/go-alibp2p-ca => ./build/_deps/go-alibp2p-ca

replace github.com/cc14514/go-certool => ./build/_deps/go-certool

replace github.com/libp2p/go-libp2p-discovery => github.com/cc14514/go-libp2p-discovery v0.0.0-20200509061928-ab91365d125c

replace github.com/libp2p/go-libp2p-kad-dht => github.com/cc14514/go-libp2p-kad-dht v0.0.3-rc1

replace github.com/libp2p/go-libp2p => github.com/cc14514/go-libp2p v0.0.3-rc4

replace github.com/libp2p/go-libp2p-circuit => github.com/cc14514/go-libp2p-circuit v0.0.3-rc0

replace github.com/tjfoc/gmsm => github.com/chainrd/gmsm v1.3.12

replace github.com/dgrijalva/jwt-go => github.com/chainrd/jwt-go v1.10.1
