.PHONY: build cluster test

default: build

build:
	go build -o bin/swarm    CRD-chain/cmd/swarm
	go build -o bin/geth     CRD-chain/cmd/geth
	go build -o bin/bootnode CRD-chain/cmd/bootnode

cluster: build
	scripts/boot-cluster.sh

test:
	go test -v CRD-chain/swarm/...
