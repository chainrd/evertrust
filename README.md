# README.md

###Use command

```
make evertrust
```

###Create json file

first create json file(genesis.json)

```
{
  "config": {
    "chainId": 738,    
    "evertrust": {        
      "noRewards":false, 
      "cfd":10,          
      "numMasters":3,   
      "blockDelay":5000, 
      "hypothecation":true,
      "perQuorum":true,
      "publicAccount":"0x86082fa9d3c14d00a8627af13cfa893e80b39101",
      "voterAddrs":["0x86082fa9d3c14d00a8627af13cfa893e80b39101","0x86082fa9d3c14d00a8627af13cfa893e80b39101"],
      "minerRewardAccount":"0x86082fa9d3c14d00a8627af13cfa893e80b39101",
      "quorumResetAccounts":["0x86082fa9d3c14d00a8627af13cfa893e80b39101","0x86082fa9d3c14d00a8627af13cfa893e80b39101"],
      "quorumResetAfterHeight":1,
      "rewardTotal":"100000",
      "allowIncrease":true,
      "gasLess":true,      
      "consortium":true,   
      "pointsChain": [
        {
            "chainId":"739",
            "chainOwner":"123456",
            "pointsSymbol":"15432523",
            "rpcHosts":[
                "http://127.0.0.1:8545"
            ]
        },
        {
          
              "chainId":"739",
              "chainOwner":"123456",
              "pointsSymbol":"15432523",
              "rpcHosts":["http://127.0.0.1:8545"]
        }
    ]  
    },
    "sm2Crypto":true
  },
  
  "nonce": "0x0000000000000042",
  "difficulty": "0x1000",
  "mixhash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "coinbase": "0x0000000000000000000000000000000000000000",
  "timestamp": "0x00",
  "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "extraData": "0x86082fa9d3c14d00a8627af13cfa893e80b39101",   
  "gasLimit": "0x271d94900"  
}

```


###Make datadir directory

Use the above json file to initialize the node and store the file in the corresponding path.

The initialization command is as follows:


```

init
/Users/liu/XXXXXXX/genesis.json
--datadir
/Users/liu/XXXXXXX/data1

```

###Create an account address

After the initialization is successful, the Keystore folder will appear in the corresponding path to store the account private key. 

Use the geth command to create an account.

```
evertrust account new --datadir "/Users/liu/XXXXXXX/data1"

```

After the creation is complete, you need to unlock the account and create a password.txt file to store the account password.

When everything is ready, start running CRD,

Note that the account address should start with 0x. The specific command can be viewed with the -h command.

The specific running command is as follows:

```
./evertrust --pprof --datadir /Users/liu/XXXXXXX/data2 --mine --minerthreads=2 --networkid 1218 --rpcaddr 0.0.0.0 --rpc --rpccorsdomain "*" --port 12182 --verbosity 5 --ethash.dagdir /Users/liu/XXXXXXX/dagdir --etherbase 0x7de2a31d6ca36302ea7b7917c4fc5ef4c12913b6 --ipcdisable --rpcport 8546  --nodiscover --nat none --unlock 0x7de2a31d6ca36302ea7b7917c4fc5ef4c12913b6 --password /Users/liu/XXXXXXX/password.txt --ccRpcPort 12344

```

Need to configure the environment variable: export CRD_BAAP_HOME="your path /CRD-chain/CRDcc"


