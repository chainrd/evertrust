package vm

import (
	"encoding/json"
	"fmt"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/ethdb"
	"CRD-chain/log"
	"CRD-chain/CRDcc/util"
	"CRD-chain/evertrust/utils"
)

var deployedContractAccountAddr = util.EthAddress("evertrust_deployed_contracts")
var DeployedContractAccountAddr = deployedContractAccountAddr
var deployedContractkeyHash = util.EthHash([]byte("deployed:contracts"))
var deployedContractAddr = "evertrust:deployed:%s"
//ctype 1 solidity 2 cc
func StoreContractAddr(evm *EVM, contractAddr common.Address, meta utils.Meta, owner string, cType int) (err error) {
	emptyAddr := common.Address{}
	if contractAddr == emptyAddr {
		return fmt.Errorf("contractAddr == emptyAddr")
	}

	if !evm.StateDB.Exist(deployedContractAccountAddr) {
		evm.StateDB.CreateAccount(deployedContractAccountAddr)
		if evm.ChainConfig().IsEIP158(evm.BlockNumber) {
			evm.StateDB.SetNonce(deployedContractAccountAddr, 1)
		}
	}

	data := evm.StateDB.GetCRDState(deployedContractAccountAddr, deployedContractkeyHash) //todo 存db?

	contractIndex := new(big.Int).Add(new(big.Int).SetBytes(data), big.NewInt(1))
	evm.StateDB.SetCRDState(deployedContractAccountAddr, deployedContractkeyHash, contractIndex.Bytes())

	var contractInfo utils.ContractInfo
	contractInfo.Owner = owner
	contractInfo.ContractType = cType
	contractInfo.Addr = contractAddr
	if meta != nil {
		name, _ := meta["name"]
		version, _ := meta["version"]
		desc, _ := meta["desc"]
		contractInfo.Name = string(name)
		contractInfo.Version = string(version)
		contractInfo.Desc = string(desc)
	}
	ev, err := json.Marshal(contractInfo)
	if err != nil {
		return fmt.Errorf("json marshal extra:%s", err.Error())
	}

	db := *ethdb.ChainDb
	key := deployedContractKey(contractIndex.String())
	has, err := db.Has(key)
	if err != nil {
		return fmt.Errorf("db has contract deployedContractAccountAddr:%v", err)
	}
	if !has {
		err = db.Put(key, ev)
		if err != nil {
			return fmt.Errorf("db put extra:%s", err.Error())
		}
	}

	return

}

func deployedContractKey(contract string) []byte {
	deploedKey := fmt.Sprintf(deployedContractAddr, contract)
	hashKey := util.EthHash([]byte(deploedKey))
	return hashKey.Bytes()
}

type ContractDesc struct {
	Addrass      string `json:"addrass"`
	Owner        string `json:"owner"`
	Name         string `json:"name"`
	Version      string `json:"version"`
	Desc         string `json:"desc"`
	ContractType int    `json:"contract_type"` //contract type:1 solidity 2 cc
}

func GetAllContract(stateDB StateDB) (list []ContractDesc, err error) {
	data := stateDB.GetCRDState(deployedContractAccountAddr, deployedContractkeyHash)
	contractIndex := new(big.Int).SetBytes(data)

	db := *ethdb.ChainDb
	for i := big.NewInt(1); i.Cmp(contractIndex) <= 0 ; i.Add(i, big.NewInt(1)) {

		key := deployedContractKey(i.String())
		data, err := db.Get(key)
		if err != nil {
			log.Error("db get", "err", err)
			continue
		}

		var contractInfo utils.ContractInfo
		err = json.Unmarshal(data, &contractInfo)
		if err != nil {
			log.Error("json unmarshal contract info", "err", err)
			continue
		}

		//suicide
		if stateDB.GetCodeSize(contractInfo.Addr) == 0 {
			log.Debug("suicide", "addr", contractInfo.Addr)
			continue
		}

		contractDesc := ContractDesc{
			Addrass:      contractInfo.Addr.Hex(),
			Owner:        contractInfo.Owner,
			Name:         contractInfo.Name,
			Version:      contractInfo.Version,
			Desc:         contractInfo.Desc,
			ContractType: contractInfo.ContractType,
		}
		list = append(list, contractDesc)
	}

	return
}
