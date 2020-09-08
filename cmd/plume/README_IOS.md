# IOS 轻节点 

## 编译

* Xcode : Version 11.4 (11E146)
* Golang : go1.14.1 darwin/amd64 
* gomobile : version +4c31acb Sun Mar 29 12:56:38 2020 +0000 (android,ios);

>在 `CRD-chain` 目录执行 `make plume-ios` 会在 `build/bin/` 目录得到静态库 `plume.framework`;
>将其导入 `IOS App` 即可, 下面给出了 `Swift` 调用 `Plume` 的 `demo`  

## 使用样例 (Web3 SDK)

```swift
class ViewController: UIViewController {

    var web: web3!
    let port = 12345
    let contractAddress = "合约地址"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        startPlume()
        setWeb3()
    }
    
    //启动轻节点
    private func startPlume() {
        guard let path = NSSearchPathForDirectoriesInDomains(FileManager.SearchPathDirectory.documentDirectory, FileManager.SearchPathDomainMask.userDomainMask, true).first else{
            return
        }

        let bootnodes = "/ip4/10.0.0.252/mux/5978:30200/ipfs/16Uiu2HAm39zRzVr5JK6P1WCba7ew8L5CBT4r5e3wcZ8V2zQRvWSM"
        let trusts = ""
        let networkid = 739
        PlumeStart(bootnodes, trusts, path, Int64(networkid), port)
    }
    
    // 配置本地url，生成web3对象
    private func setWeb3() {
        guard let url = URL(string: "http://localhost:\(port)") else {
            return
        }
        
        do{
            let mnemonics = ""
            let keystore = try BIP32Keystore(mnemonics: mnemonics)
            let manager = KeystoreManager([keystore!])
            guard let provider = Web3HttpProvider(url, network: Networks.Custom(networkID: 739), keystoreManager: manager) else {
                return
            }
            self.web = web3.init(provider: provider)
            self.web.addKeystoreManager(manager)
        } catch {
            print(error)
        }
    }
    
    //get blockNumber
    private func getBlockNumber() {
        do {
            let number = try web.eth.getBlockNumber()
            print("number=\(number)")
        } catch {
            print("error======\(error)")
        }
    }
    
    //get balance
    private func getBalance() {
        do{
            guard let address = EthereumAddress(地址字符串) else{
                return
            }
            let balance: BigUInt = try web.eth.getBalance(address: address)
            let balanceStr = Web3.Utils.formatToEthereumUnits(balance, toUnits: .eth, decimals: 18)
            
        } catch {
            print("余额获取error======\(error)")
        }
    }
    
    //sendTx 
    private func sendTx() {
        let fromAddressStr = ""
        let toAddressString = ""
        guard let fromAddress = EthereumAddress(fromAddressStr) else { return }
        guard let toAddress = EthereumAddress(toAddressString) else { return }
        guard let amount = Web3.Utils.parseToBigUInt("12.34", units: .eth) else {return}
        guard let contract = web.contract(Web3.Utils.coldWalletABI, at: toAddress, abiVersion: 2) else { return }
        guard let writeTX = contract.write("fallback") else { return }
        writeTX.transactionOptions.from = fromAddress
        writeTX.transactionOptions.value = amount
        DispatchQueue.global().async {
            do{
                let result = try writeTX.send()
                print(result)
            } catch {
                print(error)
            }
        }
        
    }
    
    // get erc20 balance
    private func getERC20Balance() {
        guard let contractETHAddress = EthereumAddress(contractAddress) else {return}
        let contract = web.contract(Web3.Utils.erc20ABI, at: contractETHAddress, abiVersion: 2)
        guard let userAddress = EthereumAddress("需要查询的地址字符串") else {return}
        guard let readTX = contract?.read("balanceOf", parameters: [userAddress] as [AnyObject]) else {return}
        do {
            let pointsBalance = try readTX.callPromise().wait()
            guard let balance = pointsBalance["0"] as? BigUInt else {return}
            let balanceStr = Web3.Utils.formatToEthereumUnits(balance, toUnits: .eth, decimals: 18)
            print(balanceStr ?? "")
        } catch {
            print(error)
        }
    }
    
    // send erc20 tx
    private func sendERC20() {
        guard let walletAddress = EthereumAddress("") else {return}
        guard let toAddress = EthereumAddress("") else {return}
        let erc20 = EthereumAddress(contractAddress)
        guard let contract = web.contract(Web3.Utils.erc20ABI, at: erc20, abiVersion: 2) else { return }
        let amount = Web3.Utils.parseToBigUInt("1.23", decimals: 18)
        var options = TransactionOptions.defaultOptions
        options.from = walletAddress
        options.gasPrice = .automatic
        options.gasLimit = .automatic
        let method = "transfer"
        guard let tx = contract.write(method, parameters: [toAddress, amount] as [AnyObject], extraData: Data(), transactionOptions: options) else { return }

        DispatchQueue.global().async {
            do{
                let res = try tx.send()
                print(res.hash)
            } catch {
                print("ERC20 trans error=========" + error.localizedDescription)
            }
        }
    }
    
    // get points name/symbol/decimals
    private func getERC20Name() {
        let erc20 = EthereumAddress(contractAddress)
        guard let contract = web.contract(Web3.Utils.erc20ABI, at: erc20, abiVersion: 2) else { return }
        let options = TransactionOptions.defaultOptions
        let mergedOptions = web.transactionOptions.merge(options)
        do {
            let resp = try contract.read("decimals", transactionOptions: mergedOptions)?.callPromise().wait()
            var decimals = BigUInt(0)
            guard let response = resp, let dec = response["0"], let decTyped = dec as? BigUInt else {return}
            decimals = decTyped
            
            let nameResp = try contract.read("name", transactionOptions: mergedOptions)?.callPromise().wait()
            var name = ""
            guard let nameResponse = nameResp, let nameDec = nameResponse["0"], let nameType = nameDec as? String else { return }
            name = nameType
            
            let symbolResp = try contract.read("symbol", transactionOptions: mergedOptions)?.callPromise().wait()
            var symbol = ""
            guard let symbolResponse = symbolResp, let symbolDec = symbolResponse["0"], let symbolType = symbolDec as? String else { return }
            symbol = symbolType
            
            print("\(name)/\(symbol)/\(decimals)")
            
        } catch {
            print(error)
        }
    }
}
```