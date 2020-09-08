# Android 轻节点
	
## 编译

* Golang : go1.14.1 darwin/amd64 
* gomobile : version +4c31acb Sun Mar 29 12:56:38 2020 +0000 (android,ios);
* Android SDK Platform-Tools : v29.0.6
* Android NDK : r21

>在 `CRD-chain` 目录执行 `make plume-android` 会在 `build/bin/` 目录得到静态库 `plume.aar`;
>将其导入 `Android App` 即可, 下面给出了 `Java` 调用 `Plume` 的 `demo`  

__导入 plume.aar：__

1 在 `app/build.gradle` 中增加 `repositories`, 与  `dependencies` 同级

```
repositories {
    flatDir(
            dirs: 'libs'
    )
}
```

2 在 `app/build.gradle` 的 `dependencies` 的 `fileTree` 属性中增加 `*.aar`

```
implementation fileTree(dir: 'libs', include: ['*.jar','*.aar'])
```

3 将 `plume.aar` 复制到 `app/libs` 目录中

## 启动

>建议将 Plume 启动在 Application 或者 Service 级别, 并定时检查状态以便重启；

```java
	private void startPlum(){
		String bootnodes = "/ip4/10.0.0.252/mux/5978:30200/ipfs/16Uiu2HAm39zRzVr5JK6P1WCba7ew8L5CBT4r5e3wcZ8V2zQRvWSM";
        String trusts = "";
        long networkid = 739;
        long rpcport = 30100;
        String homedir = getFilesDir().getAbsolutePath().toString();
        Plume.start(bootnodes, trusts, homedir, networkid, rpcport);
	}
```

# 使用样例 (Web3 SDK)

## 1、在 app/build.gradle中添加： 

```java
implementation 'org.web3j:core:4.2.0-android'
```
	
## 2、初始化web3j:

```java	
    //url: http://localhost:30100
	Web3j web3j = Web3j.build(new HttpService(url));
```	

## 3、功能使用

```java
	 /**
     * 获取余额
     * defaultBlockParameterName latest/pending
     * @return
     */
    private BigInteger getBalance() {
        Future<EthGetBalance> ethGetBalanceFuture = web3j.ethGetBalance(address, defaultBlockParameterName).sendAsync();
        try {
            balance = ethGetBalanceFuture.get().getBalance();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return balance;
    }
	
	
	 /**
     * 获取gasPrice
     *
     * @return
     */
    private BigInteger getGasPrice() {
        Future<EthGasPrice> ethGasPriceFuture = web3j.ethGasPrice().sendAsync();
        try {
            gasPrice = ethGasPriceFuture.get().getGasPrice();
        } catch (ExecutionException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        return gasPrice;
    }
	
	/**
     * 获取nonce
     * defaultBlockParameterName latest/pending
     * @return
     */
    private BigInteger getNonce() {
        Future<EthGetTransactionCount> ethGetTransactionCountFuture = web3j.ethGetTransactionCount(fromAddress, defaultBlockParameterName).sendAsync();
        try {
            nonce = ethGetTransactionCountFuture.get().getTransactionCount();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
        return nonce;
    }
	
	 /**
     * 获取gasLimit
     *
     * @param transaction
     * @return
     */
    private BigInteger getGasLimit() {
		//生成transaction对象
		BigDecimal amount = new BigDecimal("0.01");
		BigInteger value = Convert.toWei(amount, Convert.Unit.ETHER).toBigInteger();
		Transaction transaction = makeTranscation(fromAddress, toAddress, null, null, null, value);
		
        Future<EthEstimateGas> ethEstimateGasFuture = web3j.ethEstimateGas(transaction).sendAsync();
        try {
            gasLimit = ethEstimateGasFuture.get().getAmountUsed();

        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }
        return gasLimit;
    }
	
	/**
     * 生成一个普通交易对象
     *
     * @param fromAddress
     * @param toAddress
     * @param nonce
     * @param gasPrice
     * @param gasLimit
     * @param value
     * @return
     */
    private Transaction makeTranscation(String fromAddress, String toAddress, BigInteger nonce, BigInteger gasPrice, BigInteger gasLimit, BigInteger value) {
        Transaction transaction;
        transaction = Transaction.createEtherTransaction(fromAddress, nonce, gasPrice, gasLimit, toAddress, value);
        return transaction;
    }
	
	/**
     * 签名
     *
     * @return
     */
    private String signTransaction() {
        byte[] signedMessage;
        BigInteger value = Convert.toWei(BigDecimal.valueOf(10), Convert.Unit.ETHER).toBigInteger();
		String data = "";
       
        RawTransaction rawTransaction = RawTransaction.createTransaction(nonce, GAS_PRICE, GAS_LIMIT, "", value, data);
        if (prvKey.startsWith("0x")) {
            prvKey = prvKey.substring(2);
        }
        ECKeyPair ecKeyPair = ECKeyPair.create(new BigInteger(prvKey, 16));
        Credentials credentials = Credentials.create(ecKeyPair);
        signedMessage = TransactionEncoder2.signMessage(rawTransaction, 739, credentials);
        String hexValue = Numeric.toHexString(signedMessage);
        return hexValue;
    }
	
	/**
     * 交易
     *
     * @return
     */
	private String testTransaction() {
		//调用签名
		String sign = signTransaction();
		String transactionHash = null;
		if (sign != null) {
			if (!sign.startsWith("0x")) {
				sign = "0x" + sign;
			}
			//发交易
			Future<EthSendTransaction> ethSendTransactionFuture = web3j.ethSendRawTransaction(sign).sendAsync();
			try {
				transactionHash = ethSendTransactionFuture.get().getTransactionHash();
		
			} catch (InterruptedException e) {
				e.printStackTrace();
			} catch (ExecutionException e) {
				e.printStackTrace();
			}
		}
		return transactionHash;
	}
 ------------------------------------------- erc20 -------------------------------------------
 
	private String emptyAddress = "0x0000000000000000000000000000000000000000";
 
  /**
     * erc20获取余额
     *
     * @return
     */
    private BigDecimal getpointsBalance() {
        String methodName = "balanceOf";
        List<Type> inputParameters = new ArrayList<>();
        List<TypeReference<?>> outputParameters = new ArrayList<>();
        Address address = new Address(address);
        inputParameters.add(address);
        TypeReference<Uint256> typeReference = new TypeReference<Uint256>() {
        };
        outputParameters.add(typeReference);
        Function function = new Function(methodName, inputParameters, outputParameters);
        String data = FunctionEncoder.encode(function);
        Transaction transaction = Transaction.createEthCallTransaction(address, contractAddress, data);
        BigInteger balanceValue = BigInteger.ZERO;
        CompletableFuture<EthCall> ethCallCompletableFuture = web3j.ethCall(transaction, DefaultBlockParameterName.LATEST).sendAsync();
        List<Type> results = null;
        try {
            results = FunctionReturnDecoder.decode(ethCallCompletableFuture.get().getValue(), function.getOutputParameters());
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }

        return new BigDecimal((BigInteger) results.get(0).getValue()).divide(new BigDecimal(Math.pow(10, 18)));
    }
	
	/**
     * erc20代币名称
     *
     * @return
     */
    private String getName() {
		String name = "";
        List<Type> inputParameters = new ArrayList<>();
        List<TypeReference<?>> outputParameters = new ArrayList<>();
        TypeReference<Utf8String> typeReference = new TypeReference<Utf8String>() {
        };
        outputParameters.add(typeReference);

        Function function = new Function("name", inputParameters, outputParameters);

        String data = FunctionEncoder.encode(function);
        Transaction transaction = Transaction.createEthCallTransaction(emptyAddress, contractAddress, data);

        EthCall ethCall;
        try {
            ethCall = web3j.ethCall(transaction, DefaultBlockParameterName.LATEST).sendAsync().get();
            List<Type> results = FunctionReturnDecoder.decode(ethCall.getValue(), function.getOutputParameters());
            name = results.get(0).getValue().toString();
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
        return name;
    }
	
	/**
     * erc20查询代币符号
     *
     * @return
     */
    public String getpointsSymbol() {
        String methodName = "symbol";
        String symbol = null;
        String fromAddr = emptyAddress;
        List<Type> inputParameters = new ArrayList<>();
        List<TypeReference<?>> outputParameters = new ArrayList<>();

        TypeReference<Utf8String> typeReference = new TypeReference<Utf8String>() {
        };
        outputParameters.add(typeReference);

        Function function = new Function(methodName, inputParameters, outputParameters);

        String data = FunctionEncoder.encode(function);
        Transaction transaction = Transaction.createEthCallTransaction(emptyAddress, contractAddress, data);

        EthCall ethCall;
        try {
            ethCall = web3j.ethCall(transaction, DefaultBlockParameterName.LATEST).sendAsync().get();
            List<Type> results = FunctionReturnDecoder.decode(ethCall.getValue(), function.getOutputParameters());
            symbol = results.get(0).getValue().toString();
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
        return symbol;
    }
	
	/**
     * erc20代币精度
     *
     * @return
     */
    public int getpointsDecimals() {
        String methodName = "decimals";
        int decimal = 0;
        List<Type> inputParameters = new ArrayList<>();
        List<TypeReference<?>> outputParameters = new ArrayList<>();

        TypeReference<Uint8> typeReference = new TypeReference<Uint8>() {
        };
        outputParameters.add(typeReference);

        Function function = new Function(methodName, inputParameters, outputParameters);

        String data = FunctionEncoder.encode(function);
        Transaction transaction = Transaction.createEthCallTransaction(emptyAddress, contractAddress, data);

        EthCall ethCall;
        try {
            ethCall = web3j.ethCall(transaction, DefaultBlockParameterName.LATEST).sendAsync().get();
            List<Type> results = FunctionReturnDecoder.decode(ethCall.getValue(), function.getOutputParameters());
            decimal = Integer.parseInt(results.get(0).getValue().toString());
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
        return decimal;
    }
	
	/**
     * erc20代币发行总量
     *
     * @return
     */
    public BigInteger getpointsTotalSupply() {
        String methodName = "totalSupply";
        BigInteger totalSupply = BigInteger.ZERO;
        List<Type> inputParameters = new ArrayList<>();
        List<TypeReference<?>> outputParameters = new ArrayList<>();

        TypeReference<Uint256> typeReference = new TypeReference<Uint256>() {
        };
        outputParameters.add(typeReference);

        Function function = new Function(methodName, inputParameters, outputParameters);

        String data = FunctionEncoder.encode(function);
        Transaction transaction = Transaction.createEthCallTransaction(emptyAddress, contractAddress, data);

        EthCall ethCall;
        try {
            ethCall = web3j.ethCall(transaction, DefaultBlockParameterName.LATEST).sendAsync().get();
            List<Type> results = FunctionReturnDecoder.decode(ethCall.getValue(), function.getOutputParameters());
            totalSupply = (BigInteger) results.get(0).getValue();
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
        return totalSupply;
    }
	
	 /**
     * 签名
     *
     * @return
     */
    private String signTransaction(BigInteger nonce, String data, BigInteger gasPrice, BigInteger gasLimit) {
        byte[] signedMessage;
        BigInteger value = Convert.toWei(BigDecimal.valueOf(1000), Convert.Unit.ETHER).toBigInteger();
      

        RawTransaction rawTransaction = RawTransaction.createTransaction(nonce, gasPrice, gasLimit, contractAddress, value, data);
        if (prvKey.startsWith("0x")) {
            prvKey = prvKey.substring(2);
        }
        ECKeyPair ecKeyPair = ECKeyPair.create(new BigInteger(prvKey, 16));
        Credentials credentials = Credentials.create(ecKeyPair);
        signedMessage = TransactionEncoder2.signMessage(rawTransaction, 739, credentials);
        String hexValue = Numeric.toHexString(signedMessage);
        return hexValue;
    }
	
	 /**
     * erc20交易
     *
     * @return
     */
    private String pointsTrnsaction() {
        BigInteger nonce = null;
        CompletableFuture<EthGetTransactionCount> ethGetTransactionCountCompletableFuture = web3j.ethGetTransactionCount(fromAddress, DefaultBlockParameterName.PENDING).sendAsync();
        if (ethGetTransactionCountCompletableFuture == null) return null;
        try {
            nonce = ethGetTransactionCountCompletableFuture.get().getTransactionCount();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ExecutionException e) {
            e.printStackTrace();
        }

        BigInteger gasPrice = Convert.toWei(BigDecimal.valueOf(3), Convert.Unit.GWEI).toBigInteger();
        BigInteger gasLimit = BigInteger.valueOf(60000);
        BigInteger value = BigInteger.ZERO;
        String methodName = "transfer";
        String transactionHash = "";
        List<Type> inputParameters = new ArrayList<>();
        List<TypeReference<?>> outputParameters = new ArrayList<>();
        Address tAddress = new Address(toAddress);

        Uint256 pointsValue = new Uint256(BigDecimal.valueOf(10).multiply(BigDecimal.TEN.pow(18)).toBigInteger());
        inputParameters.add(tAddress);
        inputParameters.add(pointsValue);
        TypeReference<Bool> typeReference = new TypeReference<Bool>() {
        };
        outputParameters.add(typeReference);
        Function function = new Function(methodName, inputParameters, outputParameters);
        String data = FunctionEncoder.encode(function);
        String sign = signTransaction(nonce, data, gasPrice, gasLimit);
        if (sign != null) {
            CompletableFuture<EthSendTransaction> completableFuture = web3j.ethSendRawTransaction(sign).sendAsync();
            try {
                transactionHash = completableFuture.get().getTransactionHash();
            } catch (InterruptedException e) {
                e.printStackTrace();
            } catch (ExecutionException e) {
                e.printStackTrace();
            }
        }
        return transactionHash;
    }
```		
	