# 联盟链说明文档：

启动联盟链之后，如果有新的节点加入，需要配置相应的节点证书cert，才可以接入相应的联盟链。
联盟链可以设置相应的用户权限，控制部署合约和普通交易是否执行。

## 配置flag

在启动CRDc时，添加--consortium标签

```shell
./evertrust --consortium
```

## 配置文件

在/evertrust/chain/[chainId]/data/consortium/文件夹下配置consortium.conf, 例如：

```json
{
  "name" : "CRD-ecosys",
  "orgs" : [
    {
      "name" : "abc",
      "node_ca" : ["node-ca-abc.crt"],
      "user_ca" : ["user-ca-abc.crt"]
    },
    {
      "name" : "lmn",
      "node_ca" : ["node-ca-lmn.crt"],
      "user_ca" : ["user-ca-lmn.crt"]
    },
    {
      "name" : "xyz",
      "node_ca" : ["node-ca-xyz.crt"],
      "user_ca" : ["user-ca-xyz.crt"]
    }
  ],
  "dapp_auth":true,
  "user_auth":false
}
```
#### 配置文件说明

 dapp_auth  |  user_auth  |  deploy tx |  regular tx
 ---------  |  ---------  |  --------- |  ----------
   true     |     true    |     d      |      u
   false    |     true    |     u      |      u
   true     |     false   |     d      |      \-
   false    |     false   |     \-      |     \-
 
 d(dapp):表示部署solidity或者chaincode合约时，jwt points中的角色r必须是d
 u(user):表示部署solidity或者chaincode合约时，jwt points中的角色r至少是u
 -:表示不需要验证jwt points
 
## jwt points参数

```
points := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"ak": "0390d5d104823304eb44276545ce4b3bbedba28171628a1262b0ff0b58b59e3d2f",//auth pubKey
		"sk": "02595d553697305c7670dfd92628e5ff68080335265edf804aea4e6e8df5112464",//sender pubKey
		"r":  "d",//d:dapp-user, u:end-user
		"l":  5,//limit
		"s":  12345,//sequence
		"n":  "jru234m5im23i23m4mju2356msddfk4r",//nonce 
	})
```

**说明：ak-签名者的公钥，sk-发送者的公钥，r-用户角色，l-多少个normal block后points失效，s-序列号，n-随机字符串**

## jwt points位置

发送交易时设置jwt
```
meta["jwt"]="eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJhayI6IjAzOTBkNWQxMDQ4MjMzMDRlYjQ0Mjc2NTQ1Y2U0YjNiYmVkYmEyODE3MTYyOGExMjYyYjBmZjBiNThiNTllM2QyZiIsImwiOjUwMDAwMCwibiI6MSwiciI6ImQiLCJzIjo1NTU1LCJzayI6IjAyNTk1ZDU1MzY5NzMwNWM3NjcwZGZkOTI2MjhlNWZmNjgwODAzMzUyNjVlZGY4MDRhZWE0ZTZlOGRmNTExMjQ2NCJ9.agZbI5oK4OqJbkZoTslXjm8L-HB7kZ_NB2DRwZf3-r9I6QAGFV0ci2Og9pUpjjjryf4_jbrztwuhQNgIT5cxDA"
```
## 节点证书位置

由节点CA颁发给节点的证书放在/evertrust/chain/[chainId]/data/consortium/目录下，必须命名为localhost.crt

## 证书文件生成

#### orgs中node_ca证书生成，可以通过如下命令：

首先初始化：

```shell
#/bin/bash

# Init CA Files
mkdir -p ./demoCA/{private,newcerts}
touch ./demoCA/index.txt
echo 01 > ./demoCA/serial
```
openssl 配置文件openssl.cnf：

```cnf
#
# OpenSSL example configuration file.
# This is mostly being used for generation of certificate requests.
#

# This definition stops the following lines choking if HOME isn't
# defined.
HOME			= .
RANDFILE		= $ENV::HOME/.rnd

# Extra OBJECT IDENTIFIER info:
#oid_file		= $ENV::HOME/.oid
oid_section		= new_oids

# To use this configuration file with the "-extfile" option of the
# "openssl x509" utility, name here the section containing the
# X.509v3 extensions to use:
# extensions		= 
# (Alternatively, use a configuration file that has only
# X.509v3 extensions in its main [= default] section.)

[ new_oids ]

# We can add new OIDs in here for use by 'ca', 'req' and 'ts'.
# Add a simple OID like this:
# testoid1=1.2.3.4
# Or use config file substitution like this:
# testoid2=${testoid1}.5.6

# Policies used by the TSA examples.
tsa_policy1 = 1.2.3.4.1
tsa_policy2 = 1.2.3.4.5.6
tsa_policy3 = 1.2.3.4.5.7

####################################################################
[ ca ]
default_ca	= CA_default		# The default ca section

####################################################################
[ CA_default ]

dir		= ./demoCA		# Where everything is kept
certs		= $dir/certs		# Where the issued certs are kept
crl_dir		= $dir/crl		# Where the issued crl are kept
database	= $dir/index.txt	# database index file.
#unique_subject	= no			# Set to 'no' to allow creation of
					# several ctificates with same subject.
new_certs_dir	= $dir/newcerts		# default place for new certs.

certificate	= $dir/cacert.pem 	# The CA certificate
serial		= $dir/serial 		# The current serial number
crlnumber	= $dir/crlnumber	# the current crl number
					# must be commented out to leave a V1 CRL
crl		= $dir/crl.pem 		# The current CRL
private_key	= $dir/private/cakey.pem# The private key
RANDFILE	= $dir/private/.rand	# private random number file

x509_extensions	= usr_cert		# The extentions to add to the cert

# Comment out the following two lines for the "traditional"
# (and highly broken) format.
name_opt 	= ca_default		# Subject Name options
cert_opt 	= ca_default		# Certificate field options

# Extension copying option: use with caution.
# copy_extensions = copy

# Extensions to add to a CRL. Note: Netscape communicator chokes on V2 CRLs
# so this is commented out by default to leave a V1 CRL.
# crlnumber must also be commented out to leave a V1 CRL.
# crl_extensions	= crl_ext

default_days	= 365			# how long to certify for
default_crl_days= 30			# how long before next CRL
default_md	= default		# use public key default MD
preserve	= no			# keep passed DN ordering

# A few difference way of specifying how similar the request should look
# For type CA, the listed attributes must be the same, and the optional
# and supplied fields are just that :-)
policy		= policy_match

# For the CA policy
[ policy_match ]
countryName		= optional
stateOrProvinceName	= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= optional
emailAddress		= optional

# For the 'anything' policy
# At this point in time, you must list all acceptable 'object'
# types.
[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional

####################################################################
[ req ]
default_bits		= 2048
default_keyfile 	= privkey.pem
distinguished_name	= req_distinguished_name
attributes		= req_attributes
x509_extensions	= v3_ca	# The extentions to add to the self signed cert

# Passwords for private keys if not present they will be prompted for
# input_password = secret
# output_password = secret

# This sets a mask for permitted string types. There are several options. 
# default: PrintableString, T61String, BMPString.
# pkix	 : PrintableString, BMPString (PKIX recommendation before 2004)
# utf8only: only UTF8Strings (PKIX recommendation after 2004).
# nombstr : PrintableString, T61String (no BMPStrings or UTF8Strings).
# MASK:XXXX a literal mask value.
# WARNING: ancient versions of Netscape crash on BMPStrings or UTF8Strings.
string_mask = utf8only

# req_extensions = v3_req # The extensions to add to a certificate request

[ req_distinguished_name ]
countryName			= Country Name (2 letter code)
countryName_default		= AU
countryName_min			= 2
countryName_max			= 2

stateOrProvinceName		= State or Province Name (full name)
stateOrProvinceName_default	= Some-State

localityName			= Locality Name (eg, city)

0.organizationName		= Organization Name (eg, company)
0.organizationName_default	= Internet Widgits Pty Ltd

# we can do this but it is not needed normally :-)
#1.organizationName		= Second Organization Name (eg, company)
#1.organizationName_default	= World Wide Web Pty Ltd

organizationalUnitName		= Organizational Unit Name (eg, section)
#organizationalUnitName_default	=

commonName			= Common Name (e.g. server FQDN or YOUR name)
commonName_max			= 64

emailAddress			= Email Address
emailAddress_max		= 64

# SET-ex3			= SET extension number 3

[ req_attributes ]
challengePassword		= A challenge password
challengePassword_min		= 4
challengePassword_max		= 20

unstructuredName		= An optional company name

[ usr_cert ]

# These extensions are added when 'ca' signs a request.

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:TRUE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType			= server

# For an object signing certificate this would be used.
# nsCertType = objsign

# For normal client use this is typical
# nsCertType = client, email

# and for everything including object signing:
# nsCertType = client, email, objsign

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment			= "OpenSSL Generated Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy
# An alternative to produce certificates that aren't
# deprecated according to PKIX.
# subjectAltName=email:move

# Copy subject details
# issuerAltName=issuer:copy

#nsCaRevocationUrl		= http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

# This is required for TSA certificates.
# extendedKeyUsage = critical,timeStamping

[ v3_req ]

# Extensions to add to a certificate request

basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[ v3_ca ]


# Extensions for a typical CA


# PKIX recommendation.

subjectKeyIdentifier=hash

authorityKeyIdentifier=keyid:always,issuer

# This is what PKIX recommends but some broken software chokes on critical
# extensions.
#basicConstraints = critical,CA:true
# So we do this instead.
basicConstraints = CA:true

# Key usage: this is typical for a CA certificate. However since it will
# prevent it being used as an test self-signed certificate it is best
# left out by default.
# keyUsage = cRLSign, keyCertSign

# Some might want this also
# nsCertType = sslCA, emailCA

# Include email address in subject alt name: another PKIX recommendation
# subjectAltName=email:copy
# Copy issuer details
# issuerAltName=issuer:copy

# DER hex encoding of an extension: beware experts only!
# obj=DER:02:03
# Where 'obj' is a standard or added object
# You can even override a supported extension:
# basicConstraints= critical, DER:30:03:01:01:FF

[ crl_ext ]

# CRL extensions.
# Only issuerAltName and authorityKeyIdentifier make any sense in a CRL.

# issuerAltName=issuer:copy
authorityKeyIdentifier=keyid:always

[ proxy_cert_ext ]
# These extensions should be added when creating a proxy certificate

# This goes against PKIX guidelines but some CAs do it and some software
# requires this to avoid interpreting an end user certificate as a CA.

basicConstraints=CA:FALSE

# Here are some examples of the usage of nsCertType. If it is omitted
# the certificate can be used for anything *except* object signing.

# This is OK for an SSL server.
# nsCertType			= server

# For an object signing certificate this would be used.
# nsCertType = objsign

# For normal client use this is typical
# nsCertType = client, email

# and for everything including object signing:
# nsCertType = client, email, objsign

# This is typical in keyUsage for a client certificate.
# keyUsage = nonRepudiation, digitalSignature, keyEncipherment

# This will be displayed in Netscape's comment listbox.
nsComment			= "OpenSSL Generated Certificate"

# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

# This stuff is for subjectAltName and issuerAltname.
# Import the email address.
# subjectAltName=email:copy
# An alternative to produce certificates that aren't
# deprecated according to PKIX.
# subjectAltName=email:move

# Copy subject details
# issuerAltName=issuer:copy

#nsCaRevocationUrl		= http://www.domain.dom/ca-crl.pem
#nsBaseUrl
#nsRevocationUrl
#nsRenewalUrl
#nsCaPolicyUrl
#nsSslServerName

# This really needs to be in place for it to be a proxy certificate.
proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo

####################################################################
[ tsa ]

default_tsa = tsa_config1	# the default TSA section

[ tsa_config1 ]

# These are used by the TSA reply generation only.
dir		= ./demoCA		# TSA root directory
serial		= $dir/tsaserial	# The current serial number (mandatory)
crypto_device	= builtin		# OpenSSL engine to use for signing
signer_cert	= $dir/tsacert.pem 	# The TSA signing certificate
					# (optional)
certs		= $dir/cacert.pem	# Certificate chain to include in reply
					# (optional)
signer_key	= $dir/private/tsakey.pem # The TSA private key (optional)

default_policy	= tsa_policy1		# Policy if request did not specify it
					# (optional)
other_policies	= tsa_policy2, tsa_policy3	# acceptable policies (optional)
digests		= md5, sha1		# Acceptable message digests (mandatory)
accuracy	= secs:1, millisecs:500, microsecs:100	# (optional)
clock_precision_digits  = 0	# number of digits after dot. (optional)
ordering		= yes	# Is ordering defined for timestamps?
				# (optional, default: no)
tsa_name		= yes	# Must the TSA name be included in the reply?
				# (optional, default: no)
ess_cert_id_chain	= no	# Must the ESS cert id chain be included?
				# (optional, default: no)
```

配置环境变量，覆盖openssl的默认配置文件：

```shell
export OPENSSL_CONF=[your path]/openssl.cnf
```

node-ca-abc.crt证书生成命令：

```shell
cat root.crt intermediate.crt > node-ca-abc.crt
```
其中root.crt生成命令：

```shell
#/bin/bash

# Create Root-CA Certifacate Keypair
openssl ecparam -genkey -name secp256k1 -out ./demoCA/private/cakey.pem

# Create Root-CA Certifacate Request
openssl req -new -days 3650 -key ./demoCA/private/cakey.pem -out root.csr -subj "/C=CN/ST=Beijing/L=Haidian/O=CRD/OU=CRD/CN=CA-Root"

# Create Root-CA Certifacate By Sign Request
openssl ca -selfsign -in root.csr -out root.crt
```

其中intermediate.crt生成命令：

```shell
#/bin/bash

# Create intermediate-CA Certifacate Keypair
openssl ecparam -genkey -name secp256k1 -out ./demoCA/private/intermediate.key

# Create Intermediate-CA Certifacate Request
openssl req -new -days 3650 -key ./demoCA/private/intermediate.key -out intermediate.csr -subj "/C=CN/ST=Beijing/L=Haidian/O=CRD/OU=CRD/CN=CA-intermediate"

# Create Intermediate-CA Certifacate By Sign Request
openssl ca -in intermediate.csr -out intermediate.crt -days 3650 -cert root.crt -keyfile ./demoCA/private/cakey.pem
```

localhost.crt的csr文件由本地节点的私钥签名生成，生成node.csr的方式：

    a pre_string : 30740201010420
    the privkey  : (32 bytes as 64 hexits)
    a mid_string : a00706052b8104000aa144034200 (identifies secp256k1) 
    the pubkey   : (65 bytes as 130 hexits)

```shell
#/bin/bash

# Create Node CA Certifacate Keypair  
echo 30740201010420 <privkey_32bytes_64hexits> a00706052b8104000aa144034200 <pubkey_65bytes_130hexits> | xxd -r -p | openssl ec -inform d > ./demoCA/private/localhost.key

# Create Node CA Certifacate Request
openssl req -new -days 3650 -key ./demoCA/private/localhost.key -out node.csr -subj "/C=CN/ST=Beijing/L=Haidian/O=CRD/OU=CRD/CN=CA-Localhost"
```

或者通过子命令gencsr生成node.csr在当前目录下：

``` 
./evertrust gencsr --keystorefile <keystore file> --password <password file>
```

根据node.csr文件生成localhost.crt命令:

```shell
#/bin/bash

# Create Node CA Certifacate By Sign Request
openssl ca -in node.csr -out localhost.crt -days 3650 -cert intermediate.crt -keyfile ./demoCA/private/intermediate.key
```
#### orgs中user_ca证书生成，可以通过如下命令：

```shell
#/bin/bash

# Create Root-CA Certifacate Keypair
openssl ecparam -genkey -name secp256k1 -out ./demoCA/private/cakey.pem

# Create Root-CA Certifacate Request
openssl req -new -days 3650 -key ./demoCA/private/cakey.pem -out user_root.csr -subj "/C=CN/ST=Beijing/L=Haidian/O=CRD/OU=CRD/CN=CA-Root"

# Create Root-CA Certifacate By Sign Request
openssl ca -selfsign -in user_root.csr -out user_root.crt
```
