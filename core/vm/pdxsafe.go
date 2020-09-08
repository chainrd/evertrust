package vm

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/golang/protobuf/proto"
	"github.com/tjfoc/gmsm/sm2"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/core/types"
	"CRD-chain/crypto"
	"CRD-chain/log"
	"CRD-chain/params"
	"CRD-chain/CRDcc/conf"
	"CRD-chain/CRDcc/protos"
	"CRD-chain/CRDcc/util"
	"CRD-chain/rlp"
)

// CRDSafe implement PrecompiledContract interface
type CRDSafe struct{}

var JWT = "CRD_SAFE_AUTHZ"
var ACTION = "CRD_SAFE_ACTION"

// RequiredGas return different gas according to different action
// get action DONT require gas
// set action gas is calaculated by input size
func (c *CRDSafe) RequiredGas(input []byte) uint64 {
	return uint64(len(input)/192) * params.Bn256PairingPerPointGas
}

type domainItem struct {
	Name    string
	Type    string
	Desc    string
	Creator EC_PUBKEY
	Version uint64

	CAuth []EC_PUBKEY
	RAuth []EC_PUBKEY
	UAuth []EC_PUBKEY
	DAuth []EC_PUBKEY
}

type keyItem struct {
	Key     string
	Value   []byte
	Desc    string
	Creator EC_PUBKEY
	Version uint64

	RAuth []EC_PUBKEY
	UAuth []EC_PUBKEY
	DAuth []EC_PUBKEY
}

const keyCountPrefix = "CRDS_NKEY."
const PUBK_HEX_LEN = 66
const PUBK_BYTE_LEN = PUBK_HEX_LEN / 2

type EC_PUBKEY [PUBK_BYTE_LEN]byte

type jwtData struct {
	sender_key EC_PUBKEY     `json:"sk,omitempty"` // 被授权方的public key
	domain     string        `json:"d,omitempty"`  // domain`json:"aud,omitempty"`
	key        string        `json:"k,omitempty"`  // key
	action     []protos.CRDS `json:"a,omitempty`   // “C”, “R”, "U", or "D"
	nonce      string        `json:"n,omitempty"`  // nounce
	author_key EC_PUBKEY     `json:"ak",omitempty` // 授权方的public key
	sequence   uint64        `json:"s,omitempty"`  // 授权方为本次授权赋予的seq number
}

func parseJWT(spoints string, ctx *PrecompiledContractContext) (*jwtData, error) {
	// Parse takes the points string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the points to identify which key to use, but the parsed points (head and claims) is provided
	// to the callback, providing flexibility.
	token, err := jwt.Parse(spoints, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:

		if ctx.Evm.chainConfig.Sm2Crypto {
			if _, ok := token.Method.(*jwt.SigningMethodSM2); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			if token.Header["alg"] != "SM2" {
				return nil, fmt.Errorf("invalid signing alg:%v, only SM2 is prefered", token.Header["alg"])
			}
		} else {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			if token.Header["alg"] != "ES256" {
				return nil, fmt.Errorf("invalid signing alg:%v, only ES256 is prefered", token.Header["alg"])
			}
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_sec ret_key")
		ak, ok := token.Claims.(jwt.MapClaims)["ak"]
		if !ok {
			return nil, fmt.Errorf("CRDSafe: no \"ak\" in jwt payload")
		}
		hexKey, ok := ak.(string)
		if !ok || len(hexKey) != PUBK_HEX_LEN {
			return nil, fmt.Errorf("CRDSafe: invalid \"ak\" in jwt payload")
		}
		if ctx.Evm.chainConfig.Sm2Crypto {
			return sm2.Decompress(common.Hex2Bytes(hexKey)), nil
		}
		return crypto.DecompressPubkey(common.Hex2Bytes(hexKey))
	})

	if err != nil {
		return nil, err
	}

	pld := &jwtData{}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// check if token expired if set "f" and "t"
		fromTime, ok1 := claims["f"]
		toTime, ok2 := claims["t"]
		if ok1 && ok2 {
			tmp, ok := fromTime.(float64)
			if !ok {
				return nil, fmt.Errorf("CRDSafe: invalid \"f\" value in jwt payload")
			}
			f := uint64(tmp)

			tmp, ok = toTime.(float64)
			if !ok {
				return nil, fmt.Errorf("CRDSafe: invalid \"t\" value in jwt payload")
			}
			t := uint64(tmp)
			if ctx.Evm.Time.Uint64() < f || ctx.Evm.Time.Uint64() > t {
				return nil, fmt.Errorf("CRDSafe: jwt is out of date, check \"f\" and \"t\" value in jwt payload")
			}
		} else if ok1 || ok2 {
			return nil, fmt.Errorf("CRDSafe: invalid \"f\" and \"t\" value in jwt payload")
		}

		// parse sender public key(required)
		tmp, ok := claims["sk"]
		if !ok {
			return nil, fmt.Errorf("CRDSafe: nil \"sk\" in jwt payload")
		}
		s, ok := tmp.(string)
		if !ok || len(s) != PUBK_HEX_LEN {
			return nil, fmt.Errorf("CRDSafe: invalid \"sk:%s\" in jwt payload", s)
		}
		copy(pld.sender_key[:], common.Hex2Bytes(s))

		// parse domain(required)
		tmp, ok = claims["d"]
		if !ok {
			return nil, fmt.Errorf("CRDSafe: nil \"d\" in jwt payload")
		}
		s, ok = tmp.(string)
		if !ok || len(s) == 0 {
			return nil, fmt.Errorf("CRDSafe: invalid \"d:%s\" in jwt payload", s)
		}
		pld.domain = s

		// parse key(optional)
		tmp, ok = claims["k"]
		if ok {
			s, ok = tmp.(string)
			if ok && len(s) != 0 {
				pld.key = s
			}
		}

		// parse action(required)
		tmp, ok = claims["a"]
		if !ok {
			return nil, fmt.Errorf("CRDSafe: nil \"a\" in jwt payload")
		}
		s, ok = tmp.(string)
		if !ok || len(s) == 0 {
			return nil, fmt.Errorf("CRDSafe: invalid \"a:%v\" in jwt payload", s)
		}
		for _, a := range []byte(s) {
			// a should be 'C'/'R'/'U'/'D'
			switch a {
			case 'C':
				pld.action = append(pld.action, protos.CRDS_CREATE_KEY)
			case 'R':
				if pld.key == "" {
					pld.action = append(pld.action, protos.CRDS_GET_DOMAIN)
				} else {
					pld.action = append(pld.action, protos.CRDS_GET_KEY)
				}
			case 'U':
				if pld.key == "" {
					pld.action = append(pld.action, protos.CRDS_UPDATE_DOMAIN)
				} else {
					pld.action = append(pld.action, protos.CRDS_UPDATE_KEY)
				}
			case 'D':
				if pld.key == "" {
					pld.action = append(pld.action, protos.CRDS_DELETE_DOMAIN)
				} else {
					pld.action = append(pld.action, protos.CRDS_DELETE_KEY)
				}

			default:
				return nil, fmt.Errorf("CRDSafe: invalid \"a:%s\" in jwt payload", s)
			}
		}

		// parse nonce(required)
		tmp, ok = claims["n"]
		if !ok {
			return nil, fmt.Errorf("CRDSafe: nil \"n\" in jwt payload")
		}
		f, ok := tmp.(string)
		if !ok || len(f) == 0 {
			return nil, fmt.Errorf("CRDSafe: invalid \"n:%v\" in jwt payload", tmp)
		}
		pld.nonce = f

		// parse author pub key(required)
		tmp, ok = claims["ak"]
		if !ok {
			return nil, fmt.Errorf("CRDSafe: nil \"ak\" in jwt payload")
		}
		s, ok = tmp.(string)
		if !ok || len(s) != PUBK_HEX_LEN {
			return nil, fmt.Errorf("CRDSafe: invalid \"ak:%v\" in jwt payload", tmp)
		}
		copy(pld.author_key[:], common.Hex2Bytes(s))

		// parse sequence(required)
		tmp, ok = claims["s"]
		if !ok {
			return nil, fmt.Errorf("CRDSafe: nil \"s\" in jwt payload")
		}
		u, ok := tmp.(float64)
		if !ok || u == 0 {
			return nil, fmt.Errorf("CRDSafe: invalid \"s:%v\" in jwt payload", tmp)
		}
		pld.sequence = uint64(u)

		// parse chain ID(optional)
		tmp, ok = claims["c"]
		if ok {
			c, ok := tmp.(float64)
			if !ok || uint64(c) != ctx.Evm.chainConfig.ChainID.Uint64() {
				return nil, fmt.Errorf("CRDSafe: invalid \"c:%v\" in jwt payload", tmp)
			}
		}

	} else {
		return nil, fmt.Errorf("CRDSafe: invalid claims in jwt payload")
	}

	return pld, nil
}

func matchAction(a protos.CRDS, actions []protos.CRDS) bool {
	for _, action := range actions {
		if action == a {
			return true
		}
	}
	return false
}

func (c *CRDSafe) Run(ctx *PrecompiledContractContext, input []byte, extra map[string][]byte) ([]byte, error) {
	// used for estimating gas
	if extra[conf.TxEstimateGas] != nil {
		log.Error("CRDSafe estimate err", "err", extra[conf.TxEstimateGas])
		return nil, nil
	}

	tx := &protos.Transaction{}

	err := proto.Unmarshal(input, tx)
	if err != nil {
		log.Error("CRDSafe input format error", "error", err)
		return nil, err
	}
	if tx.Type != types.Transaction_invoke {
		log.Error("CRDSafe: invalid tx type", "type", tx.Type)
		return nil, err
	}
	invocation := &protos.Invocation{}
	err = proto.Unmarshal(tx.Payload, invocation)
	if err != nil {
		log.Error("proto unmarshal invocation error", "err", err)
		return nil, err
	}
	byteAction := invocation.Meta[ACTION]
	if len(byteAction) != 1 {
		return nil, errors.New("CRDSafe: invalid CRD_SAFE_ACTION type")
	}
	action := protos.CRDS(byteAction[0])

	byteParam := invocation.Args[0]

	bytepoints := invocation.Meta[JWT]
	var pld *jwtData
	if action != protos.CRDS_CREATE_DOMAIN &&
		action != protos.CRDS_GET_DOMAIN &&
		action != protos.CRDS_GET_KEY {
		pld, err = parseJWT(string(bytepoints), ctx)
		if err != nil {
			return nil, err
		}
		//jwt.New(jwt.SigningMethodES256)
		if !matchAction(action, pld.action) {
			return nil, fmt.Errorf("CRDSafe: points action:%v doesn't match CRDSafe action:%v", pld.action, action)
		}
	}

	switch action {
	case protos.CRDS_CREATE_DOMAIN:
		return createDomain(byteParam, ctx, extra)
	case protos.CRDS_UPDATE_DOMAIN:
		return updateDomain(pld, byteParam, ctx, extra)
	case protos.CRDS_DELETE_DOMAIN:
		return deleteDomain(pld, byteParam, ctx, extra)
	case protos.CRDS_GET_DOMAIN:
		return getDomain(byteParam, ctx)
	case protos.CRDS_CREATE_KEY:
		return createKey(pld, byteParam, ctx, extra)
	case protos.CRDS_UPDATE_KEY:
		return updateKey(pld, byteParam, ctx, extra)
	case protos.CRDS_DELETE_KEY:
		return deleteKey(pld, byteParam, ctx, extra)
	case protos.CRDS_GET_KEY:
		return getKey(byteParam, ctx)

	default:
		return nil, errors.New("CRDSafe: invalid operation")
	}
}

func _setState(ctx *PrecompiledContractContext, key string, value []byte) {
	keyHash := util.EthHash([]byte(key))
	ctx.Evm.StateDB.SetState(ctx.Contract.Address(), keyHash, util.EthHash(value))
}

func _setCRDState(ctx *PrecompiledContractContext, value []byte) {
	keyHash := util.EthHash(value)
	ctx.Evm.StateDB.SetCRDState(ctx.Contract.Address(), keyHash, value)
}

func _getState(ctx *PrecompiledContractContext, key string) common.Hash {
	keyHash := util.EthHash([]byte(key))
	hash := ctx.Evm.StateDB.GetState(ctx.Contract.Address(), keyHash)
	return hash
}

func _getCRDState(ctx *PrecompiledContractContext, key common.Hash) []byte {
	return ctx.Evm.StateDB.GetCRDState(ctx.Contract.Address(), key)
}

func _getDomainState(ctx *PrecompiledContractContext, _domain string) (*domainItem, error) {
	domainkey := _getState(ctx, _domain)
	if (domainkey == common.Hash{}) {
		return nil, errors.New("CRDSafe: domain doesn't exist")
	}
	_dm := _getCRDState(ctx, domainkey)
	var di domainItem
	if err := rlp.DecodeBytes(_dm, &di); err != nil {
		return nil, err
	}
	return &di, nil
}

func _setDomainState(ctx *PrecompiledContractContext, di *domainItem) error {
	_domain, err := rlp.EncodeToBytes(di)
	if err != nil {
		return err
	}
	_setState(ctx, di.Name, _domain)
	_setCRDState(ctx, _domain)
	return nil
}

func _delDomainState(ctx *PrecompiledContractContext, di *domainItem) {
	keyHash := util.EthHash([]byte(di.Name))
	ctx.Evm.StateDB.SetState(ctx.Contract.Address(), keyHash, common.Hash{})
}

func createDomain(param []byte, ctx *PrecompiledContractContext, extra map[string][]byte) ([]byte, error) {
	pubkey := extra["baap-sender-pubk"]
	if len(pubkey) != PUBK_BYTE_LEN {
		return nil, errors.New("CRDSafe: invalid public key in extra[\"baap-sender-pubk\"")
	}
	author_key := EC_PUBKEY{}
	copy(author_key[:], pubkey)
	di := &protos.DomainItem{}
	err := proto.Unmarshal(param, di)
	if err != nil {
		log.Error("CRDSafe Unmarshal DomainItem error", "error", err)
		return nil, err
	}
	//domain doesn't exist
	if di.Name == "" {
		return nil, errors.New("CRDSafe: invalid domain name")
	}
	domainKey := _getState(ctx, di.Name)
	if (domainKey != common.Hash{}) {
		return nil, errors.New("CRDSafe: domain already exists")
	}

	d := &domainItem{}
	d.Name = di.Name
	d.Type = di.Type
	d.Desc = di.Desc
	d.Creator = author_key
	d.Version = 1
	var tmp EC_PUBKEY
	for _, pubKey := range di.Cauth {
		if len(pubKey) != PUBK_BYTE_LEN {
			return nil, errors.New("CRDSafe: invalid domain Cauth pubkey")
		}
		copy(tmp[:], pubKey)
		d.CAuth = append(d.CAuth, tmp)
	}

	d.UAuth = append(d.UAuth, author_key)
	for _, pubKey := range di.Uauth {
		if len(pubKey) != PUBK_BYTE_LEN {
			return nil, errors.New("CRDSafe: invalid domain Uauth pubkey")
		}
		copy(tmp[:], pubKey)
		d.UAuth = append(d.UAuth, tmp)
	}
	d.DAuth = append(d.DAuth, author_key)
	for _, pubKey := range di.Dauth {
		if len(pubKey) != PUBK_BYTE_LEN {
			return nil, errors.New("CRDSafe: invalid domain Dauth pubkey")
		}
		copy(tmp[:], pubKey)
		d.DAuth = append(d.DAuth, tmp)
	}

	err = _setDomainState(ctx, d)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func updateDomain(pld *jwtData, param []byte, ctx *PrecompiledContractContext, extra map[string][]byte) ([]byte, error) {
	// check pld.sender is the same as tx sender
	pubkey := extra["baap-sender-pubk"]
	if len(pubkey) != PUBK_BYTE_LEN {
		return nil, errors.New("CRDSafe: invalid public key in extra[\"baap-sender-pubk\"")
	}

	if !bytes.Equal(pld.sender_key[:], pubkey) {
		return nil, errors.New("CRDSafe: jwt sender doesn't match tx sender")
	}
	// check this jwt is for domain or key operation
	if pld.key != "" {
		return nil, errors.New("CRDSafe: this jwt is for key operation")
	}

	d := &protos.DomainItem{}
	err := proto.Unmarshal(param, d)
	if err != nil {
		log.Error("CRDSafe Unmarshal DomainItem error", "error", err)
		return nil, err
	}
	// check domain name in jwt equals domain name in param
	if d.Name != pld.domain {
		return nil, errors.New("CRDSafe: domain name in jwt dones't match domain name in param")
	}

	di, err := _getDomainState(ctx, d.Name)
	if err != nil {
		return nil, err
	}

	if d.Version != di.Version {
		return nil, errors.New("CRDSafe: domain version does not match")
	}

	var canUpdate bool
	// check author is in UAuth list
	for _, pubKey := range di.UAuth {
		if pld.author_key == pubKey {
			canUpdate = true
			break
		}
	}
	if !canUpdate {
		return nil, errors.New("CRDSafe: ak(author public key) is not in domain Uauth list")
	}

	if len(d.Type) != 0 {
		di.Type = d.Type
	}
	if len(d.Desc) != 0 {
		di.Desc = d.Desc
	}
	var tmp EC_PUBKEY
	if len(d.Cauth) != 0 {
		di.CAuth = nil
	}

	for _, pubKey := range d.Cauth {
		if len(pubKey) != PUBK_BYTE_LEN {
			return nil, errors.New("CRDSafe: invalid domain Cauth pubkey")
		}
		copy(tmp[:], pubKey)
		di.CAuth = append(di.CAuth, tmp)
	}

	if len(d.Uauth) != 0 {
		// (trick) always keep owner of the domain
		di.UAuth = di.UAuth[0:1]
	}
	for _, pubKey := range d.Uauth {
		if len(pubKey) != PUBK_BYTE_LEN {
			return nil, errors.New("CRDSafe: invalid domain Uauth pubkey")
		}
		copy(tmp[:], pubKey)
		if tmp == di.UAuth[0] {
			continue
		}
		di.UAuth = append(di.UAuth, tmp)
	}

	if len(d.Dauth) != 0 {
		// (trick) always keep owner of the domain
		di.DAuth = di.DAuth[0:1]
	}
	for _, pubKey := range d.Dauth {
		if len(pubKey) != PUBK_BYTE_LEN {
			return nil, errors.New("CRDSafe: invalid domain Dauth pubkey")
		}
		copy(tmp[:], pubKey)
		if tmp == di.DAuth[0] {
			continue
		}
		di.DAuth = append(di.DAuth, tmp)
	}

	di.Version++

	err = _setDomainState(ctx, di)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func deleteDomain(pld *jwtData, param []byte, ctx *PrecompiledContractContext, extra map[string][]byte) ([]byte, error) {
	// check pld.sender is the same as tx sender
	pubkey := extra["baap-sender-pubk"]
	if len(pubkey) != PUBK_BYTE_LEN {
		return nil, errors.New("CRDSafe: invalid public key in extra[\"baap-sender-pubk\"")
	}

	if !bytes.Equal(pld.sender_key[:], pubkey) {
		return nil, errors.New("CRDSafe: jwt sender doesn't match tx sender")
	}

	// check this jwt is for domain or key operation
	if pld.key != "" {
		return nil, errors.New("CRDSafe: this jwt is for key operation")
	}

	d := &protos.DomainItem{}
	err := proto.Unmarshal(param, d)
	if err != nil {
		log.Error("CRDSafe Unmarshal DomainItem error", "error", err)
		return nil, err
	}
	// check domain name in jwt equals domain name in param
	if d.Name != pld.domain {
		return nil, errors.New("CRDSafe: domain name in jwt dones't match domain name in param")
	}

	di, err := _getDomainState(ctx, d.Name)
	if err != nil {
		return nil, err
	}
	var canDelete bool
	// check author is in UAuth list
	for _, pubKey := range di.DAuth {
		if pld.author_key == pubKey {
			canDelete = true
		}
	}
	if !canDelete {
		return nil, errors.New("CRDSafe: ak(author public key) is not in domain Dauth list")
	}

	hv := _getState(ctx, keyCountPrefix+d.Name)
	if (hv == common.Hash{0}) {
		_delDomainState(ctx, di)
	}
	return nil, nil
}

func getDomain(param []byte, ctx *PrecompiledContractContext) ([]byte, error) {
	d := &protos.DomainItem{}
	err := proto.Unmarshal(param, d)
	if err != nil {
		log.Error("CRDSafe Unmarshal DomainItem error", "error", err)
		return nil, err
	}

	di, err := _getDomainState(ctx, d.Name)
	if err != nil {
		return nil, err
	}

	ret := &protos.DomainItem{}
	ret.Name = di.Name
	ret.Type = di.Type
	ret.Desc = di.Desc
	ret.Version = di.Version

	for _idx, _ := range di.CAuth {
		ret.Cauth = append(ret.Cauth, di.CAuth[_idx][:])
	}
	for _idx, _ := range di.UAuth {
		ret.Uauth = append(ret.Uauth, di.UAuth[_idx][:])
	}
	for _idx, _ := range di.DAuth {
		ret.Dauth = append(ret.Dauth, di.DAuth[_idx][:])
	}

	hv := _getState(ctx, keyCountPrefix+di.Name)
	ret.Keycount = big.NewInt(1).SetBytes(hv.Bytes()).Uint64()

	buf, err := proto.Marshal(ret)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func _getKeyState(ctx *PrecompiledContractContext, _domain, _key string) (*keyItem, error) {
	valueHash := _getState(ctx, _domain+_key)
	if (valueHash == common.Hash{}) {
		return nil, errors.New("CRDSafe: key doesn't exist")
	}
	//key buf
	_kb := _getCRDState(ctx, valueHash)
	var ki keyItem
	if err := rlp.DecodeBytes(_kb, &ki); err != nil {
		return nil, err
	}
	return &ki, nil
}

func _setKeyState(ctx *PrecompiledContractContext, _domain string, ki *keyItem) error {
	_kb, err := rlp.EncodeToBytes(*ki)
	if err != nil {
		return err
	}
	_setState(ctx, _domain+ki.Key, _kb)
	_setCRDState(ctx, _kb)
	return nil
}

func _delKeyState(ctx *PrecompiledContractContext, _domain string, ki *keyItem) {
	keyHash := util.EthHash([]byte(_domain + ki.Key))
	ctx.Evm.StateDB.SetState(ctx.Contract.Address(), keyHash, common.Hash{})
}

// createKey required params are (Domain, Key, Value), optional AuthKey, don't need Version
// everyone can create a key under a public domain
// Auth owner can create a key under a protected domain
// someone has the signature of Auth's can create under a protected domain
func createKey(pld *jwtData, param []byte, ctx *PrecompiledContractContext, extra map[string][]byte) ([]byte, error) {
	// check pld.sender is the same as tx sender
	pubkey := extra["baap-sender-pubk"]
	if len(pubkey) != PUBK_BYTE_LEN {
		return nil, errors.New("CRDSafe: invalid public key in extra[\"baap-sender-pubk\"")
	}

	if !bytes.Equal(pld.sender_key[:], pubkey) {
		return nil, errors.New("CRDSafe: jwt sender doesn't match tx sender")
	}

	di, err := _getDomainState(ctx, pld.domain)
	if err != nil {
		return nil, err
	}
	var canCreate bool
	if len(di.CAuth) == 0 {
		// everyone can create key
		canCreate = true
	} else {
		// check author is in UAuth list
		for _, pubKey := range di.CAuth {
			if pld.author_key == pubKey {
				canCreate = true
				break
			}
		}
	}

	if !canCreate {
		return nil, errors.New("CRDSafe: ak(author public key) is not in domain Uauth list")
	}

	ki := &protos.KeyItem{}
	err = proto.Unmarshal(param, ki)
	if err != nil {
		log.Error("CRDSafe Unmarshal KeyItem error", "error", err)
		return nil, err
	}
	// jwt is only for pld.key if it is not nil
	if pld.key != "" && pld.key != ki.Key {
		return nil, errors.New("CRDSafe: key in jwt doesn't match it from keyitem")
	}

	valueHash := _getState(ctx, di.Name+ki.Key)
	if (valueHash != common.Hash{}) {
		return nil, errors.New("CRDSafe: key already exists")
	}

	k := &keyItem{}
	k.Key = ki.Key
	k.Value = ki.Value
	k.Desc = ki.Desc
	k.Version = 1
	var tmp EC_PUBKEY
	k.UAuth = append(k.UAuth, pld.sender_key)

	// use zero pubkey to indicate creating a public key,
	// which can be modified by everyone.
	if len(di.CAuth) == 0 && len(ki.Uauth) == 1 {
		if bytes.Equal(ki.Uauth[0], tmp[:]) {
			ki.Uauth = ki.Uauth[:0]
			k.UAuth = k.UAuth[:0]
		}
	}

	for _, pubKey := range ki.Uauth {
		if len(pubKey) != PUBK_BYTE_LEN {
			return nil, errors.New("CRDSafe: invalid key Uauth pubkey")
		}
		copy(tmp[:], pubKey)
		k.UAuth = append(k.UAuth, tmp)
	}
	k.DAuth = append(k.DAuth, pld.sender_key)
	for _, pubKey := range ki.Dauth {
		if len(pubKey) != PUBK_BYTE_LEN {
			return nil, errors.New("CRDSafe: invalid domain Dauth pubkey")
		}
		copy(tmp[:], pubKey)
		k.DAuth = append(k.DAuth, tmp)
	}

	if len(k.UAuth) == 0 {
		k.DAuth = k.DAuth[:0]
	}

	err = _setKeyState(ctx, di.Name, k)
	if err != nil {
		return nil, err
	}

	hv := _getState(ctx, keyCountPrefix+di.Name)
	v := big.NewInt(0).SetBytes(hv.Bytes())
	v.Add(v, big.NewInt(1))
	keyHash := util.EthHash([]byte(keyCountPrefix + di.Name))
	ctx.Evm.StateDB.SetState(ctx.Contract.Address(), keyHash, common.BigToHash(v))

	return nil, nil
}

func updateKey(pld *jwtData, param []byte, ctx *PrecompiledContractContext, extra map[string][]byte) ([]byte, error) {
	// check pld.sender is the same as tx sender
	pubkey := extra["baap-sender-pubk"]
	if len(pubkey) != PUBK_BYTE_LEN {
		return nil, errors.New("CRDSafe: invalid public key in extra[\"baap-sender-pubk\"")
	}

	if !bytes.Equal(pld.sender_key[:], pubkey) {
		return nil, errors.New("CRDSafe: jwt sender doesn't match tx sender")
	}
	// check domain is valid
	di, err := _getDomainState(ctx, pld.domain)
	if err != nil {
		return nil, err
	}
	// check key is valid
	ki := &protos.KeyItem{}
	err = proto.Unmarshal(param, ki)
	if err != nil {
		log.Error("CRDSafe Unmarshal KeyItem error", "error", err)
		return nil, err
	}
	//
	if pld.key != ki.Key {
		return nil, errors.New("CRDSafe: key in jwt doesn't match it from keyitem")
	}

	k, err := _getKeyState(ctx, di.Name, ki.Key)
	if err != nil {
		return nil, err
	}

	if k.Version != ki.Version {
		return nil, errors.New("CRDSafe: key version does not match")
	}

	var canUpdate bool
	// check author is in UAuth list
	for _, pubKey := range k.UAuth {
		if pld.author_key == pubKey {
			canUpdate = true
			break
		}
	}
	// for public key
	if len(k.UAuth) == 0 {
		canUpdate = true
	}

	if !canUpdate {
		return nil, errors.New("CRDSafe: ak(author public key) is not in key Uauth list")
	}

	k.Value = ki.Value
	k.Desc = ki.Desc
	var tmp EC_PUBKEY
	if len(ki.Uauth) != 0 {
		if len(k.UAuth) == 0 {
			ki.Uauth = ki.Uauth[:0]
			ki.Dauth = ki.Dauth[:0]
		} else {
			k.UAuth = k.UAuth[0:1]
		}
	}
	for _, pubKey := range ki.Uauth {
		if len(pubKey) != PUBK_BYTE_LEN {
			return nil, errors.New("CRDSafe: invalid key Uauth pubkey")
		}
		copy(tmp[:], pubKey)
		if tmp == k.UAuth[0] {
			continue
		}
		k.UAuth = append(k.UAuth, tmp)
	}
	if len(ki.Dauth) != 0 {
		k.DAuth = k.DAuth[0:1]
	}
	for _, pubKey := range ki.Dauth {
		if len(pubKey) != PUBK_BYTE_LEN {
			return nil, errors.New("CRDSafe: invalid key Dauth pubkey")
		}
		copy(tmp[:], pubKey)
		if tmp == k.DAuth[0] {
			continue
		}
		k.DAuth = append(k.DAuth, tmp)
	}

	k.Version++

	err = _setKeyState(ctx, di.Name, k)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

func deleteKey(pld *jwtData, param []byte, ctx *PrecompiledContractContext, extra map[string][]byte) ([]byte, error) {
	// check pld.sender is the same as tx sender
	pubkey := extra["baap-sender-pubk"]
	if len(pubkey) != PUBK_BYTE_LEN {
		return nil, errors.New("CRDSafe: invalid public key in extra[\"baap-sender-pubk\"")
	}

	if !bytes.Equal(pld.sender_key[:], pubkey) {
		return nil, errors.New("CRDSafe: jwt sender doesn't match tx sender")
	}
	// check domain is valid
	di, err := _getDomainState(ctx, pld.domain)
	if err != nil {
		return nil, err
	}
	// check key is valid
	ki := &protos.KeyItem{}
	err = proto.Unmarshal(param, ki)
	if err != nil {
		log.Error("CRDSafe Unmarshal KeyItem error", "error", err)
		return nil, err
	}
	//
	if pld.key != ki.Key {
		return nil, errors.New("CRDSafe: key in jwt doesn't match it from keyitem")
	}

	k, err := _getKeyState(ctx, di.Name, ki.Key)
	if err != nil {
		return nil, err
	}
	var canDelete bool
	// check author is in UAuth list
	for _, pubKey := range k.DAuth {
		if pld.author_key == pubKey {
			canDelete = true
			break
		}
	}
	// for public key
	if len(k.DAuth) == 0 {
		canDelete = true
	}

	if !canDelete {
		return nil, errors.New("CRDSafe: ak(author public key) is not in key Dauth list")
	}

	_delKeyState(ctx, di.Name, k)

	hv := _getState(ctx, keyCountPrefix+di.Name)
	v := big.NewInt(0).SetBytes(hv.Bytes())
	v.Sub(v, big.NewInt(1))
	keyHash := util.EthHash([]byte(keyCountPrefix + di.Name))
	ctx.Evm.StateDB.SetState(ctx.Contract.Address(), keyHash, common.BigToHash(v))

	return nil, nil
}

func getKey(param []byte, ctx *PrecompiledContractContext) ([]byte, error) {
	k := &protos.KeyItem{}
	err := proto.Unmarshal(param, k)
	if err != nil {
		log.Error("CRDSafe Unmarshal KeyItem error", "error", err)
		return nil, err
	}

	ki, err := _getKeyState(ctx, k.Dname, k.Key)
	if err != nil {
		return nil, err
	}

	k.Desc = ki.Desc
	k.Value = ki.Value
	k.Version = ki.Version

	for _idx, _ := range ki.UAuth {
		k.Uauth = append(k.Uauth, ki.UAuth[_idx][:])
	}
	for _idx, _ := range ki.DAuth {
		k.Dauth = append(k.Dauth, ki.DAuth[_idx][:])
	}

	buf, err := proto.Marshal(k)
	if err != nil {
		return nil, err
	}
	return buf, nil

}
