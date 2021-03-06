package ethapi

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/golang/protobuf/proto"
	"math/big"
	"CRD-chain/common"
	"CRD-chain/core/publicBC"
	"CRD-chain/core/types"
	"CRD-chain/core/vm"
	"CRD-chain/crypto"
	"CRD-chain/ethdb"
	"CRD-chain/log"
	"CRD-chain/CRDcc"
	pb "CRD-chain/CRDcc/protos"
	"CRD-chain/CRDcc/util"
	"CRD-chain/evertrust"
	"CRD-chain/evertrust/utils"
)

func Parsepoints(tx *types.Transaction, stateDB vm.StateDB) (points string, err error) {
	//if cc tx
	var ok bool
	var jwtBuf []byte
	to := tx.To()
	if to != nil {
		if CRDcc.CanExec(*to) {
			//is cc
			points, err := parseCCpoints(tx.Data())
			if err != nil {
				return "", fmt.Errorf("parse cc points:%v", err)
			}
			return points, nil
		}

		if *to == utils.CRDSafeContract {
			token, err := parseCCpoints(tx.Data())
			if err != nil {
				return "", fmt.Errorf("parse safe token:%v", err)
			}
			return token, nil
		}

		//keyHash := utils.CCKeyHash
		//ccBuf := stateDB.GetCRDState(*to, keyHash)
		ccBuf := stateDB.GetCode(*to)
		if len(ccBuf) != 0 {
			var deploy pb.Deployment
			err = proto.Unmarshal(ccBuf, &deploy)
			if err == nil {
				//is cc
				points, err := parseCCpoints(tx.Data())
				if err != nil {
					return "", fmt.Errorf("parse cc points:%v", err)
				}
				return points, nil
			}
		}
	}

	_, meta, err := evertrust.ParseData(tx.Data())
	if err != nil {
		return "", fmt.Errorf("parse data:%v", err)
	}
	if meta == nil {
		return "", fmt.Errorf("meta == nil")
	}

	jwtBuf, ok = meta["jwt"]
	if !ok {
		return "", fmt.Errorf("jwt not in meta, meta:%v", meta)
	}

	return string(jwtBuf), nil
}

func parseCCpoints(payload []byte) (points string, err error) {
	//payload, _, err := evertrust.ParseData(tx.Data()) //maybe parse
	txPb := &pb.Transaction{}
	err = proto.Unmarshal(payload, txPb)
	if err != nil {
		return "", fmt.Errorf("proto unmarshal tx:%v", err)
	}

	var jwtBuf []byte
	var ok bool
	txType := txPb.Type
	switch txType {
	case types.Transaction_deploy:
		deploy := pb.Deployment{}
		err = proto.Unmarshal(txPb.Payload, &deploy)
		if err != nil {
			return "", fmt.Errorf("proto unmarshal deploy:%v", err)
		}
		jwtBuf, ok = deploy.Payload.Meta["jwt"]
		if !ok {
			return "", fmt.Errorf("jwt not in deploy meta")
		}

	case types.Transaction_invoke: //start stop withdraw
		invocation := pb.Invocation{}
		err = proto.Unmarshal(txPb.Payload, &invocation)
		if err != nil {
			return "", fmt.Errorf("proto unmarshal invocation:%v", err)
		}

		jwtBuf, ok = invocation.Meta["jwt"]
		if !ok {
			return "", fmt.Errorf("jwt not in invocation meta")
		}

	}

	return string(jwtBuf), nil
}

func CheckFreeze(tx *types.Transaction, stateDB vm.StateDB, from common.Address) bool {
	//var signer types.Signer = types.HomesteadSigner{}
	//if tx.Protected() {
	//	signer = types.NewEIP155Signer(tx.ChainId())
	//}
	//from, err := types.Sender(signer, tx)
	//if err != nil {
	//	log.Error("check freeze get sender", "err", err)
	//	return false
	//}
	fromHash := util.EthHash(from.Bytes())
	r := stateDB.GetCRDState(utils.AccessCtlContract, fromHash)
	if len(r) > 0 && string(r) == "1" {
		log.Trace("string(r) == 1")
		return true
	}

	return false
}

func CheckToken(tx *types.Transaction, stateDB vm.StateDB) error {
	if tx.To() != nil && *tx.To() == utils.AccessCtlContract {
		log.Trace("access ctl token verify")
		tokenString, err := Parsepoints(tx, stateDB)
		if err != nil {
			log.Error("parse token", "err", err)
			return err
		}

		if err := checkJWT(tokenString, "a", stateDB); err != nil {
			return err
		}
		return nil
	}

	if tx.To() != nil && *tx.To() == utils.TokenRevokeContract {
		log.Trace("revoke token verify")
		tokenString, err := Parsepoints(tx, stateDB)
		if err != nil {
			log.Error("parse token", "err", err)
			return err
		}

		if err := checkJWT(tokenString, "a", stateDB); err != nil {
			return err
		}
		return nil
	}

	//DappAuth:T UserAuth:T Deploy:d regular Tx:u/d
	if evertrust.ConsortiumConf.DappAuth && evertrust.ConsortiumConf.UserAuth {
		tokenString, err := Parsepoints(tx, stateDB)
		if err != nil {
			//log.Error("parse token", "err", err)
			return fmt.Errorf("parse token:%s", err)
		}
		//if deploy contract tx must role d
		if tx.To() == nil || *tx.To() == utils.CCBaapDeploy {
			if err := checkJWT(tokenString, "d", stateDB); err != nil {
				return err
			}
		} else {
			//if not , regular tx must role u at least
			if err := checkJWT(tokenString, "u/d", stateDB); err != nil {
				return err
			}
		}
	}

	//DappAuth:F UserAuth:T Deploy:u/d regular Tx:u/d
	if !evertrust.ConsortiumConf.DappAuth && evertrust.ConsortiumConf.UserAuth {
		tokenString, err := Parsepoints(tx, stateDB)
		if err != nil {
			//log.Error("parse token", "err", err)
			return fmt.Errorf("parse token: %s", err)
		}

		//if deploy contract tx must role d
		if tx.To() == nil || *tx.To() == utils.CCBaapDeploy {
			if err := checkJWT(tokenString, "u/d", stateDB); err != nil {
				return err
			}
		} else {
			//if not , regular tx must role u at least
			if err := checkJWT(tokenString, "u/d", stateDB); err != nil {
				return err
			}
		}
	}

	//DappAuth:T UserAuth:F Deploy:d regular Tx:-
	if evertrust.ConsortiumConf.DappAuth && !evertrust.ConsortiumConf.UserAuth {
		//if deploy contract tx must role d
		if tx.To() == nil || *tx.To() == utils.CCBaapDeploy {
			tokenString, err := Parsepoints(tx, stateDB)
			if err != nil {
				log.Error("parse token", "err", err)
				return err
			}

			if err := checkJWT(tokenString, "d", stateDB); err != nil {
				return err
			}
		}
	}

	//DappAuth:F UserAuth:F Deploy:- regular Tx:-

	return nil
}

func checkJWT(tokenString string, roleLimit string, stateDB vm.StateDB) error {
	if tokenString == "" {
		//log.Error("tokenString empty")
		return errors.New("tokenString empty")
	}

	// check token revoke
	key := util.EthHash([]byte(tokenString))
	s := stateDB.GetCRDState(utils.TokenRevokeContract, key)
	if len(s) > 0 {
		return errors.New("token has been revoked")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		if token.Header["alg"] != "ES256" {
			return nil, fmt.Errorf("invalid signing alg:%v, only ES256 is prefered", token.Header["alg"])
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return nil, fmt.Errorf("token claims type error")
		}

		ak, ok := claims["ak"]
		if !ok {
			return nil, fmt.Errorf("ak no exist in claims")
		}
		hexPubKey, ok := ak.(string)
		if !ok || len(hexPubKey) != vm.PUBK_HEX_LEN {
			return nil, fmt.Errorf("ak format error")
		}

		//check public key
		_, ok = evertrust.UserCertPublicKeyMap[hexPubKey]
		if !ok {
			return nil, fmt.Errorf("ak no exist in user cert public key")
		}

		return crypto.DecompressPubkey(common.Hex2Bytes(hexPubKey))
	})

	if err != nil {
		log.Error("jwt parse", "err", err)
		return err
	}

	if claims, success := token.Claims.(jwt.MapClaims); success && token.Valid {
		limit, success := claims["l"].(float64)
		if !success {
			//log.Error("l not correct")
			return errors.New("l not correct")
		}
		if !checkLimit(tokenString, int64(limit)) {
			//log.Error("check limit fail")
			return errors.New("check limit fail")
		}

		role, success := claims["r"]
		if !success {
			log.Error("role no match", "role", role, "ok", success)
			return errors.New("role no match")
		}
		if roleLimit == "d" || roleLimit == "a" {
			if role != roleLimit {
				log.Error("role no auth", "role", role, "roleLimit", roleLimit)
				return errors.New("role no auth")
			}
		} else {
			if role == "u" || role == "d" {
			} else {
				log.Error("role no exist", "role", role)
				return errors.New("role no exist")
			}
		}

	} else {
		log.Error("token invalid")
		return errors.New("token invalid")
	}

	return nil
}

func checkLimit(pointsString string, limit int64) bool {
	db := *ethdb.ChainDb
	pointsHash := util.EthHash([]byte(pointsString))
	has, err := db.Has(pointsHash.Bytes())
	if err != nil {
		log.Error("db has", "err", err)
		return false
	}

	currentBlockNum := public.BC.CurrentBlock().Number()
	if !has {
		expiredBlockNum := big.NewInt(0).Add(big.NewInt(limit), currentBlockNum)
		err = db.Put(pointsHash.Bytes(), expiredBlockNum.Bytes())
		if err != nil {
			log.Error("db put pointsHash", "err", err)
			return false
		}
	} else {
		numByts, err := db.Get(pointsHash.Bytes())
		if err != nil {
			log.Error("db get pointsHash", "err", err)
			return false
		}

		expiredBlockNum := big.NewInt(0).SetBytes(numByts)
		if currentBlockNum.Cmp(expiredBlockNum) > 0 {
			log.Error("out of limit", "currentBlockNum", currentBlockNum.String(), "expiredBlockNum", expiredBlockNum)
			return false
		}
	}

	return true
}
