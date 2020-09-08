/*************************************************************************
 * Copyright (C) 2016-2019 CRD Technologies, Inc. All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @Time   : 2020/5/13 10:50 上午
 * @Author : liangc
 *************************************************************************/

package alibp2p

import (
	"context"
	"crypto/ecdsa"
	"math/big"
)

/*
type Config struct {
	Ctx                                           context.Context
	Homedir                                       string
	Port, ConnLow, ConnHi, BootstrapPeriod        uint64
	Bootnodes, ClientProtocols                    []string
	Discover, Relay, DisableInbound, EnableMetric bool
	Networkid, MuxPort                            *big.Int
	PrivKey                                       *ecdsa.PrivateKey
	Loglevel                                      int   // 3 INFO, 4 DEBUG, 5 TRACE -> 3-4 INFO, 5 DEBUG
	MaxMsgSize                                    int64 // min size 1MB (1024*1024)
}
*/

func MaxMsgSize(size int64) Option {
	return func(cfg *Config) error {
		if size < 1024*1024 {
			size = 1024 * 1024
		}
		cfg.MaxMsgSize = size
		return nil
	}
}

func Loglevel(level int) Option {
	return func(cfg *Config) error {
		cfg.Loglevel = level
		return nil
	}
}

func Identity(priv *ecdsa.PrivateKey) Option {
	return func(cfg *Config) error {
		cfg.PrivKey = priv
		return nil
	}
}

func Network(port, muxport, networkid uint64) Option {
	return func(cfg *Config) error {
		mp := new(big.Int)
		nid := new(big.Int)
		if muxport > 0 {
			mp = mp.SetUint64(muxport)
		}
		if networkid > 0 {
			nid = nid.SetUint64(networkid)
		}
		cfg.Networkid = nid
		cfg.Port = port
		cfg.MuxPort = mp
		return nil
	}
}

func Bootnodes(bootnodes ...string) Option {
	return func(cfg *Config) error {
		cfg.Bootnodes = bootnodes
		return nil
	}
}

func ClientProtocols(protocols ...string) Option {
	return func(cfg *Config) error {
		cfg.ClientProtocols = protocols
		return nil
	}
}

func Context(ctx context.Context) Option {
	return func(cfg *Config) error {
		cfg.Ctx = ctx
		return nil
	}
}

func Homedir(dir string) Option {
	return func(cfg *Config) error {
		cfg.Homedir = dir
		return nil
	}
}

func ConnectManger(bootstrapPeriod, connLow, connHi uint64) Option {
	return func(cfg *Config) error {
		cfg.BootstrapPeriod = bootstrapPeriod
		cfg.ConnLow, cfg.ConnHi = connLow, connHi
		return nil
	}
}

func EnableMetric(EnableMetric bool) Option {
	return func(cfg *Config) error {
		cfg.EnableMetric = EnableMetric
		return nil
	}
}

func Discover(Discover bool) Option {
	return func(cfg *Config) error {
		cfg.Discover = Discover
		return nil
	}
}

func Relay(Relay bool) Option {
	return func(cfg *Config) error {
		cfg.Relay = Relay
		return nil
	}
}

func DisableInbound(DisableInbound bool) Option {
	return func(cfg *Config) error {
		cfg.DisableInbound = DisableInbound
		return nil
	}
}
