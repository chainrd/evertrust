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
 * @Time   : 2020/3/24 11:37 上午
 * @Author : liangc
 *************************************************************************/

package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cc14514/go-alibp2p"
	ma "github.com/multiformats/go-multiaddr"
	"os"
	"path"
	"strings"
)

var (
	homedir_error = errors.New("homedir must be a dir")
	SplitFn       = func(s string) []string {
		if s != "" {
			return strings.Split(s, ",")
		}
		return nil
	}
)

type Config struct {
	cancel        context.CancelFunc
	Ctx           context.Context `json:"-"`
	Bootnodes     []string        `json:"bootnodes,omitempty"`
	Trusts        []string        `json:"trusts,omitempty"`
	Networkid     int64           `json:"networkid,omitempty"`
	Chainid       int64           `json:"chainid,omitempty"` // default same networkid
	Port          int             `json:"port,omitempty"`
	Rpcport       int             `json:"rpcport,omitempty"`
	EnableRelay   bool            `json:"enable_relay,omitempty"`
	EnableInbound bool            `json:"enable_inbound,omitempty"`
	Homedir       string          `json:"homedir,omitempty"`
	Muxport       int             `json:"muxport,omitempty"`
}

func (cfg *Config) AsMap() map[string]interface{} {
	b, _ := json.Marshal(cfg)
	m := make(map[string]interface{})
	json.Unmarshal(b, &m)
	return m
}

func (cfg *Config) String() string {
	return fmt.Sprintf(`
---- service config ---->
bootnodes : %v
trusts : %v
chainid : %v
networkid : %v
port : %v
rpcport : %v
enable relay : %v
enable inbound : %v
home dir : %v
mux port : %v
---- service config ----<
`, cfg.Bootnodes, cfg.Trusts, cfg.Chainid, cfg.Networkid, cfg.Port, cfg.Rpcport, cfg.EnableRelay, cfg.EnableInbound, cfg.Homedir, cfg.Muxport)
}

func (cfg *Config) Validate() error {
	if PLATEFORM == "pc" {
		os.MkdirAll(path.Join(cfg.Homedir, "keystore"), 0755)
	} else {
		os.MkdirAll(cfg.Homedir, 0755)
	}
	if f, err := os.Open(cfg.Homedir); err != nil {
		return err
	} else if fi, err := f.Stat(); err != nil {
		return err
	} else if !fi.IsDir() {
		return homedir_error
	}
	for _, t := range cfg.Trusts {
		if _, err := alibp2p.ECDSAPubDecode(t); err != nil {
			return err
		}
	}
	for _, b := range cfg.Bootnodes {
		if _, err := ma.NewMultiaddr(b); err != nil {
			return err
		}
	}
	return nil
}
