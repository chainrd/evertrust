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
 * @Time   : 2020/1/10 6:02 下午
 * @Author : liangc
 *************************************************************************/

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/peterh/liner"
	"gopkg.in/urfave/cli.v1"
	"io"
	"os"
	"path"
	"path/filepath"
	"CRD-chain/cmd/plume/service"
	"CRD-chain/log"
	"strings"
	"time"
)

var (
	vsn         = service.Version()
	app         *cli.App
	ostream     log.Handler
	glogger     *log.GlogHandler
	logdir      string
	def_homedir = path.Join(os.Getenv("HOME"), ".plume")
	ctx         = context.Background()
)

var (
	bootnodes     string
	trusts        string
	networkid     int64
	chainid       int64
	port          int
	rpcport       int
	loglevel      int
	enablerelay   bool
	enableinbound bool
	homedir       string
	muxport       int
)

func init() {
	app = cli.NewApp()
	app.Version = vsn
	app.Author = "cc14514@icloud.com"
	app.Name = "Plume"
	app.Description = "Light Node for CRD evertrust Blockchain"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "bootnodes,b",
			Usage: "节点的 URL 集合, 多个节点时用 ',' 分隔",
			//Value:       "/ip4/127.0.0.1/tcp/10000/ipfs/16Uiu2HAm39zRzVr5JK6P1WCba7ew8L5CBT4r5e3wcZ8V2zQRvWSM",
			Destination: &bootnodes,
		},
		cli.Int64Flag{
			Name:        "networkid,n",
			Usage:       "网络id，必须与全节点保持一致",
			Value:       111,
			Destination: &networkid,
		},
		cli.IntFlag{
			Name:        "rpcport,p",
			Usage:       "http 协议的 rpc 接口",
			Value:       18545,
			Destination: &rpcport,
		},
		cli.IntFlag{
			Name:        "port",
			Usage:       "节点端口，默认使用随机端口",
			Value:       0,
			Destination: &port,
		},
		cli.IntFlag{
			Name:        "muxport",
			Usage:       "netmux 端口，0 为不使用 mux 服务，轻节点不必使用此配置",
			Value:       0,
			Destination: &muxport,
		},
		cli.StringFlag{
			Name:        "trusts,t",
			Usage:       "信任节点的 ID 集合，如自己公司部署的全节点, 多个节点时用 ',' 分隔, 注意区别于 bootnodes 这里只是 ID 的集合",
			Destination: &trusts,
		},
		cli.StringFlag{
			Name:        "homedir,d",
			Usage:       "数据目录",
			Value:       def_homedir,
			Destination: &homedir,
		},

		cli.BoolFlag{
			Name:        "relay,r",
			Usage:       "turn on relay serve of current node",
			Destination: &enablerelay,
		},

		cli.BoolFlag{
			Name:        "inbound,i",
			Usage:       "enable inbound , may be just for bridge node",
			Destination: &enableinbound,
		},

		cli.IntFlag{
			Name:        "verbosity",
			Usage:       "Logging verbosity: 0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=detail",
			Destination: &loglevel,
			Value:       3,
		},
	}

	app.Commands = []cli.Command{
		{
			Name:   "attach",
			Usage:  "attach to console",
			Action: AttachCmd,
			Flags: []cli.Flag{
				cli.IntFlag{
					Name:        "rpcport,p",
					Usage:       "RPC server's `PORT`",
					Value:       18545,
					Destination: &rpcport,
				},
			},
		},
		{
			Name:  "console",
			Usage: "run plume node and attach to console",
			Action: func(c *cli.Context) error {
				go func() {
					if err := plume(c); err != nil {
						panic(err)
					}
				}()
				t := 0
				for {
					<-time.After(1 * time.Second)
					if err := AttachCmd(c); err != nil && t < 10 {
						t += 1
						continue
					}
					return nil
				}
			},
		},
	}

	app.Before = func(_ *cli.Context) error {
		os.MkdirAll(homedir, 0755)
		output := io.Writer(os.Stderr)
		ostream = log.StreamHandler(output, log.TerminalFormat(false))
		glogger = log.NewGlogHandler(ostream)
		// logging
		log.PrintOrigins(true)
		if logdir != "" {
			rfh, err := log.RotatingFileHandler(
				logdir,
				262144,
				log.JSONFormatOrderedEx(false, true),
			)
			if err != nil {
				return err
			}
			glogger.SetHandler(log.MultiHandler(ostream, rfh))
		}
		if os.Getenv("loglevel") == "" {
			os.Setenv("loglevel", fmt.Sprintf("%d", loglevel))
		}
		glogger.Verbosity(log.Lvl(loglevel))
		//glogger.Vmodule(ctx.GlobalString(vmoduleFlag.Name))
		//glogger.BacktraceAt(ctx.GlobalString(backtraceAtFlag.Name))
		log.Root().SetHandler(glogger)
		return nil
	}

	app.Action = plume

	app.After = func(_ *cli.Context) error {
		return nil
	}
}

func plume(_ *cli.Context) error {
	if chainid == 0 {
		chainid = networkid
	}
	cfg := &service.Config{
		Ctx:           ctx,
		Bootnodes:     service.SplitFn(bootnodes),
		Trusts:        service.SplitFn(trusts),
		Chainid:       chainid,
		Networkid:     networkid,
		Port:          port,
		Rpcport:       rpcport,
		EnableRelay:   enablerelay,
		EnableInbound: enableinbound,
		Homedir:       homedir,
		Muxport:       muxport,
	}

	fmt.Println(cfg)
	network, err := service.NewNetwork(cfg)
	if err != nil {
		return err
	}
	rpcserver := service.NewRPCServer(network)
	err = rpcserver.Start()
	if err != nil {
		return err
	}
	return nil
}

func main() {
	if err := app.Run(os.Args); err != nil {
		os.Exit(-1)
	}
}

var adminHelp = func() string {
	return `
-------------------------------------------------------------------------
# 当前 shell 支持以下指令
-------------------------------------------------------------------------
config 查看当前节点配置 
myid 获取当前节点信息
conns 获取当前网络连接信息
findpeer [id] 全网查找 id 对应的 addr 信息 
addrs [id] 本地查找 id 对应的 addr 信息 
connect [id/url] 连接一个 id 或 url
findproviders [limit] 获取已经 advertise 的 fullnode 列表, limit 为可选参数
fnodes 查看当前的 fnodes 集合提供服务的节点信息
report 查看网络资源使用情况
routingtable 展示路由表

exit 退出 shell

`
}

func AttachCmd(_ *cli.Context) error {
	func() {
		fmt.Println("----------------------------------")
		fmt.Println(" Plume Console, Rpcport", rpcport)
		fmt.Println("----------------------------------")
		var (
			targetId      = ""
			inCh          = make(chan string)
			historyFn     = filepath.Join(homedir, ".history")
			line          = liner.NewLiner()
			instructNames = []string{
				"config",
				"conns",
				"myid",
				"connect",
				"findpeer",
				"findproviders",
				"fnodes",
				"report",
				"addrs",
				"routingtable",
			}
		)
		defer func() {
			if f, err := os.Create(historyFn); err != nil {
				fmt.Println("Error writing history file: ", err)
			} else {
				line.WriteHistory(f)
				f.Close()
			}
			line.Close()
			close(inCh)
		}()

		line.SetCtrlCAborts(false)
		line.SetShouldRestart(func(err error) bool {
			return true
		})
		line.SetCompleter(func(line string) (c []string) {
			for _, n := range instructNames {
				if strings.HasPrefix(n, strings.ToLower(line)) {
					c = append(c, n)
				}
			}
			return
		})

		if f, err := os.Open(historyFn); err == nil {
			line.ReadHistory(f)
			f.Close()
		}

		for {
			label := "$> "
			if targetId != "" {
				label = fmt.Sprintf("@%s$> ", targetId[len(targetId)-6:])
			}
			if cmd, err := line.Prompt(label); err == nil {
				if cmd == "" {
					continue
				}
				line.AppendHistory(cmd)

				cmd = strings.Trim(cmd, " ")
				//app = app[:len([]byte(app))-1]
				// TODO 用正则表达式拆分指令和参数
				cmdArg := strings.Split(cmd, " ")
				//wsC.Write([]byte(cmdArg[0]))
				switch cmdArg[0] {
				case "help":
					fmt.Println(adminHelp())
				case "exit":
					if targetId != "" {
						targetId = ""
					} else {
						fmt.Println("bye bye ^_^ ")
						return
					}
				default:
					mn := cmdArg[0]
					if strings.Index(mn, "_") < 0 {
						mn = "admin_" + mn
					}
					var params = make([]interface{}, 0)
					for _, p := range cmdArg[1:] {
						params = append(params, p)
					}
					rsp, err := callrpc(service.NewReq(mn, params))
					if err != nil {
						fmt.Println("error:", err)
					} else if rsp.Error != nil {
						fmt.Println("error:", rsp.Error.Code, rsp.Error.Message)
					} else {
						_, ok := rsp.Result.(string)
						if ok {
							fmt.Println(rsp.Result)
						} else {
							j, _ := json.Marshal(rsp.Result)
							d, _ := jshow(j)
							fmt.Println(string(d))
						}
					}
				}
			} else if err == liner.ErrPromptAborted {
				fmt.Println("Aborted")
				return
			} else {
				fmt.Println("Error reading line: ", err)
				return
			}

		}
	}()
	return nil
}

func jshow(j []byte) ([]byte, error) {
	var out bytes.Buffer
	err := json.Indent(&out, j, "", "\t")
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func callrpc(req *service.Req) (*service.Rsp, error) {
	return service.CallRPC(rpcport, req)
}
