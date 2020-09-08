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
 * @Time   : 2020/2/26 4:23 下午
 * @Author : liangc
 *************************************************************************/

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	git "gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
	"io/ioutil"
	"os"
	"path"
	"strings"
)

type (
	Auth struct {
		Username, Password string
	}
	Repo struct {
		URL, TAG string
	}
	action byte
)

const (
	clone  action = 0x01
	pull          = 0x02
	ignore        = 0x03
	reset         = 0x04
)

const (
	deps_home = "_deps"
	auth_ns   = ".auth"
	tag_ns    = ".tag"
)

var (
	auth *Auth
	deps = map[string]Repo{
		"go-alibp2p":    {"https://gitee.com/cc14514/go-alibp2p.git", "v0.0.3-rc4"},
		"go-alibp2p-ca": {"https://gitee.com/cc14514/go-alibp2p-ca.git", "v0.0.2-rc2"},
		"go-certool":    {"https://gitee.com/cc14514/go-certool.git", "v0.0.2-rc1"},
	}
	callFn = func(p string, repo Repo) {
		auth = newAuth(p)
		if err := checkout_deps(auth, repo, p); err != nil {
			auth.clean(p)
			panic(err)
		}
		auth.save(p)
	}
)

func main() {
	pwd := os.Getenv("PWD")
	basedir, _ := path.Split(pwd)
	basedir = path.Join(basedir, deps_home)
	if err := os.MkdirAll(basedir, 0755); err != nil {
		panic(err)
	}

	for pn, repo := range deps {
		callFn(path.Join(basedir, pn), repo)
	}
}

func newAuth(p string) *Auth {
	a := new(Auth)
	err := a.load(p)
	if err != nil {
		a.Username = func() (pwd string) {
			for {
				fmt.Print("Username for get 'deps' : ")
				fmt.Scanln(&pwd)
				if pwd != "" {
					break
				}
			}
			return
		}()
		a.Password = func() (pwd string) {
			for {
				fmt.Print("Password for get 'deps' : ")
				fmt.Scanln(&pwd)
				if pwd != "" {
					break
				}
			}
			return
		}()
	}
	return a
}

func (a *Auth) fromBytes(buf []byte) (*Auth, error) {
	d, err := hex.DecodeString(string(buf))
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(d, a)
	return a, err
}

func (a *Auth) toBytes() []byte {
	d, _ := json.Marshal(a)
	return []byte(hex.EncodeToString(d))
}

func (a *Auth) clean(p string) error {
	if !strings.Contains(p, deps_home) {
		return errors.New("must in 'deps_home'")
	}
	err := os.Remove(path.Join(strings.Split(p, deps_home)[0], deps_home, auth_ns))
	if err != nil {
		return err
	}
	return nil
}
func (a *Auth) save(p string) error {
	if !strings.Contains(p, deps_home) {
		return errors.New("must save to 'deps_home'")
	}
	err := ioutil.WriteFile(path.Join(strings.Split(p, deps_home)[0], deps_home, auth_ns), a.toBytes(), 0755)
	if err != nil {
		return err
	}
	return nil
}

func (a *Auth) load(p string) error {
	if !strings.Contains(p, deps_home) {
		return errors.New("must load from 'deps_home'")
	}
	buf, err := ioutil.ReadFile(path.Join(strings.Split(p, deps_home)[0], deps_home, auth_ns))
	if err != nil {
		return err
	}
	_, err = a.fromBytes(buf)
	return err
}

func (a *Auth) toHttpBasicAuth() *http.BasicAuth {
	return &http.BasicAuth{
		Username: a.Username,
		Password: a.Password,
	}
}

func checkout_deps(auth *Auth, repo Repo, to string) error {

	switch verifyDeps(to, repo.TAG) {
	case pull:
		r, err := git.PlainOpen(to)
		if err != nil {
			return err
		}
		// Get the working directory for the repository
		w, err := r.Worktree()
		if err != nil {
			return err
		}
		// Pull the latest changes from the origin remote and merge into the current branch
		opts := &git.PullOptions{
			RemoteName:    "origin",
			Auth:          auth.toHttpBasicAuth(),
			ReferenceName: plumbing.NewBranchReferenceName("master"),
		}

		if repo.TAG != "" {
			ref, err := r.Tag(repo.TAG)
			if err != nil {
				return err
			}
			opts.ReferenceName = ref.Name()
		}

		err = w.Pull(opts)
		if err != nil {
			fmt.Println(err)
		}
		// Print the latest commit that was just pulled
		ref, err := r.Head()
		if err != nil {
			return err
		}
		commit, err := r.CommitObject(ref.Hash())
		if err != nil {
			return err
		}
		fmt.Println("pulled alibp2p :", commit)
	case clone:
		var (
			err  error
			opts = &git.CloneOptions{
				URL:           repo.URL,
				Auth:          auth.toHttpBasicAuth(),
				Progress:      os.Stdout,
				ReferenceName: plumbing.NewBranchReferenceName("master"),
			}
		)
		if repo.TAG != "" {
			opts.ReferenceName = plumbing.NewTagReferenceName(repo.TAG)
			defer func() {
				if err == nil {
					ioutil.WriteFile(path.Join(to, tag_ns), []byte(repo.TAG), 0755)
				}
			}()
		}
		_, err = git.PlainClone(to, false, opts)
		if err != nil {
			return err
		}
		fmt.Println("checkout alibp2p to :", to)
	case reset:
		os.RemoveAll(to)
		return checkout_deps(auth, repo, to)
	default:
	}
	return nil
}

func verifyDeps(t, tag string) action {
	_, err := ioutil.ReadDir(t)
	if err != nil {
		return clone
	}
	_btag, _tagerr := ioutil.ReadFile(path.Join(t, tag_ns))
	if tag != "" {
		if _tagerr == nil {
			if _btag != nil && string(_btag) == tag {
				return ignore
			}
		}
		return reset
	}

	if _btag != nil {
		return reset
	}

	return pull
}
