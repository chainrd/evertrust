// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

// Constants containing the genesis allocation of built-in genesis blocks.
// Their content is an RLP-encoded list of (address, balance) tuples.
// Use mkalloc.go to create/update them.

// nolint: misspell
const mainnetAllocData = ""

//\xf8i\xe2\x94H^*\xaf7\u07f7k\xaa6\xb26\xb1!\xfd\x97\xcc\n\xff\xe1\x8c\t\xb1\x8a\xb5\xdfq\x80\xb6\xb8\x00\x00\x00\u2506\b/\xa9\xd3\xc1M\x00\xa8bz\xf1<\xfa\x89>\x80\xb3\x91\x01\x8c\t\xb1\x8a\xb5\xdfq\x80\xb6\xb8\x00\x00\x00\xe2\x94\xdeX|\xffl\x117\xc4\xeb\x99,\xf8\x14\x9e\xcf\xf3\xe1c\xee\a\x8c\t\xb1\x8a\xb5\xdfq\x80\xb6\xb8\x00\x00\x00"
//"\xe3\xe2\x94SZr\xf6a\x04)$e&\xbb|\xd5CU\u434a\xd3\u03cc O\xce^>%\x02a\x10\x00\x00\x00"  正式账户

//三个账户
//\xf8i\xe2\x94H^*\xaf7\u07f7k\xaa6\xb26\xb1!\xfd\x97\xcc\n\xff\xe1\x8c`\xefk\x1a\xbao\a#0\x00\x00\x00\u2506\b/\xa9\xd3\xc1M\x00\xa8bz\xf1<\xfa\x89>\x80\xb3\x91\x01\x8c`\xefk\x1a\xbao\a#0\x00\x00\x00\u2527M\x83p\u0726\xc1\xee\xf7i_\xfc\xba\x1c\xdaI\xdf\xf6C\xe1\x8c`\xefk\x1a\xbao\a#0\x00\x00\x00"
const testnetAllocData ="\xf8i\xe2\x94H^*\xaf7\u07f7k\xaa6\xb26\xb1!\xfd\x97\xcc\n\xff\xe1\x8c`\xefk\x1a\xbao\a#0\x00\x00\x00\u2506\b/\xa9\xd3\xc1M\x00\xa8bz\xf1<\xfa\x89>\x80\xb3\x91\x01\x8c`\xefk\x1a\xbao\a#0\x00\x00\x00\u2527M\x83p\u0726\xc1\xee\xf7i_\xfc\xba\x1c\xdaI\xdf\xf6C\xe1\x8c`\xefk\x1a\xbao\a#0\x00\x00\x00"

const rinkebyAllocData = ""

const CRDCMainnetAllocData  ="\xe3\xe2\x94\x01{\xaa\x04\x111\x12\x8d,H*\u007f\x1f\xf6\xa7)y}\u204c\x1bw\t\x03NlB\x05\xb4\x00\x00\x00"
