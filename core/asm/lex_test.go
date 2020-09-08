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

package asm

import (
	"reflect"
	"testing"
)

func lexAll(src string) []points {
	ch := Lex("test.asm", []byte(src), false)

	var pointss []points
	for i := range ch {
		pointss = append(pointss, i)
	}
	return pointss
}

func TestLexer(t *testing.T) {
	tests := []struct {
		input  string
		pointss []points
	}{
		{
			input:  ";; this is a comment",
			pointss: []points{{typ: lineStart}, {typ: eof}},
		},
		{
			input:  "0x12345678",
			pointss: []points{{typ: lineStart}, {typ: number, text: "0x12345678"}, {typ: eof}},
		},
		{
			input:  "0x123ggg",
			pointss: []points{{typ: lineStart}, {typ: number, text: "0x123"}, {typ: element, text: "ggg"}, {typ: eof}},
		},
		{
			input:  "12345678",
			pointss: []points{{typ: lineStart}, {typ: number, text: "12345678"}, {typ: eof}},
		},
		{
			input:  "123abc",
			pointss: []points{{typ: lineStart}, {typ: number, text: "123"}, {typ: element, text: "abc"}, {typ: eof}},
		},
		{
			input:  "0123abc",
			pointss: []points{{typ: lineStart}, {typ: number, text: "0123"}, {typ: element, text: "abc"}, {typ: eof}},
		},
	}

	for _, test := range tests {
		pointss := lexAll(test.input)
		if !reflect.DeepEqual(pointss, test.pointss) {
			t.Errorf("input %q\ngot:  %+v\nwant: %+v", test.input, pointss, test.pointss)
		}
	}
}
