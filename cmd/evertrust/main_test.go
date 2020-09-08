package main

import "testing"

func TestConsortiumSet(t *testing.T) {
	err := consortiumSet()
	if err != nil {
		t.Fatalf("consortium set:%v", err)
	}
}
