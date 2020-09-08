package router

import (
	"testing"

	"CRD-chain/p2p/discover"
)

func TestContains(t *testing.T) {
	set := []discover.ShortID{{0}, {1}}
	id := discover.ShortID{0}
	if !contains(set, id) {
		t.Errorf("set %v doen't contain %v", set, id)
	}

	id = discover.ShortID{2}
	if contains(set, id) {
		t.Errorf("set %v contains %v", set, id)
	}
}

func TestRemoveNID(t *testing.T) {
	set := []discover.ShortID{{1}, {4}, {2}, {3}}
	set = removeNID(set, discover.ShortID{3})
	if contains(set, discover.ShortID{3}) {
		t.Errorf("removeNID faild, set:%v", set)
	}
	set = removeNID(set, discover.ShortID{4})
	set = removeNID(set, discover.ShortID{2})
	set = removeNID(set, discover.ShortID{1})

	if len(set) != 0 {
		t.Errorf("removeNID faild, set:%v", set)
	}
}

func TestMergeRI(t *testing.T)  {
	set1:= []routeItem{{discover.ShortID{1}, 1}, {discover.ShortID{2}, 2},{discover.ShortID{5}, 5}}
	set2:= []routeItem{{discover.ShortID{1}, 1}, {discover.ShortID{2}, 2},{discover.ShortID{3}, 3}}
	set := mergeRI(set1, set2)
	if len(set) != len(set1)+len(set2) {
		t.Errorf("len(set):%d not equal len(set1):%d + len(set2):%d", len(set), len(set1), len(set2))
	}
	if set[0].Hops !=1|| set[1].Hops !=1 || set[2].Hops !=2 || set[3].Hops !=2 ||
		set[4].Hops != 3 || set[5].Hops != 5 {
			t.Errorf("merge order test faild %v", set)
		}
}
