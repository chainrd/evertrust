package router

import (
	"CRD-chain/p2p/discover"
)

// check node ID exist
func contains(set []discover.ShortID, id discover.ShortID) bool {
	for _, val := range set {
		if val == id {
			return true
		}
	}
	return false
}

// remove node ID
func removeNID(set []discover.ShortID, id discover.ShortID) []discover.ShortID {
	var ret []discover.ShortID
	for _, val := range set {
		if val != id {
			ret = append(ret, val)
		}
	}
	return ret
}

// remove Route Item
func removeRI(set []routeItem, i routeItem) []routeItem {
	var ret []routeItem
	for _, val := range set {
		if val.Id != i.Id {
			ret = append(ret, val)
		}
	}
	return ret
}

// merge Route Items
func mergeRI(a, b []routeItem) []routeItem {
	var tmp []routeItem
	for len(a) > 0 && len(b) > 0 {
		if a[0].Hops > b[0].Hops {
			tmp = append(tmp, b[0])
			b = b[1:]
		} else {
			tmp = append(tmp, a[0])
			a = a[1:]
		}
	}
	if len(a) != 0 {
		tmp = append(tmp, a...)
	}
	if len(b) != 0 {
		tmp = append(tmp, b...)
	}
	return tmp
}

// find difference between two route Items
func findDiff(set []routeItem, sub []routeItem) []routeItem {
	var tmp []routeItem
	for _, sb := range sub {
		isSame := false
		for _, st := range set {
			if sb.Id == st.Id {
				isSame = true
			}
		}
		if !isSame {
			tmp = append(tmp, sb)
		}
	}
	return tmp
}

// there is no repeated item in both a and b
func _nodesEqual(a, b []discover.ShortID) bool {
	if len(a) != len(b) {
		return false
	}
	var flag bool
	for _, ida := range a {
		flag = false
		for _, idb := range b {
			if ida == idb {
				flag = true
				break
			}
		}
		if !flag {
			return flag
		}
	}
	return flag
}
