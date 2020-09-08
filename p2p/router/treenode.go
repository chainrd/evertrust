package router

import (
	"io"

	"CRD-chain/p2p/discover"
	"CRD-chain/rlp"
)

type treeNode struct {
	//root  discover.ShortID
	leafs map[uint32]discover.ShortID
	num   uint32
}

func newTreeNode() *treeNode {
	return &treeNode{leafs: make(map[uint32]discover.ShortID)}
}

func (tree *treeNode) addLeaf(id discover.ShortID) {
	//p := r.peerTree[r.routerID]
	if tree == nil {
		return
	}
	for i := uint32(0); i < tree.num; i++ {
		if tree.leafs[i] == id {
			return
		}
	}
	tree.leafs[tree.num] = id
	tree.num++
}

func (tree *treeNode) delLeaf(id discover.ShortID) bool {
	for i := uint32(0); tree != nil && i < tree.num; i++ {
		if tree.leafs[i] == id {
			tree.leafs[i] = tree.leafs[tree.num-1]
			tree.num--
			return true
		}
	}
	return false
}

func (tree *treeNode) contains(id discover.ShortID) bool {
	for i := uint32(0); tree != nil && i < tree.num; i++ {
		if tree.leafs[i] == id {
			return true
		}
	}
	return false
}

func (p *treeNode) EncodeRLP(w io.Writer) (err error) {
	var t []discover.ShortID
	for i := uint32(0); i < p.num; i++ {
		t = append(t, p.leafs[i])
	}
	return rlp.Encode(w, t)
}

func (p *treeNode) DecodeRLP(s *rlp.Stream) error {
	var t []discover.ShortID
	err := s.Decode(&t)
	if err != nil {
		return err
	}
	p.leafs = make(map[uint32]discover.ShortID)
	p.num = uint32(len(t))
	for idx, id := range t {
		p.leafs[uint32(idx+1)] = id
	}
	return nil
}
