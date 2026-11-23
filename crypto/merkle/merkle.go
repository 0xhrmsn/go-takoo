// Package merkle commits to an ordered list with a single 32-byte root, and
// lets you prove one entry is in the list without handing over the rest.
//
// The tree is shaped like RFC 6962's (Certificate Transparency) but hashed
// with SHA3-256. A leaf is the hash of the RFC 6962 leaf prefix 0x00 and the
// entry, an inner node the hash of the node prefix 0x01 and its two
// children, so leaves and nodes
// can't be confused. When a level has an odd number of hashes, the last one
// moves up as it is instead of being paired with itself. Bitcoin's
// duplicate-the-last-one rule let two different transaction lists share a
// root (CVE-2012-2459); this one doesn't.
package merkle

import (
	"crypto/subtle"
	"fmt"

	"go-takoo/crypto"
)

const (
	tagMerkleLeafs byte = 0x00
	tagMerkleNodes byte = 0x01
)

// merkle keeps every level of the tree, leaves first and the root last, so
// Proof never has to hash anything again.
type merkle struct {
	levels [][]crypto.Hash
}

// NewMerkle builds the tree over entries in the given order. Entries can be
// any length, even empty. With no entries at all you get an empty tree,
// whose Root is the hash of nothing and which can't produce proofs.
func NewMerkle(entries [][]byte) *merkle {
	if len(entries) == 0 {
		return &merkle{}
	}

	level := make([]crypto.Hash, len(entries))
	for i, e := range entries {
		level[i] = crypto.MultiHash256([]byte{tagMerkleLeafs}, e)
	}

	m := &merkle{levels: [][]crypto.Hash{level}}
	for len(level) > 1 {
		next := make([]crypto.Hash, 0, (len(level)+1)/2)
		for i := 0; i+1 < len(level); i += 2 {
			next = append(next, crypto.MultiHash256([]byte{tagMerkleNodes}, level[i][:], level[i+1][:]))
		}
		if len(level)%2 == 1 {
			next = append(next, level[len(level)-1])
		}
		level = next
		m.levels = append(m.levels, level)
	}

	return m
}

// Proof returns the sibling hashes Verify needs for the entry at index, from
// the bottom of the tree up. Levels where the node had no sibling are
// skipped, so a proof can be shorter than the tree is tall.
func (m *merkle) Proof(index int) ([][]byte, error) {
	if len(m.levels) == 0 {
		return nil, fmt.Errorf("crypto/merkle: merkle tree has no leaves")
	}
	if n := len(m.levels[0]); index < 0 || index >= n {
		return nil, fmt.Errorf("crypto/merkle: merkle leaf index %d out of range, want 0..%d", index, n-1)
	}

	proof := make([][]byte, 0, len(m.levels)-1)
	for _, level := range m.levels[:len(m.levels)-1] {
		// No sibling: the node moved up alone.
		if index^1 < len(level) {
			proof = append(proof, level[index^1].Bytes())
		}
		index /= 2
	}

	return proof, nil
}

// Root returns the root hash. It covers every entry and their order, but not
// how many entries there are; if that number matters, as it does for a block
// header, sign or hash it alongside the root.
func (m *merkle) Root() []byte {
	if len(m.levels) == 0 {
		return crypto.Hash256(nil).Bytes()
	}

	return m.levels[len(m.levels)-1][0].Bytes()
}

// Verify reports whether leaf is entry number index in a tree of total
// entries with this root.
//
// total decides the shape of the tree and the root doesn't pin it down, so
// take it from somewhere you trust, like a signed header. Bad input just
// gives false: an index out of range, a sibling that isn't 32 bytes, too
// many or too few siblings.
func Verify(root, leaf []byte, index, total int, proof [][]byte) bool {
	if total <= 0 || index < 0 || index >= total {
		return false
	}
	// Refuse a mis-sized sibling before hashing anything.
	for _, sibling := range proof {
		if len(sibling) != crypto.HashSize {
			return false
		}
	}

	compute := crypto.MultiHash256([]byte{tagMerkleLeafs}, leaf)
	// size/2 + size%2 rounds up like (size+1)/2, but can't overflow when
	// total is the largest int.
	for size := total; size > 1; size, index = size/2+size%2, index/2 {
		// No sibling: the node moved up alone.
		if index^1 >= size {
			continue
		}
		if len(proof) == 0 {
			return false
		}
		left, right := compute[:], proof[0]
		if index%2 == 1 {
			left, right = right, left
		}
		compute = crypto.MultiHash256([]byte{tagMerkleNodes}, left, right)
		proof = proof[1:]
	}
	// Leftover siblings mean a proof for another tree.
	if len(proof) != 0 {
		return false
	}

	return subtle.ConstantTimeCompare(compute[:], root) == 1
}
