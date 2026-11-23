package merkle

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"go-takoo/crypto"
)

func TestRootMatchesAnIndependentConstruction(t *testing.T) {
	for n := 0; n <= 300; n++ {
		entries := labelled(n)
		if got, want := NewMerkle(entries).Root(), recursive(entries); !bytes.Equal(got, want) {
			t.Fatalf("%d entries: got %x, want %x", n, got, want)
		}
	}
}

func TestRootOfNothingIsTheHashOfNothing(t *testing.T) {
	const want = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
	for _, entries := range [][][]byte{nil, {}} {
		if got := hex.EncodeToString(NewMerkle(entries).Root()); got != want {
			t.Fatalf("got %s, want %s", got, want)
		}
	}
}

// TestRootIsPinned holds the root of five entries, computed outside Go. Roots are
// consensus, and bottomUp shares the package's tags: renumbering one would move
// both and leave the oracle silent, but not this.
func TestRootIsPinned(t *testing.T) {
	const want = "2641f4ef3d8fa766c6e383e02eb0d07111df01e1b32aa4953246a8ccb2883efd"
	if got := hex.EncodeToString(NewMerkle(labelled(5)).Root()); got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

// A leaf and an internal node are hashed under different tags, so a node can
// never be replayed as a leaf. Without that separation the tree loses its
// second-preimage resistance.
func TestLeavesAndNodesUseDifferentTags(t *testing.T) {
	a, b := []byte("a"), []byte("b")
	node := NewMerkle([][]byte{a, b}).Root()
	leafA, leafB := crypto.MultiHash256([]byte{0x00}, a), crypto.MultiHash256([]byte{0x00}, b)
	asLeaf := NewMerkle([][]byte{append(leafA[:], leafB[:]...)}).Root()
	if bytes.Equal(node, asLeaf) {
		t.Fatal("an internal node hashes the same as a leaf holding its children")
	}
}

// Duplicating the last entry must change the root. A construction that pairs an
// odd tail with itself gives [a b c] and [a b c c] the same root, which lets one
// transaction list stand in for another (CVE-2012-2459).
func TestDuplicatingTheTailChangesTheRoot(t *testing.T) {
	for _, n := range []int{3, 5, 7, 9, 11, 13, 21, 33, 129, 255} {
		entries := labelled(n)
		doubled := append(append([][]byte(nil), entries...), entries[n-1])
		if bytes.Equal(NewMerkle(entries).Root(), NewMerkle(doubled).Root()) {
			t.Fatalf("%d entries: duplicating the tail left the root alone", n)
		}
	}
}

func TestRootIsStableAndDoesNotAlias(t *testing.T) {
	m := NewMerkle(labelled(37))
	first := m.Root()
	if len(first) != crypto.HashSize {
		t.Fatalf("root is %d bytes, want %d", len(first), crypto.HashSize)
	}
	clear(first)
	if again := m.Root(); bytes.Equal(again, first) {
		t.Fatal("a later root shares storage with an earlier one")
	}
}

func TestProofVerifies(t *testing.T) {
	for n := 1; n <= 200; n++ {
		entries := labelled(n)
		m := NewMerkle(entries)
		root := m.Root()
		for i := range entries {
			proof, err := m.Proof(i)
			if err != nil {
				t.Fatalf("%d entries, index %d: %v", n, i, err)
			}
			if !Verify(root, entries[i], i, n, proof) {
				t.Fatalf("%d entries, index %d: a genuine proof was refused", n, i)
			}
		}
	}
}

func TestProofRejectsAnIndexOutsideTheTree(t *testing.T) {
	for _, c := range []struct{ n, index int }{{0, 0}, {1, 1}, {1, -1}, {4, 4}, {4, 99}, {8, -3}} {
		_, err := NewMerkle(labelled(c.n)).Proof(c.index)
		if err == nil {
			t.Fatalf("%d entries, index %d: accepted", c.n, c.index)
		}
		if !strings.Contains(err.Error(), "crypto/merkle:") {
			t.Fatalf("error does not name the package: %v", err)
		}
	}
}

func TestVerifyRejectsATamperedProof(t *testing.T) {
	const n = 64
	entries := labelled(n)
	m := NewMerkle(entries)
	root := m.Root()

	for i := 0; i < n; i += 7 {
		proof, err := m.Proof(i)
		if err != nil {
			t.Fatal(err)
		}
		other := entries[(i+1)%n]
		short := proof[:len(proof)-1]
		long := append(append([][]byte(nil), proof...), root)
		flipped := bytes.Clone(entries[i])
		flipped[0] ^= 1
		bent := append([][]byte(nil), proof...)
		bent[0] = bytes.Clone(bent[0])
		bent[0][0] ^= 1

		for name, ok := range map[string]bool{
			"another entry":      Verify(root, other, i, n, proof),
			"one bit of a leaf":  Verify(root, flipped, i, n, proof),
			"one bit of sibling": Verify(root, entries[i], i, n, bent),
			"a short proof":      Verify(root, entries[i], i, n, short),
			"a long proof":       Verify(root, entries[i], i, n, long),
			"a wrong index":      Verify(root, entries[i], (i+1)%n, n, proof),
			"a truncated root":   Verify(root[:crypto.HashSize-1], entries[i], i, n, proof),
			"a zero total":       Verify(root, entries[i], i, 0, proof),
			"a negative index":   Verify(root, entries[i], -1, n, proof),
		} {
			if ok {
				t.Fatalf("index %d: %s was accepted", i, name)
			}
		}
	}
}

// An index past the end must be refused even where the proof is empty: in a tree
// of one entry the loop never runs, and the leaf alone already is the root.
func TestVerifyRejectsAnIndexPastTheEnd(t *testing.T) {
	for _, n := range []int{1, 2, 5} {
		entries := labelled(n)
		m := NewMerkle(entries)
		proof, err := m.Proof(n - 1)
		if err != nil {
			t.Fatal(err)
		}
		for _, index := range []int{n, n + 1, 2 * n} {
			if Verify(m.Root(), entries[n-1], index, n, proof) {
				t.Errorf("%d entries: index %d was accepted", n, index)
			}
		}
	}
}

// A sibling of the wrong width is refused before any hashing, so a peer cannot
// make a verifier hash a megabyte on the way to a refusal it was always going to
// reach. The leaf is exempt: that is content, and any length is legitimate.
func TestVerifyRejectsASiblingOfTheWrongWidth(t *testing.T) {
	entries := labelled(8)
	m := NewMerkle(entries)
	proof, err := m.Proof(3)
	if err != nil {
		t.Fatal(err)
	}
	for _, width := range []int{0, 1, crypto.HashSize - 1, crypto.HashSize + 1, 1 << 20} {
		bent := append([][]byte(nil), proof...)
		bent[0] = make([]byte, width)
		if Verify(m.Root(), entries[3], 3, len(entries), bent) {
			t.Fatalf("a %d-byte sibling was accepted", width)
		}
	}
}

func TestVerifyAcceptsAnyLeafLength(t *testing.T) {
	for _, size := range []int{0, 1, 1000, 1 << 16} {
		entries := [][]byte{make([]byte, size), []byte("other")}
		m := NewMerkle(entries)
		proof, err := m.Proof(0)
		if err != nil {
			t.Fatal(err)
		}
		if !Verify(m.Root(), entries[0], 0, 2, proof) {
			t.Fatalf("a %d-byte leaf was refused", size)
		}
	}
}

// The root does not commit to the entry count, so a genuine proof also verifies
// against some other tree sizes. This pins that the gap exists and stays small:
// a caller must take total from a signed source, never from the wire beside the
// proof.
func TestTotalIsNotAuthenticatedByTheRoot(t *testing.T) {
	accepted, checked := 0, 0
	for n := 2; n <= 24; n++ {
		entries := labelled(n)
		m := NewMerkle(entries)
		root := m.Root()
		for i := range entries {
			proof, err := m.Proof(i)
			if err != nil {
				t.Fatal(err)
			}
			for total := 1; total <= 48; total++ {
				for index := 0; index < total; index++ {
					if index == i && total == n {
						continue
					}
					checked++
					if Verify(root, entries[i], index, total, proof) {
						accepted++
					}
				}
			}
		}
	}
	if accepted == 0 {
		t.Fatal("no alternative (index, total) was accepted; the gap this documents has closed")
	}
	if share := float64(accepted) / float64(checked); share > 0.02 {
		t.Fatalf("%.2f%% of alternative (index, total) pairs accepted, want under 2%%", 100*share)
	}
}

func TestVerifyTerminatesForEveryTotal(t *testing.T) {
	entries := labelled(8)
	m := NewMerkle(entries)
	proof, err := m.Proof(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, total := range []int{1, 2, 3, 1 << 20, 1 << 40, int(^uint(0) >> 1)} {
		Verify(m.Root(), entries[0], 0, total, proof)
	}
}

// (size+1)/2 used to wrap at the largest int, so a tree that size took one
// level and an empty proof was enough.
func TestVerifyDoesNotOverflowAtTheLargestTotal(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	leaf := []byte("x")
	root := crypto.MultiHash256([]byte{tagMerkleLeafs}, leaf)
	if Verify(root[:], leaf, maxInt-1, maxInt, nil) {
		t.Fatal("an empty proof verified in a tree of the largest size")
	}

	entries := labelled(2)
	m := NewMerkle(entries)
	proof, err := m.Proof(1)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{1, 3} {
		if Verify(m.Root(), entries[1], index, maxInt, proof) {
			t.Errorf("a two-leaf proof verified as index %d of the largest tree", index)
		}
	}
}

func TestProofDoesNotAliasTheTree(t *testing.T) {
	entries := labelled(16)
	m := NewMerkle(entries)
	proof, err := m.Proof(5)
	if err != nil {
		t.Fatal(err)
	}
	for i := range proof {
		clear(proof[i])
	}
	again, _ := m.Proof(5)
	if !Verify(m.Root(), entries[5], 5, 16, again) {
		t.Fatal("clearing a proof changed the tree")
	}
}

func labelled(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = fmt.Appendf(nil, "transaction %d", i)
	}

	return out
}

// recursive is the other formulation of the same tree: split at the largest
// power of two below n and join the halves. The package builds level by level,
// so this works as an independent oracle rather than a copy of the code under
// test.
func recursive(entries [][]byte) []byte {
	n := len(entries)
	switch {
	case n == 0:
		return crypto.Hash256(nil).Bytes()
	case n == 1:
		return crypto.MultiHash256([]byte{0x00}, entries[0]).Bytes()
	}
	k := 1
	for k<<1 < n {
		k <<= 1
	}

	return crypto.MultiHash256([]byte{0x01}, recursive(entries[:k]), recursive(entries[k:])).Bytes()
}

// FuzzVerify hands Verify whatever an attacker could put in a proof: any
// index, any total and siblings of any width. It must never panic, and on an
// honest proof it accepts the real leaf and nothing else.
func FuzzVerify(f *testing.F) {
	f.Add(uint8(7), 3, 7, []byte("transaction 3"), []byte{})
	f.Add(uint8(1), 0, 1, []byte("transaction 0"), make([]byte, 70))
	f.Add(uint8(0), 0, 0, []byte{}, make([]byte, 32))
	f.Fuzz(func(t *testing.T, size uint8, index, total int, leaf, junk []byte) {
		entries := labelled(int(size))
		tree := NewMerkle(entries)
		root := tree.Root()

		var forged [][]byte
		for sibling := range slices.Chunk(junk, crypto.HashSize) {
			forged = append(forged, sibling)
		}
		_ = Verify(root, leaf, index, total, forged)

		if index < 0 || index >= len(entries) {
			return
		}
		proof, err := tree.Proof(index)
		if err != nil {
			t.Fatalf("Proof(%d) of %d entries: %v", index, len(entries), err)
		}
		if !Verify(root, entries[index], index, len(entries), proof) {
			t.Fatalf("an honest proof for entry %d of %d was rejected", index, len(entries))
		}
		if Verify(root, leaf, index, len(entries), proof) != bytes.Equal(leaf, entries[index]) {
			t.Fatalf("entry %d of %d: %q verified in place of %q", index, len(entries), leaf, entries[index])
		}
	})
}

func BenchmarkNewMerkle(b *testing.B) {
	entries := labelled(1000)
	b.ReportAllocs()
	for b.Loop() {
		_ = NewMerkle(entries)
	}
}

func BenchmarkProof(b *testing.B) {
	tree := NewMerkle(labelled(10000))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := tree.Proof(4321); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	entries := labelled(10000)
	tree := NewMerkle(entries)
	root := tree.Root()
	proof, err := tree.Proof(4321)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if !Verify(root, entries[4321], 4321, len(entries), proof) {
			b.Fatal("an honest proof was rejected")
		}
	}
}
