// Package hd derives a validator's BLS keys from one seed, so a single backup
// can bring back every key an operator has used. It follows Ethereum:
// EIP-2333 for how keys are derived and EIP-2334 for paths like
// "m/12381/1/0/0/0".
//
// This works differently from BIP-32 or SLIP-0010. There is no chain code; a
// child comes straight from its parent's private key and the index. Every
// step is hardened by nature, so paths don't use the ' mark and there is no
// public derivation. And each step goes through a Lamport key, which keeps
// the door open for a post-quantum backup signature later.
//
// Nodes have no serialized form. Keep the seed and the path.
package hd

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"go-takoo/crypto/bls12381"
)

// Limits on the seed and the path, plus EIP-2333's Lamport sizes. The spec
// wants at least 32 bytes of seed; 64 is our cap, the size of a BIP-39 seed.
// The depth and length caps keep a hostile path from costing much. A Lamport
// key is 255 chunks of 32 bytes.
const (
	minSeedSize   = 32
	maxSeedSize   = 64
	maxDepth      = 16
	maxPathLength = 1 + maxDepth*len("/4294967295")
	lamportK      = 32
	lamportL      = 255 * lamportK
)

// DerivationPath is the list of indexes from the master key down. Any uint32
// is fine, and since every step is hardened anyway, the text form has no '
// marks.
type DerivationPath []uint32

// parsePathElement reads one index: plain decimal, no leading zeros, below
// 2^32. A ' or h suffix is rejected because EIP-2334 doesn't use one.
func parsePathElement(e string) (uint32, error) {
	if e == "" {
		return 0, fmt.Errorf("crypto/bls12381/hd: bad path element %q", e)
	}
	if last := e[len(e)-1]; last == '\'' || last == 'h' {
		return 0, fmt.Errorf("crypto/bls12381/hd: path element %q carries a hardened mark, which EIP-2334 does not use (every step is hardened already)", e)
	}

	n, err := strconv.ParseUint(e, 10, 32)
	if err != nil {
		if errors.Is(err, strconv.ErrRange) {
			return 0, fmt.Errorf("crypto/bls12381/hd: path element %q out of range, want < 2^32", e)
		}
		return 0, fmt.Errorf("crypto/bls12381/hd: bad path element %q", e)
	}
	if len(e) > 1 && e[0] == '0' {
		return 0, fmt.Errorf("crypto/bls12381/hd: path element %q has a leading zero, want its canonical spelling", e)
	}

	return uint32(n), nil
}

// ParseDerivationPath reads a path like "m/12381/1/0/0/0"; "m" on its own is
// the master key. Length and depth are checked before parsing anything, so a
// huge input is turned away cheaply.
func ParseDerivationPath(s string) (DerivationPath, error) {
	if s == "" {
		return nil, fmt.Errorf("crypto/bls12381/hd: empty derivation path")
	}
	if len(s) > maxPathLength {
		return nil, fmt.Errorf("crypto/bls12381/hd: derivation path is %d bytes, want at most %d", len(s), maxPathLength)
	}

	head, rest, more := strings.Cut(s, "/")
	if head != "m" {
		return nil, fmt.Errorf("crypto/bls12381/hd: derivation path must start with \"m\"")
	}
	if !more {
		return nil, nil
	}

	depth := strings.Count(rest, "/") + 1
	if depth > maxDepth {
		return nil, fmt.Errorf("crypto/bls12381/hd: derivation depth %d exceeds %d", depth, maxDepth)
	}

	path := make(DerivationPath, 0, depth)
	for {
		var e string
		e, rest, more = strings.Cut(rest, "/")
		index, err := parsePathElement(e)
		if err != nil {
			return nil, err
		}
		path = append(path, index)
		if !more {
			return path, nil
		}
	}
}

// String prints the path the way ParseDerivationPath reads it.
func (p DerivationPath) String() string {
	out := append(make([]byte, 0, 1+len(p)*len("/4294967295")), 'm')
	for _, index := range p {
		out = append(out, '/')
		out = strconv.AppendUint(out, uint64(index), 10)
	}

	return string(out)
}

// DerivedKey is one node in the tree: a private key and the path that led to
// it. There's no chain code because EIP-2333 doesn't have one.
type DerivedKey struct {
	key  *bls12381.PrivateKey
	path DerivationPath
}

// NewMasterKey derives the master key from a 32 to 64 byte seed, using
// EIP-2333's derive_master_SK, which is just KeyGen.
func NewMasterKey(seed []byte) (*DerivedKey, error) {
	if len(seed) < minSeedSize || len(seed) > maxSeedSize {
		return nil, fmt.Errorf("crypto/bls12381/hd: seed must be %d to %d bytes: got %d", minSeedSize, maxSeedSize, len(seed))
	}

	key, err := bls12381.PrivateKeyFromSeed(seed)
	if err != nil {
		return nil, err
	}

	return &DerivedKey{key: key}, nil
}

// Derive returns the child at index, following EIP-2333's derive_child_SK.
// The parent key and its bitwise complement are each stretched with HKDF into
// a Lamport key of 255 chunks, salted with the index. Every chunk is hashed,
// all those hashes are hashed together into compressed_lamport_PK, and
// KeyGen turns that into the child key.
//
// You can't get the child without the parent's private key.
func (k *DerivedKey) Derive(index uint32) (*DerivedKey, error) {
	if len(k.path) >= maxDepth {
		return nil, fmt.Errorf("crypto/bls12381/hd: derivation depth %d exceeds %d", len(k.path)+1, maxDepth)
	}

	var salt [4]byte
	binary.BigEndian.PutUint32(salt[:], index)
	ikm := k.key.Bytes()
	notIKM := make([]byte, len(ikm))
	for i, b := range ikm {
		notIKM[i] = ^b
	}

	lamportPK := sha256.New()
	for _, lamportIKM := range [][]byte{ikm, notIKM} {
		prk, err := hkdf.Extract(sha256.New, lamportIKM, salt[:])
		if err != nil {
			return nil, fmt.Errorf("crypto/bls12381/hd: HKDF failed: %v", err)
		}
		okm, err := hkdf.Expand(sha256.New, prk, "", lamportL)
		if err != nil {
			return nil, fmt.Errorf("crypto/bls12381/hd: HKDF failed: %v", err)
		}
		for i := 0; i < len(okm); i += lamportK {
			digest := sha256.Sum256(okm[i : i+lamportK])
			_, _ = lamportPK.Write(digest[:])
		}
	}

	var compressedLamportPK [32]byte
	_ = lamportPK.Sum(compressedLamportPK[:0])
	childSK, err := bls12381.PrivateKeyFromSeed(compressedLamportPK[:])
	if err != nil {
		return nil, err
	}

	return &DerivedKey{key: childSK, path: append(slices.Clip(k.path), index)}, nil
}

// DerivePath walks path one index at a time, starting from a copy of k, so k
// itself never changes. An empty path just returns the copy. The total depth
// is checked up front.
func (k *DerivedKey) DerivePath(path DerivationPath) (*DerivedKey, error) {
	if depth := len(k.path) + len(path); depth > maxDepth {
		return nil, fmt.Errorf("crypto/bls12381/hd: derivation depth %d exceeds %d", depth, maxDepth)
	}

	key, err := k.PrivateKey()
	if err != nil {
		return nil, err
	}

	out := &DerivedKey{key: key, path: k.Path()}
	for _, index := range path {
		if out, err = out.Derive(index); err != nil {
			return nil, err
		}
	}

	return out, nil
}

// Format makes fmt print a redacted placeholder whatever the verb, so the key
// can't end up in a log.
func (DerivedKey) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "hd.DerivedKey(REDACTED)")
}

// Path returns a copy of the node's path, safe to modify.
func (k *DerivedKey) Path() DerivationPath {
	return slices.Clone(k.path)
}

// PrivateKey returns a copy of the node's key that's independent of k.
func (k *DerivedKey) PrivateKey() (*bls12381.PrivateKey, error) {
	return bls12381.PrivateKeyFromBytes(k.key.Bytes())
}
