// Package hd derives Ed25519 account keys from one seed, so a single backup,
// a BIP-39 mnemonic for instance, brings back every account. It follows
// SLIP-0010, which is what most Ed25519 wallets use:
//
//	master = HMAC-SHA512(key "ed25519 seed", seed)
//	child  = HMAC-SHA512(key chain code, 0x00 || parent key || index)
//
// The first 32 bytes of each result are the node's key and the last 32 its
// chain code. Ed25519 only supports hardened derivation, so you need the
// parent's private key to get a child; there's no deriving public keys from
// a public key.
package hd

import (
	"crypto/fips140"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"go-takoo/crypto"
	"go-takoo/crypto/bech32m"
	"go-takoo/crypto/ed25519"
)

// HardenedKeyStart is 2^31. An index at or above it is hardened and written
// with a ', so "44'" means HardenedKeyStart+44.
//
// The rest are limits on paths and seeds (16 to 64 bytes, as in BIP-32), the
// split of each HMAC result into key and chain code, and the layout String
// writes:
//
//	version (1) | scheme (1) | depth (1) | path (4 per level) | chain code (32) | key (32)
//
// maxExtendedKeyLength is the longest string that layout can produce, so
// oversized input is rejected before decoding.
const (
	HardenedKeyStart uint32 = 0x80000000

	maxDepth      int = 16
	maxPathLength int = 1 + maxDepth*len("/4294967295'")

	minSeedSize int = 16
	maxSeedSize int = 64

	nodeChainCodeSize int = sha512.Size - nodeKeySize
	nodeKeySize       int = sha512.Size / 2

	extendedKeyVersion    byte = 0
	extendedKeyHeaderSize int  = 3

	maxExtendedKeyPayload = extendedKeyHeaderSize + 4*maxDepth + nodeChainCodeSize + nodeKeySize
	maxExtendedKeyLength  = len(crypto.ExtendedPrivateKeyHRP) + 1 + (maxExtendedKeyPayload*8+4)/5 + 6
)

// DerivationPath is the list of indexes from the master key down, all of them
// hardened.
type DerivationPath []uint32

// parsePathElement reads one element like "44'": plain decimal with no
// leading zeros, followed by ', h or H, and below 2^31. Without the mark it
// is rejected, since Ed25519 can't derive unhardened children.
func parsePathElement(e string) (uint32, error) {
	if e == "" {
		return 0, fmt.Errorf("crypto/ed25519/hd: invalid derivation path: empty element")
	}

	digits := e
	hardened := false
	last := e[len(e)-1]
	if last == '\'' || last == 'h' || last == 'H' {
		digits, hardened = e[:len(e)-1], true
	}
	n, err := strconv.ParseUint(digits, 10, 32)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return 0, fmt.Errorf("crypto/ed25519/hd: invalid derivation path: element %q is not a number", e)
	}
	if len(digits) > 1 && digits[0] == '0' {
		return 0, fmt.Errorf("crypto/ed25519/hd: invalid derivation path: element %q has a leading zero", e)
	}
	if !hardened {
		return 0, fmt.Errorf("crypto/ed25519/hd: ed25519 supports only hardened derivation: element %q", e)
	}
	if err != nil || n >= uint64(HardenedKeyStart) {
		return 0, fmt.Errorf("crypto/ed25519/hd: invalid derivation path: element %q is out of range, want below %d'", e, HardenedKeyStart)
	}

	return uint32(n) + HardenedKeyStart, nil
}

// ParseDerivationPath reads a path like "m/44'/1'/0'"; "m" on its own is the
// master key. Length and depth are checked before parsing anything, so a
// huge input is turned away cheaply.
func ParseDerivationPath(s string) (DerivationPath, error) {
	if s == "" {
		return nil, fmt.Errorf("crypto/ed25519/hd: invalid derivation path: empty path")
	}
	if len(s) > maxPathLength {
		return nil, fmt.Errorf("crypto/ed25519/hd: invalid derivation path: %d bytes, want at most %d", len(s), maxPathLength)
	}

	head, rest, more := strings.Cut(s, "/")
	if head != "m" {
		return nil, fmt.Errorf("crypto/ed25519/hd: invalid derivation path: must start with \"m\"")
	}
	if !more {
		return nil, nil
	}

	depth := strings.Count(rest, "/") + 1
	if depth > maxDepth {
		return nil, fmt.Errorf("crypto/ed25519/hd: derivation is deeper than %d levels: %d levels", maxDepth, depth)
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

// String prints the path the way ParseDerivationPath reads it, with ' on
// hardened indexes.
func (p DerivationPath) String() string {
	out := append(make([]byte, 0, 1+len(p)*len("/4294967295'")), 'm')
	for _, index := range p {
		out = append(out, '/')
		if index >= HardenedKeyStart {
			out = strconv.AppendUint(out, uint64(index-HardenedKeyStart), 10)
			out = append(out, '\'')
			continue
		}
		out = strconv.AppendUint(out, uint64(index), 10)
	}

	return string(out)
}

// ExtendedKey is one node in the tree: its key, its chain code and the path
// that led to it. Key and chain code are arrays, so copying an ExtendedKey
// really copies them instead of sharing memory.
type ExtendedKey struct {
	key       [nodeKeySize]byte
	chainCode [nodeChainCodeSize]byte
	path      DerivationPath
}

// NewMasterKey derives the master key from a 16 to 64 byte seed, as SLIP-0010
// says, with HMAC-SHA512 keyed by "ed25519 seed".
//
// It doesn't work under GODEBUG=fips140=only: FIPS mode won't take an HMAC
// key shorter than 112 bits, and "ed25519 seed" is only 96.
func NewMasterKey(seed []byte) (ExtendedKey, error) {
	if fips140.Enforced() {
		return ExtendedKey{}, fmt.Errorf("crypto/ed25519/hd: master key derivation is unavailable under GODEBUG=fips140=only")
	}
	if len(seed) < minSeedSize || len(seed) > maxSeedSize {
		return ExtendedKey{}, fmt.Errorf("crypto/ed25519/hd: seed must be %d to %d bytes: got %d", minSeedSize, maxSeedSize, len(seed))
	}

	masterKeySalt := []byte("ed25519 seed")
	hmac := hmac.New(sha512.New, masterKeySalt)
	_, _ = hmac.Write(seed)
	i := hmac.Sum(nil)

	var k ExtendedKey
	_ = copy(k.key[:], i[:nodeKeySize])
	_ = copy(k.chainCode[:], i[nodeKeySize:])

	return k, nil
}

// ExtendedKeyFromString parses what String prints. It checks everything it
// can: the length before decoding, then the "xprv" prefix, the version, the
// scheme, the depth, that the size matches the depth, that every index is
// hardened, and that neither key nor chain code is all zeros.
func ExtendedKeyFromString(s string) (ExtendedKey, error) {
	if s == "" {
		return ExtendedKey{}, fmt.Errorf("crypto/ed25519/hd: empty extended key string")
	}
	l := len(s)
	if l > maxExtendedKeyLength {
		return ExtendedKey{}, fmt.Errorf("crypto/ed25519/hd: invalid extended key: %d bytes, want at most %d", l, maxExtendedKeyLength)
	}

	hrp, b, err := bech32m.DecodeToBase256NoLimit(s)
	if err != nil {
		return ExtendedKey{}, fmt.Errorf("crypto/ed25519/hd: invalid extended key: %w", err)
	}
	if hrp != crypto.ExtendedPrivateKeyHRP {
		return ExtendedKey{}, fmt.Errorf("crypto/ed25519/hd: invalid extended key: prefix %q, want %q", hrp, crypto.ExtendedPrivateKeyHRP)
	}
	l = len(b)
	if l < extendedKeyHeaderSize {
		return ExtendedKey{}, fmt.Errorf("crypto/ed25519/hd: invalid extended key: payload is %d bytes, want at least %d", l, extendedKeyHeaderSize)
	}
	if b[0] != extendedKeyVersion {
		return ExtendedKey{}, fmt.Errorf("crypto/ed25519/hd: invalid extended key: version %d, want %d", b[0], extendedKeyVersion)
	}
	if crypto.Scheme(b[1]) != crypto.SchemeEd25519 {
		return ExtendedKey{}, fmt.Errorf("crypto/ed25519/hd: invalid extended key: scheme %d, want %d", b[1], crypto.SchemeEd25519)
	}

	depth := int(b[2])
	if depth > maxDepth {
		return ExtendedKey{}, fmt.Errorf("crypto/ed25519/hd: invalid extended key: depth %d, want at most %d", depth, maxDepth)
	}

	want := extendedKeyHeaderSize + depth*4 + nodeChainCodeSize + nodeKeySize
	if l != want {
		return ExtendedKey{}, fmt.Errorf("crypto/ed25519/hd: invalid extended key: payload is %d bytes, want %d for depth %d", l, want, depth)
	}

	path := make(DerivationPath, depth)
	for i := range path {
		path[i] = binary.BigEndian.Uint32(b[extendedKeyHeaderSize+4*i:])
		if path[i] < HardenedKeyStart {
			return ExtendedKey{}, fmt.Errorf("crypto/ed25519/hd: invalid extended key: child index %d is not hardened", path[i])
		}
	}

	k := ExtendedKey{path: path}
	material := b[extendedKeyHeaderSize+4*depth:]
	_ = copy(k.chainCode[:], material[:nodeChainCodeSize])
	_ = copy(k.key[:], material[nodeChainCodeSize:])
	if k.key == [nodeKeySize]byte{} || k.chainCode == [nodeChainCodeSize]byte{} {
		return ExtendedKey{}, fmt.Errorf("crypto/ed25519/hd: invalid extended key: all-zero material")
	}

	return k, nil
}

// Derive returns the child at index, which has to be hardened. Secret buffers
// are wiped along the way.
func (k *ExtendedKey) Derive(index uint32) (*ExtendedKey, error) {
	if index < HardenedKeyStart {
		return nil, fmt.Errorf("crypto/ed25519/hd: ed25519 supports only hardened derivation: child index %d", index)
	}
	if len(k.path) >= maxDepth {
		return nil, fmt.Errorf("crypto/ed25519/hd: derivation is deeper than %d levels: %d levels", maxDepth, len(k.path)+1)
	}

	var data [1 + nodeKeySize + 4]byte
	_ = copy(data[1:1+nodeKeySize], k.key[:])
	binary.BigEndian.PutUint32(data[1+nodeKeySize:], index)

	hmac := hmac.New(sha512.New, k.chainCode[:])
	_, _ = hmac.Write(data[:])
	clear(data[:])
	i := hmac.Sum(nil)
	defer clear(i)

	child := &ExtendedKey{path: make(DerivationPath, len(k.path)+1)}
	_ = copy(child.key[:], i[:nodeKeySize])
	_ = copy(child.chainCode[:], i[nodeKeySize:])
	_ = copy(child.path, k.path)
	child.path[len(k.path)] = index

	return child, nil
}

// DerivePath walks path one index at a time and returns where it ends up,
// wiping the nodes in between. k itself never changes; an empty path gives
// back a copy. The whole path is checked before any work starts.
func (k *ExtendedKey) DerivePath(path DerivationPath) (*ExtendedKey, error) {
	depth := len(k.path) + len(path)
	if depth > maxDepth {
		return nil, fmt.Errorf("crypto/ed25519/hd: derivation is deeper than %d levels: %d levels", maxDepth, depth)
	}
	for _, index := range path {
		if index < HardenedKeyStart {
			return nil, fmt.Errorf("crypto/ed25519/hd: ed25519 supports only hardened derivation: child index %d", index)
		}
	}
	if len(path) == 0 {
		return &ExtendedKey{key: k.key, chainCode: k.chainCode, path: slices.Clone(k.path)}, nil
	}

	node := k
	for _, index := range path {
		child, err := node.Derive(index)
		if err != nil {
			return nil, err
		}
		if node != k {
			clear(node.key[:])
			clear(node.chainCode[:])
		}
		node = child
	}

	return node, nil
}

// Format makes fmt print a redacted placeholder whatever the verb, so neither
// key nor chain code can end up in a log. Call String when you really mean
// to export it.
//
// fmt can't call Format on a value held in an unexported struct field; it
// reflects into it and prints the arrays. Key and chain code stay arrays
// anyway, so a copy never shares memory with the original; hold an
// ExtendedKey by pointer, or in an exported field, if it might get printed.
func (ExtendedKey) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "hd.ExtendedKey(REDACTED)")
}

// Path returns a copy of the node's path, safe to modify.
func (k *ExtendedKey) Path() DerivationPath {
	return slices.Clone(k.path)
}

// PrivateKey returns the account key for this node.
func (k *ExtendedKey) PrivateKey() (*ed25519.PrivateKey, error) {
	return ed25519.PrivateKeyFromBytes(k.key[:])
}

// String exports the node as Bech32m with the "xprv" prefix, in the layout
// described above. It runs past Bech32m's usual 90-character limit, hence the
// no-limit encoder, and it isn't the same format as BIP-32's xprv. Anyone
// with this string can derive every account below this node.
func (k *ExtendedKey) String() string {
	buf := make([]byte, extendedKeyHeaderSize+len(k.path)*4+nodeChainCodeSize+nodeKeySize)
	buf[0] = extendedKeyVersion
	buf[1] = byte(crypto.SchemeEd25519)
	buf[2] = byte(len(k.path))

	offset := extendedKeyHeaderSize
	for _, index := range k.path {
		binary.BigEndian.PutUint32(buf[offset:], index)
		offset += 4
	}

	offset += copy(buf[offset:], k.chainCode[:])

	_ = copy(buf[offset:], k.key[:])

	s, _ := bech32m.EncodeFromBase256NoLimit(crypto.ExtendedPrivateKeyHRP, buf)

	return s
}
