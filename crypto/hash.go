package crypto

import (
	"bytes"
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// HashSize is the length of a SHA3-256 digest. The other two are for the hex
// text form.
const (
	HashSize    int    = 32
	hexHashSize int    = HashSize * 2
	hashPrefix  string = "0x"
)

// Hash is a SHA3-256 digest: the standard SHA3 from FIPS 202, not the
// Keccak-256 Ethereum uses. Transaction and block IDs, merkle roots and
// addresses are all one of these.
//
// It works as a map key and compares with ==. The zero value means unset.
type Hash [HashSize]byte

// MultiHash256 hashes the pieces as if they were one buffer, without
// allocating the concatenation.
//
// Where one piece ends and the next begins is not part of the hash: ("ab",
// "c") and ("a", "bc") come out the same. Callers have to keep the split
// unambiguous themselves, with fixed sizes or a leading tag, the way Address
// and merkle do.
func MultiHash256(data ...[]byte) Hash {
	hasher := sha3.New256()
	for _, b := range data {
		_, _ = hasher.Write(b)
	}

	var h Hash
	_ = hasher.Sum(h[:0])

	return h
}

// Hash256 returns the SHA3-256 of data.
func Hash256(data []byte) Hash {
	return sha3.Sum256(data)
}

// HashFromBytes turns 32 raw bytes into a Hash; any other length is an error.
func HashFromBytes(b []byte) (Hash, error) {
	var h Hash
	err := h.SetBytes(b)
	if err != nil {
		return Hash{}, err
	}

	return h, nil
}

// HashFromString parses 64 hex digits, upper or lower case, with or without
// a leading "0x".
func HashFromString(s string) (Hash, error) {
	if len(s) == 0 {
		return Hash{}, fmt.Errorf("crypto: hash string is empty")
	}

	// Length first: s[:2] on a one-character string would panic.
	if len(s) >= 2 && strings.EqualFold(s[:2], hashPrefix) {
		s = s[2:]
	}
	if len(s) != hexHashSize {
		return Hash{}, fmt.Errorf("crypto: hash string length %d, want %d", len(s), hexHashSize)
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return Hash{}, err
	}

	return HashFromBytes(b)
}

// Bytes returns a copy of the digest, safe to modify.
func (h Hash) Bytes() []byte {
	return bytes.Clone(h[:])
}

// Empty reports whether h is unset.
func (h Hash) Empty() bool {
	return h.Equal(Hash{})
}

// Equal reports whether h and other are the same digest.
func (h Hash) Equal(other Hash) bool {
	return bytes.Equal(h[:], other[:])
}

// String returns "0x" followed by the digest in lowercase hex.
func (h Hash) String() string {
	return hashPrefix + hex.EncodeToString(h[:])
}

// Format lets fmt print plain hex, without "0x", with %x or %X, and String
// with %s, %v and %q.
func (h Hash) Format(state fmt.State, verb rune) {
	switch verb {
	case 'x':
		_, _ = io.WriteString(state, hex.EncodeToString(h[:]))
	case 'X':
		_, _ = io.WriteString(state, strings.ToUpper(hex.EncodeToString(h[:])))
	case 's', 'v', 'q':
		text := h.String()
		if verb == 'q' {
			text = `"` + text + `"`
		}
		_, _ = io.WriteString(state, text)
	default:
		_, _ = fmt.Fprintf(state, "%%!%c(crypto.Hash=%s)", verb, h.String())
	}
}

// MarshalText makes JSON and other text encodings use the "0x" hex form.
func (h Hash) MarshalText() ([]byte, error) {
	return []byte(h.String()), nil
}

// UnmarshalText accepts anything HashFromString does. If it fails, h is left
// as it was.
func (h *Hash) UnmarshalText(text []byte) error {
	parsed, err := HashFromString(string(text))
	if err != nil {
		return err
	}
	*h = parsed

	return nil
}

// SetBytes copies b into h, but only if b is exactly HashSize bytes long;
// otherwise h stays as it was.
func (h *Hash) SetBytes(b []byte) error {
	l := len(b)
	if l != HashSize {
		return fmt.Errorf("crypto: hash length %d, want %d", l, HashSize)
	}
	_ = copy(h[:], b)

	return nil
}
