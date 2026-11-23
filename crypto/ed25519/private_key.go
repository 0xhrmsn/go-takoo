// Package ed25519 provides the account keys for package crypto, using
// Ed25519 from RFC 8032.
//
// RFC 8032 leaves a few edge cases up to the implementation, and on a chain
// that is dangerous: if two nodes disagree about a single signature, the
// chain forks. So this package is strict about what it accepts. A public key
// has to be the canonical encoding of a point in the prime-order subgroup, a
// signature's R has to be one too, and its S has to be below the group
// order. Verification itself is the standard library's cofactorless check.
package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"

	"go-takoo/crypto"
	"go-takoo/crypto/bech32m"
)

const (
	// privateKeySize is the standard library's 64-byte form: the seed followed
	// by the public key. Only the 32-byte seed is secret, so that's all we
	// export.
	privateKeySize int = ed25519.PrivateKeySize

	seedSize int = ed25519.SeedSize

	// stringPrivateKeySize is the length of String's form: "prv", the separator,
	// the scheme character, 52 characters of seed and 6 of checksum.
	stringPrivateKeySize int = len(crypto.PrivateKeyHRP) + 2 + (seedSize*8+4)/5 + 6
)

// PrivateKey is an account's signing key. It stays in the standard library's
// 64-byte form so signing doesn't have to recompute the public key.
//
// The bytes sit behind a pointer on purpose. fmt can't call Format on a value
// in an unexported struct field and reflects into it instead; with a pointer
// it finds an address there, not the seed.
type PrivateKey struct {
	inner *[privateKeySize]byte
}

// PrivateKeyFromBytes builds a key from its 32-byte seed. Any 32 bytes make a
// valid seed, so the only possible error is the wrong length.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != seedSize {
		return nil, fmt.Errorf("crypto/ed25519: private key size %d, want %d", len(b), seedSize)
	}

	return &PrivateKey{
		inner: (*[privateKeySize]byte)(ed25519.NewKeyFromSeed(b)),
	}, nil
}

// PrivateKeyFromString parses what String prints: Bech32m with the "prv"
// prefix, the scheme as the first character after the separator, then the
// seed. Its exact length is checked before decoding, and a key string of
// another scheme is refused.
func PrivateKeyFromString(s string) (*PrivateKey, error) {
	if len(s) != stringPrivateKeySize {
		return nil, fmt.Errorf("crypto/ed25519: private key string has %d characters, want %d", len(s), stringPrivateKeySize)
	}

	hrp, typ, b, err := bech32m.DecodeToBase256WithType(s)
	if err != nil {
		return nil, fmt.Errorf("crypto/ed25519: private key string is not bech32m: %v", err)
	}
	if hrp != crypto.PrivateKeyHRP {
		return nil, fmt.Errorf("crypto/ed25519: private key string has prefix %q, want %q", hrp, crypto.PrivateKeyHRP)
	}
	if crypto.Scheme(typ) != crypto.SchemeEd25519 {
		return nil, fmt.Errorf("crypto/ed25519: private key string is for scheme %s, want %s", crypto.Scheme(typ), crypto.SchemeEd25519)
	}

	return PrivateKeyFromBytes(b)
}

// Bytes returns a copy of the seed. That's the secret.
func (prv *PrivateKey) Bytes() []byte {
	return bytes.Clone(prv.inner[:seedSize])
}

// Equal reports whether x is the same key. The comparison runs in constant
// time, and a key from another scheme is never equal.
func (prv *PrivateKey) Equal(x crypto.PrivateKey) bool {
	xEd25519, ok := x.(*PrivateKey)
	if !ok {
		return false
	}

	return ed25519.PrivateKey(prv.inner[:]).Equal(ed25519.PrivateKey(xEd25519.inner[:]))
}

// Format makes fmt print a redacted placeholder whatever the verb, so the
// secret can't slip into a log. Call String when you really mean to export
// it.
func (PrivateKey) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "ed25519.PrivateKey(REDACTED)")
}

// Public returns the public key that goes with this key.
func (prv *PrivateKey) Public() crypto.PublicKey {
	return &PublicKey{
		inner: [publicKeySize]byte(prv.inner[seedSize:]),
	}
}

// Sign signs msg the RFC 8032 way. It's deterministic: the same key and
// message always give the same signature, so there is no random nonce that
// could leak the key. The error is always nil; it's there so a key that
// lives somewhere else, like a hardware signer, can report a failure.
func (prv *PrivateKey) Sign(msg []byte) (crypto.Signature, error) {
	return &Signature{
		inner: [signatureSize]byte(ed25519.Sign(prv.inner[:], msg)),
	}, nil
}

// String exports the seed as Bech32m with the "prv" prefix, the scheme
// showing as "p", the first character after the separator. Whoever has this
// string controls the account.
func (prv *PrivateKey) String() string {
	s, _ := bech32m.EncodeFromBase256WithType(crypto.PrivateKeyHRP, byte(crypto.SchemeEd25519), prv.inner[:seedSize])

	return s
}
