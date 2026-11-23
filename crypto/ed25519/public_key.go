package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"filippo.io/edwards25519"

	"go-takoo/crypto"
	"go-takoo/crypto/bech32m"
)

const (
	// publicKeySize is a compressed point: y, with the sign of x in the top bit.
	publicKeySize int = ed25519.PublicKeySize

	// stringPublicKeySize is the length of String's form: "pub", the separator,
	// the scheme character, 52 characters of key and 6 of checksum.
	stringPublicKeySize int = len(crypto.PublicKeyHRP) + 2 + (publicKeySize*8+4)/5 + 6
)

// Values the subgroup checks need, computed once at startup.
var (
	identity = edwards25519.NewIdentityPoint()
	inv8     = inverseOfCofactor()
	zero     = edwards25519.NewScalar()
)

// PublicKey is an account's public key. The only ways to get one are
// PublicKeyFromBytes and PrivateKey.Public, so it has always passed the
// checks. A fixed-size array, so the key compares with == and works as a map
// key.
type PublicKey struct {
	inner [publicKeySize]byte
}

// inverseOfCofactor returns 1/8 modulo the group order, for isPrimeOrder. 8
// is always a valid scalar, so the panic can't actually happen.
func inverseOfCofactor() *edwards25519.Scalar {
	cofactor := [32]byte{8}
	s, err := new(edwards25519.Scalar).SetCanonicalBytes(cofactor[:])
	if err != nil {
		panic("crypto/ed25519: 8 is not a canonical scalar: " + err.Error())
	}

	return new(edwards25519.Scalar).Invert(s)
}

// isPrimeOrder reports whether p lies in the prime-order subgroup.
// Multiplying by 8 and then by 1/8 gives p back only when p has no torsion
// component.
func isPrimeOrder(p *edwards25519.Point) bool {
	cleared := new(edwards25519.Point).MultByCofactor(p)

	return new(edwards25519.Point).VarTimeDoubleScalarBaseMult(inv8, cleared, zero).Equal(p) == 1
}

// isSmallOrder reports whether p is one of the eight low-order points, the
// ones that multiplying by 8 sends to the identity. No private key maps to
// them, and a signature under one can verify for many messages.
func isSmallOrder(p *edwards25519.Point) bool {
	return new(edwards25519.Point).MultByCofactor(p).Equal(identity) == 1
}

// PublicKeyFromBytes reads a 32-byte public key and accepts it only if some
// private key could actually have produced it.
//
// Besides the obvious length and on-curve checks, it rejects a non-canonical
// encoding, because two encodings of one point would give one key two
// addresses. It rejects small-order points, which nobody owns. And it rejects
// points with a torsion component, because nodes that verify with and
// without the cofactor could disagree about them.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != publicKeySize {
		return nil, fmt.Errorf("crypto/ed25519: public key size %d, want %d", len(b), publicKeySize)
	}

	point, err := new(edwards25519.Point).SetBytes(b)
	switch {
	case err != nil:
		return nil, fmt.Errorf("crypto/ed25519: public key is not a point on edwards25519: %v", err)
	case !bytes.Equal(point.Bytes(), b):
		return nil, fmt.Errorf("crypto/ed25519: public key is a non-canonical encoding, want the one its own point produces")
	case isSmallOrder(point):
		return nil, fmt.Errorf("crypto/ed25519: public key is a small-order point, which no private key owns")
	case !isPrimeOrder(point):
		return nil, fmt.Errorf("crypto/ed25519: public key carries a torsion component, so it is not a point any private key derives")
	}

	return &PublicKey{
		inner: [publicKeySize]byte(b),
	}, nil
}

// PublicKeyFromString parses what String prints ("pub" in Bech32m, the scheme
// as the first character after the separator) and runs the same checks as
// PublicKeyFromBytes. Its exact length is checked before decoding, and a key
// string of another scheme is refused.
func PublicKeyFromString(s string) (*PublicKey, error) {
	if len(s) != stringPublicKeySize {
		return nil, fmt.Errorf("crypto/ed25519: public key string has %d characters, want %d", len(s), stringPublicKeySize)
	}

	hrp, typ, b, err := bech32m.DecodeToBase256WithType(s)
	if err != nil {
		return nil, fmt.Errorf("crypto/ed25519: public key string is not bech32m: %v", err)
	}
	if hrp != crypto.PublicKeyHRP {
		return nil, fmt.Errorf("crypto/ed25519: public key string has prefix %q, want %q", hrp, crypto.PublicKeyHRP)
	}
	if crypto.Scheme(typ) != crypto.SchemeEd25519 {
		return nil, fmt.Errorf("crypto/ed25519: public key string is for scheme %s, want %s", crypto.Scheme(typ), crypto.SchemeEd25519)
	}

	return PublicKeyFromBytes(b)
}

// Address returns the address of the account this key controls: SHA3-256 of
// the scheme byte 0x01 followed by the key.
func (pub *PublicKey) Address() crypto.Address {
	return crypto.Address(crypto.MultiHash256([]byte{byte(pub.Scheme())}, pub.inner[:]))
}

// Bytes returns a copy of the key, safe to modify.
func (pub *PublicKey) Bytes() []byte {
	return bytes.Clone(pub.inner[:])
}

// Equal reports whether x is the same key. Keys from other schemes never are.
func (pub *PublicKey) Equal(x crypto.PublicKey) bool {
	xEd25519, ok := x.(*PublicKey)
	if !ok {
		return false
	}

	return pub.inner == xEd25519.inner
}

// Scheme returns SchemeEd25519.
func (pub PublicKey) Scheme() crypto.Scheme {
	return crypto.SchemeEd25519
}

// String returns the key in Bech32m with the "pub" prefix, the scheme showing
// as "p", the first character after the separator.
func (pub *PublicKey) String() string {
	s, _ := bech32m.EncodeFromBase256WithType(crypto.PublicKeyHRP, byte(crypto.SchemeEd25519), pub.inner[:])

	return s
}

// Verify reports whether sign is this key's signature on msg, using the
// standard library's cofactorless check. Keys and signatures were already
// vetted when they were parsed, so every node reaches the same answer. A
// signature from another scheme is simply false.
func (pub *PublicKey) Verify(msg []byte, sign crypto.Signature) bool {
	xEd25519, ok := sign.(*Signature)
	if !ok {
		return false
	}

	return ed25519.Verify(pub.inner[:], msg, xEd25519.inner[:])
}
