package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"filippo.io/edwards25519"

	"go-takoo/crypto"
)

// signatureSize is R followed by S, 32 bytes each; stringSignatureSize is the
// same in hex digits.
const (
	signatureSize       int = ed25519.SignatureSize
	stringSignatureSize int = signatureSize * 2
)

// Signature is an Ed25519 signature. Its R is a canonical point in the
// prime-order subgroup and its S is below the group order.
type Signature struct {
	inner [signatureSize]byte
}

// SignatureFromBytes reads a 64-byte signature.
//
// It refuses an S at or above the group order; otherwise anyone could take a
// valid signature, add the order to S, and get a second one that also
// verifies, changing any ID computed over it. It also holds R to the same
// rules as a public key. The cofactorless check in Verify already fails a
// torsioned R, but a cofactored or batch verifier would pass it, so refusing
// it here keeps every kind of verifier in agreement.
func SignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != signatureSize {
		return nil, fmt.Errorf("crypto/ed25519: signature size %d, want %d", len(b), signatureSize)
	}
	if _, err := new(edwards25519.Scalar).SetCanonicalBytes(b[signatureSize/2:]); err != nil {
		return nil, fmt.Errorf("crypto/ed25519: signature's S is not below the group order")
	}
	r := b[:signatureSize/2]
	point, err := new(edwards25519.Point).SetBytes(r)
	switch {
	case err != nil:
		return nil, fmt.Errorf("crypto/ed25519: signature's R is not a point on edwards25519: %v", err)
	case !bytes.Equal(point.Bytes(), r):
		return nil, fmt.Errorf("crypto/ed25519: signature's R is a non-canonical encoding, want the one its own point produces")
	case isSmallOrder(point):
		return nil, fmt.Errorf("crypto/ed25519: signature's R is a small-order point, which no private key owns")
	case !isPrimeOrder(point):
		return nil, fmt.Errorf("crypto/ed25519: signature's R carries a torsion component, so it is not a point any private key derives")
	}

	return &Signature{
		inner: [signatureSize]byte(b),
	}, nil
}

// SignatureFromString parses the 128 hex digits String prints.
func SignatureFromString(s string) (*Signature, error) {
	if len(s) == 0 {
		return nil, fmt.Errorf("crypto/ed25519: empty signature string")
	}
	if len(s) != stringSignatureSize {
		return nil, fmt.Errorf("crypto/ed25519: signature string has %d hex digits, want %d", len(s), signatureSize*2)
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("crypto/ed25519: signature string is not hex: %v", err)
	}

	return SignatureFromBytes(b)
}

// Bytes returns a copy of the signature, safe to modify.
func (sign *Signature) Bytes() []byte {
	return bytes.Clone(sign.inner[:])
}

// Equal reports whether x is the same signature. Signatures are public, so
// a plain comparison does. Signatures from other schemes never are.
func (sign *Signature) Equal(x crypto.Signature) bool {
	xEd25519, ok := x.(*Signature)
	if !ok {
		return false
	}

	return bytes.Equal(sign.inner[:], xEd25519.inner[:])
}

// String returns the signature as 128 lowercase hex digits.
func (sign *Signature) String() string {
	return hex.EncodeToString(sign.inner[:])
}
