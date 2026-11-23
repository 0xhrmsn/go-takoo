package bls12381

import (
	"bytes"
	"encoding/hex"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"go-takoo/crypto"
)

// signatureSize is a compressed G1 point, 48 bytes; stringSignatureSize is
// that in hex digits.
const (
	signatureSize       int = bls12381.SizeOfG1AffineCompressed
	stringSignatureSize int = signatureSize * 2
)

// The domain tags of the IETF proof-of-possession ciphersuite for the
// minimal-signature-size variant, where messages are hashed to G1. Votes are
// hashed under dstSignature and possession proofs under dstPop, so neither
// can be used as the other. They are part of consensus and can't change.
var (
	dstSignature = []byte("BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_")
	dstPop       = []byte("BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_")
)

// Signature is a BLS signature, a point in G1, kept both encoded and decoded.
type Signature struct {
	inner [signatureSize]byte
	point bls12381.G1Affine
}

// AggregateSignature adds signatures into one. The result can be the point at
// infinity; that isn't an error, but it won't verify against any real key.
// An empty list or a nil element is an error.
func AggregateSignature(signs []*Signature) (*Signature, error) {
	if len(signs) == 0 {
		return nil, fmt.Errorf("crypto/bls12381: nothing to aggregate")
	}

	var sum bls12381.G1Jac
	for i, sign := range signs {
		if sign == nil {
			return nil, fmt.Errorf("crypto/bls12381: element %d is nil", i)
		}
		_ = sum.AddMixed(&sign.point)
	}

	var point bls12381.G1Affine
	_ = point.FromJacobian(&sum)

	return &Signature{
		inner: point.Bytes(),
		point: point,
	}, nil
}

// SignatureFromBytes reads a 48-byte signature. gnark-crypto rejects bad
// encodings and points outside G1. The point at infinity is allowed, as the
// IETF draft says, but it never verifies.
func SignatureFromBytes(b []byte) (*Signature, error) {
	if len(b) != signatureSize {
		return nil, fmt.Errorf("crypto/bls12381: signature size %d, want %d", len(b), signatureSize)
	}

	var point bls12381.G1Affine
	if _, err := point.SetBytes(b); err != nil {
		return nil, fmt.Errorf("crypto/bls12381: signature is not a point in G1: %v", err)
	}

	return &Signature{
		inner: [signatureSize]byte(b),
		point: point,
	}, nil
}

// SignatureFromString parses the 96 hex digits String prints.
func SignatureFromString(s string) (*Signature, error) {
	if len(s) == 0 {
		return nil, fmt.Errorf("crypto/bls12381: empty signature string")
	}
	if len(s) != stringSignatureSize {
		return nil, fmt.Errorf("crypto/bls12381: signature string has %d hex digits, want %d", len(s), stringSignatureSize)
	}

	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("crypto/bls12381: signature string is not hex: %v", err)
	}

	return SignatureFromBytes(b)
}

// Aggregate is AggregateSignature with sign first in the list. Every other
// element has to be a BLS12-381 signature too.
func (sign *Signature) Aggregate(others []crypto.AggregateSignature) (crypto.AggregateSignature, error) {
	signs := append(make([]*Signature, 0, len(others)+1), sign)
	for i, x := range others {
		xBls, ok := x.(*Signature)
		if !ok {
			return nil, fmt.Errorf("crypto/bls12381: element %d is not a BLS12-381 signature", i+1)
		}
		signs = append(signs, xBls)
	}

	aggregate, err := AggregateSignature(signs)
	if err != nil {
		return nil, err
	}

	return aggregate, nil
}

// Bytes returns a copy of the 48-byte signature, safe to modify.
func (sign *Signature) Bytes() []byte {
	return bytes.Clone(sign.inner[:])
}

// Equal reports whether x is the same signature. Signatures from other
// schemes never are.
func (sign *Signature) Equal(x crypto.AggregateSignature) bool {
	xBls12381, ok := x.(*Signature)
	if !ok {
		return false
	}

	return bytes.Equal(sign.inner[:], xBls12381.inner[:])
}

// String returns the signature as 96 lowercase hex digits.
func (sign *Signature) String() string {
	return hex.EncodeToString(sign.inner[:])
}
