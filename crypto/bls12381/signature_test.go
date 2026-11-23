package bls12381

import (
	"bytes"
	"strings"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

func TestSignatureRoundTripsAndEqual(t *testing.T) {
	priv := mustKey(t)
	sign := mustSign(t, priv, []byte("hex me"))

	s := sign.String()
	if len(s) != stringSignatureSize {
		t.Errorf("signature string is %d digits, want %d", len(s), stringSignatureSize)
	}
	back, err := SignatureFromString(s)
	if err != nil {
		t.Fatalf("SignatureFromString: %v", err)
	}
	if !back.Equal(sign) {
		t.Error("a signature did not survive its string round trip")
	}
	fromBytes, err := SignatureFromBytes(sign.Bytes())
	if err != nil || !fromBytes.Equal(sign) {
		t.Errorf("a signature did not survive its byte round trip: %v", err)
	}
	if sign.Equal(mustSign(t, priv, []byte("other"))) || sign.Equal(nil) {
		t.Error("a signature compared equal to another or to nil")
	}

	for _, bad := range []string{"", "zz", strings.Repeat("z", stringSignatureSize)} {
		if _, err := SignatureFromString(bad); err == nil {
			t.Errorf("SignatureFromString(%.8q) was accepted", bad)
		}
	}
	for _, size := range []int{0, 47, 49, 96} {
		if _, err := SignatureFromBytes(make([]byte, size)); err == nil {
			t.Errorf("SignatureFromBytes(%d bytes) was accepted", size)
		}
	}
}

// TestInfinitySignatureParsesButNeverVerifies pins a choice: the point at
// infinity is a valid encoding, since an aggregate can land on it, as Prysm
// also allows. It must still verify nothing.
func TestInfinitySignatureParsesButNeverVerifies(t *testing.T) {
	var infinity bls12381.G1Affine
	encoded := infinity.Bytes()
	sign, err := SignatureFromBytes(encoded[:])
	if err != nil {
		t.Fatalf("the infinity signature was refused: %v", err)
	}
	pub := mustKey(t).Public()
	msg := []byte("m")
	if pub.Verify(msg, sign) || pub.VerifyPossession(sign) ||
		AggregateVerify([]*PublicKey{pub.(*PublicKey)}, [][]byte{msg}, sign) {
		t.Error("the infinity signature verified")
	}
	// Both at infinity is the dangerous pair: gnark drops infinite points from
	// the pairing, so nothing is left and the product is 1.
	var zero PublicKey
	if zero.Verify(msg, sign) || zero.VerifyPossession(sign) {
		t.Error("the infinity signature verified under the infinity key")
	}
}

func TestSignatureFromBytesRefusesNonCanonicalEncodings(t *testing.T) {
	for name, b := range nonCanonical(signatureSize) {
		if _, err := SignatureFromBytes(b); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestSignatureFromBytesKeepsItsOwnCopy(t *testing.T) {
	raw := mustSign(t, mustKey(t), []byte("m")).Bytes()
	sign, err := SignatureFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(raw)
	clear(raw)
	if !bytes.Equal(sign.Bytes(), want) {
		t.Error("the signature changed with the caller's buffer")
	}
}

func TestAggregateSignatureRejectsNothingAndNil(t *testing.T) {
	if _, err := AggregateSignature(nil); err == nil {
		t.Error("aggregating no signatures succeeded")
	}
	if _, err := AggregateSignature([]*Signature{mustSign(t, mustKey(t), []byte("m")), nil}); err == nil {
		t.Error("aggregating a nil signature succeeded")
	}
}

// FuzzSignatureFromBytes checks that whatever is accepted is a point in G1,
// infinity included, whose own encoding is the input.
func FuzzSignatureFromBytes(f *testing.F) {
	_, _, g1, _ := bls12381.Generators()
	generator := g1.Bytes()
	f.Add(generator[:])
	f.Add(make([]byte, signatureSize))
	f.Add(append([]byte{0xc0}, make([]byte, signatureSize-1)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		sign, err := SignatureFromBytes(b)
		if err != nil {
			return
		}
		if !sign.point.IsInSubGroup() || sign.point.Bytes() != sign.inner {
			t.Fatalf("accepted %x, which is not the canonical encoding of a point in G1", b)
		}
	})
}
