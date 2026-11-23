package ed25519

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func TestSignatureRoundTrips(t *testing.T) {
	sig, _ := testKey(t, 7).Sign([]byte("msg"))
	if got, err := SignatureFromBytes(sig.Bytes()); err != nil || !got.Equal(sig) {
		t.Errorf("FromBytes(Bytes): %v", err)
	}
	for _, s := range []string{sig.String(), strings.ToUpper(sig.String())} {
		if got, err := SignatureFromString(s); err != nil || !got.Equal(sig) {
			t.Errorf("FromString(%q): %v", s, err)
		}
	}
}

func TestSignatureRejects(t *testing.T) {
	if _, err := SignatureFromBytes(make([]byte, signatureSize-1)); err == nil || !strings.Contains(err.Error(), "signature size 63, want 64") {
		t.Errorf("63 bytes: err = %v", err)
	}
	tests := []struct {
		name, in, want string
	}{
		{"empty", "", "empty signature string"},
		{"odd length", strings.Repeat("a", stringSignatureSize-1), "has 127 hex digits, want 128"},
		{"not hex", strings.Repeat("z", stringSignatureSize), "not hex"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := SignatureFromString(tt.in); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

// S + l is the same scalar written past the group order: a second spelling of
// a valid signature, which anyone could otherwise produce from the first.
func TestSignatureFromBytesRejectsSPastTheGroupOrder(t *testing.T) {
	sig, _ := testKey(t, 7).Sign([]byte("transfer 10 to bob"))
	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	raw := sig.Bytes()
	s := new(big.Int).SetBytes(reversed(raw[32:]))
	malleated := append(raw[:32:32], reversed(new(big.Int).Add(s, l).FillBytes(make([]byte, 32)))...)
	if _, err := SignatureFromBytes(malleated); err == nil || !strings.Contains(err.Error(), "not below the group order") {
		t.Fatalf("err = %v", err)
	}
	if _, err := SignatureFromString(hex.EncodeToString(malleated)); err == nil {
		t.Fatal("the malleated signature was accepted as a string")
	}
}

func TestSignatureBytesIsACopy(t *testing.T) {
	sig, _ := testKey(t, 7).Sign([]byte("msg"))
	before := sig.String()
	sig.Bytes()[0] ^= 0xff
	if sig.String() != before {
		t.Fatal("writing into Bytes changed the signature")
	}
}

func TestSignatureEqual(t *testing.T) {
	priv := testKey(t, 7)
	a, _ := priv.Sign([]byte("a"))
	again, _ := priv.Sign([]byte("a"))
	b, _ := priv.Sign([]byte("b"))
	if !a.Equal(again) || a.Equal(b) || a.Equal(nil) {
		t.Fatal("Equal does not tell signatures apart")
	}
}
