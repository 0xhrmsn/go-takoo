package ed25519

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"go-takoo/crypto"
	"go-takoo/crypto/bech32m"
)

// The first three vectors of RFC 8032, section 7.1.
var rfc8032Vectors = []struct {
	name, seed, pub, msg, sig string
}{
	{
		"empty message",
		"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
		"",
		"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
	},
	{
		"one byte",
		"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
		"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
		"72",
		"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
	},
	{
		"two bytes",
		"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
		"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
		"af82",
		"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
	},
}

func mustHex(tb testing.TB, s string) []byte {
	tb.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func testKey(tb testing.TB, fill byte) *PrivateKey {
	tb.Helper()
	priv, err := PrivateKeyFromBytes(bytes.Repeat([]byte{fill}, seedSize))
	if err != nil {
		tb.Fatal(err)
	}
	return priv
}

func TestSignMatchesRFC8032(t *testing.T) {
	for _, v := range rfc8032Vectors {
		t.Run(v.name, func(t *testing.T) {
			priv, err := PrivateKeyFromBytes(mustHex(t, v.seed))
			if err != nil {
				t.Fatal(err)
			}
			pub := priv.Public()
			if got := hex.EncodeToString(pub.Bytes()); got != v.pub {
				t.Errorf("public key %s, want %s", got, v.pub)
			}
			msg := mustHex(t, v.msg)
			sig, err := priv.Sign(msg)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(sig.Bytes()); got != v.sig {
				t.Errorf("signature %s, want %s", got, v.sig)
			}
			if !pub.Verify(msg, sig) {
				t.Error("the vector signature does not verify")
			}
		})
	}
}

func TestPrivateKeyRoundTrips(t *testing.T) {
	priv := testKey(t, 7)
	if got, err := PrivateKeyFromString(priv.String()); err != nil || !got.Equal(priv) {
		t.Errorf("FromString(String): %v", err)
	}
	if s := priv.String(); !strings.HasPrefix(s, crypto.PrivateKeyHRP+"1p") || len(s) != stringPrivateKeySize {
		t.Errorf("String = %.8q... (%d characters), want \"prv1p\" and %d", s, len(s), stringPrivateKeySize)
	}
	if got, err := PrivateKeyFromBytes(priv.Bytes()); err != nil || !got.Equal(priv) {
		t.Errorf("FromBytes(Bytes): %v", err)
	}
}

// One key, one external form: Bytes is RFC 8032's seed, the same 32 bytes
// String encodes under "prv" after the scheme character. The 64-byte expanded
// key is never accepted, so a key whose public half disagrees with its seed --
// which would let two signatures on one message give away the secret scalar --
// cannot be built.
func TestPrivateKeyIsTheSeed(t *testing.T) {
	priv := testKey(t, 7)
	hrp, typ, fromString, err := bech32m.DecodeToBase256WithType(priv.String())
	if err != nil || hrp != crypto.PrivateKeyHRP || crypto.Scheme(typ) != crypto.SchemeEd25519 {
		t.Fatalf("hrp %q type %d err %v, want %q and %d", hrp, typ, err, crypto.PrivateKeyHRP, crypto.SchemeEd25519)
	}
	if !bytes.Equal(priv.Bytes(), bytes.Repeat([]byte{7}, seedSize)) || !bytes.Equal(priv.Bytes(), fromString) {
		t.Fatalf("Bytes %x, String carries %x, want both the seed", priv.Bytes(), fromString)
	}
	expanded := append(priv.Bytes(), priv.Public().Bytes()...)
	if _, err := PrivateKeyFromBytes(expanded); err == nil {
		t.Error("the 64-byte expanded form was accepted")
	}
}

// A key printed into a log is a key leaked. String is the deliberate export;
// every other way of printing it is redacted.
func TestPrivateKeyIsRedactedWhenPrinted(t *testing.T) {
	priv := testKey(t, 7)
	secret := priv.String()
	for _, out := range []string{
		fmt.Sprint(priv), fmt.Sprintf("%v", priv), fmt.Sprintf("%s", priv), fmt.Sprintf("%+v", priv),
		fmt.Sprintf("%#v", priv), fmt.Sprintf("%x", priv), fmt.Sprintf("%v", *priv),
		fmt.Sprintf("%v", struct{ Key *PrivateKey }{priv}), fmt.Sprintf("%+v", struct{ Key PrivateKey }{*priv}),
	} {
		if strings.Contains(out, secret) || strings.Contains(out, hex.EncodeToString(priv.Bytes())) {
			t.Errorf("printing leaked the key: %s", out)
		}
	}
}

func TestPrivateKeyFromBytesChecksSize(t *testing.T) {
	for _, n := range []int{0, seedSize - 1, seedSize + 1, 2 * seedSize} {
		if _, err := PrivateKeyFromBytes(make([]byte, n)); err == nil || !strings.Contains(err.Error(), "private key size") {
			t.Errorf("%d-byte key: err = %v", n, err)
		}
	}
}

func TestPrivateKeyFromStringRejects(t *testing.T) {
	encode := func(hrp string, scheme crypto.Scheme, b []byte) string {
		s, err := bech32m.EncodeFromBase256WithType(hrp, byte(scheme), b)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	valid := testKey(t, 7).String()
	last := strings.IndexByte("qpzry9x8gf2tvdw0s3jn54khce6mua7l", valid[len(valid)-1])
	tests := []struct {
		name, in, want string
	}{
		{"empty", "", "has 0 characters, want 63"},
		{"wrong length", "prv1notbech32m", "has 14 characters, want 63"},
		{"short key", encode(crypto.PrivateKeyHRP, crypto.SchemeEd25519, make([]byte, seedSize-1)), "has 61 characters, want 63"},
		{"not bech32m", valid[:len(valid)-1] + string("qpzry9x8gf2tvdw0s3jn54khce6mua7l"[(last+1)%32]), "not bech32m"},
		{"wrong prefix", encode(crypto.PublicKeyHRP, crypto.SchemeEd25519, make([]byte, seedSize)), `prefix "pub", want "prv"`},
		{"another scheme", encode(crypto.PrivateKeyHRP, crypto.SchemeBLS12381, make([]byte, seedSize)), "is for scheme Bls12381, want Ed25519"},
		{"unknown scheme", encode(crypto.PrivateKeyHRP, 0, make([]byte, seedSize)), "is for scheme Unknown, want Ed25519"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PrivateKeyFromString(tt.in); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPrivateKeyAccessorsReturnCopies(t *testing.T) {
	priv := testKey(t, 7)
	priv.Bytes()[0] ^= 0xff
	if !priv.Equal(testKey(t, 7)) {
		t.Fatal("writing into Bytes changed the key")
	}
}

// A constructor that wiped its input would turn a second call with the same
// buffer into the key of the all-zero seed, which anyone can compute.
func TestPrivateKeyFromBytesLeavesItsInputAlone(t *testing.T) {
	b := bytes.Repeat([]byte{7}, seedSize)
	first, _ := PrivateKeyFromBytes(b)
	second, err := PrivateKeyFromBytes(b)
	if err != nil || !second.Equal(first) || !bytes.Equal(b, bytes.Repeat([]byte{7}, seedSize)) {
		t.Fatalf("PrivateKeyFromBytes changed its input to %x", b)
	}
}

func TestPrivateKeyEqual(t *testing.T) {
	a := testKey(t, 7)
	if !a.Equal(testKey(t, 7)) || a.Equal(testKey(t, 8)) || a.Equal(nil) {
		t.Fatal("Equal does not tell keys apart")
	}
}

// sink keeps a discarded result reachable, so the compiler cannot drop the
// work being measured.
var sink byte

func BenchmarkSign(b *testing.B) {
	priv := testKey(b, 7)
	msg := make([]byte, 32)
	for b.Loop() {
		sig, _ := priv.Sign(msg)
		sink ^= sig.Bytes()[0]
	}
}
