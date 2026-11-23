package transaction

import (
	"bytes"
	"testing"

	"go-takoo/crypto"
	"go-takoo/crypto/bls12381"
	"go-takoo/crypto/ed25519"
)

func testKey(t *testing.T, fill byte) *ed25519.PrivateKey {
	t.Helper()
	key, err := ed25519.PrivateKeyFromBytes(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestAuthSignsAndVerifies(t *testing.T) {
	key := testKey(t, 7)
	msg := []byte("the transaction's ID")
	auth, err := NewAuth(key, msg)
	if err != nil {
		t.Fatal(err)
	}

	if !auth.Verify(msg) {
		t.Fatal("a sound auth was rejected")
	}
	if auth.Verify([]byte("another message")) {
		t.Error("an auth verified over the wrong message")
	}
	other, err := NewAuth(testKey(t, 8), msg)
	if err != nil {
		t.Fatal(err)
	}
	if (Auth{PK: other.PK, Sign: auth.Sign}).Verify(msg) {
		t.Error("a signature verified under another key")
	}
	for _, i := range []int{0, len(auth.Sign) / 2, len(auth.Sign) - 1} {
		bent := Auth{PK: auth.PK, Sign: bytes.Clone(auth.Sign)}
		bent.Sign[i] ^= 1
		if bent.Verify(msg) {
			t.Errorf("a signature altered at byte %d verified", i)
		}
	}
}

// PK is the typed key: the scheme byte, then the key. Those are the bytes an
// address hashes, so Address must be the key's own address.
func TestAuthPKIsTheTypedKey(t *testing.T) {
	key := testKey(t, 7)
	auth, err := NewAuth(key, []byte("m"))
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public()
	if want := append([]byte{byte(crypto.SchemeEd25519)}, pub.Bytes()...); !bytes.Equal(auth.PK, want) {
		t.Fatalf("PK = %x, want %x", auth.PK, want)
	}
	if len(auth.PK) != 33 || len(auth.Sign) != 64 {
		t.Errorf("PK %d bytes, Sign %d bytes, want 33 and 64", len(auth.PK), len(auth.Sign))
	}
	got, err := auth.Address()
	if err != nil || got != pub.Address() {
		t.Fatalf("Address = %v (%v), want %v", got, err, pub.Address())
	}
	if want := crypto.Address(crypto.Hash256(auth.PK)); got != want {
		t.Errorf("Address = %v, want SHA3-256 of PK %v", got, want)
	}
}

// A key that does not parse, or one of a scheme that cannot sign transactions,
// is refused by Key and Address, and Verify is false rather than a panic.
func TestAuthRefusesBadKeys(t *testing.T) {
	msg := []byte("m")
	good, err := NewAuth(testKey(t, 7), msg)
	if err != nil {
		t.Fatal(err)
	}
	validator, err := bls12381.PrivateKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	blsPK := append([]byte{byte(crypto.SchemeBLS12381)}, validator.Public().Bytes()...)

	for name, auth := range map[string]Auth{
		"no key":          {Sign: good.Sign},
		"scheme only":     {PK: good.PK[:1], Sign: good.Sign},
		"short key":       {PK: good.PK[:32], Sign: good.Sign},
		"unknown scheme":  {PK: append([]byte{0}, good.PK[1:]...), Sign: good.Sign},
		"validator key":   {PK: blsPK, Sign: good.Sign},
		"no signature":    {PK: good.PK},
		"short signature": {PK: good.PK, Sign: good.Sign[:63]},
	} {
		if auth.Verify(msg) {
			t.Errorf("%s: verified", name)
		}
		if name == "no signature" || name == "short signature" {
			continue
		}
		if _, err := auth.Key(); err == nil {
			t.Errorf("%s: Key accepted it", name)
		}
		if _, err := auth.Address(); err == nil {
			t.Errorf("%s: Address accepted it", name)
		}
	}
}
