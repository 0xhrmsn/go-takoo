package bls12381

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"go-takoo/crypto"
	"go-takoo/crypto/bech32m"
)

func mustKey(t testing.TB) *PrivateKey {
	t.Helper()
	seed := make([]byte, seedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand: %v", err)
	}
	priv, err := PrivateKeyFromSeed(seed)
	if err != nil {
		t.Fatalf("PrivateKeyFromSeed: %v", err)
	}

	return priv
}

func mustSign(t testing.TB, priv *PrivateKey, msg []byte) *Signature {
	t.Helper()
	sign, err := priv.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	return sign.(*Signature)
}

// TestValidatorKeysAreNotAccountKeys pins the split crypto.go describes: a
// validator key that met the account contract could sign transactions, and a
// transaction signature could be offered where a vote is checked.
func TestValidatorKeysAreNotAccountKeys(t *testing.T) {
	priv := mustKey(t)
	for name, v := range map[string]any{
		"private key": priv,
		"public key":  priv.Public(),
		"signature":   mustSign(t, priv, []byte("m")),
	} {
		_, isPriv := v.(crypto.PrivateKey)
		_, isPub := v.(crypto.PublicKey)
		_, isSign := v.(crypto.Signature)
		if isPriv || isPub || isSign {
			t.Errorf("the BLS %s meets an account interface", name)
		}
	}
}

func TestSizesAreTheMinimalSignatureVariant(t *testing.T) {
	priv := mustKey(t)
	if got := len(priv.Bytes()); got != 32 {
		t.Errorf("private key is %d bytes, want 32", got)
	}
	if got := len(priv.Public().Bytes()); got != 96 {
		t.Errorf("public key is %d bytes, want 96 (compressed G2)", got)
	}
	if got := len(mustSign(t, priv, []byte("m")).Bytes()); got != 48 {
		t.Errorf("signature is %d bytes, want 48 (compressed G1)", got)
	}
}

func TestSeedsMakeDistinctKeysAndShortSeedsAreRefused(t *testing.T) {
	seen := make(map[string]bool, 32)
	for range 32 {
		key := string(mustKey(t).Bytes())
		if seen[key] {
			t.Fatal("two random seeds gave the same key")
		}
		seen[key] = true
	}
	if _, err := PrivateKeyFromSeed(make([]byte, seedSize-1)); err == nil {
		t.Error("a seed shorter than 32 bytes was accepted")
	}
}

func TestPrivateKeyRejections(t *testing.T) {
	for _, size := range []int{0, 1, 31, 33, 48} {
		if _, err := PrivateKeyFromBytes(make([]byte, size)); err == nil {
			t.Errorf("PrivateKeyFromBytes(%d bytes) was accepted", size)
		}
	}
	if _, err := PrivateKeyFromBytes(make([]byte, privateKeySize)); err == nil {
		t.Error("the zero key was accepted")
	}
	// The order and the order plus one are second spellings of zero and one.
	for _, offset := range []int64{0, 1} {
		b := make([]byte, privateKeySize)
		_ = new(big.Int).Add(groupOrder, big.NewInt(offset)).FillBytes(b)
		if _, err := PrivateKeyFromBytes(b); err == nil {
			t.Errorf("order+%d was accepted", offset)
		}
	}
	b := make([]byte, privateKeySize)
	_ = new(big.Int).Sub(groupOrder, big.NewInt(1)).FillBytes(b)
	if _, err := PrivateKeyFromBytes(b); err != nil {
		t.Errorf("order-1, the largest key, was refused: %v", err)
	}
}

func TestPrivateKeyStringRoundTrip(t *testing.T) {
	priv := mustKey(t)
	s := priv.String()
	if !strings.HasPrefix(s, crypto.PrivateKeyHRP+"1z") || len(s) != stringPrivateKeySize {
		t.Errorf("private key string %.8q... (%d characters), want \"prv1z\" and %d", s, len(s), stringPrivateKeySize)
	}
	back, err := PrivateKeyFromString(s)
	if err != nil {
		t.Fatalf("PrivateKeyFromString: %v", err)
	}
	if !back.Equal(priv) {
		t.Error("a private key did not survive its round trip")
	}
	if _, err := PrivateKeyFromString(priv.Public().String()); err == nil {
		t.Error("a public key string parsed as a private key")
	}
	// The same 32 bytes under the Ed25519 scheme: an account key string must
	// never parse as a validator key.
	ed, err := bech32m.EncodeFromBase256WithType(crypto.PrivateKeyHRP, byte(crypto.SchemeEd25519), priv.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrivateKeyFromString(ed); err == nil || !strings.Contains(err.Error(), "is for scheme Ed25519, want Bls12381") {
		t.Errorf("an Ed25519 key string: err = %v", err)
	}
	wrongPrefix, err := bech32m.EncodeFromBase256WithType(crypto.PublicKeyHRP, byte(crypto.SchemeBLS12381), priv.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for bad, want := range map[string]string{
		"":            "has 0 characters, want 63",
		"not bech32m": "has 11 characters, want 63",
		corrupt(s):    "is not bech32m",
		wrongPrefix:   `has prefix "pub", want "prv"`,
	} {
		if _, err := PrivateKeyFromString(bad); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%.12q: err = %v, want %q", bad, err, want)
		}
	}
}

// corrupt changes the last character of a Bech32m string, which its checksum
// always catches, and leaves the length alone.
func corrupt(s string) string {
	if s[len(s)-1] == 'q' {
		return s[:len(s)-1] + "p"
	}

	return s[:len(s)-1] + "q"
}

func TestPrivateKeyIsRedactedWhenPrinted(t *testing.T) {
	priv := mustKey(t)
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

// TestSplitIsFreshAndSumsToTheKey: the halves gnark multiplies by must change
// on every call, or the blinding hides nothing, and must still add up to the
// key mod r.
func TestSplitIsFreshAndSumsToTheKey(t *testing.T) {
	priv := mustKey(t)
	a1, b1 := priv.split()
	a2, b2 := priv.split()
	if a1.Cmp(a2) == 0 || b1.Cmp(b2) == 0 {
		t.Error("two splits gave the same halves")
	}
	for _, h := range [][2]*big.Int{{a1, b1}, {a2, b2}} {
		if sum := new(big.Int).Add(h[0], h[1]); sum.Mod(sum, groupOrder).Cmp(priv.inner) != 0 {
			t.Error("the halves do not add up to the key")
		}
	}
}

func TestPrivateKeyEqual(t *testing.T) {
	priv := mustKey(t)
	same, err := PrivateKeyFromBytes(priv.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Equal(same) {
		t.Error("a key differs from its own bytes")
	}
	if priv.Equal(mustKey(t)) {
		t.Error("two keys compared equal")
	}
	if priv.Equal(nil) {
		t.Error("a key compared equal to nil")
	}
}

// TestCiphersuiteTags pins the domain separation tags. They are consensus: a
// chain that changes them cannot verify its own history.
func TestCiphersuiteTags(t *testing.T) {
	if got, want := string(dstSignature), "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"; got != want {
		t.Errorf("signature DST = %q, want %q", got, want)
	}
	if got, want := string(dstPop), "BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"; got != want {
		t.Errorf("proof-of-possession DST = %q, want %q", got, want)
	}
}

// TestPossessionIsNotASignature is what the separate tag buys: a proof of possession
// is the key signing its own public key, and must not double as a signature
// over that message, nor the reverse.
func TestPossessionIsNotASignature(t *testing.T) {
	priv := mustKey(t)
	pub := priv.Public()
	proof, err := priv.ProvePossession()
	if err != nil {
		t.Fatalf("ProvePossession: %v", err)
	}
	if !pub.VerifyPossession(proof) {
		t.Fatal("a sound proof of possession was rejected")
	}
	if pub.Verify(pub.Bytes(), proof) {
		t.Error("a proof of possession verified as a signature over the public key")
	}
	if pub.VerifyPossession(mustSign(t, priv, pub.Bytes())) {
		t.Error("a signature over the public key verified as a proof of possession")
	}
	if mustKey(t).Public().VerifyPossession(proof) {
		t.Error("a proof of possession verified for the wrong key")
	}
	if pub.VerifyPossession(nil) {
		t.Error("a nil proof verified")
	}
}
