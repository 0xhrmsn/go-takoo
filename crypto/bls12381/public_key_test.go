package bls12381

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"

	"go-takoo/crypto"
	"go-takoo/crypto/bech32m"
)

var (
	_ crypto.AggregatePrivateKey = (*PrivateKey)(nil)
	_ crypto.AggregatePublicKey  = (*PublicKey)(nil)
	_ crypto.AggregateSignature  = (*Signature)(nil)
)

func TestSignAndVerify(t *testing.T) {
	priv := mustKey(t)
	pub := priv.Public()
	msg := []byte("the message")
	sign := mustSign(t, priv, msg)

	if !pub.Verify(msg, sign) {
		t.Fatal("a sound signature was rejected")
	}
	if pub.Verify([]byte("a different message"), sign) {
		t.Error("a signature verified over the wrong message")
	}
	if mustKey(t).Public().Verify(msg, sign) {
		t.Error("a signature verified under the wrong key")
	}
	if pub.Verify(msg, nil) {
		t.Error("a nil signature verified")
	}
	var zero PublicKey
	if zero.Verify(msg, sign) {
		t.Error("the zero public key verified a signature")
	}

	// One flipped bit must break it; most bent encodings do not even decode.
	raw := sign.Bytes()
	for _, i := range []int{0, 1, len(raw) / 2, len(raw) - 1} {
		bent := bytes.Clone(raw)
		bent[i] ^= 0x01
		if bentSign, err := SignatureFromBytes(bent); err == nil && pub.Verify(msg, bentSign) {
			t.Errorf("a signature altered at byte %d verified", i)
		}
	}
}

// TestAggregateKeyVerify is how consensus checks a quorum certificate: the
// signers' keys are summed and the aggregate is verified once.
func TestAggregateKeyVerify(t *testing.T) {
	const signers = 12
	msg := []byte("one message, everybody signs it")
	keys := make([]*PublicKey, signers)
	signs := make([]*Signature, signers)
	for i := range keys {
		priv := mustKey(t)
		keys[i], signs[i] = priv.Public().(*PublicKey), mustSign(t, priv, msg)
	}
	aggregate, err := AggregateSignature(signs)
	if err != nil {
		t.Fatalf("AggregateSignature: %v", err)
	}
	verify := func(keys []*PublicKey, msg []byte, sign *Signature) bool {
		t.Helper()
		sum, err := AggregatePublicKey(keys)
		if err != nil {
			t.Fatalf("AggregatePublicKey: %v", err)
		}
		return sum.Verify(msg, sign)
	}

	if !verify(keys, msg, aggregate) {
		t.Fatal("a sound aggregate was rejected")
	}
	if verify(keys, []byte("a different message"), aggregate) {
		t.Error("an aggregate verified over the wrong message")
	}
	if verify(keys[:signers-1], msg, aggregate) {
		t.Error("an aggregate verified against a set missing a signer")
	}
	swapped := append([]*PublicKey(nil), keys...)
	swapped[3] = mustKey(t).Public().(*PublicKey)
	if verify(swapped, msg, aggregate) {
		t.Error("an aggregate verified against a set with a substituted key")
	}
	partial, err := AggregateSignature(signs[:signers-1])
	if err != nil {
		t.Fatal(err)
	}
	if verify(keys, msg, partial) {
		t.Error("an incomplete aggregate verified against the full set")
	}
}

// foreignPub and foreignSign stand for values of another algorithm: they meet
// the interfaces but are not BLS, so every method that takes one must refuse it.
type (
	foreignPub  struct{ crypto.AggregatePublicKey }
	foreignSign struct{ crypto.AggregateSignature }
)

// TestAggregateThroughTheInterfaces is a quorum checked without naming BLS: the
// methods must give byte for byte what the package functions give.
func TestAggregateThroughTheInterfaces(t *testing.T) {
	const signers = 5
	msg := []byte("block 7")
	keys := make([]*PublicKey, signers)
	signs := make([]*Signature, signers)
	pubs := make([]crypto.AggregatePublicKey, signers)
	parts := make([]crypto.AggregateSignature, signers)
	for i := range keys {
		priv := mustKey(t)
		keys[i], signs[i] = priv.Public().(*PublicKey), mustSign(t, priv, msg)
		pubs[i], parts[i] = keys[i], signs[i]
	}

	sum, err := pubs[0].Aggregate(pubs[1:])
	if err != nil {
		t.Fatal(err)
	}
	aggregate, err := parts[0].Aggregate(parts[1:])
	if err != nil {
		t.Fatal(err)
	}
	wantSum, _ := AggregatePublicKey(keys)
	wantAggregate, _ := AggregateSignature(signs)
	if !sum.Equal(wantSum) || !aggregate.Equal(wantAggregate) {
		t.Fatal("the methods aggregate differently from the package functions")
	}
	if !sum.Verify(msg, aggregate) {
		t.Fatal("a sound quorum was rejected")
	}
	if alone, err := pubs[0].Aggregate(nil); err != nil || !alone.Equal(pubs[0]) {
		t.Errorf("aggregating one key gave another key: %v", err)
	}

	if x, err := pubs[0].Aggregate([]crypto.AggregatePublicKey{pubs[1], foreignPub{}}); err == nil || x != nil || !strings.Contains(err.Error(), "element 2 is not") {
		t.Error("a foreign public key was aggregated")
	}
	if x, err := parts[0].Aggregate([]crypto.AggregateSignature{parts[1], foreignSign{}}); err == nil || x != nil || !strings.Contains(err.Error(), "element 2 is not") {
		t.Error("a foreign signature was aggregated")
	}
	if x, err := pubs[0].Aggregate([]crypto.AggregatePublicKey{(*PublicKey)(nil)}); err == nil || x != nil {
		t.Error("a nil public key was aggregated")
	}
	if x, err := parts[0].Aggregate([]crypto.AggregateSignature{(*Signature)(nil)}); err == nil || x != nil {
		t.Error("a nil signature was aggregated")
	}
}

func TestAggregateVerifyDistinctMessages(t *testing.T) {
	const signers = 6
	keys := make([]*PublicKey, signers)
	msgs := make([][]byte, signers)
	signs := make([]*Signature, signers)
	for i := range keys {
		priv := mustKey(t)
		keys[i], msgs[i] = priv.Public().(*PublicKey), fmt.Appendf(nil, "message %d", i)
		signs[i] = mustSign(t, priv, msgs[i])
	}
	aggregate, err := AggregateSignature(signs)
	if err != nil {
		t.Fatal(err)
	}
	if !AggregateVerify(keys, msgs, aggregate) {
		t.Fatal("a sound aggregate over distinct messages was rejected")
	}
	swapped := append([][]byte(nil), msgs...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if AggregateVerify(keys, swapped, aggregate) {
		t.Error("an aggregate verified with two messages transposed")
	}
	if AggregateVerify(keys[:signers-1], msgs, aggregate) {
		t.Error("an aggregate verified with mismatched counts")
	}
	if AggregateVerify(keys, msgs, nil) {
		t.Error("a nil aggregate verified")
	}
	var zero PublicKey
	for name, key := range map[string]*PublicKey{"nil": nil, "infinity": &zero} {
		bad := append([]*PublicKey(nil), keys...)
		bad[2] = key
		if AggregateVerify(bad, msgs, aggregate) {
			t.Errorf("an aggregate verified with a %s key", name)
		}
	}
}

// TestAggregateVerifyGroupsRepeatedMessages: under the proof-of-possession
// ciphersuite every key has proven its scalar, so keys over the same message
// may be summed; PoP at registration is what makes that safe.
func TestAggregateVerifyGroupsRepeatedMessages(t *testing.T) {
	msg, other := []byte("shared"), []byte("alone")
	a, b, c := mustKey(t), mustKey(t), mustKey(t)
	aggregate, err := AggregateSignature([]*Signature{mustSign(t, a, msg), mustSign(t, b, msg), mustSign(t, c, other)})
	if err != nil {
		t.Fatal(err)
	}
	keys := []*PublicKey{a.Public().(*PublicKey), b.Public().(*PublicKey), c.Public().(*PublicKey)}
	if !AggregateVerify(keys, [][]byte{msg, msg, other}, aggregate) {
		t.Error("a sound aggregate with a repeated message was rejected")
	}
	if AggregateVerify(keys, [][]byte{msg, other, msg}, aggregate) {
		t.Error("an aggregate verified with the wrong key on the repeated message")
	}

	// Whoever knows sk knows -sk, and can prove possession of both. Their keys
	// sum to infinity, which gnark drops from the pairing, so without a guard
	// the pair would claim msg while the aggregate holds only c's signature.
	negBytes := make([]byte, privateKeySize)
	_ = new(big.Int).Sub(groupOrder, a.inner).FillBytes(negBytes)
	negA, err := PrivateKeyFromBytes(negBytes)
	if err != nil {
		t.Fatal(err)
	}
	onlyC, err := AggregateSignature([]*Signature{mustSign(t, a, msg), mustSign(t, negA, msg), mustSign(t, c, other)})
	if err != nil {
		t.Fatal(err)
	}
	cancel := []*PublicKey{a.Public().(*PublicKey), negA.Public().(*PublicKey), c.Public().(*PublicKey)}
	if AggregateVerify(cancel, [][]byte{msg, msg, other}, onlyC) {
		t.Error("keys that cancel out on one message verified it")
	}
}

// TestAggregateVerifyRefusesTheSameSignerTwice: one key listed twice on one
// message, next to its signature added to itself, is mathematically sound,
// but anything counting the list would count one signer as two.
func TestAggregateVerifyRefusesTheSameSignerTwice(t *testing.T) {
	msg := []byte("block 7")
	priv := mustKey(t)
	sign := mustSign(t, priv, msg)
	doubled, err := AggregateSignature([]*Signature{sign, sign})
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(*PublicKey)
	if AggregateVerify([]*PublicKey{pub, pub}, [][]byte{msg, msg}, doubled) {
		t.Error("one signer verified as two")
	}
}

// TestRogueKeyAttackWorksWithoutProofOfPossession is the reason ProvePossession
// exists, demonstrated: a published key of (attacker - honest) lets the
// attacker alone forge an aggregate for both, and only VerifyPossession refuses it.
func TestRogueKeyAttackWorksWithoutProofOfPossession(t *testing.T) {
	honest := mustKey(t).Public().(*PublicKey)
	attacker := mustKey(t)

	var rogueJac, honestJac bls12381.G2Jac
	_ = rogueJac.FromAffine(&attacker.Public().(*PublicKey).point)
	_ = honestJac.FromAffine(&honest.point)
	_ = rogueJac.SubAssign(&honestJac)
	var rogueAff bls12381.G2Affine
	_ = rogueAff.FromJacobian(&rogueJac)
	rogueBytes := rogueAff.Bytes()
	rogue, err := PublicKeyFromBytes(rogueBytes[:])
	if err != nil {
		t.Fatalf("the rogue key did not decode: %v", err)
	}

	msg := []byte("a message the honest signer never saw")
	sum, err := AggregatePublicKey([]*PublicKey{honest, rogue})
	if err != nil {
		t.Fatal(err)
	}
	if !sum.Verify(msg, mustSign(t, attacker, msg)) {
		t.Fatal("the forgery did not verify; this test no longer demonstrates anything")
	}

	proof, err := attacker.ProvePossession()
	if err != nil {
		t.Fatal(err)
	}
	if rogue.VerifyPossession(proof) {
		t.Error("a proof of possession verified for the rogue key")
	}
}

func TestSchemeIsBLS12381(t *testing.T) {
	pub := mustKey(t).Public()
	if pub.Scheme() != crypto.SchemeBLS12381 {
		t.Fatalf("scheme %d, want %d", pub.Scheme(), crypto.SchemeBLS12381)
	}
}

func TestPublicKeyRejections(t *testing.T) {
	for _, size := range []int{0, 1, 48, 95, 97} {
		if _, err := PublicKeyFromBytes(make([]byte, size)); err == nil {
			t.Errorf("PublicKeyFromBytes(%d bytes) was accepted", size)
		}
	}
	var infinity bls12381.G2Affine
	infinityBytes := infinity.Bytes()
	if _, err := PublicKeyFromBytes(infinityBytes[:]); err == nil {
		t.Error("the point at infinity was accepted")
	}
	if _, err := PublicKeyFromBytes(bytes.Repeat([]byte{0xff}, publicKeySize)); err == nil {
		t.Error("nonsense was accepted")
	}
	if _, err := AggregatePublicKey(nil); err == nil {
		t.Error("aggregating no keys succeeded")
	}
	if _, err := AggregatePublicKey([]*PublicKey{mustKey(t).Public().(*PublicKey), nil}); err == nil {
		t.Error("aggregating a nil key succeeded")
	}
	pub := mustKey(t).Public().(*PublicKey)
	var negated bls12381.G2Affine
	_ = negated.Neg(&pub.point)
	negatedBytes := negated.Bytes()
	cancel, err := PublicKeyFromBytes(negatedBytes[:])
	if err != nil {
		t.Fatal(err)
	}
	if sum, err := AggregatePublicKey([]*PublicKey{pub, cancel}); err == nil || sum != nil {
		t.Error("keys that cancel out aggregated to the point at infinity")
	}
}

// TestPublicKeyFromBytesRefusesNonCanonicalEncodings pins what gnark refuses
// on our behalf, so that PublicKeyFromBytes need not re-encode to check: a
// coordinate not below p, an infinity with bits set, an uncompressed or an
// invalid flag.
func TestPublicKeyFromBytesRefusesNonCanonicalEncodings(t *testing.T) {
	for name, b := range nonCanonical(publicKeySize) {
		if _, err := PublicKeyFromBytes(b); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestPublicKeyFromBytesKeepsItsOwnCopy(t *testing.T) {
	raw := mustKey(t).Public().Bytes()
	pub, err := PublicKeyFromBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Clone(raw)
	clear(raw)
	if !bytes.Equal(pub.Bytes(), want) {
		t.Error("the key changed with the caller's buffer")
	}
}

// nonCanonical spells encodings of size bytes that no point produces. For G2
// the coordinate is two field elements, and each half is tried at p.
func nonCanonical(size int) map[string][]byte {
	p := fp.Modulus().FillBytes(make([]byte, fp.Bytes))
	out := map[string][]byte{}
	for half := 0; half < size/fp.Bytes; half++ {
		b := make([]byte, size)
		_ = copy(b[half*fp.Bytes:], p)
		b[0] |= 0x80
		out[fmt.Sprintf("coordinate %d at p", half)] = b
	}
	junk := make([]byte, size)
	junk[0], junk[size-1] = 0xc0, 1
	out["infinity with bits set"] = junk
	for _, flag := range []byte{0x00, 0x20, 0x60, 0xe0} {
		b := make([]byte, size)
		b[0], b[size-1] = flag, 1
		out[fmt.Sprintf("flag %#x", flag)] = b
	}
	return out
}

func TestPublicKeyStringRoundTripAndEqual(t *testing.T) {
	pub := mustKey(t).Public()
	s := pub.String()
	if !strings.HasPrefix(s, crypto.PublicKeyHRP+"1z") || len(s) != stringPublicKeySize {
		t.Errorf("public key string %.8q... (%d characters), want \"pub1z\" and %d", s, len(s), stringPublicKeySize)
	}
	back, err := PublicKeyFromString(s)
	if err != nil {
		t.Fatalf("PublicKeyFromString: %v", err)
	}
	if !back.Equal(pub) {
		t.Error("a public key did not survive its round trip")
	}
	if pub.Equal(mustKey(t).Public()) || pub.Equal(nil) {
		t.Error("a public key compared equal to another key or to nil")
	}
	if _, err := PublicKeyFromString(mustKey(t).String()); err == nil {
		t.Error("a private key string parsed as a public key")
	}
	wrongPrefix, err := bech32m.EncodeFromBase256WithType(crypto.PrivateKeyHRP, byte(crypto.SchemeBLS12381), pub.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	wrongScheme, err := bech32m.EncodeFromBase256WithType(crypto.PublicKeyHRP, byte(crypto.SchemeEd25519), pub.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	for bad, want := range map[string]string{
		"":            "has 0 characters, want 165",
		"not bech32m": "has 11 characters, want 165",
		corrupt(s):    "is not bech32m",
		wrongPrefix:   `has prefix "prv", want "pub"`,
		wrongScheme:   "is for scheme Ed25519, want Bls12381",
	} {
		if _, err := PublicKeyFromString(bad); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%.12q: err = %v, want %q", bad, err, want)
		}
	}
}

// FuzzPublicKeyFromBytes checks that whatever is accepted is a finite point
// in G2 whose own encoding is the input, so each key has exactly one encoding.
func FuzzPublicKeyFromBytes(f *testing.F) {
	_, _, _, g2 := bls12381.Generators()
	generator := g2.Bytes()
	f.Add(generator[:])
	f.Add(make([]byte, publicKeySize))
	f.Add(append([]byte{0xc0}, make([]byte, publicKeySize-1)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		pub, err := PublicKeyFromBytes(b)
		if err != nil {
			return
		}
		if pub.point.IsInfinity() || !pub.point.IsInSubGroup() || pub.point.Bytes() != pub.inner {
			t.Fatalf("accepted %x, which is not the canonical encoding of a point in G2", b)
		}
	})
}

func BenchmarkSign(b *testing.B) {
	priv := mustKey(b)
	msg := []byte("block 1")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := priv.Sign(msg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	priv := mustKey(b)
	pub, msg := priv.Public(), []byte("block 1")
	sign := mustSign(b, priv, msg)
	b.ReportAllocs()
	for b.Loop() {
		if !pub.Verify(msg, sign) {
			b.Fatal("a sound signature was rejected")
		}
	}
}

// BenchmarkAggregateVerify checks a quorum certificate: 64 validators voting
// on one block.
func BenchmarkAggregateVerify(b *testing.B) {
	const n = 64
	msg := []byte("block 1")
	pubs := make([]*PublicKey, n)
	msgs := make([][]byte, n)
	signs := make([]*Signature, n)
	for i := range n {
		priv := mustKey(b)
		pubs[i], msgs[i], signs[i] = priv.Public().(*PublicKey), msg, mustSign(b, priv, msg)
	}
	sign, err := AggregateSignature(signs)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if !AggregateVerify(pubs, msgs, sign) {
			b.Fatal("a sound certificate was rejected")
		}
	}
}

func BenchmarkPublicKeyFromBytes(b *testing.B) {
	encoded := mustKey(b).Public().Bytes()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := PublicKeyFromBytes(encoded); err != nil {
			b.Fatal(err)
		}
	}
}
