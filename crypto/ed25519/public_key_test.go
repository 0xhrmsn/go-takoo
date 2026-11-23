package ed25519

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"filippo.io/edwards25519"

	"go-takoo/crypto"
	"go-takoo/crypto/bech32m"
)

// ed25519 is the account scheme; if a change here stopped it meeting the
// account contract, the build of these tests fails.
var (
	_ crypto.PrivateKey = (*PrivateKey)(nil)
	_ crypto.PublicKey  = (*PublicKey)(nil)
	_ crypto.Signature  = (*Signature)(nil)
)

func TestPublicKeyFromBytesRejects(t *testing.T) {
	genuine := testKey(t, 7).Public().Bytes()
	point, err := new(edwards25519.Point).SetBytes(genuine)
	if err != nil {
		t.Fatal(err)
	}
	// (0, -1), the point of order 2.
	order2, err := new(edwards25519.Point).SetBytes(mustHex(t, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		in   []byte
		want string
	}{
		{"short", genuine[:publicKeySize-1], "public key size 31, want 32"},
		{"not on the curve", mustHex(t, "0200000000000000000000000000000000000000000000000000000000000000"), "not a point on edwards25519"},
		{"y written as p+3", mustHex(t, "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), "non-canonical encoding"},
		{"identity", mustHex(t, "0100000000000000000000000000000000000000000000000000000000000000"), "small-order point"},
		{"order 2", order2.Bytes(), "small-order point"},
		{"genuine key plus the order-2 point", new(edwards25519.Point).Add(point, order2).Bytes(), "torsion component"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PublicKeyFromBytes(tt.in); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
			if len(tt.in) != publicKeySize {
				return
			}
			// A signature's R is held to the same rules, so the same point
			// fails there for the same reason. S = 0 is below the order.
			sig := append(tt.in[:publicKeySize:publicKeySize], make([]byte, 32)...)
			if _, err := SignatureFromBytes(sig); err == nil || !strings.Contains(err.Error(), "signature's R") || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("as R: err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPublicKeyRoundTrips(t *testing.T) {
	pub := testKey(t, 7).Public()
	if got, err := PublicKeyFromBytes(pub.Bytes()); err != nil || !got.Equal(pub) {
		t.Errorf("FromBytes(Bytes): %v", err)
	}
	if got, err := PublicKeyFromString(pub.String()); err != nil || !got.Equal(pub) {
		t.Errorf("FromString(String): %v", err)
	}
	if s := pub.String(); !strings.HasPrefix(s, crypto.PublicKeyHRP+"1p") || len(s) != stringPublicKeySize {
		t.Errorf("String = %.8q... (%d characters), want \"pub1p\" and %d", s, len(s), stringPublicKeySize)
	}
}

func TestPublicKeyFromStringRejects(t *testing.T) {
	key := testKey(t, 7).Public().Bytes()
	wrongPrefix, err := bech32m.EncodeFromBase256WithType(crypto.PrivateKeyHRP, byte(crypto.SchemeEd25519), key)
	if err != nil {
		t.Fatal(err)
	}
	otherScheme, err := bech32m.EncodeFromBase256WithType(crypto.PublicKeyHRP, byte(crypto.SchemeBLS12381), key)
	if err != nil {
		t.Fatal(err)
	}
	valid := testKey(t, 7).Public().String()
	last := strings.IndexByte("qpzry9x8gf2tvdw0s3jn54khce6mua7l", valid[len(valid)-1])
	tests := []struct {
		name, in, want string
	}{
		{"empty", "", "has 0 characters, want 63"},
		{"wrong length", "pub1notbech32m", "has 14 characters, want 63"},
		{"not bech32m", valid[:len(valid)-1] + string("qpzry9x8gf2tvdw0s3jn54khce6mua7l"[(last+1)%32]), "not bech32m"},
		{"wrong prefix", wrongPrefix, `prefix "prv", want "pub"`},
		{"another scheme", otherScheme, "is for scheme Bls12381, want Ed25519"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := PublicKeyFromString(tt.in); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

// The address is permanent once funds sit at it, and wallets outside this repo
// compute it too, so one is pinned as a literal, computed outside Go: SHA3-256
// of the scheme (0x01) and the public key of RFC 8032's first vector.
func TestAddressIsPinned(t *testing.T) {
	pub, err := PublicKeyFromBytes(mustHex(t, rfc8032Vectors[0].pub))
	if err != nil {
		t.Fatal(err)
	}
	const want = "442e8fc33e3582260e9b48f80e9397ce5f6677516dc04056d8b914f82cab4cb3"
	if got := hex.EncodeToString(pub.Address().Bytes()); got != want {
		t.Fatalf("address %s, want %s", got, want)
	}
}

func TestPublicKeyBytesIsACopy(t *testing.T) {
	pub := testKey(t, 7).Public()
	before := pub.Address()
	pub.Bytes()[0] ^= 0xff
	if pub.Address() != before {
		t.Fatal("writing into Bytes changed the key")
	}
}

func TestVerifyRejects(t *testing.T) {
	priv := testKey(t, 7)
	pub := priv.Public()
	msg := []byte("transfer 10 to bob")
	sig, _ := priv.Sign(msg)

	// A bit of S: a flipped bit in R mostly lands off the curve or outside
	// the subgroup, and SignatureFromBytes refuses that before Verify runs.
	flipped := sig.Bytes()
	flipped[40] ^= 1

	tests := []struct {
		name string
		pub  crypto.PublicKey
		msg  []byte
		sig  []byte
	}{
		{"other message", pub, []byte("transfer 99 to bob"), sig.Bytes()},
		{"other key", testKey(t, 8).Public(), msg, sig.Bytes()},
		{"flipped bit", pub, msg, flipped},
		{"empty message", pub, nil, sig.Bytes()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := SignatureFromBytes(tt.sig)
			if err != nil {
				t.Fatal(err)
			}
			if tt.pub.Verify(tt.msg, s) {
				t.Fatal("verified")
			}
		})
	}
}

// foreignSignature is a signature of some other scheme that happens to be 64
// bytes, which is how a P-256 one is laid out.
type foreignSignature struct{ b []byte }

func (s foreignSignature) Bytes() []byte                 { return s.b }
func (s foreignSignature) Equal(x crypto.Signature) bool { return false }
func (s foreignSignature) String() string                { return "" }

func TestVerifyRefusesASignatureOfAnotherScheme(t *testing.T) {
	priv := testKey(t, 7)
	msg := []byte("transfer 10 to bob")
	sig, _ := priv.Sign(msg)
	if priv.Public().Verify(msg, foreignSignature{sig.Bytes()}) {
		t.Fatal("ed25519 bytes inside another scheme's signature verified")
	}
}

func TestVerifyDoesNotAllocate(t *testing.T) {
	priv := testKey(t, 7)
	pub := priv.Public()
	msg := make([]byte, 32)
	sig, _ := priv.Sign(msg)
	if n := testing.AllocsPerRun(100, func() { pub.Verify(msg, sig) }); n != 0 {
		t.Fatalf("Verify allocates %v times per call, want 0", n)
	}
}

func TestSchemeIsEd25519(t *testing.T) {
	pub := testKey(t, 7).Public()
	if pub.Scheme() != crypto.SchemeEd25519 {
		t.Fatalf("scheme %d, want %d", pub.Scheme(), crypto.SchemeEd25519)
	}
}

func reversed(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

func TestPublicKeyEqual(t *testing.T) {
	a := testKey(t, 7).Public()
	if !a.Equal(testKey(t, 7).Public()) || a.Equal(testKey(t, 8).Public()) || a.Equal(nil) {
		t.Fatal("Equal does not tell keys apart")
	}
}

// Public keys arrive from transactions and peers, so every accepted one must
// be canonical and in the prime-order subgroup: [l-1]P + P is the identity.
func FuzzPublicKeyFromBytes(f *testing.F) {
	f.Add(testKey(f, 7).Public().Bytes())
	f.Add(mustHex(f, "0100000000000000000000000000000000000000000000000000000000000000"))
	f.Add(mustHex(f, "f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))
	lMinus1 := mustHex(f, "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
	f.Fuzz(func(t *testing.T, b []byte) {
		pub, err := PublicKeyFromBytes(b)
		if err != nil {
			return
		}
		if !bytes.Equal(pub.Bytes(), b) {
			t.Fatalf("%x: kept as %x", b, pub.Bytes())
		}
		p, err := new(edwards25519.Point).SetBytes(b)
		if err != nil {
			t.Fatalf("%x accepted but not a point: %v", b, err)
		}
		k, err := new(edwards25519.Scalar).SetCanonicalBytes(lMinus1)
		if err != nil {
			t.Fatal(err)
		}
		lp := new(edwards25519.Point).Add(new(edwards25519.Point).ScalarMult(k, p), p)
		if lp.Equal(edwards25519.NewIdentityPoint()) != 1 || p.Equal(edwards25519.NewIdentityPoint()) == 1 {
			t.Fatalf("%x accepted outside the prime-order subgroup", b)
		}
	})
}

func BenchmarkPublicKeyFromBytes(b *testing.B) {
	raw := testKey(b, 7).Public().Bytes()
	for b.Loop() {
		pub, _ := PublicKeyFromBytes(raw)
		sink ^= pub.inner[0]
	}
}

func BenchmarkVerify(b *testing.B) {
	priv := testKey(b, 7)
	pub := priv.Public()
	msg := make([]byte, 32)
	sig, _ := priv.Sign(msg)
	for b.Loop() {
		if pub.Verify(msg, sig) {
			sink ^= 1
		}
	}
}

// inv8 is the scalar isPrimeOrder rests on: 8·inv8 must be 1 modulo the order.
func TestInverseOfCofactorIsTheInverse(t *testing.T) {
	eight, err := new(edwards25519.Scalar).SetCanonicalBytes(append([]byte{8}, make([]byte, 31)...))
	if err != nil {
		t.Fatal(err)
	}
	one, err := new(edwards25519.Scalar).SetCanonicalBytes(append([]byte{1}, make([]byte, 31)...))
	if err != nil {
		t.Fatal(err)
	}
	if new(edwards25519.Scalar).Multiply(eight, inv8).Equal(one) != 1 {
		t.Fatal("8 times inv8 is not 1")
	}
}

// The twelve vectors of "Taming the many EdDSAs" (Chalkias, de Valence,
// Lindstrom, Nikolaenko, 2020; github.com/novifinancial/ed25519-speccheck,
// cases.json). Each sits on an edge where implementations disagree: small-order
// and mixed-order A and R, S past the order, non-canonical A and R. Which of
// them a verifier accepts is a consensus rule (docs/PROTOCOL.md, Bab 2), and
// this package rejects every one. For reference, the project's own table has
// Go's crypto/ed25519 accept 0-3 and 11, and libsodium and dalek-strict accept
// 3; a node built on any of those, used as is, would fork from this one.
var specCheckVectors = []struct {
	name, msg, pub, sig string
}{
	{"0: small A, small R, S = 0", "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000"},
	{"1: small A, mixed R", "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"},
	{"2: mixed A, small R", "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e"},
	{"3: mixed A, mixed R", "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009"},
	{"4: mixed A and R, passes cofactored only", "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09"},
	{"5: mixed A, R of order L", "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c", "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d", "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405"},
	{"6: S > L", "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40", "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623", "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514"},
	{"7: S >> L", "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40", "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623", "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22"},
	{"8: non-canonical R, reduced for the hash", "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f"},
	{"9: non-canonical R, not reduced for the hash", "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41", "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908"},
	{"10: non-canonical A, reduced for the hash", "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"},
	{"11: non-canonical A, not reduced for the hash", "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04"},
}

func TestSpecCheckVectorsAreAllRejected(t *testing.T) {
	for _, v := range specCheckVectors {
		t.Run(v.name, func(t *testing.T) {
			pub, err := PublicKeyFromBytes(mustHex(t, v.pub))
			if err != nil {
				return
			}
			sig, err := SignatureFromBytes(mustHex(t, v.sig))
			if err != nil {
				return
			}
			if pub.Verify(mustHex(t, v.msg), sig) {
				t.Fatal("accepted")
			}
		})
	}
}

func TestNilVerification(t *testing.T) {
	var absent *PublicKey
	var sig *Signature
	if (new(PublicKey)).Verify(nil, sig) || absent.Verify(nil, sig) {
		t.Fatal("verified absent input")
	}
}
