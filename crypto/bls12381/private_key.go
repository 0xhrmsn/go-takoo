// Package bls12381 provides the validator keys for package crypto: BLS
// signatures on the BLS12-381 curve, following the IETF BLS draft.
//
// Signatures are 48-byte G1 points and public keys 96-byte G2 points, the
// "minimal signature size" variant Sui and the Internet Computer also use.
// Votes are the message sent most often and a quorum certificate rides in
// every block, so the smaller signature is the one worth having; a public key
// is sent once, when a validator registers or rotates its key. Signing and
// verifying are also cheaper, since messages hash to G1 rather than G2.
//
// It uses the proof-of-possession ciphersuite: a key can only be aggregated
// once its owner has proven they hold the secret, which is what stops
// rogue-key attacks. Votes and proofs are hashed under different tags, so one
// can't be passed off as the other.
//
// The curve math comes from gnark-crypto, which isn't constant-time. To keep
// the key from leaking through timing it is never multiplied in directly;
// split cuts it into two random halves every time instead.
package bls12381

import (
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"go-takoo/crypto"
	"go-takoo/crypto/bech32m"
)

// seedSize is the least key material the IETF KeyGen allows, keyGenLength
// how many bytes HKDF produces before reducing mod r (48, so the result is
// close to uniform), and privateKeySize the size of an encoded scalar.
const (
	seedSize       = 32
	keyGenLength   = 48
	privateKeySize = fr.Bytes

	// stringPrivateKeySize is the length of String's form: "prv", the separator,
	// the scheme character, 52 characters of scalar and 6 of checksum.
	stringPrivateKeySize = len(crypto.PrivateKeyHRP) + 2 + (privateKeySize*8+4)/5 + 6
)

// groupOrder is r. A private key is a number from 1 to r-1.
var groupOrder = fr.Modulus()

// PrivateKey is the key a validator signs votes with.
type PrivateKey struct {
	inner *big.Int
}

// keyGen is the IETF KeyGen, which EIP-2333 calls HKDF_mod_r: run
// HKDF-SHA256 over the key material, reduce the output mod r, and go round
// again with a fresh salt in the unlikely case the result is zero. It wipes
// its copy of ikm, so a caller that wipes ikm leaves no copy of it behind.
func keyGen(ikm []byte) (*big.Int, error) {
	secret := make([]byte, len(ikm)+1)
	_ = copy(secret, ikm)

	info := string([]byte{0, keyGenLength})
	salt := []byte("BLS-SIG-KEYGEN-SALT-")

	sk := new(big.Int)

	for sk.Sign() == 0 {
		next := sha256.Sum256(salt)
		salt = next[:]
		prk, err := hkdf.Extract(sha256.New, secret, salt)
		if err != nil {
			return nil, fmt.Errorf("crypto/bls12381: HKDF failed: %v", err)
		}
		okm, err := hkdf.Expand(sha256.New, prk, info, keyGenLength)
		if err != nil {
			return nil, fmt.Errorf("crypto/bls12381: HKDF failed: %v", err)
		}
		_ = sk.SetBytes(okm)
		_ = sk.Mod(sk, groupOrder)
	}
	clear(secret)

	return sk, nil
}

// PrivateKeyFromSeed derives a key from seed, which must be at least 32
// bytes. The same seed always gives the same key, so the seed should come
// from a good random source or from package hd.
func PrivateKeyFromSeed(seed []byte) (*PrivateKey, error) {
	if len(seed) < seedSize {
		return nil, fmt.Errorf("crypto/bls12381: seed size %d, want at least %d", len(seed), seedSize)
	}

	scalar, err := keyGen(seed)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		inner: scalar,
	}, nil
}

// PrivateKeyFromBytes reads the 32 bytes Bytes returns. Zero and anything at
// or above r are rejected, so each key has exactly one encoding.
func PrivateKeyFromBytes(b []byte) (*PrivateKey, error) {
	if len(b) != privateKeySize {
		return nil, fmt.Errorf("crypto/bls12381: private key size %d, want %d", len(b), privateKeySize)
	}

	scalar := new(big.Int).SetBytes(b)
	if scalar.Sign() == 0 {
		return nil, fmt.Errorf("crypto/bls12381: private key is zero, which owns no public key")
	}
	if scalar.Cmp(groupOrder) >= 0 {
		return nil, fmt.Errorf("crypto/bls12381: private key is not below the group order")
	}

	return &PrivateKey{
		inner: scalar,
	}, nil
}

// PrivateKeyFromString parses what String prints ("prv" in Bech32m, the
// scheme as the first character after the separator). Its exact length is
// checked before decoding, and a key string of another scheme is refused.
func PrivateKeyFromString(s string) (*PrivateKey, error) {
	if len(s) != stringPrivateKeySize {
		return nil, fmt.Errorf("crypto/bls12381: private key string has %d characters, want %d", len(s), stringPrivateKeySize)
	}

	hrp, typ, b, err := bech32m.DecodeToBase256WithType(s)
	if err != nil {
		return nil, fmt.Errorf("crypto/bls12381: private key string is not bech32m: %v", err)
	}
	if hrp != crypto.PrivateKeyHRP {
		return nil, fmt.Errorf("crypto/bls12381: private key string has prefix %q, want %q", hrp, crypto.PrivateKeyHRP)
	}
	if crypto.Scheme(typ) != crypto.SchemeBLS12381 {
		return nil, fmt.Errorf("crypto/bls12381: private key string is for scheme %s, want %s", crypto.Scheme(typ), crypto.SchemeBLS12381)
	}

	return PrivateKeyFromBytes(b)
}

// split returns two halves a and b with a + b = key mod r, where a is fresh
// randomness every time. Multiplying a point by both and adding gives the
// same result as using the key, but the variable-time code only ever sees
// random-looking numbers.
func (prv *PrivateKey) split() (a, b *big.Int) {
	var sk, ea, eb fr.Element
	_ = sk.SetBigInt(prv.inner)
	_ = ea.MustSetRandom()
	_ = eb.Sub(&sk, &ea)

	return ea.BigInt(new(big.Int)), eb.BigInt(new(big.Int))
}

// sign hashes msg onto G1 under the tag dst and multiplies by the key, by way
// of split.
func (prv *PrivateKey) sign(msg, dst []byte) (crypto.AggregateSignature, error) {
	hashed, err := bls12381.HashToG1(msg, dst)
	if err != nil {
		return nil, fmt.Errorf("crypto/bls12381: could not hash the message to a curve point: %v", err)
	}

	a, b := prv.split()
	var q, sum, part bls12381.G1Jac
	_ = q.FromAffine(&hashed)
	_ = sum.ScalarMultiplication(&q, a)
	_ = part.ScalarMultiplication(&q, b)
	_ = sum.AddAssign(&part)

	var point bls12381.G1Affine
	_ = point.FromJacobian(&sum)

	return &Signature{
		inner: point.Bytes(),
		point: point,
	}, nil
}

// Bytes returns the key as 32 big-endian bytes. That's the secret.
func (prv *PrivateKey) Bytes() []byte {
	out := make([]byte, privateKeySize)
	_ = prv.inner.FillBytes(out)

	return out
}

// Equal reports whether x is the same key, comparing in constant time. Keys
// from other schemes never are.
func (prv *PrivateKey) Equal(x crypto.AggregatePrivateKey) bool {
	xBls, ok := x.(*PrivateKey)
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare(prv.Bytes(), xBls.Bytes()) == 1
}

// Format makes fmt print a redacted placeholder whatever the verb, so the key
// can't end up in a log. Call String when you really mean to export it.
func (PrivateKey) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "bls12381.PrivateKey(REDACTED)")
}

// ProvePossession signs the key's own public key under the
// proof-of-possession tag. A validator sends this once, when it registers.
// Because the tag differs from Sign's, the proof can't be used as a vote,
// and no vote can stand in for a proof.
func (prv *PrivateKey) ProvePossession() (crypto.AggregateSignature, error) {
	return prv.sign(prv.Public().Bytes(), dstPop)
}

// Public returns the public key. It's computed fresh on every call, so hold
// on to it if you need it often.
func (prv *PrivateKey) Public() crypto.AggregatePublicKey {
	a, b := prv.split()
	var sum, part bls12381.G2Jac
	_ = sum.ScalarMultiplicationBase(a)
	_ = part.ScalarMultiplicationBase(b)
	_ = sum.AddAssign(&part)

	var point bls12381.G2Affine
	_ = point.FromJacobian(&sum)

	return &PublicKey{
		possessionKnown: true,
		inner:           point.Bytes(),
		point:           point,
	}
}

// Sign signs msg into a 48-byte signature. BLS signing is deterministic, so
// the same key and message always give the same signature. It only fails if msg can't be hashed to the
// curve.
func (prv *PrivateKey) Sign(msg []byte) (crypto.AggregateSignature, error) {
	return prv.sign(msg, dstSignature)
}

// String exports the key as Bech32m with the "prv" prefix, the scheme showing
// as "z", the first character after the separator. Whoever has this string
// can vote as the validator.
func (prv *PrivateKey) String() string {
	s, _ := bech32m.EncodeFromBase256WithType(crypto.PrivateKeyHRP, byte(crypto.SchemeBLS12381), prv.Bytes())

	return s
}
