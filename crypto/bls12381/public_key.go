package bls12381

import (
	"bytes"
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"go-takoo/crypto"
	"go-takoo/crypto/bech32m"
)

// publicKeySize is a compressed G2 point, 96 bytes. stringPublicKeySize is
// the length of its Bech32m form: "pub", the separator, the scheme character,
// 154 characters of key and 6 of checksum.
const (
	publicKeySize       = bls12381.SizeOfG2AffineCompressed
	stringPublicKeySize = len(crypto.PublicKeyHRP) + 2 + (publicKeySize*8+4)/5 + 6
)

// negGenerator is the G2 generator, negated. It turns the check
// e(sig, G2) == e(H(m), pk) into e(sig, -G2) * e(H(m), pk) == 1, which needs
// only one final exponentiation.
var negGenerator = func() bls12381.G2Affine {
	_, _, _, g2 := bls12381.Generators()
	var neg bls12381.G2Affine
	return *neg.Neg(&g2)
}()

// PublicKey is a validator's public key, a point in G2. Both the encoded
// bytes and the decoded point are kept so neither has to be recomputed. It
// is never the point at infinity after parsing. Use Equal or the canonical
// bytes for key identity, independent of local possession verification.
type PublicKey struct {
	inner           [publicKeySize]byte
	point           bls12381.G2Affine
	possessionKnown bool
}

// AggregatePublicKey adds keys together into one key that checks the
// combined signature on a single message. Each distinct input must come
// from PrivateKey.Public or WithProofOfPossession. The sum is a verification
// key and cannot itself be supplied as a registered signer.
func AggregatePublicKey(pubs []*PublicKey) (*PublicKey, error) {
	if len(pubs) == 0 {
		return nil, fmt.Errorf("crypto/bls12381: nothing to aggregate")
	}

	seen := make(map[[publicKeySize]byte]struct{}, len(pubs))
	var sum bls12381.G2Jac
	for i, key := range pubs {
		if key == nil || key.point.IsInfinity() {
			return nil, fmt.Errorf("crypto/bls12381: element %d has no material", i)
		}
		if !key.possessionKnown {
			return nil, fmt.Errorf("crypto/bls12381: unverified validator key at index %d", i)
		}
		if _, exists := seen[key.inner]; exists {
			return nil, fmt.Errorf("crypto/bls12381: duplicate validator key at index %d", i)
		}
		seen[key.inner] = struct{}{}
		_ = sum.AddMixed(&key.point)
	}

	var out bls12381.G2Affine
	_ = out.FromJacobian(&sum)
	if out.IsInfinity() {
		return nil, fmt.Errorf("crypto/bls12381: the keys cancel out to the point at infinity, which no private key owns")
	}
	return &PublicKey{
		inner: out.Bytes(),
		point: out,
	}, nil
}

// AggregateVerify reports whether sign is the combined signature of pubs[i]
// signing msgs[i] for every i.
//
// Messages may repeat. Keys that signed the same message are added up first,
// so the cost is one pairing per distinct message plus one, all done as a
// single pairing check. As with AggregatePublicKey, every key should have
// passed its possession check. Anything malformed, such as mismatched
// lengths or a group of keys that sums to infinity, just returns false.
//
// The same key on the same message twice is refused too. Otherwise one
// signer, listed twice next to a doubled signature, would verify as two, and
// anything counting the list would count it twice.
func AggregateVerify(pubs []*PublicKey, msgs [][]byte, sign *Signature) bool {
	if len(pubs) == 0 || len(pubs) != len(msgs) || sign == nil {
		return false
	}

	type pair struct {
		key [publicKeySize]byte
		msg string
	}
	group := make(map[string]int, len(msgs))
	pairs := make(map[pair]struct{}, len(msgs))
	distinct := make([][]byte, 0, len(msgs))
	sums := make([]bls12381.G2Jac, 0, len(msgs))
	for i, key := range pubs {
		if key == nil || !key.possessionKnown || key.point.IsInfinity() {
			return false
		}
		p := pair{key: key.inner, msg: string(msgs[i])}
		if _, dup := pairs[p]; dup {
			return false
		}
		pairs[p] = struct{}{}
		g, seen := group[string(msgs[i])]
		if !seen {
			g = len(sums)
			group[string(msgs[i])] = g
			distinct = append(distinct, msgs[i])
			sums = append(sums, bls12381.G2Jac{})
		}
		_ = sums[g].AddMixed(&key.point)
	}

	hashes := append(make([]bls12381.G1Affine, 0, len(sums)+1), sign.point)
	keys := append(make([]bls12381.G2Affine, 0, len(sums)+1), negGenerator)
	for g := range sums {
		var key bls12381.G2Affine
		_ = key.FromJacobian(&sums[g])
		if key.IsInfinity() {
			return false
		}
		hashed, err := bls12381.HashToG1(distinct[g], dstSignature)
		if err != nil {
			return false
		}
		hashes = append(hashes, hashed)
		keys = append(keys, key)
	}
	ok, err := bls12381.PairingCheck(hashes, keys)

	return err == nil && ok
}

// PublicKeyFromBytes reads a 96-byte public key. gnark-crypto already rejects
// bad encodings and points outside G2; on top of that we reject the point at
// infinity, which no private key owns.
func PublicKeyFromBytes(b []byte) (*PublicKey, error) {
	if len(b) != publicKeySize {
		return nil, fmt.Errorf("crypto/bls12381: public key size %d, want %d", len(b), publicKeySize)
	}

	var point bls12381.G2Affine
	if _, err := point.SetBytes(b); err != nil {
		return nil, fmt.Errorf("crypto/bls12381: public key is not a point in G2: %v", err)
	}
	if point.IsInfinity() {
		return nil, fmt.Errorf("crypto/bls12381: public key is the point at infinity, which no private key owns")
	}

	return &PublicKey{
		inner: [publicKeySize]byte(b),
		point: point,
	}, nil
}

// PublicKeyFromString parses what String prints ("pub" in Bech32m, the scheme
// as the first character after the separator) and runs the same checks as
// PublicKeyFromBytes. Its exact length is checked before decoding, and a key
// string of another scheme is refused.
func PublicKeyFromString(s string) (*PublicKey, error) {
	if len(s) != stringPublicKeySize {
		return nil, fmt.Errorf("crypto/bls12381: public key string has %d characters, want %d", len(s), stringPublicKeySize)
	}

	hrp, typ, b, err := bech32m.DecodeToBase256WithType(s)
	if err != nil {
		return nil, fmt.Errorf("crypto/bls12381: public key string is not bech32m: %v", err)
	}
	if hrp != crypto.PublicKeyHRP {
		return nil, fmt.Errorf("crypto/bls12381: public key string has prefix %q, want %q", hrp, crypto.PublicKeyHRP)
	}
	if crypto.Scheme(typ) != crypto.SchemeBLS12381 {
		return nil, fmt.Errorf("crypto/bls12381: public key string is for scheme %s, want %s", crypto.Scheme(typ), crypto.SchemeBLS12381)
	}

	return PublicKeyFromBytes(b)
}

// verify checks e(sign, -G2) * e(H(msg), pub) == 1, with msg hashed under
// dst. The infinite-key check comes first on purpose: gnark-crypto skips
// pairs that contain infinity, so an infinite key would happily accept an
// infinite signature.
func (pub *PublicKey) verify(msg, dst []byte, sign crypto.AggregateSignature) bool {
	xBls, ok := sign.(*Signature)
	if !ok || xBls == nil || pub == nil || pub.point.IsInfinity() {
		return false
	}

	hashed, err := bls12381.HashToG1(msg, dst)
	if err != nil {
		return false
	}

	ok, err = bls12381.PairingCheck(
		[]bls12381.G1Affine{
			xBls.point,
			hashed,
		},
		[]bls12381.G2Affine{
			negGenerator,
			pub.point,
		},
	)

	return err == nil && ok
}

// Aggregate is AggregatePublicKey with pub first in the list. Every other
// element has to be a BLS12-381 key too.
func (pub *PublicKey) Aggregate(others []crypto.AggregatePublicKey) (crypto.AggregatePublicKey, error) {
	pubs := append(make([]*PublicKey, 0, len(others)+1), pub)
	for i, x := range others {
		xBls, ok := x.(*PublicKey)
		if !ok {
			return nil, fmt.Errorf("crypto/bls12381: element %d is not a BLS12-381 public key", i+1)
		}
		pubs = append(pubs, xBls)
	}

	aggregate, err := AggregatePublicKey(pubs)
	if err != nil {
		return nil, err
	}

	return aggregate, nil
}

// Bytes returns a copy of the 96-byte key, safe to modify.
func (pub *PublicKey) Bytes() []byte {
	return bytes.Clone(pub.inner[:])
}

// Equal reports whether x is the same key. Keys from other schemes never are.
func (pub *PublicKey) Equal(x crypto.AggregatePublicKey) bool {
	xBls, ok := x.(*PublicKey)
	if !ok {
		return false
	}

	return pub.inner == xBls.inner
}

// Scheme returns SchemeBLS12381. Validator keys have no address, so this only
// labels the algorithm.
func (PublicKey) Scheme() crypto.Scheme {
	return crypto.SchemeBLS12381
}

// String returns the key in Bech32m with the "pub" prefix, the scheme showing
// as "z", the first character after the separator. At 165 characters it runs
// past Bech32m's usual 90-character limit.
func (pub *PublicKey) String() string {
	s, _ := bech32m.EncodeFromBase256WithType(crypto.PublicKeyHRP, byte(crypto.SchemeBLS12381), pub.inner[:])

	return s
}

// Verify reports whether sign is a valid vote signature on msg under pub. It
// works the same for a single key or an aggregated one. A possession proof
// never passes here.
func (pub *PublicKey) Verify(msg []byte, sign crypto.AggregateSignature) bool {
	return pub.verify(msg, dstSignature, sign)
}

// VerifyPossession reports whether proof is the possession proof for pub, as
// made by ProvePossession. A validator's key has to pass this before it is
// aggregated with anyone else's.
func (pub *PublicKey) VerifyPossession(proof crypto.AggregateSignature) bool {
	return pub != nil && pub.verify(pub.inner[:], dstPop, proof)
}

// WithProofOfPossession returns a copy eligible for aggregation after checking
// the proof against this exact key. Deserialized keys must pass this step at
// registration and rotation. Neither the receiver nor other copies change.
func (pub *PublicKey) WithProofOfPossession(proof crypto.AggregateSignature) (*PublicKey, error) {
	if !pub.VerifyPossession(proof) {
		return nil, fmt.Errorf("crypto/bls12381: invalid proof of possession")
	}
	verified := *pub
	verified.possessionKnown = true
	return &verified, nil
}
