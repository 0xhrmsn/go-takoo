// Package crypto holds the key, signature, hash and address types the chain
// works with. The actual algorithms live in subpackages: ed25519 for
// accounts and bls12381 for validators.
//
// Account keys and validator keys are deliberately different types. An
// account key signs transactions, and its public key gives the account its
// address. A validator key signs consensus votes; votes on the same block
// can be added together into one signature, so checking a whole quorum costs
// a single verification. Validator keys have no address of their own. A
// validator is known by its account, which lets it swap its validator key
// without moving its stake.
//
// Keeping the two apart means the compiler won't let you pass a transaction
// signature where a vote is expected, or the other way round.
//
// Private keys are not wiped from memory. A key lives in its object, which has
// no way to erase itself, and its text form is a Go string, which can't be
// erased either, so wiping temporary copies would change nothing. Two buffers
// are the exception: bls12381 wipes its copy of a caller's seed, and
// ed25519/hd wipes the nodes in the middle of a path, which can derive more
// than the key the path leads to.
package crypto

// Bech32m prefixes for keys, shared by every scheme. The scheme follows as
// the first character after the separator ("pub1p..." for Ed25519,
// "pub1z..." for BLS12-381), so a key string says which algorithm it belongs
// to, and parsing it with the wrong package fails instead of giving a
// different key.
const (
	ExtendedPrivateKeyHRP string = "xprv"
	PrivateKeyHRP         string = "prv"
	PublicKeyHRP          string = "pub"
)

// Scheme numbers. The scheme byte goes into every account address, so these
// can't change once the chain is live. A new algorithm gets a new number, and
// a retired number is never handed out again.
const (
	SchemeEd25519  Scheme = 0x01
	SchemeBLS12381 Scheme = 0x02
)

// Scheme says which signature algorithm a key uses.
type Scheme byte

// String returns the algorithm name for logs and error messages, or
// "Unknown" for a number that isn't a scheme.
func (s Scheme) String() string {
	switch s {
	case SchemeEd25519:
		return "Ed25519"
	case SchemeBLS12381:
		return "Bls12381"
	default:
		return "Unknown"
	}
}

// AggregatePrivateKey is the key a validator votes with.
//
// ProvePossession is for registration: the validator signs its own public
// key to show it really holds the secret, and only keys that came with that
// proof are ever added together. Without it, someone could register a key
// crafted from other validators' keys and forge a combined signature in
// their name (the rogue-key attack).
//
// Bytes and String give out the secret itself. Printing the key with fmt
// shows a redacted placeholder instead, so it won't end up in a log by
// accident.
type AggregatePrivateKey interface {
	Bytes() []byte
	Equal(AggregatePrivateKey) bool
	ProvePossession() (AggregateSignature, error)
	Public() AggregatePublicKey
	Sign([]byte) (AggregateSignature, error)
	String() string
}

// PrivateKey is the key an account signs transactions with. Its public key
// decides the account's address.
//
// As with AggregatePrivateKey, Bytes and String expose the secret while fmt
// only ever prints a placeholder.
type PrivateKey interface {
	Bytes() []byte
	Equal(PrivateKey) bool
	Public() PublicKey
	Sign([]byte) (Signature, error)
	String() string
}

// AggregatePublicKey is a validator's public key. Aggregate adds keys
// together so the sum checks the sum of their signatures on one message;
// imported BLS keys must first be admitted with WithProofOfPossession.
type AggregatePublicKey interface {
	Aggregate([]AggregatePublicKey) (AggregatePublicKey, error)
	Bytes() []byte
	Equal(AggregatePublicKey) bool
	Scheme() Scheme
	String() string
	Verify([]byte, AggregateSignature) bool
	VerifyPossession(AggregateSignature) bool
}

// PublicKey is an account's public key. A key always gives the same Address,
// and Verify is false for a signature from a different scheme.
type PublicKey interface {
	Address() Address
	Bytes() []byte
	Equal(PublicKey) bool
	Scheme() Scheme
	String() string
	Verify([]byte, Signature) bool
}

// AggregateSignature is a validator's vote signature. Votes on the same
// message add up into one signature of the same size, which is why a block's
// quorum certificate stays small no matter how many validators signed.
type AggregateSignature interface {
	Aggregate([]AggregateSignature) (AggregateSignature, error)
	Bytes() []byte
	Equal(AggregateSignature) bool
	String() string
}

// Signature is what an account key produces when it signs. Check it with the
// matching PublicKey's Verify.
type Signature interface {
	Bytes() []byte
	Equal(Signature) bool
	String() string
}
