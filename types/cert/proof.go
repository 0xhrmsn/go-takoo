// Package cert holds the certificate a committee produces when it agrees on
// something: the bitmap of who signed and the one aggregate signature they add
// up to.
//
// It sits in types, not in consensus, on purpose. A proof is carried inside the
// block header, so its layout is frozen the moment a chain has a genesis, while
// the rules that decide when a proof is valid -- the two-thirds threshold, the
// round it belongs to, who the committee even is -- belong to whichever
// consensus engine is running and may be replaced. Keeping the shape here lets
// the engine change without touching the block format.
package cert

import (
	"bytes"
	"fmt"
	"math/bits"
)

// MaxCommitteeSize bounds how long a signer bitmap may be, so a peer cannot
// hand over a proof that claims a committee far larger than any epoch holds and
// make the reader allocate for it.
const MaxCommitteeSize = 1024

// Proof is a committee's collective signature over one digest.
//
// It says the listed members signed; it does not say what they signed, nor that
// enough of them did. The digest comes from whatever carries the proof (a block
// header names its own ancestor), and the threshold is the engine's rule. A
// proof for a block means that block was certified, which is not the same as
// committed: under a two-chain commit rule a block is final only once its child
// is certified too.
type Proof struct {
	// Signers is a bitmap over the committee, one bit per member, in index
	// order. A bitmap rather than a list of addresses: at 128 members it is 16
	// bytes instead of 4 KB, and it cannot name the same signer twice.
	Signers []byte
	// Signature is the BLS aggregate of every signature the bitmap claims.
	Signature []byte
}

// BasicCheck rejects what can be judged without a committee: sizes, and a
// bitmap that claims nobody. Whether the signers add up to a quorum, and
// whether the signature verifies, needs the epoch's committee and is checked
// there.
func (p Proof) BasicCheck() error {
	if len(p.Signers) == 0 {
		return fmt.Errorf("types/cert: proof has no signer bitmap")
	}
	if len(p.Signers)*8 > MaxCommitteeSize {
		return fmt.Errorf("types/cert: signer bitmap covers %d members, want at most %d", len(p.Signers)*8, MaxCommitteeSize)
	}
	if p.Count() == 0 {
		return fmt.Errorf("types/cert: proof claims no signers")
	}
	if len(p.Signature) == 0 {
		return fmt.Errorf("types/cert: proof carries no signature")
	}

	return nil
}

// Count is how many members the bitmap claims signed.
func (p Proof) Count() int {
	total := 0
	for _, b := range p.Signers {
		total += bits.OnesCount8(b)
	}

	return total
}

// Signed reports whether the member at index signed. An index past the bitmap
// did not sign: a proof drawn for a smaller committee never speaks for members
// it has no bit for.
func (p Proof) Signed(index int) bool {
	if index < 0 || index/8 >= len(p.Signers) {
		return false
	}

	return p.Signers[index/8]&(1<<(index%8)) != 0
}

// Equal compares two proofs. The bitmap is compared as bytes, so two proofs
// with the same signers but differently sized bitmaps are not equal -- which is
// what the encoding requires anyway, since both are hashed as they stand.
func (p Proof) Equal(other Proof) bool {
	return bytes.Equal(p.Signers, other.Signers) && bytes.Equal(p.Signature, other.Signature)
}

// NewSigners returns an empty bitmap wide enough for size members.
func NewSigners(size int) []byte {
	return make([]byte, (size+7)/8)
}

// SetSigner marks index as having signed. It is the only way a bitmap is
// filled, so the layout lives in one place.
func SetSigner(signers []byte, index int) {
	if index < 0 || index/8 >= len(signers) {
		return
	}
	signers[index/8] |= 1 << (index % 8)
}
