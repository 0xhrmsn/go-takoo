package crypto

import (
	"bytes"
	"fmt"
	"io"

	"go-takoo/crypto/bech32m"
)

// AddressSize is how long an address is: one SHA3-256 digest. addressHRP is
// the Bech32m prefix of its text form.
const (
	AddressSize int    = 32
	addressHRP  string = "ad"
)

// Address identifies an account. It's the SHA3-256 of the key's scheme byte
// followed by the public key, so the same key bytes under two schemes still
// give two different addresses.
//
// Being an array, it works as a map key and compares with ==. The zero value
// means "no address"; you won't get it from a real key.
type Address [AddressSize]byte

// AddressFromBytes turns 32 raw bytes into an Address. It only checks the
// length; whether any key owns the address is not its concern.
func AddressFromBytes(b []byte) (Address, error) {
	var a Address
	err := a.SetBytes(b)
	if err != nil {
		return Address{}, err
	}

	return a, nil
}

// AddressFromString parses what String prints: Bech32m with the "ad" prefix.
// A bad checksum, another prefix or the wrong length is an error.
func AddressFromString(s string) (Address, error) {
	if len(s) == 0 {
		return Address{}, fmt.Errorf("crypto: empty address string")
	}

	hrp, b, err := bech32m.DecodeToBase256(s)
	if err != nil {
		return Address{}, fmt.Errorf("crypto: address string is not bech32m: %v", err)
	}
	if hrp != addressHRP {
		return Address{}, fmt.Errorf("crypto: address string has prefix %q, want %q", hrp, addressHRP)
	}

	return AddressFromBytes(b)
}

// Bytes returns a copy of the address, safe to modify.
func (a Address) Bytes() []byte {
	return bytes.Clone(a[:])
}

// Empty reports whether a is the zero address.
func (a Address) Empty() bool {
	return a.Equal(Address{})
}

// Equal reports whether a and other are the same address.
func (a Address) Equal(other Address) bool {
	return bytes.Equal(a[:], other[:])
}

// String is the form people see, "ad1..." in Bech32m. Its checksum catches
// most typos.
func (a Address) String() string {
	s, _ := bech32m.EncodeFromBase256(addressHRP, a[:])

	return s
}

// Format lets fmt print the address as hex with %x or %X, and as String with
// %s, %v and %q.
func (a Address) Format(state fmt.State, verb rune) {
	switch verb {
	case 'x':
		_, _ = fmt.Fprintf(state, "%x", a[:])
	case 'X':
		_, _ = fmt.Fprintf(state, "%X", a[:])
	case 's', 'v', 'q':
		text := a.String()
		if verb == 'q' {
			text = `"` + text + `"`
		}
		_, _ = io.WriteString(state, text)
	default:
		_, _ = fmt.Fprintf(state, "%%!%c(crypto.Address=%s)", verb, a.String())
	}
}

// MarshalText makes JSON and other text encodings use the Bech32m form.
func (a Address) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

// UnmarshalText reads the Bech32m form. If it fails, a is left as it was.
func (a *Address) UnmarshalText(text []byte) error {
	parsed, err := AddressFromString(string(text))
	if err != nil {
		return err
	}
	*a = parsed

	return nil
}

// SetBytes copies b into a, but only if b is exactly AddressSize bytes long;
// otherwise a stays as it was.
func (a *Address) SetBytes(b []byte) error {
	l := len(b)
	if l != AddressSize {
		return fmt.Errorf("crypto: address length %d, want %d", l, AddressSize)
	}
	_ = copy(a[:], b)

	return nil
}
