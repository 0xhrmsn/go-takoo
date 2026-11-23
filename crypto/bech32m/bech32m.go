// This file contains code modified from the btcd project,
// which is licensed under the ISC License.
//
// Original license: https://github.com/btcsuite/btcd/blob/master/LICENSE
// The full ISC notice is reproduced in THIRD_PARTY_NOTICES.md at the repo root.

// Package bech32m provides a Go implementation of the bech32m format specified
// in BIP 350.
//
// Bech32m strings consist of a human-readable part (hrp), followed by the
// separator 1, then a checksummed data part encoded using the 32 characters
// "qpzry9x8gf2tvdw0s3jn54khce6mua7l". Bech32m keeps the format of bech32 (BIP
// 173) and only changes the checksum constant. This package accepts bech32m
// alone: a string with the original bech32 checksum is rejected.
//
// The NoLimit functions do NOT validate against the BIP-173 maximum length of
// 90 characters and are meant for longer strings such as serialized extended
// keys, NOT addresses. Their callers bound the length themselves.
//
// More info: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
package bech32m

import (
	"fmt"
	"math"
	"strings"
)

const (
	// checksumConst is the constant used for bech32m checksum verification,
	// defined in BIP 350.
	checksumConst int = 0x2bc830a3

	// charset is the set of characters used in the data section of bech32m
	// strings. Note that this is ordered, such that for a given charset[i], i
	// is the binary value of the character.
	charset string = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

	// maxHRPLength is the maximum length of the human-readable part allowed by
	// BIP 173.
	maxHRPLength int = 83
)

var (
	// gen encodes the generator polynomial for the bech32 BCH checksum.
	gen = [5]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

	// charsetRev maps each ASCII character to its index in charset, or -1 if
	// the character is not part of charset. It replaces a search through
	// charset for every character decoded.
	charsetRev = func() [128]int8 {
		var t [128]int8
		for i := range t {
			t[i] = -1
		}
		for i := 0; i < len(charset); i++ {
			t[charset[i]] = int8(i)
		}
		return t
	}()

	// polymodStep holds, for each of the 32 possible values b of the top 5 bits of
	// the checksum, the XOR of gen[i] for every bit i set in b. It precomputes the
	// generator step of bech32Polymod, which would otherwise test the 5 bits one
	// by one for every character.
	polymodStep = func() [32]int {
		var t [32]int
		for b := 0; b < 32; b++ {
			v := 0
			for j := 0; j < 5; j++ {
				if (b>>uint(j))&1 == 1 {
					v ^= gen[j]
				}
			}
			t[b] = v
		}
		return t
	}()
)

// toBytes converts each character in the string 'chars' to the value of the
// index of the corresponding character in 'charset'.
func toBytes(chars string) ([]byte, error) {
	decoded := make([]byte, len(chars))
	for i := 0; i < len(chars); i++ {
		c := chars[i]
		if c >= 128 || charsetRev[c] < 0 {
			return nil, fmt.Errorf("crypto/bech32m: invalid character not part of charset: %v", c)
		}
		decoded[i] = byte(charsetRev[c])
	}

	return decoded, nil
}

// bech32Polymod calculates the BCH checksum for a given hrp, values and
// checksum data. Checksum is optional, and if nil a 0 checksum is assumed.
//
// Values and checksum (if provided) MUST be encoded as 5 bits per element (base
// 32), otherwise the results are undefined.
//
// For more details on the polymod calculation, please refer to BIP 173.
func bech32Polymod(hrp string, values, checksum []byte) int {
	chk := 1

	for i := 0; i < len(hrp); i++ {
		chk = (chk&0x1ffffff)<<5 ^ (int(hrp[i]) >> 5) ^ polymodStep[chk>>25]
	}

	chk = (chk&0x1ffffff)<<5 ^ polymodStep[chk>>25]

	for i := 0; i < len(hrp); i++ {
		chk = (chk&0x1ffffff)<<5 ^ (int(hrp[i]) & 31) ^ polymodStep[chk>>25]
	}

	for _, v := range values {
		chk = (chk&0x1ffffff)<<5 ^ int(v) ^ polymodStep[chk>>25]
	}

	if checksum == nil {
		for v := 0; v < 6; v++ {
			chk = (chk&0x1ffffff)<<5 ^ polymodStep[chk>>25]
		}
	} else {
		for _, v := range checksum {
			chk = (chk&0x1ffffff)<<5 ^ int(v) ^ polymodStep[chk>>25]
		}
	}

	return chk
}

// writeBech32Checksum calculates the bech32m checksum expected for a string
// that will have the given hrp and payload data and writes it to the provided
// string builder.
//
// The payload data MUST be encoded as a base 32 (5 bits per element) byte slice
// and the hrp MUST only use the allowed character set (ascii chars between 33
// and 126), otherwise the results are undefined.
//
// For more details on the checksum calculation, please refer to BIP 173 and
// BIP 350.
func writeBech32Checksum(hrp string, data []byte, builder *strings.Builder) {
	polymod := bech32Polymod(hrp, data, nil) ^ checksumConst
	for i := 0; i < 6; i++ {
		b := byte((polymod >> uint(5*(5-i))) & 31)

		c := charset[b]
		_ = builder.WriteByte(c)
	}
}

// bech32VerifyChecksum verifies whether the bech32m string specified by the
// provided hrp and payload data (encoded as 5 bits per element byte slice) has
// the correct checksum suffix. Only the bech32m constant is accepted.
//
// Data MUST have at least 6 elements, otherwise this function panics.
//
// For more details on the checksum verification, please refer to BIP 173 and
// BIP 350.
func bech32VerifyChecksum(hrp string, data []byte) bool {
	checksum := data[len(data)-6:]
	values := data[:len(data)-6]

	return bech32Polymod(hrp, values, checksum) == checksumConst
}

// decodeNoLimit decodes a bech32m encoded string, returning the human-readable
// part and the data part excluding the checksum. This function does NOT
// validate against the BIP-173 maximum length allowed for bech32 strings. A
// human-readable part longer than 83 characters is rejected, and the error for
// an invalid checksum never suggests the correct one, as BIP 173 advises.
//
// Note that the returned data is 5-bit (base32) encoded and the human-readable
// part will be lowercase.
func decodeNoLimit(bech string) (string, []byte, error) {
	if len(bech) < 8 {
		return "", nil, fmt.Errorf("crypto/bech32m: invalid bech32 string length %d", len(bech))
	}

	var hasLower, hasUpper bool
	for i := 0; i < len(bech); i++ {
		if bech[i] < 33 || bech[i] > 126 {
			return "", nil, fmt.Errorf("crypto/bech32m: invalid character in string: '%c'", bech[i])
		}

		hasLower = hasLower || (bech[i] >= 97 && bech[i] <= 122)
		hasUpper = hasUpper || (bech[i] >= 65 && bech[i] <= 90)
		if hasLower && hasUpper {
			return "", nil, fmt.Errorf("crypto/bech32m: string not all lowercase or all uppercase")
		}
	}

	if hasUpper {
		bech = strings.ToLower(bech)
	}

	one := strings.LastIndexByte(bech, '1')
	if one < 1 || one+7 > len(bech) {
		return "", nil, fmt.Errorf("crypto/bech32m: separator index %d", one)
	}

	hrp := bech[:one]
	data := bech[one+1:]
	if len(hrp) > maxHRPLength {
		return "", nil, fmt.Errorf("crypto/bech32m: human-readable part length %d, want 1 to %d", len(hrp), maxHRPLength)
	}

	decoded, err := toBytes(data)
	if err != nil {
		return "", nil, err
	}

	// Never suggest the right checksum (BIP-173).
	if !bech32VerifyChecksum(hrp, decoded) {
		return "", nil, fmt.Errorf("crypto/bech32m: invalid checksum")
	}

	payloadLen := len(decoded) - 6
	return hrp, decoded[:payloadLen:payloadLen], nil
}

// decode decodes a bech32m encoded string, returning the human-readable part
// and the data part excluding the checksum. The maximum allowed length for a
// bech32m string is 90.
//
// Note that the returned data is 5-bit (base32) encoded and the human-readable
// part will be lowercase.
func decode(bech string) (string, []byte, error) {
	if len(bech) > 90 {
		return "", nil, fmt.Errorf("crypto/bech32m: invalid bech32 string length %d", len(bech))
	}

	return decodeNoLimit(bech)
}

// checkHRP verifies that the human-readable part has 1 to 83 characters, all of
// them ascii chars between 33 and 126, as BIP 173 requires.
func checkHRP(hrp string) error {
	if len(hrp) == 0 || len(hrp) > maxHRPLength {
		return fmt.Errorf("crypto/bech32m: human-readable part length %d, want 1 to %d", len(hrp), maxHRPLength)
	}

	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return fmt.Errorf("crypto/bech32m: character %#02x in human-readable part, want printable ASCII 33 to 126", hrp[i])
		}
	}

	return nil
}

// encode encodes a byte slice into a bech32m string with the given
// human-readable part (HRP). The HRP is validated with checkHRP, then converted
// to lowercase if needed since mixed cased encodings are not permitted and
// lowercase is used for checksum purposes. Note that the bytes must each
// encode 5 bits (base32).
func encode(hrp string, data []byte) (string, error) {
	if err := checkHRP(hrp); err != nil {
		return "", err
	}

	hrp = strings.ToLower(hrp)
	var builder strings.Builder
	builder.Grow(len(hrp) + 1 + len(data) + 6)
	_, _ = builder.WriteString(hrp)
	_, _ = builder.WriteString("1")

	for _, b := range data {
		if int(b) >= len(charset) {
			return "", fmt.Errorf("crypto/bech32m: invalid data byte: %v", b)
		}
		_ = builder.WriteByte(charset[b])
	}

	writeBech32Checksum(hrp, data, &builder)

	return builder.String(), nil
}

// convertBits converts a byte slice where each byte is encoding fromBits bits,
// to a byte slice where each byte is encoding toBits bits. If pad is set, an
// unfinished group is padded with zeroes; if not, any incomplete group must be
// shorter than fromBits and all zeroes.
func convertBits(data []byte, fromBits, toBits uint8, pad bool) ([]byte, error) {
	if fromBits < 1 || fromBits > 8 || toBits < 1 || toBits > 8 {
		return nil, fmt.Errorf("crypto/bech32m: only bit groups between 1 and 8 allowed")
	}

	// int64 keeps the size from overflowing on 32-bit platforms.
	maxSize := 0
	if size := int64(len(data))*int64(fromBits)/int64(toBits) + 1; size <= math.MaxInt {
		maxSize = int(size)
	}

	regrouped := make([]byte, 0, maxSize)

	var acc uint32
	var filledBits uint8
	toMask := uint32(1)<<toBits - 1

	for _, b := range data {
		if uint32(b) >= 1<<fromBits {
			return nil, fmt.Errorf("crypto/bech32m: invalid data byte: %v", b)
		}

		acc = acc<<fromBits | uint32(b)
		filledBits += fromBits

		for filledBits >= toBits {
			filledBits -= toBits
			regrouped = append(regrouped, byte(acc>>filledBits&toMask))
		}
	}

	if pad {
		if filledBits > 0 {
			regrouped = append(regrouped, byte(acc<<(toBits-filledBits)&toMask))
		}
	} else if filledBits > 0 && (filledBits >= fromBits || acc&(1<<filledBits-1) != 0) {
		return nil, fmt.Errorf("crypto/bech32m: invalid incomplete group")
	}

	return regrouped[:len(regrouped):len(regrouped)], nil
}

// EncodeFromBase256 converts a base256-encoded byte slice into a base32-encoded
// byte slice and then encodes it into a bech32m string with the given
// human-readable part (HRP). The HRP will be converted to lowercase if needed
// since mixed cased encodings are not permitted and lowercase is used for
// checksum purposes. A result longer than the BIP-173 maximum of 90 characters
// is rejected before any work is done.
func EncodeFromBase256(hrp string, data []byte) (string, error) {
	if err := checkHRP(hrp); err != nil {
		return "", err
	}

	encodedLen := int64(len(hrp)) + 1 + (int64(len(data))*8+4)/5 + 6
	if encodedLen > 90 {
		return "", fmt.Errorf("crypto/bech32m: invalid bech32 string length %d", encodedLen)
	}

	return EncodeFromBase256NoLimit(hrp, data)
}

// EncodeFromBase256NoLimit is identical to EncodeFromBase256, but does NOT
// validate against the BIP-173 maximum length allowed for bech32 strings. It is
// meant for custom uses, such as serialized extended keys, NOT addresses.
func EncodeFromBase256NoLimit(hrp string, data []byte) (string, error) {
	converted, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}
	
	return encode(hrp, converted)
}

// DecodeToBase256 decodes a bech32m-encoded string into its associated
// human-readable part (HRP) and base32-encoded data, converts that data to a
// base256-encoded byte slice and returns it along with the lowercase HRP.
func DecodeToBase256(bech string) (string, []byte, error) {
	hrp, data, err := decode(bech)
	if err != nil {
		return "", nil, err
	}

	converted, err := convertBits(data, 5, 8, false)
	if err != nil {
		return "", nil, err
	}

	return hrp, converted, nil
}

// DecodeToBase256NoLimit is identical to DecodeToBase256, but does NOT validate
// against the BIP-173 maximum length allowed for bech32 strings. It is meant for
// custom uses, such as serialized extended keys, NOT addresses.
func DecodeToBase256NoLimit(bech string) (string, []byte, error) {
	hrp, data, err := decodeNoLimit(bech)
	if err != nil {
		return "", nil, err
	}

	converted, err := convertBits(data, 5, 8, false)
	if err != nil {
		return "", nil, err
	}

	return hrp, converted, nil
}

// EncodeFromBase256WithType converts a base256-encoded byte slice into a
// base32-encoded byte slice, puts the given type in front of it as one more
// 5-bit element and encodes the result into a bech32m string with the given
// human-readable part (HRP). The type shows up as the first character after
// the separator, the way a segwit witness version does, so it must be below
// 32.
//
// This function does NOT validate against the BIP-173 maximum length allowed
// for bech32 strings.
func EncodeFromBase256WithType(hrp string, typ byte, data []byte) (string, error) {
	if int(typ) >= len(charset) {
		return "", fmt.Errorf("crypto/bech32m: type %d does not fit in 5 bits", typ)
	}

	converted, err := convertBits(data, 8, 5, true)
	if err != nil {
		return "", err
	}

	return encode(hrp, append([]byte{typ}, converted...))
}

// DecodeToBase256WithType decodes a bech32m string written by
// EncodeFromBase256WithType into its human-readable part (HRP), its type and
// its data, converted back to a base256-encoded byte slice. The HRP is
// returned in lowercase.
//
// This function does NOT validate against the BIP-173 maximum length allowed
// for bech32 strings, so callers must bound the length of bech first.
func DecodeToBase256WithType(bech string) (string, byte, []byte, error) {
	hrp, data, err := decodeNoLimit(bech)
	if err != nil {
		return "", 0, nil, err
	}
	if len(data) == 0 {
		return "", 0, nil, fmt.Errorf("crypto/bech32m: no type character")
	}

	converted, err := convertBits(data[1:], 5, 8, false)
	if err != nil {
		return "", 0, nil, err
	}

	return hrp, data[0], converted, nil
}
