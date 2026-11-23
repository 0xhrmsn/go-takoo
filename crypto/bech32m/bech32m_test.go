// This file contains code modified from the btcd project,
// which is licensed under the ISC License.
//
// Original license: https://github.com/btcsuite/btcd/blob/master/LICENSE
//
// btcd's package implements both Bech32 and Bech32m, so its vectors for plain
// Bech32 and its DecodeGeneric version check do not carry over. What remains is
// the Bech32m half, which matches BIP-350's own vectors, and the bit-conversion
// tables, which are independent of the checksum.

package bech32m

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// sample is a 49-byte payload shared by the conversion table and the
// benchmarks.
const sample = "cbe6365ddbcda9a9915422c3f091c13f8c7b2f263b8d34067bd12c274408473fa764871c9dd51b1bb34873b3473b633ed1"

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}

	return b
}

// withChecksum appends a valid Bech32m checksum to hrp and 5-bit data without
// any of encode's checks, so a test can build a string that is sound in every
// respect but the one it means to break.
func withChecksum(hrp string, data []byte) string {
	var b strings.Builder
	_, _ = b.WriteString(hrp + "1")
	for _, v := range data {
		_ = b.WriteByte(charset[v])
	}
	writeBech32Checksum(hrp, data, &b)

	return b.String()
}

// TestBIP350Vectors runs the valid and invalid strings of BIP-350. A valid one
// must re-encode to its lowercase form, and must stop decoding once one
// character after the separator is flipped.
func TestBIP350Vectors(t *testing.T) {
	valid := []string{
		"A1LQFN3A",
		"a1lqfn3a",
		"an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
		"abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
		"11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
		"split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
		"?1v759aa",
	}
	for _, s := range valid {
		hrp, data, err := decode(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if encoded, err := encode(hrp, data); err != nil || encoded != strings.ToLower(s) {
			t.Fatalf("%q re-encoded to %q (%v)", s, encoded, err)
		}
		pos := strings.LastIndexByte(s, '1')
		if _, _, err := decode(s[:pos+1] + string(s[pos+1]^1) + s[pos+2:]); err == nil {
			t.Fatalf("%q: a flipped character decoded", s)
		}
	}

	invalid := map[string]string{
		"\x201xj0phk":   "hrp character below the printable range",
		"\x7f1g6xzxy":   "hrp character above the printable range",
		"\x801vctc34":   "hrp character outside ascii",
		"qyrz8wqd2c9m":  "no separator",
		"1qyrz8wqd2c9m": "empty hrp",
		"16plkw9":       "empty hrp",
		"1p2gdwpf":      "empty hrp",
		"y1b0jsk6g":     "invalid data character b",
		"lt1igcx5c0":    "invalid data character i",
		"in1muywd":      "checksum too short",
		"mm1crxm3i":     "invalid character in checksum",
		"au1s5cgom":     "invalid character in checksum",
		"M1VUXWEZ":      "checksum computed over the uppercase hrp",
		"aBcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx":                                               "mixed case in the hrp",
		"abcdef1L7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx":                                               "mixed case in the data",
		"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw":                                               "a Bech32 checksum, not Bech32m",
		"an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4": "over 90 characters",
	}
	for s, why := range invalid {
		if _, _, err := DecodeToBase256(s); err == nil {
			t.Errorf("%q decoded: %s", s, why)
		}
	}

	// A broken string fails its checksum too, so these are checked by reason:
	// each guard has to refuse its case before the checksum would.
	for s, want := range map[string]string{
		"y1b0jsk6g":     "not part of charset",
		"1qyrz8wqd2c9m": "separator index",
		"a1lqfn3":       "string length",
	} {
		if _, _, err := decode(s); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", s, err, want)
		}
	}
}

// TestBase256RoundTrip encodes bytes under an hrp spelled in upper, lower and
// mixed case, which must all give one lowercase string, and decodes that string
// in both cases back to the lowercase hrp and the same bytes.
func TestBase256RoundTrip(t *testing.T) {
	tests := []struct{ hrp, data string }{
		{"a", ""},
		{"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio", ""},
		{"abcdef", "00443214c74254b635cf84653a56d7c675be77df"},
		{"1", "0000000000000000000000000000000000000000"},
		{"split", "c5f38b70305f519bf66d85fb6cf03058f3dde463ecd7918f2dc743918f2d"},
		{"takoo", strings.Repeat("ab", 32)},
	}
	for _, tt := range tests {
		data := mustHex(t, tt.data)
		encoded, err := EncodeFromBase256(tt.hrp, data)
		if err != nil {
			t.Fatalf("%q: %v", tt.hrp, err)
		}
		mixed := []byte(tt.hrp)
		for i := 0; i < len(mixed); i += 2 {
			mixed[i] = strings.ToUpper(string(mixed[i]))[0]
		}
		for _, hrp := range []string{strings.ToUpper(tt.hrp), string(mixed)} {
			if got, err := EncodeFromBase256(hrp, data); err != nil || got != encoded {
				t.Fatalf("%q encoded to %q, want %q (%v)", hrp, got, encoded, err)
			}
		}
		for _, s := range []string{encoded, strings.ToUpper(encoded)} {
			hrp, got, err := DecodeToBase256(s)
			if err != nil || hrp != strings.ToLower(tt.hrp) || !bytes.Equal(got, data) {
				t.Fatalf("%q decoded to %q %x (%v)", s, hrp, got, err)
			}
		}
	}
}

// TestLengthCapsAreExact pins the BIP-173 limits at their edge: 90 characters
// pass and 91 do not, on both sides of the bounded pair, and an hrp of 84
// characters is refused even without the overall cap.
func TestLengthCapsAreExact(t *testing.T) {
	payload := make([]byte, 50) // 80 data characters
	for _, c := range []struct {
		hrp string
		ok  bool
	}{{"abc", true}, {"abcd", false}} {
		s, err := EncodeFromBase256(c.hrp, payload)
		if (err == nil) != c.ok {
			t.Fatalf("encoding to %d characters: %v", len(c.hrp)+87, err)
		}
		long, _ := EncodeFromBase256NoLimit(c.hrp, payload)
		if _, _, err := DecodeToBase256(long); (err == nil) != c.ok {
			t.Fatalf("decoding %d characters: %v", len(long), err)
		}
		if c.ok && s != long {
			t.Fatal("the bounded and unbounded encoders disagree")
		}
	}

	if _, _, err := DecodeToBase256NoLimit(withChecksum(strings.Repeat("a", maxHRPLength+1), nil)); err == nil {
		t.Error("an hrp over the cap decoded")
	}
	if _, _, err := DecodeToBase256NoLimit(withChecksum(strings.Repeat("a", maxHRPLength), nil)); err != nil {
		t.Errorf("an hrp at the cap was refused: %v", err)
	}
}

// TestNoLimitPair runs a payload too long for the bounded pair through the
// unbounded one, which extended keys need, and checks a broken checksum is
// still caught there.
func TestNoLimitPair(t *testing.T) {
	payload := make([]byte, 120)
	for i := range payload {
		payload[i] = byte(i)
	}
	input, err := EncodeFromBase256NoLimit("takoo", payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EncodeFromBase256("takoo", payload); err == nil {
		t.Fatal("the bounded encoder accepted a payload past the cap")
	}
	if hrp, data, err := DecodeToBase256NoLimit(input); err != nil || hrp != "takoo" || !bytes.Equal(data, payload) {
		t.Fatalf("round trip: %q %x (%v)", hrp, data, err)
	}
	last := strings.IndexByte(charset, input[len(input)-1])
	if _, _, err := DecodeToBase256NoLimit(input[:len(input)-1] + string(charset[(last+1)%len(charset)])); err == nil {
		t.Fatal("a broken checksum decoded")
	}
}

// TestWithTypePair covers the encoding Pactus uses for typed payloads: the
// type rides as the first 5-bit character after the separator, the data
// follows on its own, and neither function caps the length.
func TestWithTypePair(t *testing.T) {
	for _, size := range []int{0, 1, 32, 96} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i * 7)
		}
		for typ := range byte(32) {
			s, err := EncodeFromBase256WithType("takoo", typ, payload)
			if err != nil {
				t.Fatalf("type %d, %d bytes: %v", typ, size, err)
			}
			if got := s[len("takoo1")]; got != charset[typ] {
				t.Fatalf("type %d shows as %q, want %q", typ, got, charset[typ])
			}
			hrp, gotTyp, data, err := DecodeToBase256WithType(s)
			if err != nil || hrp != "takoo" || gotTyp != typ || !bytes.Equal(data, payload) {
				t.Fatalf("round trip of type %d, %d bytes: %q %d %x (%v)", typ, size, hrp, gotTyp, data, err)
			}
		}
	}

	for _, typ := range []byte{32, 33, 128, 255} {
		if _, err := EncodeFromBase256WithType("takoo", typ, []byte{1}); err == nil {
			t.Errorf("type %d, which does not fit in 5 bits, was accepted", typ)
		}
	}
	if _, err := EncodeFromBase256WithType("", 1, []byte{1}); err == nil {
		t.Error("an empty hrp was accepted")
	}

	noType, err := encode("takoo", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := DecodeToBase256WithType(noType); err == nil || !strings.Contains(err.Error(), "no type character") {
		t.Errorf("a string without a type character: err = %v", err)
	}
	notByteAligned, err := encode("takoo", []byte{1, 0x1f, 0x1c, 0x10})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := DecodeToBase256WithType(notByteAligned); err == nil {
		t.Error("data that does not pack into whole bytes was accepted after the type")
	}
	s, err := EncodeFromBase256WithType("takoo", 1, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	last := strings.IndexByte(charset, s[len(s)-1])
	if _, _, _, err := DecodeToBase256WithType(s[:len(s)-1] + string(charset[(last+1)%len(charset)])); err == nil {
		t.Error("a broken checksum decoded")
	}
}

// TestEncodeRejects covers what the encoders refuse: an hrp that is empty,
// over the cap or not printable ASCII, and a 5-bit value with no character.
func TestEncodeRejects(t *testing.T) {
	for _, hrp := range []string{"", strings.Repeat("a", maxHRPLength+1), "tak oo", "tak\x00oo", "tak\x7foo", "tak\x80oo"} {
		if _, err := EncodeFromBase256(hrp, []byte{1, 2, 3}); err == nil {
			t.Errorf("EncodeFromBase256 accepted hrp %q", hrp)
		}
		if _, err := EncodeFromBase256NoLimit(hrp, []byte{1, 2, 3}); err == nil {
			t.Errorf("EncodeFromBase256NoLimit accepted hrp %q", hrp)
		}
	}
	// The conversion never makes a value over 31, so only encode itself can
	// be handed one.
	for _, b := range []byte{32, 33, 128, 255} {
		if _, err := encode("takoo", []byte{0, b, 0}); err == nil {
			t.Errorf("encode accepted the 5-bit value %d", b)
		}
	}
}

// TestDecodeRejectsIncompleteByteGroups covers a string whose checksum is sound
// but whose 5-bit data leaves a partial byte with bits set: bech32m does not
// need a byte-aligned payload, so the conversion is where this is caught.
func TestDecodeRejectsIncompleteByteGroups(t *testing.T) {
	notByteAligned, err := encode("takoo", []byte{0x1f, 0x1c, 0x10})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decode(notByteAligned); err != nil {
		t.Fatalf("the string itself is valid bech32m: %v", err)
	}
	if _, _, err := DecodeToBase256(notByteAligned); err == nil {
		t.Error("DecodeToBase256 accepted data that does not pack into whole bytes")
	}
	if _, _, err := DecodeToBase256NoLimit(notByteAligned); err == nil {
		t.Error("DecodeToBase256NoLimit accepted data that does not pack into whole bytes")
	}
}

// TestConvertBits runs the bit-conversion tables, which are independent of the
// checksum and so carry over from btcd unchanged.
func TestConvertBits(t *testing.T) {
	tests := []struct {
		input, output    string
		fromBits, toBits uint8
		pad              bool
	}{
		// Empty input.
		{"", "", 8, 5, false},
		{"", "", 8, 5, true},
		{"", "", 5, 8, false},
		{"", "", 5, 8, true},
		// Zero, with and without padding.
		{"00", "00", 8, 5, false},
		{"00", "0000", 8, 5, true},
		{"0000", "00", 5, 8, false},
		{"0000", "0000", 5, 8, true},
		// Ending exactly on a byte edge, where padding changes nothing.
		{"0000000000", "0000000000000000", 8, 5, false},
		{"0000000000", "0000000000000000", 8, 5, true},
		{"0000000000000000", "0000000000", 5, 8, false},
		{"0000000000000000", "0000000000", 5, 8, true},
		// Full bytes.
		{"ffffff", "1f1f1f1f1e", 8, 5, true},
		{"1f1f1f1f1e", "ffffff", 5, 8, false},
		{"1f1f1f1f1e", "ffffff00", 5, 8, true},
		// Arbitrary values.
		{"c9ca", "190705", 8, 5, false},
		{"c9ca", "19070500", 8, 5, true},
		{"19070500", "c9ca", 5, 8, false},
		{"19070500", "c9ca00", 5, 8, true},
		// The failing cases below, with padding.
		{"ff", "1f1c", 8, 5, true},
		{"1f1c10", "ff20", 5, 8, true},
		// A long payload, both ways.
		{sample, "190f13030c170e1b1916141a13040a14040b011f01040e01071e0607160b1906070e06130801131b1a0416020e110008081c1f1a0e19040703120e1d0a06181b160d0407070c1a07070d11131d1408", 8, 5, true},
		{"190f13030c170e1b1916141a13040a14040b011f01040e01071e0607160b1906070e06130801131b1a0416020e110008081c1f1a0e19040703120e1d0a06181b160d0407070c1a07070d11131d1408", sample + "00", 5, 8, true},
	}
	for i, tt := range tests {
		got, err := convertBits(mustHex(t, tt.input), tt.fromBits, tt.toBits, tt.pad)
		if err != nil || !bytes.Equal(got, mustHex(t, tt.output)) {
			t.Fatalf("case %d: got %x, want %s (%v)", i, got, tt.output, err)
		}
	}

	failures := []struct {
		input            string
		fromBits, toBits uint8
		pad              bool
	}{
		{"ff", 8, 5, false},     // incomplete group without padding
		{"1f1c10", 5, 8, false}, // incomplete group without padding
		{"", 0, 5, false},       // bit group below 1
		{"", 10, 5, false},      // bit group above 8
		{"", 5, 0, false},       // bit group below 1
		{"", 5, 10, false},      // bit group above 8
		{"20", 5, 8, true},      // a value that does not fit 5 bits
		{"ff", 5, 8, true},      // a value that does not fit 5 bits
	}
	for i, tt := range failures {
		if _, err := convertBits(mustHex(t, tt.input), tt.fromBits, tt.toBits, tt.pad); err == nil {
			t.Fatalf("failure case %d was accepted", i)
		}
	}
}

func BenchmarkEncodeDecodeCycle(b *testing.B) {
	data, _ := convertBits(mustHex(b, sample), 8, 5, true)
	b.ReportAllocs()
	for b.Loop() {
		s, err := encode("bc", data)
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := decode(s); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConvertBitsDown converts 8 bits to 5; one allocation is expected,
// for the output.
func BenchmarkConvertBitsDown(b *testing.B) {
	data := mustHex(b, sample)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := convertBits(data, 8, 5, true); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkConvertBitsUp converts 5 bits to 8; one allocation is expected, for
// the output.
func BenchmarkConvertBitsUp(b *testing.B) {
	data, _ := convertBits(mustHex(b, sample), 8, 5, true)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := convertBits(data, 5, 8, true); err != nil {
			b.Fatal(err)
		}
	}
}

// FuzzDecode feeds arbitrary strings to the decoders that key and address
// strings go through. None may panic, and whatever one accepts has to encode
// back to the same string in lowercase, so no two strings decode to the same
// data.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{"a1lqfn3a", "A1LQFN3A", "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx", "?1v759aa", "a1qqqqqq", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		want := strings.ToLower(s)
		_, _, _ = DecodeToBase256(s)
		if hrp, data, err := DecodeToBase256NoLimit(s); err == nil {
			if got, err := EncodeFromBase256NoLimit(hrp, data); err != nil || got != want {
				t.Fatalf("%q decoded, but encodes back to %q (%v)", s, got, err)
			}
		}
		if hrp, typ, data, err := DecodeToBase256WithType(s); err == nil {
			if got, err := EncodeFromBase256WithType(hrp, typ, data); err != nil || got != want {
				t.Fatalf("%q decoded with a type, but encodes back to %q (%v)", s, got, err)
			}
		}
	})
}
