package bcs

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

type decEverything struct {
	Flag   bool
	A      uint8
	B      uint16
	C      uint32
	D      uint64
	S      string
	Raw    []byte
	Bytes  [4]byte
	Named  [3]encMyByte
	Flags  [2]bool
	Shorts [2]uint16
	Words  [2]uint32
	Longs  [2]uint64
	Ptr    *uint32
	List   []encPrimitives
}

func TestValuesSurviveARoundTrip(t *testing.T) {
	n := uint32(77)
	want := decEverything{
		Flag:   true,
		A:      0x11,
		B:      0x2233,
		C:      0x44556677,
		D:      0x8899AABBCCDDEEFF,
		S:      "a memo with unicode: né",
		Raw:    []byte{0xDE, 0xAD, 0xBE, 0xEF},
		Bytes:  [4]byte{1, 2, 3, 4},
		Named:  [3]encMyByte{5, 6, 7},
		Flags:  [2]bool{true, false},
		Shorts: [2]uint16{9, 10},
		Words:  [2]uint32{11, 12},
		Longs:  [2]uint64{13, 14},
		Ptr:    &n,
		// Empty, not nil: the two share an encoding, and the decoder always
		// hands back the empty form.
		List: []encPrimitives{
			{A: 1, S: "one", Raw: []byte{}},
			{A: 2, Raw: []byte{9}},
		},
	}

	b, err := EncodeToBytes(want)
	if err != nil {
		t.Fatalf("EncodeToBytes: %v", err)
	}

	var got decEverything
	if err := DecodeFromBytes(b, &got); err != nil {
		t.Fatalf("DecodeFromBytes: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip gave\n%+v\nwant\n%+v", got, want)
	}

	// Re-encoding what came back must reproduce the same bytes, which is what
	// makes a decoded value safe to hash or sign.
	again, err := EncodeToBytes(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, b) {
		t.Errorf("re-encoded to %x, want %x", again, b)
	}
}

func TestDecodeReadsTheSameBytesAsDecodeFromBytes(t *testing.T) {
	b, err := EncodeToBytes(encPrimitives{A: 3, S: "x"})
	if err != nil {
		t.Fatal(err)
	}

	var fromReader, fromBytes encPrimitives
	if err := Decode(bytes.NewReader(b), &fromReader); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if err := DecodeFromBytes(b, &fromBytes); err != nil {
		t.Fatalf("DecodeFromBytes: %v", err)
	}
	if !reflect.DeepEqual(fromReader, fromBytes) {
		t.Errorf("Decode gave %+v, DecodeFromBytes gave %+v", fromReader, fromBytes)
	}
}

func TestDecodePassesOnTheReadersError(t *testing.T) {
	var v encPrimitives
	if err := Decode(errReader{}, &v); err == nil {
		t.Error("a failing reader went unreported")
	}
}

// A nil slice and an empty one encode identically, so the decoder cannot tell
// them apart and always hands back an empty, non-nil slice.
func TestNilAndEmptySlicesShareOneEncoding(t *testing.T) {
	type holder struct {
		List []uint32
	}

	fromNil, err := EncodeToBytes(holder{})
	if err != nil {
		t.Fatal(err)
	}
	fromEmpty, err := EncodeToBytes(holder{List: []uint32{}})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromNil, fromEmpty) {
		t.Fatalf("nil encoded to %x, empty to %x", fromNil, fromEmpty)
	}

	var got holder
	if err := DecodeFromBytes(fromNil, &got); err != nil {
		t.Fatal(err)
	}
	if got.List == nil {
		t.Error("decoded to a nil slice")
	}
	if len(got.List) != 0 {
		t.Errorf("decoded %d elements, want none", len(got.List))
	}
}

// The decoder keeps a window into its input while reading; anything it stores
// has to be copied out, or a reused buffer would rewrite the value later.
func TestDecodedBytesDoNotAliasTheInput(t *testing.T) {
	type holder struct {
		Raw []byte
	}
	b, err := EncodeToBytes(holder{Raw: []byte{1, 2, 3, 4}})
	if err != nil {
		t.Fatal(err)
	}

	var got holder
	if err := DecodeFromBytes(b, &got); err != nil {
		t.Fatal(err)
	}
	clear(b)
	if !bytes.Equal(got.Raw, []byte{1, 2, 3, 4}) {
		t.Errorf("the decoded bytes changed to %x when the input was cleared", got.Raw)
	}
}

// Bytes after the value mean the sender and the reader disagree about the
// shape. Ignoring them would let two different messages decode the same.
func TestTrailingBytesAreRefused(t *testing.T) {
	b, err := EncodeToBytes(encPrimitives{A: 1})
	if err != nil {
		t.Fatal(err)
	}

	var got encPrimitives
	err = DecodeFromBytes(append(bytes.Clone(b), 0), &got)
	if err == nil {
		t.Fatal("a trailing byte was ignored")
	}
	if !strings.Contains(err.Error(), "trailing bytes") {
		t.Errorf("error is %q", err)
	}
}

func TestTruncatedInputIsRefusedAtEveryLength(t *testing.T) {
	n := uint32(5)
	full, err := EncodeToBytes(decEverything{
		S:    "memo",
		Raw:  []byte{1, 2},
		Ptr:  &n,
		List: []encPrimitives{{A: 1}},
	})
	if err != nil {
		t.Fatal(err)
	}

	for cut := range len(full) {
		var got decEverything
		if err := DecodeFromBytes(full[:cut], &got); err == nil {
			t.Fatalf("%d bytes out of %d decoded without an error", cut, len(full))
		}
	}
}

// A failed decode must leave the caller's value as it was: the reader fills a
// fresh copy and only assigns once the whole value has landed.
func TestAFailedDecodeLeavesTheTargetAlone(t *testing.T) {
	before := encPrimitives{A: 42, S: "keep me"}
	got := before

	if err := DecodeFromBytes([]byte{0xFF}, &got); err == nil {
		t.Fatal("malformed input decoded cleanly")
	}
	if !reflect.DeepEqual(got, before) {
		t.Errorf("the target changed to %+v", got)
	}
}

func TestDecoderRefusesMalformedInput(t *testing.T) {
	type boolArray struct {
		Flags [2]bool
	}
	type text struct {
		S string
	}
	type optional struct {
		Ptr *uint32
	}
	type numbers struct {
		List []uint32
	}

	tests := []struct {
		name   string
		input  []byte
		target any
		want   string
	}{
		{"a bool that is neither 0 nor 1", []byte{2}, new(encPrimitives), "neither 0 nor 1"},
		{"a bool inside an array", []byte{0, 2}, new(boolArray), "neither 0 nor 1"},
		{"a string that is not UTF-8", []byte{2, 0xFF, 0xFE}, new(text), "UTF-8"},
		{"a present pointer with nothing behind it", []byte{1}, new(optional), "past the end"},
		{"a length prefix larger than the input", []byte{0x64, 1, 2, 3, 4}, new(numbers), "exceeds the remaining input"},
		{"a discriminant with no variant", []byte{7}, new(encShape), "variant 7"},
		{"a padded length prefix", []byte{0x80, 0x00}, new(text), "not minimal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DecodeFromBytes(tt.input, tt.target)
			if err == nil {
				t.Fatal("DecodeFromBytes accepted it")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error is %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

// Padding is skipped by the codec but still counts toward the Go size of the
// element, so a short input can ask for far more memory than it occupies. The
// budget is what stops it.
type decFat struct {
	Padding [8192]byte `encoding:"-"`
	Ptr     *uint8
}

func TestTheDecodeBudgetStopsAmplification(t *testing.T) {
	type holder struct {
		List []decFat
	}

	// Each element costs one byte on the wire and 8200 in memory, so a few
	// thousand of them fit the input while blowing past the 32 MiB budget.
	const n = 5000
	input := binary.AppendUvarint(nil, n)
	input = append(input, make([]byte, n)...)

	var got holder
	err := DecodeFromBytes(input, &got)
	if err == nil {
		t.Fatalf("%d bytes of input allocated %d elements", len(input), len(got.List))
	}
	if !strings.Contains(err.Error(), "more memory than its input allows") {
		t.Errorf("error is %q, want the budget to be what refused it", err)
	}

	// Well under the budget, the same shape decodes.
	const few = 100
	small := append(binary.AppendUvarint(nil, few), make([]byte, few)...)
	if err := DecodeFromBytes(small, &got); err != nil {
		t.Fatalf("%d elements were refused: %v", few, err)
	}
	if len(got.List) != few {
		t.Errorf("decoded %d elements, want %d", len(got.List), few)
	}
}

func TestDecoderRefusesTypesItCannotRead(t *testing.T) {
	tests := []struct {
		name   string
		target any
		want   string
	}{
		{"an int", new(int), "no encoding"},
		{"a map", new(map[string]uint8), "no encoding"},
		{"an unexported field", new(encUnexported), "field is unexported"},
		{"a slice of nothing", new(encNothingSlice), "encodes to nothing"},
		{"a recursive type", new(selfPointer), "recursive type"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DecodeFromBytes([]byte{0}, tt.target)
			if err == nil {
				t.Fatal("DecodeFromBytes accepted it")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error is %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

func TestEnumDecodesIntoTheSelectedVariantOnly(t *testing.T) {
	for _, want := range []encShape{
		{Kind: 0, Number: 0x01020304},
		{Kind: 1, Text: "hi"},
	} {
		b, err := EncodeToBytes(want)
		if err != nil {
			t.Fatal(err)
		}

		var got encShape
		if err := DecodeFromBytes(b, &got); err != nil {
			t.Fatalf("DecodeFromBytes: %v", err)
		}
		if got != want {
			t.Errorf("decoded %+v, want %+v", got, want)
		}
	}
}

// minSize is what the length and budget checks are measured against, so it has
// to be the true floor: never larger than a real encoding of the type.
func TestMinSizeIsTheSmallestEncoding(t *testing.T) {
	type pair struct {
		A uint32
		B uint64
	}
	type withSkip struct {
		A    uint16
		Skip int `encoding:"-"`
	}

	tests := []struct {
		name string
		typ  reflect.Type
		want int
	}{
		{"bool", reflect.TypeOf(false), 1},
		{"uint8", reflect.TypeOf(uint8(0)), 1},
		{"uint16", reflect.TypeOf(uint16(0)), 2},
		{"uint32", reflect.TypeOf(uint32(0)), 4},
		{"uint64", reflect.TypeOf(uint64(0)), 8},
		{"a string is only its length prefix", reflect.TypeOf(""), 1},
		{"a slice is only its length prefix", reflect.TypeOf([]uint64{}), 1},
		{"a pointer is only its presence byte", reflect.TypeOf((*uint64)(nil)), 1},
		{"an array multiplies", reflect.TypeOf([4]uint32{}), 16},
		{"a struct adds up", reflect.TypeOf(pair{}), 12},
		{"a skipped field costs nothing", reflect.TypeOf(withSkip{}), 2},
		{"an enum is the tag plus its smallest variant", reflect.TypeOf(encShape{}), 2},
		{"a recursive type bottoms out", reflect.TypeOf(selfPointer{}), 2},
		{"a type with no encoding", reflect.TypeOf(0), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := minSize(tt.typ, map[reflect.Type]int{}); got != tt.want {
				t.Errorf("minSize(%s) = %d, want %d", tt.typ, got, tt.want)
			}
		})
	}
}

// Whatever minSize claims, a real encoding of the zero value must be at least
// that long, or the length checks would reject input they should accept.
func TestMinSizeNeverOverstates(t *testing.T) {
	values := []any{
		encPrimitives{}, encArrays{}, encOptional{}, encShape{},
		decEverything{}, uint16(0), [4]uint32{}, "",
	}
	for _, v := range values {
		typ := reflect.TypeOf(v)
		b, err := EncodeToBytes(v)
		if err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if least := minSize(typ, map[reflect.Type]int{}); len(b) < least {
			t.Errorf("%s encodes to %d bytes but minSize says %d", typ, len(b), least)
		}
	}
}

func FuzzDecodeFromBytesNeverPanics(f *testing.F) {
	seed, err := EncodeToBytes(decEverything{S: "seed", Raw: []byte{1}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{0})
	f.Add([]byte{0xFF, 0xFF, 0xFF})

	f.Fuzz(func(t *testing.T, b []byte) {
		var got decEverything
		if err := DecodeFromBytes(b, &got); err != nil {
			return
		}

		// Anything the decoder accepts must re-encode to the bytes it came
		// from, or two inputs would stand for one value.
		again, err := EncodeToBytes(got)
		if err != nil {
			t.Fatalf("a decoded value would not re-encode: %v", err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("%x decoded and re-encoded to %x", b, again)
		}
	})
}

func BenchmarkDecodeFromBytes(b *testing.B) {
	v := encPrimitives{
		Flag: true,
		D:    1 << 40,
		S:    "a transaction memo",
		Raw:  bytes.Repeat([]byte{7}, 64),
	}
	encoded, err := EncodeToBytes(v)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	for b.Loop() {
		var got encPrimitives
		if err := DecodeFromBytes(encoded, &got); err != nil {
			b.Fatal(err)
		}
	}
}

// A pointer to a type whose Go size dwarfs its encoding is the sharpest form of
// the amplification the budget exists to stop: two bytes on the wire asking for
// 64 MiB of memory.
type decHuge struct {
	Padding [64 << 20]byte `encoding:"-"`
	Flag    bool
}

type decPointerHolder struct {
	Ptr *decHuge
}

type decOneBool struct {
	Flag bool
}

type decOptionalStruct struct {
	Ptr *decOneBool
}

func TestArraysOfCompositeElementsReadEachOne(t *testing.T) {
	want := encArrayOfStructs{Items: [2]encNested{
		{A: 1, S: "a"},
		{A: 2, S: "bb"},
	}}

	b, err := EncodeToBytes(want)
	if err != nil {
		t.Fatal(err)
	}

	var got encArrayOfStructs
	if err := DecodeFromBytes(b, &got); err != nil {
		t.Fatalf("DecodeFromBytes: %v", err)
	}
	if got != want {
		t.Errorf("decoded %+v, want %+v", got, want)
	}

	// The element reader is what fails here, part-way through the array.
	if err := DecodeFromBytes(b[:len(b)-1], &got); err == nil {
		t.Error("a truncated array decoded cleanly")
	}
}

// An array of zero-byte elements reads nothing at all, the mirror of writing
// nothing: the count lives in the type, and the elements carry no data.
func TestAnArrayOfNothingReadsNothing(t *testing.T) {
	b, err := EncodeToBytes(encNothingArray{After: 9})
	if err != nil {
		t.Fatal(err)
	}

	var got encNothingArray
	if err := DecodeFromBytes(b, &got); err != nil {
		t.Fatalf("DecodeFromBytes: %v", err)
	}
	if got.After != 9 {
		t.Errorf("decoded After = %d, want 9", got.After)
	}
}

func TestPointerDecodingChecksTheBudgetBeforeAllocating(t *testing.T) {
	// Present, then one byte for the bool behind it. The length check passes;
	// only the budget stands between this and a 64 MiB allocation.
	err := DecodeFromBytes([]byte{1, 0}, new(decPointerHolder))
	if err == nil {
		t.Fatal("two bytes allocated 64 MiB")
	}
	if !strings.Contains(err.Error(), "more memory than its input allows") {
		t.Errorf("error is %q, want the budget to be what refused it", err)
	}
}

func TestAFailureBehindAPointerIsReported(t *testing.T) {
	// Present, and long enough to clear the length check, so the failure comes
	// from the pointee's own reader: a bool byte that is neither 0 nor 1.
	err := DecodeFromBytes([]byte{1, 2}, new(decOptionalStruct))
	if err == nil {
		t.Fatal("a malformed value behind a pointer decoded cleanly")
	}
	if !strings.Contains(err.Error(), "neither 0 nor 1") {
		t.Errorf("error is %q", err)
	}
}

// The slice reader checks the length prefix against the input before it
// allocates, but an element can still fail once reading starts.
func TestOneBadElementStopsTheDecode(t *testing.T) {
	// One element: a uint32, then a two-byte string that is not UTF-8.
	input := append(binary.AppendUvarint(nil, 1), 0, 0, 0, 0)
	input = append(input, 2, 0xFF, 0xFE)

	err := DecodeFromBytes(input, new(encSliceOfStructs))
	if err == nil {
		t.Fatal("a slice with a malformed element decoded cleanly")
	}
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("error is %q", err)
	}
}

func TestEnumDecodingRefusesABrokenDiscriminant(t *testing.T) {
	for name, input := range map[string][]byte{
		"nothing at all":  {},
		"a padded tag":    {0x80, 0x00},
		"a tag too large": {0x80, 0x01},
	} {
		t.Run(name, func(t *testing.T) {
			if err := DecodeFromBytes(input, new(encShape)); err == nil {
				t.Fatal("DecodeFromBytes accepted it")
			}
		})
	}
}

func TestDecoderRefusesTheSameShapesTheEncoderDoes(t *testing.T) {
	tests := []struct {
		name   string
		target any
		want   string
	}{
		{"an array of unencodable elements", new(encArrayOfUnexported), "field is unexported"},
		{"a tag that does not parse", new(encBadTag), "unknown tag option"},
		{"an enum whose variants come first", new(encEnumVariantFirst), "comes before the variants"},
		{"an enum variant with no encoding", new(encEnumUnencodableVariant), "no encoding"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := DecodeFromBytes([]byte{0}, tt.target)
			if err == nil {
				t.Fatal("DecodeFromBytes accepted it")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error is %q, want it to mention %q", err, tt.want)
			}
		})
	}
}
