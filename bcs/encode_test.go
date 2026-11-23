package bcs

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

type encPrimitives struct {
	Flag bool
	A    uint8
	B    uint16
	C    uint32
	D    uint64
	S    string
	Raw  []byte
}

// The wire form is the part other implementations have to agree with, so it is
// pinned here as literal bytes rather than checked by round-tripping alone.
func TestEncodingIsLittleEndianAndLengthPrefixed(t *testing.T) {
	v := encPrimitives{
		Flag: true,
		A:    0x11,
		B:    0x2233,
		C:    0x44556677,
		D:    0x8899AABBCCDDEEFF,
		S:    "hi",
		Raw:  []byte{0xDE, 0xAD},
	}
	const want = "01" + "11" + "3322" + "77665544" + "ffeeddccbbaa9988" + "026869" + "02dead"

	got, err := EncodeToBytes(v)
	if err != nil {
		t.Fatalf("EncodeToBytes: %v", err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("encoded to %x, want %s", got, want)
	}
}

func TestEncodeWritesTheSameBytesAsEncodeToBytes(t *testing.T) {
	v := encPrimitives{A: 7, S: "x"}

	want, err := EncodeToBytes(v)
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := Encode(&out, v); err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("Encode wrote %x, EncodeToBytes gave %x", out.Bytes(), want)
	}
}

func TestEncodePassesOnTheWritersError(t *testing.T) {
	if err := Encode(errWriter{}, encPrimitives{A: 1}); err == nil {
		t.Error("a failing writer went unreported")
	}
	if err := Encode(&shortWriter{n: 1}, encPrimitives{S: "long enough"}); err == nil {
		t.Error("a short write went unreported")
	}
}

// EncodeToBytes hands back a copy, not the pooled buffer, so a later encode on
// the same goroutine cannot rewrite what a caller is still holding.
func TestEncodeToBytesDoesNotAliasThePool(t *testing.T) {
	first, err := EncodeToBytes(encPrimitives{A: 0xAA})
	if err != nil {
		t.Fatal(err)
	}
	keep := bytes.Clone(first)

	for range 50 {
		if _, err := EncodeToBytes(encPrimitives{A: 0xBB, S: strings.Repeat("x", 300)}); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(first, keep) {
		t.Fatalf("an earlier result changed to %x", first)
	}
}

type encMyByte uint8

type encArrays struct {
	Bytes  [4]byte
	Named  [3]encMyByte
	Flags  [2]bool
	Shorts [2]uint16
	Words  [2]uint32
	Longs  [2]uint64
}

func TestArraysAreWrittenWithoutALengthPrefix(t *testing.T) {
	v := encArrays{
		Bytes:  [4]byte{1, 2, 3, 4},
		Named:  [3]encMyByte{5, 6, 7},
		Flags:  [2]bool{true, false},
		Shorts: [2]uint16{0x0102, 0x0304},
		Words:  [2]uint32{0x01020304, 0x05060708},
		Longs:  [2]uint64{1, 2},
	}
	const want = "01020304" + "050607" + "0100" + "02010403" +
		"04030201" + "08070605" + "0100000000000000" + "0200000000000000"

	got, err := EncodeToBytes(v)
	if err != nil {
		t.Fatalf("EncodeToBytes: %v", err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("encoded to %x, want %s", got, want)
	}
}

// A byte array is copied three different ways depending on whether its element
// is exactly byte and whether the value can be addressed. All three must land
// on the same bytes.
func TestByteArraysCopyTheSameWayFromEveryShape(t *testing.T) {
	type holder struct {
		A [4]byte
	}
	want := []byte{9, 8, 7, 6}

	fromValue, err := EncodeToBytes([4]byte{9, 8, 7, 6})
	if err != nil {
		t.Fatal(err)
	}
	fromField, err := EncodeToBytes(&holder{A: [4]byte{9, 8, 7, 6}})
	if err != nil {
		t.Fatal(err)
	}
	fromNamed, err := EncodeToBytes([4]encMyByte{9, 8, 7, 6})
	if err != nil {
		t.Fatal(err)
	}

	for name, got := range map[string][]byte{
		"a bare array":       fromValue,
		"an addressable one": fromField,
		"a named byte type":  fromNamed,
	} {
		if !bytes.Equal(got, want) {
			t.Errorf("%s encoded to %x, want %x", name, got, want)
		}
	}
}

type encOptional struct {
	Ptr *uint32
}

// A pointer field carries a presence byte. Nil writes the byte alone; set
// writes the byte and the value behind it.
func TestPointersCarryAPresenceByte(t *testing.T) {
	absent, err := EncodeToBytes(encOptional{})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0}; !bytes.Equal(absent, want) {
		t.Errorf("a nil pointer encoded to %x, want %x", absent, want)
	}

	n := uint32(0x01020304)
	present, err := EncodeToBytes(encOptional{Ptr: &n})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{1, 4, 3, 2, 1}; !bytes.Equal(present, want) {
		t.Errorf("a set pointer encoded to %x, want %x", present, want)
	}
}

type encSkipped struct {
	Kept    uint8
	Derived chan int `encoding:"-"`
	Also    uint8
}

func TestSkippedFieldsAreNotEncodedOrResolved(t *testing.T) {
	got, err := EncodeToBytes(encSkipped{Kept: 1, Also: 2})
	if err != nil {
		t.Fatalf("EncodeToBytes: %v", err)
	}
	if want := []byte{1, 2}; !bytes.Equal(got, want) {
		t.Errorf("encoded to %x, want %x", got, want)
	}
}

type encUnexported struct {
	A uint8
	b uint8
}

type encNothingSlice struct {
	Empties []struct{}
}

type encNothingArray struct {
	Empties [4]struct{}
	After   uint8
}

func TestEncoderRefusesTypesItCannotWrite(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"an int", 42, "no encoding"},
		{"a float", 1.5, "no encoding"},
		{"a map", map[string]uint8{}, "no encoding"},
		{"an unexported field", encUnexported{}, "field is unexported"},
		{"a slice of nothing", encNothingSlice{}, "encodes to nothing"},
		{"a recursive type", selfPointer{}, "recursive type"},
		{"nothing at all", nil, "nothing to encode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncodeToBytes(tt.value)
			if err == nil {
				t.Fatal("EncodeToBytes accepted it")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error is %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

// An element that always encodes to zero bytes is refused inside a slice, where
// the count could not be recovered, but allowed inside an array, whose length
// is already known from the type.
func TestAnArrayOfNothingWritesNothing(t *testing.T) {
	got, err := EncodeToBytes(encNothingArray{After: 9})
	if err != nil {
		t.Fatalf("EncodeToBytes: %v", err)
	}
	if want := []byte{9}; !bytes.Equal(got, want) {
		t.Errorf("encoded to %x, want %x", got, want)
	}
}

func TestStringsMustBeValidUTF8(t *testing.T) {
	type holder struct {
		S string
	}
	_, err := EncodeToBytes(holder{S: string([]byte{0xFF, 0xFE})})
	if err == nil {
		t.Fatal("invalid UTF-8 was encoded")
	}
	if !strings.Contains(err.Error(), "UTF-8") {
		t.Errorf("error is %q, want it to mention UTF-8", err)
	}
}

type encShape struct {
	Kind   uint8 `encoding:"enum"`
	Number uint32
	Text   string
}

func TestEnumWritesTheTagThenTheSelectedVariant(t *testing.T) {
	number, err := EncodeToBytes(encShape{Kind: 0, Number: 0x01020304})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0, 4, 3, 2, 1}; !bytes.Equal(number, want) {
		t.Errorf("variant 0 encoded to %x, want %x", number, want)
	}

	text, err := EncodeToBytes(encShape{Kind: 1, Text: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{1, 2, 'h', 'i'}; !bytes.Equal(text, want) {
		t.Errorf("variant 1 encoded to %x, want %x", text, want)
	}
}

// Only the selected variant is written, so a value left in another one would
// vanish silently. Refusing to encode is what keeps the struct and its bytes
// saying the same thing.
func TestEnumRefusesToDropAnUnselectedVariant(t *testing.T) {
	_, err := EncodeToBytes(encShape{Kind: 0, Number: 1, Text: "lost"})
	if err == nil {
		t.Fatal("a value outside the selected variant was dropped")
	}
	if !strings.Contains(err.Error(), "does not encode it") {
		t.Errorf("error is %q", err)
	}
}

func TestEnumRefusesATagWithNoVariant(t *testing.T) {
	_, err := EncodeToBytes(encShape{Kind: 7})
	if err == nil {
		t.Fatal("an out-of-range discriminant was encoded")
	}
	if !strings.Contains(err.Error(), "variant 7") {
		t.Errorf("error is %q, want it to name the variant", err)
	}
}

func BenchmarkEncodeToBytes(b *testing.B) {
	v := encPrimitives{
		Flag: true,
		D:    1 << 40,
		S:    "a transaction memo",
		Raw:  bytes.Repeat([]byte{7}, 64),
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := EncodeToBytes(v); err != nil {
			b.Fatal(err)
		}
	}
}

type encNested struct {
	A uint32
	S string
}

type encArrayOfStructs struct {
	Items [2]encNested
}

type encArrayOfUnexported struct {
	Items [2]encUnexported
}

type encBadTag struct {
	A uint8 `encoding:"bogus"`
}

type encEnumVariantFirst struct {
	A    uint8
	Kind uint8 `encoding:"enum"`
}

type encEnumUnencodableVariant struct {
	Kind uint8 `encoding:"enum"`
	A    int
}

type encSliceOfStructs struct {
	Items []encNested
}

// An array of anything but a fixed-width scalar falls through to the generic
// loop, which writes each element with the element's own writer.
func TestArraysOfCompositeElementsWriteEachOne(t *testing.T) {
	v := encArrayOfStructs{Items: [2]encNested{
		{A: 1, S: "a"},
		{A: 2, S: "bb"},
	}}
	const want = "01000000" + "0161" + "02000000" + "026262"

	got, err := EncodeToBytes(v)
	if err != nil {
		t.Fatalf("EncodeToBytes: %v", err)
	}
	if hex.EncodeToString(got) != want {
		t.Fatalf("encoded to %x, want %s", got, want)
	}
}

// A type is refused when it is planned, not when the bad part is reached, so
// the error has to carry the field it came from.
func TestPlanningErrorsNameTheField(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"an array of unencodable elements", encArrayOfUnexported{}, "field is unexported"},
		{"a tag that does not parse", encBadTag{}, "unknown tag option"},
		{"an enum whose variants come first", encEnumVariantFirst{}, "comes before the variants"},
		{"an enum variant with no encoding", encEnumUnencodableVariant{}, "no encoding"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := EncodeToBytes(tt.value)
			if err == nil {
				t.Fatal("EncodeToBytes accepted it")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error is %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

// One bad element stops the whole value. A slice that wrote its good elements
// and gave up would leave a length prefix that no longer matches.
func TestOneBadElementStopsTheEncode(t *testing.T) {
	v := encSliceOfStructs{Items: []encNested{
		{A: 1, S: "fine"},
		{A: 2, S: string([]byte{0xFF})},
	}}
	if _, err := EncodeToBytes(v); err == nil {
		t.Fatal("a slice with an unencodable element was written")
	}

	arr := encArrayOfStructs{Items: [2]encNested{{S: "fine"}, {S: string([]byte{0xFF})}}}
	if _, err := EncodeToBytes(arr); err == nil {
		t.Fatal("an array with an unencodable element was written")
	}
}

func TestEncodeReportsABadValueBeforeItWrites(t *testing.T) {
	var out bytes.Buffer
	if err := Encode(&out, 42); err == nil {
		t.Fatal("an int was encoded")
	}
	if out.Len() != 0 {
		t.Errorf("%d bytes reached the writer", out.Len())
	}
}
