package bcs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestFixedWidthValuesRoundTrip(t *testing.T) {
	buf := getBuffer()
	defer bufferPool.Put(buf)

	buf.writeBool(true)
	buf.writeBool(false)
	buf.writeUint8(0xAB)
	buf.writeUint16(0xBEEF)
	buf.writeUint32(0xDEADBEEF)
	buf.writeUint64(0x0123456789ABCDEF)

	// Little-endian, and each width is exactly as wide as it claims.
	want := []byte{
		1, 0,
		0xAB,
		0xEF, 0xBE,
		0xEF, 0xBE, 0xAD, 0xDE,
		0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
	}
	if got := buf.str[buf.off:]; !bytes.Equal(got, want) {
		t.Fatalf("wrote %x, want %x", got, want)
	}

	if v, err := buf.readBool(); err != nil || !v {
		t.Errorf("readBool = %v, %v", v, err)
	}
	if v, err := buf.readBool(); err != nil || v {
		t.Errorf("readBool = %v, %v", v, err)
	}
	if v, err := buf.readUint8(); err != nil || v != 0xAB {
		t.Errorf("readUint8 = %x, %v", v, err)
	}
	if v, err := buf.readUint16(); err != nil || v != 0xBEEF {
		t.Errorf("readUint16 = %x, %v", v, err)
	}
	if v, err := buf.readUint32(); err != nil || v != 0xDEADBEEF {
		t.Errorf("readUint32 = %x, %v", v, err)
	}
	if v, err := buf.readUint64(); err != nil || v != 0x0123456789ABCDEF {
		t.Errorf("readUint64 = %x, %v", v, err)
	}
	if buf.length() != 0 {
		t.Errorf("%d bytes left over", buf.length())
	}
}

// Every reader must refuse an input that stops short rather than reading
// whatever happens to follow in the backing array.
func TestReadingPastTheEndFails(t *testing.T) {
	tests := []struct {
		name string
		have int
		read func(*buffer) error
	}{
		{"bool", 0, func(b *buffer) error { _, err := b.readBool(); return err }},
		{"uint8", 0, func(b *buffer) error { _, err := b.readUint8(); return err }},
		{"uint16", 1, func(b *buffer) error { _, err := b.readUint16(); return err }},
		{"uint32", 3, func(b *buffer) error { _, err := b.readUint32(); return err }},
		{"uint64", 7, func(b *buffer) error { _, err := b.readUint64(); return err }},
		{"bytes", 1, func(b *buffer) error { _, err := b.readBytes(); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := getBuffer()
			defer bufferPool.Put(buf)
			buf.str = append(buf.str, bytes.Repeat([]byte{9}, tt.have)...)
			if err := tt.read(buf); err == nil {
				t.Fatalf("read %d bytes out of an input of %d", tt.have+1, tt.have)
			}
		})
	}
}

func TestNextChecksItsBounds(t *testing.T) {
	buf := getBuffer()
	defer bufferPool.Put(buf)
	buf.str = append(buf.str, 1, 2, 3, 4)

	if _, err := buf.next(-1); err == nil {
		t.Error("next(-1) was allowed")
	}
	if _, err := buf.next(5); err == nil {
		t.Error("next(5) on four bytes was allowed")
	}
	b, err := buf.next(4)
	if err != nil || !bytes.Equal(b, []byte{1, 2, 3, 4}) {
		t.Fatalf("next(4) = %x, %v", b, err)
	}
	if _, err := buf.next(1); err == nil {
		t.Error("next past a fully consumed buffer was allowed")
	}
}

func TestBoolByteMustBeZeroOrOne(t *testing.T) {
	for _, b := range []byte{2, 0x80, 0xFF} {
		buf := getBuffer()
		buf.str = append(buf.str, b)
		if _, err := buf.readBool(); err == nil {
			t.Errorf("byte %#x decoded as a bool", b)
		}
		bufferPool.Put(buf)
	}
}

func TestUvarintRoundTrips(t *testing.T) {
	values := []uint64{0, 1, 0x7F, 0x80, 300, 1 << 32, 1<<64 - 1}
	buf := getBuffer()
	defer bufferPool.Put(buf)

	for _, v := range values {
		buf.writeUvarint(v)
	}
	for _, want := range values {
		got, err := buf.readUvarint()
		if err != nil {
			t.Fatalf("readUvarint: %v", err)
		}
		if got != want {
			t.Errorf("readUvarint = %d, want %d", got, want)
		}
	}
}

// One value, one encoding. A padded varint decodes to the same number, so
// accepting it would let a peer restate the same message in a second form and
// slip past anything that compares bytes.
func TestUvarintRejectsNonCanonicalInput(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", nil},
		{"truncated", []byte{0x80}},
		{"truncated long", []byte{0x80, 0x80, 0x80}},
		{"padded one", []byte{0x81, 0x00}},
		{"padded zero", []byte{0x80, 0x00}},
		{"overflows 64 bits", []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := getBuffer()
			defer bufferPool.Put(buf)
			buf.str = append(buf.str, tt.input...)
			if v, err := buf.readUvarint(); err == nil {
				t.Fatalf("%x decoded to %d", tt.input, v)
			}
		})
	}
}

func TestBytesCarryTheirLength(t *testing.T) {
	buf := getBuffer()
	defer bufferPool.Put(buf)

	for _, want := range [][]byte{nil, {}, []byte("short"), bytes.Repeat([]byte{7}, 1000)} {
		buf.reset()
		buf.writeBytes(want)

		// The prefix is a uvarint, so a short payload costs one byte of frame.
		if n := len(want); n < 0x80 && buf.length() != n+1 {
			t.Errorf("%d bytes were framed in %d", n, buf.length())
		}
		got, err := buf.readBytes()
		if err != nil {
			t.Fatalf("readBytes: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("readBytes = %x, want %x", got, want)
		}
	}
}

// readBytes hands back a window into the buffer, not a copy. Callers that keep
// the bytes past the decode have to clone them, and readBytes in decode.go does.
func TestReadBytesAliasesTheBuffer(t *testing.T) {
	buf := getBuffer()
	defer bufferPool.Put(buf)
	buf.writeBytes([]byte("payload"))

	b, err := buf.readBytes()
	if err != nil {
		t.Fatal(err)
	}
	b[0] = 'X'
	if buf.str[buf.off-len(b)] != 'X' {
		t.Fatal("readBytes copied, so the decoder need not clone")
	}
}

func TestReserveStopsRunawayAllocation(t *testing.T) {
	buf := getBuffer()
	defer bufferPool.Put(buf)
	buf.remaining = maxDecodeAlloc

	if err := buf.reserve(1000, 8); err != nil {
		t.Fatalf("a modest reservation was refused: %v", err)
	}
	if want := maxDecodeAlloc - 8000; buf.remaining != want {
		t.Errorf("budget is %d, want %d", buf.remaining, want)
	}

	// The product is what matters, and it must not wrap.
	if err := buf.reserve(1<<63, 4); err == nil {
		t.Error("a reservation that overflows 64 bits was allowed")
	}
	if err := buf.reserve(maxDecodeAlloc, 1); err == nil {
		t.Error("a reservation past the budget was allowed")
	}
	if err := buf.reserve(0, 0); err != nil {
		t.Errorf("reserving nothing failed: %v", err)
	}
}

func TestGrowRefusesImpossibleSizes(t *testing.T) {
	for _, tt := range []struct {
		name string
		size int
		want string
	}{
		{"negative", -1, "negative size"},
		{"larger than any allocation", 1 << 62, "too large"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			buf := getBuffer()
			defer bufferPool.Put(buf)
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("grow(%d) returned instead of panicking", tt.size)
				}
				if msg, _ := r.(string); !strings.Contains(msg, tt.want) {
					t.Errorf("panicked with %v, want it to mention %q", r, tt.want)
				}
			}()
			buf.grow(tt.size)
		})
	}
}

func TestGrowKeepsWhatWasAlreadyWritten(t *testing.T) {
	buf := getBuffer()
	defer bufferPool.Put(buf)

	for i := range 2000 {
		buf.writeUint8(byte(i))
	}
	for i := range 2000 {
		if got := buf.str[i]; got != byte(i) {
			t.Fatalf("byte %d is %d after growing", i, got)
		}
	}
}

type shortWriter struct{ n int }

func (w *shortWriter) Write(p []byte) (int, error) { return min(w.n, len(p)), nil }

type errWriter struct{}

func (errWriter) Write(p []byte) (int, error) { return 0, errors.New("no") }

type liarWriter struct{}

func (liarWriter) Write(p []byte) (int, error) { return len(p) + 1, nil }

func TestWriteToReportsWhatTheWriterDid(t *testing.T) {
	tests := []struct {
		name   string
		writer io.Writer
		want   error
	}{
		{"a writer that stops early", &shortWriter{n: 2}, io.ErrShortWrite},
		{"a writer that fails", errWriter{}, nil},
		{"a writer that overcounts", liarWriter{}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := getBuffer()
			defer bufferPool.Put(buf)
			buf.writeBytes([]byte("payload"))

			err := buf.writeTo(tt.writer)
			if err == nil {
				t.Fatal("writeTo reported success")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("error is %v, want %v", err, tt.want)
			}
		})
	}
}

func TestWriteToEmptiesTheBuffer(t *testing.T) {
	buf := getBuffer()
	defer bufferPool.Put(buf)

	var out bytes.Buffer
	if err := buf.writeTo(&out); err != nil {
		t.Fatalf("writing nothing failed: %v", err)
	}

	buf.writeBytes([]byte("payload"))
	if err := buf.writeTo(&out); err != nil {
		t.Fatalf("writeTo: %v", err)
	}
	if buf.length() != 0 {
		t.Errorf("%d bytes left in the buffer", buf.length())
	}
	if out.Len() != len("payload")+1 {
		t.Errorf("wrote %d bytes, want %d", out.Len(), len("payload")+1)
	}
}

type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, errors.New("no") }

type liarReader struct{}

func (liarReader) Read(p []byte) (int, error) { return len(p) + 1, nil }

func TestReadFromTakesEverythingTheReaderHas(t *testing.T) {
	payload := bytes.Repeat([]byte{7}, 4096)

	// A *bytes.Reader reports its length, which lets readFrom size the buffer
	// in one go; anything else is read in chunks until EOF.
	for _, r := range []io.Reader{bytes.NewReader(payload), strings.NewReader(string(payload))} {
		buf := getBuffer()
		if err := buf.readFrom(r); err != nil {
			t.Fatalf("readFrom: %v", err)
		}
		if got := buf.str[buf.off:]; !bytes.Equal(got, payload) {
			t.Errorf("read %d bytes, want %d", len(got), len(payload))
		}
		bufferPool.Put(buf)
	}
}

func TestReadFromReportsWhatTheReaderDid(t *testing.T) {
	for name, r := range map[string]io.Reader{
		"a reader that fails":      errReader{},
		"a reader that overcounts": liarReader{},
	} {
		t.Run(name, func(t *testing.T) {
			buf := getBuffer()
			defer bufferPool.Put(buf)
			if err := buf.readFrom(r); err == nil {
				t.Fatal("readFrom reported success")
			}
		})
	}
}

// decodeFrom borrows the caller's bytes instead of copying them, so it has to
// hand the buffer back in a state the pool can reuse.
func TestDecodeFromRestoresTheBuffer(t *testing.T) {
	buf := getBuffer()
	defer bufferPool.Put(buf)
	buf.str = append(buf.str, 1, 2, 3)

	var v uint8
	if err := buf.decodeFrom([]byte{9}, &v); err != nil {
		t.Fatalf("decodeFrom: %v", err)
	}
	if v != 9 {
		t.Errorf("decoded %d, want 9", v)
	}
	if buf.off != 0 || buf.length() != 0 {
		t.Errorf("buffer came back at offset %d with %d bytes", buf.off, buf.length())
	}
	if cap(buf.str) < 3 {
		t.Error("the original backing array was dropped")
	}
}

func TestEncodeRejectsWhatItCannotName(t *testing.T) {
	buf := getBuffer()
	defer bufferPool.Put(buf)

	var nilPointer *uint8
	for name, v := range map[string]any{
		"nothing at all": nil,
		"a nil pointer":  nilPointer,
		"an int":         42,
	} {
		t.Run(name, func(t *testing.T) {
			if err := buf.encode(v); err == nil {
				t.Fatal("encode accepted it")
			}
		})
	}
}

func TestDecodeNeedsSomewhereToPutTheValue(t *testing.T) {
	buf := getBuffer()
	defer bufferPool.Put(buf)

	var nilPointer *uint8
	for name, v := range map[string]any{
		"nothing at all": nil,
		"a nil pointer":  nilPointer,
		"a plain value":  uint8(0),
	} {
		t.Run(name, func(t *testing.T) {
			if err := buf.decode(v); err == nil {
				t.Fatal("decode accepted it")
			}
		})
	}
}

func TestUvarintFastPathMatchesTheSlowOne(t *testing.T) {
	// Values below 0x80 take a hand-rolled single-byte path; the rest go
	// through binary.Uvarint. Both must agree with the encoder.
	for v := range uint64(0x100) {
		buf := getBuffer()
		buf.writeUvarint(v)
		want := binary.AppendUvarint(nil, v)
		if !bytes.Equal(buf.str[buf.off:], want) {
			t.Fatalf("%d encoded to %x, want %x", v, buf.str[buf.off:], want)
		}
		got, err := buf.readUvarint()
		if err != nil || got != v {
			t.Fatalf("%d round-tripped to %d, %v", v, got, err)
		}
		bufferPool.Put(buf)
	}
}
