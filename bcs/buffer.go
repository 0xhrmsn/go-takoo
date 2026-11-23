package bcs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"reflect"
	"strconv"
	"sync"
)

// The codec is written for a 64-bit word: the blank constant below fails to
// compile anywhere else, rather than letting a length silently truncate.
//
// maxDecodeAlloc is what one decode may allocate. The input is the only thing
// that bounds a length prefix otherwise, and a short message can name a very
// large one.
const (
	_                 uint   = strconv.IntSize - 64
	maxDecodeAlloc    uint64 = 32 << 20
	maxFrameSize             = 32 << 20
	maxPooledCapacity        = 64 << 10
)

// Buffers are pooled because encoding is on the hot path of every block. They
// drop large backing arrays on release.
var bufferPool = sync.Pool{New: func() any { return new(buffer) }}

// buffer is the scratch space a single encode or decode runs in: str holds the
// bytes, off is how far a decode has read, and remaining is what is left of the
// allocation budget.
type buffer struct {
	str       []byte
	off       int
	remaining uint64
}

func getBuffer() *buffer {
	buf := bufferPool.Get().(*buffer)
	buf.reset()

	return buf
}

// writeTo empties the buffer into w, and holds w to its own report: a writer
// that claims to have written more than it was given is broken in a way worth
// naming rather than trusting.
func (buf *buffer) writeTo(w io.Writer) error {
	l := buf.length()
	if l == 0 {
		buf.reset()
		return nil
	}

	m, err := w.Write(buf.str[buf.off:])
	if m < 0 || m > l {
		return fmt.Errorf("utils/encoding: writer reported an invalid byte count")
	}

	buf.off += m
	if err != nil {
		return err
	}
	if m != l {
		return io.ErrShortWrite
	}
	buf.reset()

	return nil
}

// readFrom accepts one frame. Read one extra byte to distinguish a full
// frame from a truncated oversized message, even on readers without a length.
func (buf *buffer) readFrom(r io.Reader) error {
	if br, ok := r.(*bytes.Reader); ok && br.Len() > maxFrameSize {
		return fmt.Errorf("bcs: frame exceeds %d bytes", maxFrameSize)
	}
	var chunk [4096]byte
	emptyReads := 0
	for {
		dst := chunk[:min(len(chunk), maxFrameSize-len(buf.str)+1)]
		n, err := r.Read(dst)
		if n < 0 || n > len(dst) {
			return fmt.Errorf("bcs: invalid reader byte count")
		}
		if n > maxFrameSize-len(buf.str) {
			return fmt.Errorf("bcs: frame exceeds %d bytes", maxFrameSize)
		}
		buf.str = append(buf.str, dst[:n]...)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if n == 0 {
			emptyReads++
			if emptyReads >= 100 {
				return io.ErrNoProgress
			}
		} else {
			emptyReads = 0
		}
	}
}

func (buf *buffer) release() {
	if cap(buf.str) > maxPooledCapacity {
		buf.str = nil
	}
	buf.reset()
	bufferPool.Put(buf)
}

func (buf *buffer) length() int { return len(buf.str) - buf.off }

func (buf *buffer) reset() { buf.str, buf.off = buf.str[:0], 0 }

// next takes the following n bytes, or refuses if they are not all there. What
// it returns is a window into the buffer, not a copy, so anything kept past the
// decode has to be cloned.
func (buf *buffer) next(n int) ([]byte, error) {
	if n < 0 || n > buf.length() {
		return nil, fmt.Errorf("utils/encoding: read past the end of the buffer")
	}
	b := buf.str[buf.off : buf.off+n]
	buf.off += n

	return b, nil
}

// reserve charges n elements of size bytes against the budget before anything
// is allocated. The multiplication is the point: a length prefix and an element
// size that are each plausible can still overflow, so the product is taken in
// full width and checked.
func (buf *buffer) reserve(n, size uint64) error {
	hi, total := bits.Mul64(n, size)
	if hi != 0 || total > buf.remaining {
		return fmt.Errorf("utils/encoding: decoded value needs more memory than its input allows")
	}
	buf.remaining -= total

	return nil
}

// grow makes room for n more bytes and returns where they start. A request too
// large to allocate arrives here as a runtime panic about slice length, which
// says nothing about this package; it is turned into one that does.
func (buf *buffer) grow(n int) int {
	if n < 0 {
		panic("utils/encoding: grow: negative size")
	}

	i := len(buf.str)
	if n <= cap(buf.str)-i {
		buf.str = buf.str[:i+n]
		return i
	}

	if buf.str == nil && n <= 64 {
		buf.str = make([]byte, n, 64)
		return 0
	}
	defer func() {
		if recover() != nil {
			panic("utils/encoding: encoded value is too large")
		}
	}()
	buf.str = append(buf.str, make([]byte, max(n, cap(buf.str)))...)[:i+n]

	return i
}

// encode writes one value, following a pointer to reach what it points at. A
// nil one has nothing behind it to write, which is an error rather than an
// empty encoding.
func (buf *buffer) encode(v any) error {
	val := reflect.ValueOf(v)
	if !val.IsValid() {
		return fmt.Errorf("utils/encoding: nothing to encode")
	}
	if val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return fmt.Errorf("utils/encoding: nothing to encode")
		}
		val = val.Elem()
	}

	writer, err := cachedWriter(val.Type())
	if err != nil {
		return err
	}

	return writer(buf, val)
}

// decode reads one value into v, which has to be a pointer for there to be
// anywhere to put it. It fills a fresh value and assigns only once the whole
// thing has landed, so a failure leaves the caller with what it had.
func (buf *buffer) decode(v any) error {
	val := reflect.ValueOf(v)
	if val.Kind() != reflect.Pointer || val.IsNil() {
		return fmt.Errorf("utils/encoding: decode target must be a non-nil pointer")
	}

	typ := val.Type().Elem()
	reader, err := cachedReader(typ)
	if err != nil {
		return err
	}

	buf.remaining = maxDecodeAlloc
	if err := buf.reserve(1, uint64(typ.Size())); err != nil {
		return err
	}
	fresh := reflect.New(typ).Elem()
	if err := reader(buf, fresh); err != nil {
		return err
	}
	if buf.length() != 0 {
		return fmt.Errorf("utils/encoding: trailing bytes after the value: %d left", buf.length())
	}
	val.Elem().Set(fresh)

	return nil
}

// decodeFrom decodes out of the caller's bytes rather than copying them in,
// then puts the buffer back the way it found it so the pool can reuse it.
func (buf *buffer) decodeFrom(b []byte, v any) error {
	str := buf.str
	buf.str = b
	err := buf.decode(v)
	buf.str, buf.off = str[:0], 0

	return err
}

func (buf *buffer) writeBool(v bool) {
	n := buf.grow(1)
	if !v {
		buf.str[n] = 0
	} else {
		buf.str[n] = 1
	}
}

func (buf *buffer) readBool() (bool, error) {
	b, err := buf.next(1)
	if err != nil {
		return false, err
	}
	switch b[0] {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, fmt.Errorf("utils/encoding: bool byte is neither 0 nor 1")
	}
}

func (buf *buffer) writeUint8(v uint8) {
	n := buf.grow(1)
	buf.str[n] = v
}

func (buf *buffer) readUint8() (uint8, error) {
	b, err := buf.next(1)
	if err != nil {
		return 0, err
	}

	return uint8(b[0]), nil
}

func (buf *buffer) writeUint16(v uint16) {
	n := buf.grow(2)
	binary.LittleEndian.PutUint16(buf.str[n:], v)
}

func (buf *buffer) readUint16() (uint16, error) {
	b, err := buf.next(2)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint16(b), nil
}

func (buf *buffer) writeUint32(v uint32) {
	n := buf.grow(4)
	binary.LittleEndian.PutUint32(buf.str[n:], v)
}

func (buf *buffer) readUint32() (uint32, error) {
	b, err := buf.next(4)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint32(b), nil
}

func (buf *buffer) writeUint64(v uint64) {
	n := buf.grow(8)
	binary.LittleEndian.PutUint64(buf.str[n:], v)
}

func (buf *buffer) readUint64() (uint64, error) {
	b, err := buf.next(8)
	if err != nil {
		return 0, err
	}

	return binary.LittleEndian.Uint64(b), nil
}

func (buf *buffer) writeUvarint(v uint64) {
	buf.str = binary.AppendUvarint(buf.str, v)
}

// readUvarint reads a length or a variant number, and insists on the shortest
// encoding of it. A padded varint means the same number, so accepting one would
// let the same message be restated in a second form and slip past anything that
// compares bytes.
func (buf *buffer) readUvarint() (uint64, error) {
	if buf.off < len(buf.str) && buf.str[buf.off] < 0x80 {
		v := uint64(buf.str[buf.off])
		buf.off++
		return v, nil
	}
	v, m := binary.Uvarint(buf.str[buf.off:])
	switch {
	case m <= 0, m > 1 && buf.str[buf.off+m-1] == 0:
		return 0, fmt.Errorf("utils/encoding: varint is truncated, overflows, or is not minimal")
	}
	buf.off += m

	return v, nil
}

func (buf *buffer) writeBytes(b []byte) {
	buf.writeUvarint(uint64(len(b)))
	n := buf.grow(len(b))
	_ = copy(buf.str[n:], b)
}

func (buf *buffer) readBytes() ([]byte, error) {
	n, err := buf.readUvarint()
	if err != nil {
		return nil, err
	}
	b, err := buf.next(int(n))
	if err != nil {
		return nil, err
	}

	return b, nil
}
