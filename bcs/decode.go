package bcs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"unicode/utf8"
)

// Decode reads one frame of at most 32 MiB from r. The transport must delimit
// frames and set its own I/O deadlines.
func Decode(r io.Reader, v any) error {
	buf := getBuffer()
	defer buf.release()
	if err := buf.readFrom(r); err != nil {
		return err
	}

	return buf.decode(v)
}

// DecodeBytes reads one value out of b, borrowing b rather than copying it.
// Anything the value keeps is cloned on the way in.
func DecodeFromBytes(b []byte, v any) error {
	if len(b) > maxFrameSize {
		return fmt.Errorf("bcs: frame exceeds %d bytes", maxFrameSize)
	}
	buf := getBuffer()
	err := buf.decodeFrom(b, v)
	buf.release()

	return err
}

// funcReader reads one value of the type it was made for, the mirror of
// funcWriter and planned at the same time.
type funcReader func(dec *buffer, val reflect.Value) error

// makeReader plans how a type is read. It matches the cases in makeWriter one
// for one; a difference between the two lists would be a format that can be
// written and not read.
func makeReader(typ reflect.Type) (funcReader, error) {
	kind := typ.Kind()
	switch {
	case kind == reflect.Bool:
		return readBool, nil
	case kind == reflect.Uint8:
		return readUint8, nil
	case kind == reflect.Uint16:
		return readUint16, nil
	case kind == reflect.Uint32:
		return readUint32, nil
	case kind == reflect.Uint64:
		return readUint64, nil
	case kind == reflect.String:
		return readString, nil
	case kind == reflect.Slice && typ.Elem().Kind() == reflect.Uint8:
		return readBytes, nil
	case kind == reflect.Slice:
		return makeSliceReader(typ)
	case kind == reflect.Array && typ.Elem().Kind() == reflect.Uint8:
		return makeByteArrayReader(typ), nil
	case kind == reflect.Array:
		return makeArrayReader(typ)
	case kind == reflect.Pointer:
		return makePointerReader(typ)
	case kind == reflect.Struct && isEnum(typ):
		return makeEnumReader(typ)
	case kind == reflect.Struct:
		return makeStructReader(typ)
	default:
		return nil, fmt.Errorf("utils/encoding: type has no encoding: %s", typ)
	}
}

func readBool(dec *buffer, val reflect.Value) error {
	v, err := dec.readBool()
	if err != nil {
		return err
	}
	val.SetBool(v)

	return nil
}

func readUint8(dec *buffer, val reflect.Value) error {
	v, err := dec.readUint8()
	if err != nil {
		return err
	}
	val.SetUint(uint64(v))

	return nil
}

func readUint16(dec *buffer, val reflect.Value) error {
	v, err := dec.readUint16()
	if err != nil {
		return err
	}
	val.SetUint(uint64(v))

	return nil
}

func readUint32(dec *buffer, val reflect.Value) error {
	v, err := dec.readUint32()
	if err != nil {
		return err
	}
	val.SetUint(uint64(v))

	return nil
}

func readUint64(dec *buffer, val reflect.Value) error {
	v, err := dec.readUint64()
	if err != nil {
		return err
	}
	val.SetUint(v)

	return nil
}

func readString(dec *buffer, val reflect.Value) error {
	b, err := dec.readBytes()
	if err != nil {
		return err
	}
	if !utf8.Valid(b) {
		return fmt.Errorf("utils/encoding: string is not valid UTF-8")
	}
	if err := dec.reserve(uint64(len(b)), 1); err != nil {
		return err
	}
	val.SetString(string(b))

	return nil
}

// readBytes clones what it reads. The decoder works in a window onto its
// input, and that input is the caller's and may be reused.
func readBytes(buf *buffer, val reflect.Value) error {
	b, err := buf.readBytes()
	if err != nil {
		return err
	}
	if err := buf.reserve(uint64(len(b)), 1); err != nil {
		return err
	}
	val.SetBytes(bytes.Clone(b))

	return nil
}

// makeSliceReader checks the count twice before it allocates: against the
// bytes actually left, so a length prefix cannot describe more elements than
// could possibly fit, and against the budget, so what does fit still cannot ask
// for unbounded memory.
func makeSliceReader(typ reflect.Type) (funcReader, error) {
	elem := tc.resolve(typ.Elem())
	if elem.readerError != nil {
		return nil, elem.readerError
	}

	least := minSize(typ.Elem(), map[reflect.Type]int{})
	if least == 0 {
		return nil, fmt.Errorf("utils/encoding: slice element encodes to nothing: %s", typ)
	}
	size := uint64(typ.Elem().Size())
	empty := reflect.MakeSlice(typ, 0, 0)

	return func(dec *buffer, val reflect.Value) error {
		n, err := dec.readUvarint()
		if err != nil {
			return err
		}
		if n > uint64(dec.length()/least) {
			return fmt.Errorf("utils/encoding: length prefix exceeds the remaining input: %d elements, at most %d fit", n, dec.length()/least)
		}
		if n == 0 {
			val.Set(empty)
			return nil
		}
		if err := dec.reserve(n, size); err != nil {
			return err
		}
		val.Grow(int(n))
		val.SetLen(int(n))
		for i := 0; i < int(n); i++ {
			if err := elem.reader(dec, val.Index(i)); err != nil {
				return err
			}
		}

		return nil
	}, nil
}

// makeByteArrayReader takes a fixed run of bytes, its length known from the
// type rather than from the input.
func makeByteArrayReader(typ reflect.Type) funcReader {
	n := typ.Len()
	exactByte := typ.Elem() == byteType

	return func(dec *buffer, val reflect.Value) error {
		b, err := dec.next(n)
		if err != nil {
			return err
		}
		if exactByte {
			_ = reflect.Copy(val, reflect.ValueOf(b))
			return nil
		}
		for i := 0; i < n; i++ {
			val.Index(i).SetUint(uint64(b[i]))
		}
		return nil
	}
}

func readNothing(*buffer, reflect.Value) error { return nil }

// makeArrayReader reads a fixed number of elements, with the same scalar fast
// paths the writer has.
func makeArrayReader(typ reflect.Type) (funcReader, error) {
	n := typ.Len()
	switch typ.Elem().Kind() {
	case reflect.Uint16:
		return func(dec *buffer, val reflect.Value) error {
			s, err := dec.next(n * 2)
			if err != nil {
				return err
			}
			for i := 0; i < n; i++ {
				val.Index(i).SetUint(uint64(binary.LittleEndian.Uint16(s[i*2:])))
			}
			return nil
		}, nil
	case reflect.Uint32:
		return func(dec *buffer, val reflect.Value) error {
			s, err := dec.next(n * 4)
			if err != nil {
				return err
			}
			for i := 0; i < n; i++ {
				val.Index(i).SetUint(uint64(binary.LittleEndian.Uint32(s[i*4:])))
			}
			return nil
		}, nil
	case reflect.Uint64:
		return func(dec *buffer, val reflect.Value) error {
			s, err := dec.next(n * 8)
			if err != nil {
				return err
			}
			for i := 0; i < n; i++ {
				val.Index(i).SetUint(binary.LittleEndian.Uint64(s[i*8:]))
			}
			return nil
		}, nil
	case reflect.Bool:
		return func(dec *buffer, val reflect.Value) error {
			s, err := dec.next(n)
			if err != nil {
				return err
			}
			for i := 0; i < n; i++ {
				switch s[i] {
				case 0:
					val.Index(i).SetBool(false)
				case 1:
					val.Index(i).SetBool(true)
				default:
					return fmt.Errorf("utils/encoding: bool byte is neither 0 nor 1")
				}
			}
			return nil
		}, nil
	}

	elem := tc.resolve(typ.Elem())
	if elem.readerError != nil {
		return nil, elem.readerError
	}
	if minSize(typ.Elem(), map[reflect.Type]int{}) == 0 {
		return readNothing, nil
	}
	return func(dec *buffer, val reflect.Value) error {
		for i := 0; i < n; i++ {
			if err := elem.reader(dec, val.Index(i)); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

// makePointerReader reads the presence byte, and only then allocates. A
// pointer is the cheapest thing to name on the wire and can be the most
// expensive to honour, so the budget is charged before reflect.New runs.
func makePointerReader(typ reflect.Type) (funcReader, error) {
	elem := tc.resolve(typ.Elem())
	if elem.readerError != nil {
		return nil, elem.readerError
	}
	least := minSize(typ.Elem(), map[reflect.Type]int{})
	size := uint64(typ.Elem().Size())

	return func(dec *buffer, val reflect.Value) error {
		present, err := dec.readBool()
		if err != nil {
			return err
		}
		if !present {
			return nil
		}
		if dec.length() < least {
			return fmt.Errorf("utils/encoding: read past the end of the buffer")
		}
		if err := dec.reserve(1, size); err != nil {
			return err
		}
		out := reflect.New(typ.Elem())
		if err := elem.reader(dec, out.Elem()); err != nil {
			return err
		}
		val.Set(out)
		return nil
	}, nil
}

// makeStructReader reads the fields in the order the writer wrote them.
func makeStructReader(typ reflect.Type) (funcReader, error) {
	type field struct {
		index int
		read  funcReader
	}

	fields := make([]field, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag, err := parseTag(f)
		if err != nil {
			return nil, fmt.Errorf("%w (%s.%s)", err, typ, f.Name)
		}
		if tag.skip {
			continue
		}
		if f.PkgPath != "" {
			return nil, fmt.Errorf("utils/encoding: struct field is unexported: %s.%s (tag it encoding:\"-\" if it is derived)", typ, f.Name)
		}

		c := tc.resolve(f.Type)
		if c.readerError != nil {
			return nil, fmt.Errorf("%w (%s.%s)", c.readerError, typ, f.Name)
		}
		fields = append(fields, field{index: i, read: c.reader})
	}

	return func(dec *buffer, val reflect.Value) error {
		for _, f := range fields {
			if err := f.read(dec, val.Field(f.index)); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

// makeEnumReader reads the variant number, which decides both where the value
// goes and how the rest of the bytes are read.
func makeEnumReader(typ reflect.Type) (funcReader, error) {
	p, err := planEnum(typ)
	if err != nil {
		return nil, err
	}
	for _, m := range p.members {
		if m.info.readerError != nil {
			return nil, fmt.Errorf("%w (%s.%s)", m.info.readerError, typ, typ.Field(m.index).Name)
		}
	}

	return func(dec *buffer, val reflect.Value) error {
		variant, err := dec.readUvarint()
		if err != nil {
			return err
		}
		if variant >= uint64(len(p.members)) {
			return fmt.Errorf("utils/encoding: %s is variant %d, but it declares %d", typ, variant, len(p.members))
		}
		live := p.members[variant]
		val.Field(p.tag).SetUint(variant)

		return live.info.reader(dec, val.Field(live.index))
	}, nil
}

// minSize is the fewest bytes a value of this type can possibly occupy, which
// is what the length and budget checks are measured against. It has to be a
// true floor: claiming more than the smallest real encoding would turn valid
// input into an error. Recursive types settle at zero through the memo, and
// their callers refuse them before the figure is ever used.
func minSize(typ reflect.Type, memo map[reflect.Type]int) int {
	if n, ok := memo[typ]; ok {
		return n
	}
	memo[typ] = 0
	n := 0
	switch typ.Kind() {
	case reflect.Bool, reflect.Uint8, reflect.String, reflect.Slice, reflect.Pointer:
		n = 1
	case reflect.Uint16:
		n = 2
	case reflect.Uint32:
		n = 4
	case reflect.Uint64:
		n = 8
	case reflect.Array:
		n = typ.Len() * minSize(typ.Elem(), memo)
	case reflect.Struct:
		if isEnum(typ) {
			least, first := 0, true
			for i := 0; i < typ.NumField(); i++ {
				f := typ.Field(i)
				tag, err := parseTag(f)
				if err != nil || tag.skip || tag.enum {
					continue
				}
				if size := minSize(f.Type, memo); first || size < least {
					least, first = size, false
				}
			}
			n = 1 + least

			break
		}
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			tag, err := parseTag(f)
			if err != nil || tag.skip {
				continue
			}
			n += minSize(f.Type, memo)
		}
	}
	memo[typ] = n

	return n
}
