// Package encoding is the codec the chain puts on the wire and in storage. It
// is modelled on BCS but bound to no spec: a value carries no field names and
// no type marks, only its bytes in declaration order, so both sides have to
// know the Go type to read anything at all.
//
// The format is canonical by construction. Integers are little-endian at a
// fixed width; lengths and enum variants are uvarints in their shortest form; a
// slice carries its count and an array does not; a pointer carries one byte for
// whether it is there. One value has one encoding and the decoder refuses every
// other spelling, which is what lets a decoded value be hashed, signed, and
// compared as bytes.
//
// Reordering the fields of a type changes its encoding and says nothing about
// it, so the types that go between peers are pinned to literal bytes by their
// own tests.
package bcs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"unicode/utf8"
)

var byteType = reflect.TypeOf(byte(0))

// Encode writes v to w. The whole value is built in memory first, so w never
// sees a half-written value that turned out not to encode.
func Encode(w io.Writer, v any) error {
	buf := getBuffer()
	defer bufferPool.Put(buf)
	if err := buf.encode(v); err != nil {
		return err
	}

	return buf.writeTo(w)
}

// Encode2Bytes returns v as bytes. The result is a copy: the buffer it was
// built in goes back to the pool and will be written over.
func EncodeToBytes(v any) ([]byte, error) {
	buf := getBuffer()
	defer bufferPool.Put(buf)
	if err := buf.encode(v); err != nil {
		return nil, err
	}

	return bytes.Clone(buf.str[buf.off:]), nil
}

// funcWriter writes one value of the type it was made for. Planning the type
// once and keeping the closure is what keeps reflection off the hot path.
type funcWriter func(enc *buffer, val reflect.Value) error

// makeWriter plans how a type is written, once, when it is first seen. The
// order of the cases matters: byte slices and byte arrays are copied wholesale
// rather than element by element, so they are matched before the general forms.
func makeWriter(typ reflect.Type) (funcWriter, error) {
	kind := typ.Kind()
	switch {
	case kind == reflect.Bool:
		return writeBool, nil
	case kind == reflect.Uint8:
		return writeUint8, nil
	case kind == reflect.Uint16:
		return writeUint16, nil
	case kind == reflect.Uint32:
		return writeUint32, nil
	case kind == reflect.Uint64:
		return writeUint64, nil
	case kind == reflect.String:
		return writeString, nil
	case kind == reflect.Slice && typ.Elem().Kind() == reflect.Uint8:
		return writeBytes, nil
	case kind == reflect.Slice:
		return makeSliceWriter(typ)
	case kind == reflect.Array && typ.Elem().Kind() == reflect.Uint8:
		return makeBytesArrayWriter(typ), nil
	case kind == reflect.Array:
		return makeArrayWriter(typ)
	case kind == reflect.Pointer:
		return makePointerWriter(typ)
	case kind == reflect.Struct && isEnum(typ):
		return makeEnumWriter(typ)
	case kind == reflect.Struct:
		return makeStructWriter(typ)
	default:
		return nil, fmt.Errorf("utils/encoding: type has no encoding: %s", typ)
	}
}

func writeBool(enc *buffer, val reflect.Value) error {
	enc.writeBool(val.Bool())

	return nil
}

func writeUint8(enc *buffer, val reflect.Value) error {
	enc.writeUint8(uint8(val.Uint()))

	return nil
}

func writeUint16(enc *buffer, val reflect.Value) error {
	enc.writeUint16(uint16(val.Uint()))

	return nil
}

func writeUint32(enc *buffer, val reflect.Value) error {
	enc.writeUint32(uint32(val.Uint()))

	return nil
}

func writeUint64(enc *buffer, val reflect.Value) error {
	enc.writeUint64(uint64(val.Uint()))

	return nil
}

// writeString refuses a string that is not valid UTF-8. A Go string can hold
// arbitrary bytes, and letting one through would mean a value the decoder is
// bound to reject.
func writeString(enc *buffer, val reflect.Value) error {
	s := val.String()
	if !utf8.ValidString(s) {
		return fmt.Errorf("utils/encoding: string is not valid UTF-8")
	}
	enc.writeBytes([]byte(s))

	return nil
}

func writeBytes(enc *buffer, val reflect.Value) error {
	enc.writeBytes(val.Bytes())

	return nil
}

// makeSliceWriter writes the count and then the elements. An element that
// always encodes to nothing is refused: the bytes would not say how many there
// were, so the decoder could not get the count back.
func makeSliceWriter(typ reflect.Type) (funcWriter, error) {
	elem := tc.resolve(typ.Elem())
	if elem.writerError != nil {
		return nil, elem.writerError
	}
	if minSize(typ.Elem(), map[reflect.Type]int{}) == 0 {
		return nil, fmt.Errorf("utils/encoding: slice element encodes to nothing: %s", typ)
	}

	return func(enc *buffer, val reflect.Value) error {
		n := val.Len()
		enc.writeUvarint(uint64(n))
		for i := 0; i < n; i++ {
			if err := elem.writer(enc, val.Index(i)); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

// makeBytesArrayWriter copies a fixed-width byte array straight out, with no
// count in front of it: the length is in the type. Which of the three copies
// applies depends on whether the element is exactly byte and whether the value
// can be addressed, and all three land on the same bytes.
func makeBytesArrayWriter(typ reflect.Type) funcWriter {
	n := typ.Len()
	exactByte := typ.Elem() == byteType

	return func(buf *buffer, val reflect.Value) error {
		at := buf.grow(n)
		switch {
		case exactByte && val.CanAddr():
			buf.str = append(buf.str[:at], val.Bytes()...)
		case exactByte:
			reflect.Copy(reflect.ValueOf(buf.str[at:at+n]), val)
		default:
			s := buf.str[at:]
			for i := 0; i < n; i++ {
				s[i] = byte(val.Index(i).Uint())
			}
		}
		return nil
	}
}

func writeNothing(*buffer, reflect.Value) error { return nil }

// makeArrayWriter writes a fixed number of elements, again with no count. The
// scalar kinds are filled in one pass over the destination; anything else falls
// through to the element's own writer.
func makeArrayWriter(typ reflect.Type) (funcWriter, error) {
	l := typ.Len()
	switch typ.Elem().Kind() {
	case reflect.Bool:
		return func(enc *buffer, val reflect.Value) error {
			at := enc.grow(l)
			s := enc.str[at:]
			for i := 0; i < l; i++ {
				if val.Index(i).Bool() {
					s[i] = 1
				} else {
					s[i] = 0
				}
			}
			return nil
		}, nil
	case reflect.Uint16:
		return func(enc *buffer, val reflect.Value) error {
			at := enc.grow(l * 2)
			s := enc.str[at:]
			for i := 0; i < l; i++ {
				binary.LittleEndian.PutUint16(s[i*2:], uint16(val.Index(i).Uint()))
			}
			return nil
		}, nil
	case reflect.Uint32:
		return func(enc *buffer, val reflect.Value) error {
			at := enc.grow(l * 4)
			s := enc.str[at:]
			for i := 0; i < l; i++ {
				binary.LittleEndian.PutUint32(s[i*4:], uint32(val.Index(i).Uint()))
			}
			return nil
		}, nil
	case reflect.Uint64:
		return func(enc *buffer, val reflect.Value) error {
			at := enc.grow(l * 8)
			s := enc.str[at:]
			for i := 0; i < l; i++ {
				binary.LittleEndian.PutUint64(s[i*8:], val.Index(i).Uint())
			}
			return nil
		}, nil
	}

	elem := tc.resolve(typ.Elem())
	if elem.writerError != nil {
		return nil, elem.writerError
	}
	// An element that is always zero bytes has nothing to write.
	if minSize(typ.Elem(), map[reflect.Type]int{}) == 0 {
		return writeNothing, nil
	}

	return func(enc *buffer, val reflect.Value) error {
		for i := 0; i < l; i++ {
			if err := elem.writer(enc, val.Index(i)); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

// makePointerWriter writes one byte for whether the pointer is set, and the
// value behind it if so. That byte is all that distinguishes an absent value
// from a zero one.
func makePointerWriter(typ reflect.Type) (funcWriter, error) {
	elem := tc.resolve(typ.Elem())
	if elem.writerError != nil {
		return nil, elem.writerError
	}

	return func(enc *buffer, val reflect.Value) error {
		if val.IsNil() {
			enc.writeBool(false)
			return nil
		}
		enc.writeBool(true)
		return elem.writer(enc, val.Elem())
	}, nil
}

// makeStructWriter writes the fields in declaration order, skipping the ones
// tagged out. Nothing names them on the wire, so that order is the format.
func makeStructWriter(typ reflect.Type) (funcWriter, error) {
	type field struct {
		index int
		write funcWriter
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
		if c.writerError != nil {
			return nil, fmt.Errorf("%w (%s.%s)", c.writerError, typ, f.Name)
		}
		fields = append(fields, field{index: i, write: c.writer})
	}

	return func(enc *buffer, val reflect.Value) error {
		for _, f := range fields {
			if err := f.write(enc, val.Field(f.index)); err != nil {
				return err
			}
		}
		return nil
	}, nil
}

// makeEnumWriter writes the variant number and then that variant alone. A
// value sitting in any other variant is refused rather than dropped, so the
// struct and its bytes cannot come to mean different things.
func makeEnumWriter(typ reflect.Type) (funcWriter, error) {
	p, err := planEnum(typ)
	if err != nil {
		return nil, err
	}
	for _, m := range p.members {
		if m.info.writerError != nil {
			return nil, fmt.Errorf("%w (%s.%s)", m.info.writerError, typ, typ.Field(m.index).Name)
		}
	}

	return func(enc *buffer, val reflect.Value) error {
		variant := val.Field(p.tag).Uint()
		if variant >= uint64(len(p.members)) {
			return fmt.Errorf("utils/encoding: %s is variant %d, but it declares %d", typ, variant, len(p.members))
		}
		live := p.members[variant]
		for i, m := range p.members {
			if uint64(i) != variant && !val.Field(m.index).IsZero() {
				return fmt.Errorf("utils/encoding: %s.%s is set, but variant %d does not encode it", typ, typ.Field(m.index).Name, variant)
			}
		}
		enc.writeUvarint(variant)

		return live.info.writer(enc, val.Field(live.index))
	}, nil
}
