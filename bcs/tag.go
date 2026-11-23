package bcs

import (
	"fmt"
	"reflect"
	"strings"
)

// tags is what a field's `encoding:"..."` tag asked for. The two options are
// mutually exclusive: a field is either left out of the encoding or it is the
// thing that selects a variant, never both.
type tags struct {
	skip bool
	enum bool
}

// parseTag reads one field's tag and refuses anything it does not recognise,
// so a typo in a struct definition surfaces when the type is planned rather
// than being ignored into a silently different wire format.
func parseTag(f reflect.StructField) (tags, error) {
	var tag tags
	raw, ok := f.Tag.Lookup("encoding")
	if !ok {
		return tag, nil
	}
	for opt := range strings.SplitSeq(raw, ",") {
		switch opt {
		case "":
			continue
		case "-":
			tag.skip = true
		case "enum":
			tag.enum = true
		default:
			return tag, fmt.Errorf("utils/encoding: unknown tag option: %q", opt)
		}
	}
	if tag.skip && tag.enum {
		return tag, fmt.Errorf("utils/encoding: a field is skipped or the enum discriminant, not both")
	}
	if tag.enum && !isUint(f.Type.Kind()) {
		return tag, fmt.Errorf("utils/encoding: enum discriminant must be an unsigned integer: %s", f.Type)
	}
	return tag, nil
}

// isUint reports whether a kind is one of the fixed-width unsigned integers.
// The range stops short of uint and uintptr on purpose: both are sized by the
// platform, and a discriminant whose width moves between builds would move the
// wire format with it.
func isUint(kind reflect.Kind) bool {
	return kind >= reflect.Uint8 && kind <= reflect.Uint64
}

// isEnum reports whether a struct is a tagged union rather than a plain record,
// which is what sends it down the enum path instead of the struct one. A tag
// that does not parse is passed over here and reported properly further on,
// where the field name is still at hand.
func isEnum(typ reflect.Type) bool {
	for i := 0; i < typ.NumField(); i++ {
		if tag, err := parseTag(typ.Field(i)); err == nil && tag.enum {
			return true
		}
	}
	return false
}
