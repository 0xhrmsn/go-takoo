package bcs

import (
	"fmt"
	"reflect"
)

// enumMember is one variant: where it sits in the struct, and the plan for
// reading and writing whatever it holds.
type enumMember struct {
	index int
	info  *typeInfo
}

// enumPlan is a tagged union reduced to what the codec needs at run time: the
// field that names the variant, and the variants themselves in declaration
// order. That order is the wire numbering, so moving a field renumbers the
// union.
type enumPlan struct {
	tag     int
	members []enumMember
}

// planEnum works out that layout once, when the type is first seen, and refuses
// any shape it could not encode unambiguously.
//
// planEnum must only run inside typeCache.build (through generate), while
// tc.next is live: it calls tc.resolve for every variant, and outside a build
// tc.next is nil and resolve panics.
func planEnum(typ reflect.Type) (enumPlan, error) {
	p := enumPlan{tag: -1}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		tag, err := parseTag(f)
		if err != nil {
			return p, fmt.Errorf("%w (%s.%s)", err, typ, f.Name)
		}
		if tag.skip {
			continue
		}

		switch {
		case f.PkgPath != "":
			return p, fmt.Errorf("utils/encoding: struct field is unexported: %s.%s (tag it encoding:\"-\" if it is derived)", typ, f.Name)
		// Exactly one discriminant, and it comes first. Reading it before the
		// variants is what lets the decoder know which one to expect.
		case (p.tag < 0) != tag.enum:
			return p, fmt.Errorf("utils/encoding: %s declares one enum discriminant, and it comes before the variants it selects", typ)
		case tag.enum:
			p.tag = i
		default:
			p.members = append(p.members, enumMember{index: i, info: tc.resolve(f.Type)})
		}
	}
	if p.tag < 0 || len(p.members) == 0 {
		return p, fmt.Errorf("utils/encoding: %s declares an enum discriminant but no variant after it", typ)
	}
	// The discriminant has to be able to name every variant, or the ones past
	// its range would be unreachable rather than merely unused.
	if bits := typ.Field(p.tag).Type.Bits(); bits < 64 && len(p.members) > 1<<bits {
		return p, fmt.Errorf("utils/encoding: %s declares %d variants, and its %d-bit discriminant holds %d", typ, len(p.members), bits, 1<<bits)
	}

	return p, nil
}
