package bcs

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// planEnum reads tc.next, which only typeCache.build normally fills, and
// resolve panics on a nil map. This stands the same scaffolding up so the
// function can be exercised on its own.
func planFor(t *testing.T, v any) (enumPlan, error) {
	t.Helper()
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.next = map[reflect.Type]*typeInfo{}
	defer func() { tc.next = nil }()

	return planEnum(reflect.TypeOf(v))
}

func TestPlanEnumFindsTheTagAndTheVariants(t *testing.T) {
	type good struct {
		Kind uint8 `encoding:"enum"`
		A    uint8
		B    string
	}

	p, err := planFor(t, good{})
	if err != nil {
		t.Fatalf("planEnum: %v", err)
	}
	if p.tag != 0 {
		t.Errorf("discriminant is field %d, want 0", p.tag)
	}
	if len(p.members) != 2 {
		t.Fatalf("found %d variants, want 2", len(p.members))
	}
	if p.members[0].index != 1 || p.members[1].index != 2 {
		t.Errorf("variants sit at %d and %d, want 1 and 2", p.members[0].index, p.members[1].index)
	}
}

// A skipped field is never resolved, so it may hold a type the codec has no
// encoding for at all.
func TestPlanEnumIgnoresSkippedFields(t *testing.T) {
	type withDerived struct {
		Kind    uint8         `encoding:"enum"`
		Derived chan struct{} `encoding:"-"`
		A       uint8
	}

	p, err := planFor(t, withDerived{})
	if err != nil {
		t.Fatalf("planEnum: %v", err)
	}
	if len(p.members) != 1 || p.members[0].index != 2 {
		t.Errorf("got %d variants at %v, want one at index 2", len(p.members), p.members)
	}
}

func TestPlanEnumRejectsMalformedShapes(t *testing.T) {
	type variantFirst struct {
		A    uint8
		Kind uint8 `encoding:"enum"`
	}
	type twoTags struct {
		Kind  uint8 `encoding:"enum"`
		A     uint8
		Other uint8 `encoding:"enum"`
	}
	type tagOnly struct {
		Kind uint8 `encoding:"enum"`
	}
	type unexported struct {
		Kind uint8 `encoding:"enum"`
		a    uint8
	}
	type badTag struct {
		Kind uint8 `encoding:"enum"`
		A    uint8 `encoding:"bogus"`
	}
	type allSkipped struct {
		A uint8 `encoding:"-"`
	}

	tests := []struct {
		name  string
		value any
		want  string
	}{
		{"a variant before the discriminant", variantFirst{}, "comes before the variants"},
		{"two discriminants", twoTags{}, "comes before the variants"},
		{"a discriminant with nothing after it", tagOnly{}, "no variant after it"},
		{"an unexported variant", unexported{}, "field is unexported"},
		{"a tag that does not parse", badTag{}, "unknown tag option"},
		{"nothing but skipped fields", allSkipped{}, "no variant after it"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := planFor(t, tt.value)
			if err == nil {
				t.Fatal("planEnum accepted the type")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error is %q, want it to mention %q", err, tt.want)
			}
		})
	}
}

// The discriminant has to be able to name every variant. A uint8 holds 256, so
// the 257th is refused rather than silently unreachable.
func TestPlanEnumChecksTheDiscriminantIsWideEnough(t *testing.T) {
	build := func(variants int, kind reflect.Type) reflect.Type {
		fields := []reflect.StructField{{
			Name: "Kind",
			Type: kind,
			Tag:  `encoding:"enum"`,
		}}
		for i := range variants {
			fields = append(fields, reflect.StructField{
				Name: fmt.Sprintf("V%d", i),
				Type: reflect.TypeOf(uint8(0)),
			})
		}

		return reflect.StructOf(fields)
	}

	uint8Type := reflect.TypeOf(uint8(0))
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.next = map[reflect.Type]*typeInfo{}
	defer func() { tc.next = nil }()

	if _, err := planEnum(build(256, uint8Type)); err != nil {
		t.Errorf("256 variants in a uint8 were refused: %v", err)
	}

	_, err := planEnum(build(257, uint8Type))
	if err == nil {
		t.Fatal("257 variants fit in a uint8, apparently")
	}
	if !strings.Contains(err.Error(), "8-bit discriminant") {
		t.Errorf("error is %q, want it to name the width", err)
	}

	// A 64-bit discriminant skips the check: 1<<64 does not fit in an int, and
	// no struct comes close to that many fields anyway.
	if _, err := planEnum(build(257, reflect.TypeOf(uint64(0)))); err != nil {
		t.Errorf("a uint64 discriminant was refused: %v", err)
	}
}
