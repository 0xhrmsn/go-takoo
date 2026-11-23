package bcs

import (
	"reflect"
	"strings"
	"testing"
)

type tagged struct {
	Plain    uint8
	Empty    uint8 `encoding:""`
	Commas   uint8 `encoding:",,"`
	Skipped  uint8 `encoding:"-"`
	Variant  uint8 `encoding:"enum"`
	Both     uint8 `encoding:"-,enum"`
	Unknown  uint8 `encoding:"bogus"`
	Trailing uint8 `encoding:"enum,"`
	Signed   int8  `encoding:"enum"`
	Text     string
	Word     uint    `encoding:"enum"`
	Pointer  uintptr `encoding:"enum"`
}

func fieldByName(t *testing.T, name string) reflect.StructField {
	t.Helper()
	f, ok := reflect.TypeOf(tagged{}).FieldByName(name)
	if !ok {
		t.Fatalf("no field named %s", name)
	}

	return f
}

func TestParseTagReadsTheOptions(t *testing.T) {
	tests := []struct {
		field string
		want  tags
	}{
		{"Plain", tags{}},
		{"Empty", tags{}},
		{"Commas", tags{}},
		{"Skipped", tags{skip: true}},
		{"Variant", tags{enum: true}},
		{"Trailing", tags{enum: true}},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			got, err := parseTag(fieldByName(t, tt.field))
			if err != nil {
				t.Fatalf("parseTag: %v", err)
			}
			if got != tt.want {
				t.Errorf("parseTag = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseTagRejectsTheRest(t *testing.T) {
	tests := []struct {
		field string
		want  string
	}{
		{"Both", "not both"},
		{"Unknown", "unknown tag option"},
		{"Signed", "unsigned integer"},
		// The check is a Kind range from Uint8 to Uint64. A plain uint sits
		// below it and uintptr above, so neither may carry a discriminant even
		// though both are unsigned.
		{"Word", "unsigned integer"},
		{"Pointer", "unsigned integer"},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			_, err := parseTag(fieldByName(t, tt.field))
			if err == nil {
				t.Fatal("parseTag accepted the tag")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error is %q, want it to mention %q", err, tt.want)
			}
			if !strings.Contains(err.Error(), "utils/encoding:") {
				t.Errorf("error does not name the package: %v", err)
			}
		})
	}
}

func TestIsUintCoversOnlyTheFixedWidths(t *testing.T) {
	yes := []any{uint8(0), uint16(0), uint32(0), uint64(0)}
	no := []any{uint(0), uintptr(0), int8(0), int64(0), "", false, 0.0}

	for _, v := range yes {
		if k := reflect.TypeOf(v).Kind(); !isUint(k) {
			t.Errorf("isUint(%s) = false, want true", k)
		}
	}
	for _, v := range no {
		if k := reflect.TypeOf(v).Kind(); isUint(k) {
			t.Errorf("isUint(%s) = true, want false", k)
		}
	}
}

func TestIsEnumFindsTheDiscriminant(t *testing.T) {
	type withTag struct {
		Kind uint8 `encoding:"enum"`
		A    uint8
	}
	type withoutTag struct {
		A uint8
		B uint8
	}
	// The tag is there but unusable, so parseTag errors and isEnum never sees
	// the option. The type falls through to the plain struct path, where the
	// same tag is reported properly.
	type withBadTag struct {
		Kind string `encoding:"enum"`
		A    uint8
	}
	type empty struct{}

	tests := []struct {
		name string
		typ  reflect.Type
		want bool
	}{
		{"tagged", reflect.TypeOf(withTag{}), true},
		{"untagged", reflect.TypeOf(withoutTag{}), false},
		{"tag that does not parse", reflect.TypeOf(withBadTag{}), false},
		{"no fields", reflect.TypeOf(empty{}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isEnum(tt.typ); got != tt.want {
				t.Errorf("isEnum(%s) = %v, want %v", tt.typ, got, tt.want)
			}
		})
	}
}
