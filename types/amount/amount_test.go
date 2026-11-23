package amount

import (
	"encoding/json"
	"math"
	"math/bits"
	"strings"
	"testing"
)

var (
	amountStringSink string
	amountSink       Amount
	amountTextSink   []byte
)

func TestAddRefusesToWrap(t *testing.T) {
	if _, err := Amount(math.MaxUint64).Add(1); err == nil {
		t.Errorf("max amount + 1 = %v, want an overflow error", err)
	}
	if _, err := Amount(math.MaxUint64).Add(0); err != nil {
		t.Errorf("max amount + 0: %v", err)
	}

	got, err := Amount(100).Add(50)
	if err != nil || got != 150 {
		t.Errorf("100 + 50 = %d, %v", got, err)
	}
}

func TestSubRefusesToGoBelowZero(t *testing.T) {
	if _, err := Amount(10).Sub(20); err == nil {
		t.Errorf("10 - 20 = %v, want an underflow error", err)
	}

	got, err := Amount(10).Sub(10)
	if err != nil || got != 0 {
		t.Errorf("10 - 10 = %d, %v", got, err)
	}
}

func TestSum(t *testing.T) {
	got, err := Sum()
	if err != nil || got != 0 {
		t.Errorf("Sum() = %d, %v; want 0", got, err)
	}

	got, err = Sum(1, 2, 3, 4)
	if err != nil || got != 10 {
		t.Errorf("Sum(1,2,3,4) = %d, %v; want 10", got, err)
	}

	if _, err := Sum(Amount(math.MaxUint64), 1, 1); err == nil {
		t.Errorf("Sum(Max, 1, 1) = %v, want an overflow error", err)
	}
}

func TestStringIsExactAtEveryMagnitude(t *testing.T) {
	tests := []struct {
		units Amount
		want  string
	}{
		{0, "0.00000000"},
		{1, "0.00000001"},
		{UnitsPerCoin - 1, "0.99999999"},
		{UnitsPerCoin, "1.00000000"},
		{UnitsPerCoin + UnitsPerCoin/2, "1.50000000"},
		{9_007_199_254_740_993, "90071992.54740993"},
		{Amount(math.MaxUint64), "184467440737.09551615"},
	}
	for _, tt := range tests {
		if got := tt.units.String(); got != tt.want {
			t.Errorf("Amount(%d).String() = %q, want %q", tt.units, got, tt.want)
		}
	}
}

func TestStringRoundTrip(t *testing.T) {
	for i := uint64(0); i < 200_000; i++ {
		units := Amount(i*982_451_653 + 7)

		text := units.String()
		if got, err := FromString(text); err != nil || got != units {
			t.Fatalf("%d printed as %q, which reads back as %d, %v", units, text, got, err)
		}
	}
}

func TestStringFractionAlwaysFullWidth(t *testing.T) {
	for _, units := range []Amount{1, 10, 10_000_000, UnitsPerCoin - 1} {
		text := units.String()
		dot := strings.IndexByte(text, '.')
		if got := len(text) - dot - 1; got != 8 {
			t.Errorf("Amount(%d).String() = %q, fraction is %d digits, want 8",
				units, text, got)
		}
	}
}

func FuzzAmountString(f *testing.F) {
	for _, u := range []uint64{0, 1, UnitsPerCoin, math.MaxUint64} {
		f.Add(u)
	}
	f.Fuzz(func(t *testing.T, units uint64) {
		a := Amount(units)

		text := a.String()
		dot := strings.IndexByte(text, '.')
		if dot < 0 {
			t.Fatalf("%d printed as %q with no decimal point", units, text)
		}
		if got := len(text) - dot - 1; got != 8 {
			t.Fatalf("%d printed as %q, fraction is %d digits", units, text, got)
		}

		if got, err := FromString(text); err != nil || got != a {
			t.Fatalf("%d printed as %q, reads back as %d, %v", units, text, got, err)
		}
	})
}

func TestFromString(t *testing.T) {
	tests := []struct {
		in   string
		want Amount
	}{
		{"0", 0},
		{"1", Unit},
		{"1.5", Unit + Unit/2},
		{"1.50000000", Unit + Unit/2},
		{"0.00000001", 1},
		{"0.1", 10_000_000},
		{"007.25", 7*Unit + Unit/4},
		{"90071992.54740993", 9_007_199_254_740_993},
		{"184467440737.09551615", Amount(math.MaxUint64)},
	}
	for _, tt := range tests {
		if got, err := FromString(tt.in); err != nil || got != tt.want {
			t.Errorf("FromString(%q) = %d, %v; want %d", tt.in, got, err, tt.want)
		}
	}
}

func TestFromStringRejects(t *testing.T) {
	for _, in := range []string{
		"", ".", "1.", ".5", "1.5.0",
		"-1", "+1", " 1", "1 ", "1,5", "1e3", "0x10", "1_000", "1.-5", "1.+5",
		"1.123456789",
		"184467440737.09551616",
		"184467440738",
		"99999999999999999999",
	} {
		if got, err := FromString(in); err == nil {
			t.Errorf("FromString(%q) = %d, want an error", in, got)
		}
	}
}

func FuzzFromString(f *testing.F) {
	for _, s := range []string{"0", "1.5", "0.00000001", "184467440737.09551615", "1.", "-1", "1e3"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		a, err := FromString(s)
		if err != nil {
			if a != 0 {
				t.Fatalf("FromString(%q) = %d on error %v, want zero", s, a, err)
			}
			return
		}
		if back, err := FromString(a.String()); err != nil || back != a {
			t.Fatalf("%q read as %d, printed as %q, read back as %d, %v", s, a, a.String(), back, err)
		}
	})
}

func TestJSONIsTheStringForm(t *testing.T) {
	type doc struct {
		Stake Amount `json:"stake"`
	}

	got, err := json.Marshal(doc{Stake: Amount(math.MaxUint64)})
	if err != nil || string(got) != `{"stake":"184467440737.09551615"}` {
		t.Fatalf("json.Marshal = %s, %v", got, err)
	}

	var back doc
	if err := json.Unmarshal(got, &back); err != nil || back.Stake != Amount(math.MaxUint64) {
		t.Fatalf("json.Unmarshal(%s) = %d, %v", got, back.Stake, err)
	}

	for _, in := range []string{`{"stake":"1.123456789"}`, `{"stake":"-1"}`, `{"stake":150000000}`} {
		back := doc{Stake: 7}
		if err := json.Unmarshal([]byte(in), &back); err == nil || back.Stake != 7 {
			t.Errorf("json.Unmarshal(%s) = %d, %v; want an error and 7 kept", in, back.Stake, err)
		}
	}
}

func FuzzAmountArithmetic(f *testing.F) {
	f.Add(uint64(0), uint64(0))
	f.Add(uint64(0), uint64(1))
	f.Add(uint64(1), uint64(math.MaxUint64))
	f.Add(uint64(math.MaxUint64), uint64(math.MaxUint64))
	f.Add(uint64(math.MaxUint64), uint64(1))

	f.Fuzz(func(t *testing.T, x, y uint64) {
		a, b := Amount(x), Amount(y)

		sum, err := a.Add(b)
		wantSum, carry := bits.Add64(x, y, 0)
		if (err != nil) != (carry != 0) {
			t.Fatalf("%d + %d: error %v, carry %d", x, y, err, carry)
		}
		if err == nil && uint64(sum) != wantSum {
			t.Fatalf("%d + %d reported %d", x, y, sum)
		}
		if err != nil && sum != 0 {
			t.Fatalf("%d + %d: got %d on error %v; want zero", x, y, sum, err)
		}

		diff, err := a.Sub(b)
		if (err != nil) != (x < y) {
			t.Fatalf("%d - %d: error %v does not match underflow", x, y, err)
		}
		if err == nil && uint64(diff) != x-y {
			t.Fatalf("%d - %d reported %d", x, y, diff)
		}
		if err != nil && diff != 0 {
			t.Fatalf("%d - %d: got %d on error %v; want zero", x, y, diff, err)
		}
	})
}

func BenchmarkFromString(b *testing.B) {
	for _, tc := range []struct {
		name string
		text string
	}{
		{"whole", "1"},
		{"short-fraction", "1.5"},
		{"full", "123456789.12345678"},
		{"max", "184467440737.09551615"},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				amountSink, _ = FromString(tc.text)
			}
		})
	}
}

func BenchmarkAmountString(b *testing.B) {
	for _, tc := range []struct {
		name  string
		value Amount
	}{
		{"zero", 0},
		{"one-unit", 1},
		{"one-coin", Unit},
		{"mixed", 123456789123456789},
		{"max", Amount(math.MaxUint64)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				amountStringSink = tc.value.String()
			}
		})
	}
}

func BenchmarkMarshalText(b *testing.B) {
	b.ReportAllocs()
	a := Amount(123456789123456789)
	for b.Loop() {
		amountTextSink, _ = a.MarshalText()
	}
}
