package amount

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

const UnitsPerCoin = 100_000_000

const _ = uint(UnitsPerCoin-100_000_000) + uint(100_000_000-UnitsPerCoin)

const Unit Amount = UnitsPerCoin

type Amount uint64

func FromString(s string) (Amount, error) {
	whole, frac, hasDot := strings.Cut(s, ".")
	if whole == "" || (hasDot && (frac == "" || len(frac) > 8)) {
		return 0, fmt.Errorf("types/amount: %q is not an amount, want digits with at most 8 decimals", s)
	}

	coins, err := strconv.ParseUint(whole, 10, 64)
	if err != nil || coins > math.MaxUint64/UnitsPerCoin {
		return 0, fmt.Errorf("types/amount: %q is not an amount, whole part is not a number in range", s)
	}

	var units uint64
	if hasDot {
		if units, err = strconv.ParseUint(frac+"00000000"[len(frac):], 10, 64); err != nil {
			return 0, fmt.Errorf("types/amount: %q is not an amount, fraction is not a number", s)
		}
	}

	return Amount(coins * UnitsPerCoin).Add(Amount(units))
}

func Sum(amounts ...Amount) (Amount, error) {
	var total Amount
	for _, a := range amounts {
		var err error
		if total, err = total.Add(a); err != nil {
			return 0, err
		}
	}

	return total, nil
}

func (a Amount) Add(b Amount) (Amount, error) {
	if a+b < a {
		return 0, fmt.Errorf("types/amount: amount overflow: %d plus %d, refusing to wrap", uint64(a), uint64(b))
	}

	return a + b, nil
}

func (a Amount) Sub(b Amount) (Amount, error) {
	if a < b {
		return 0, fmt.Errorf("types/amount: amount underflow: %d is short of %d", uint64(a), uint64(b))
	}

	return a - b, nil
}

func (a Amount) String() string {
	var storage [21]byte
	out := strconv.AppendUint(storage[:0], uint64(a)/UnitsPerCoin, 10)
	out = append(out, '.')
	start := len(out)
	out = append(out, '0', '0', '0', '0', '0', '0', '0', '0')
	frac := uint64(a) % UnitsPerCoin
	for i := len(out) - 1; i >= start; i-- {
		out[i] = '0' + byte(frac%10)
		frac /= 10
	}

	return string(out)
}

func (a Amount) MarshalText() ([]byte, error) {
	return []byte(a.String()), nil
}

func (a *Amount) UnmarshalText(text []byte) error {
	parsed, err := FromString(string(text))
	if err != nil {
		return err
	}
	*a = parsed

	return nil
}
