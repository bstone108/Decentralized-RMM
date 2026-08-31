package enroll

import (
	"fmt"
	"strconv"
	"strings"
)

// UseMode is the allowed-use contract for an enrollment grant.
type UseMode string

const (
	UseExactlyOne UseMode = "exactly-one"
	UseFinite     UseMode = "finite"
	UseUnlimited  UseMode = "unlimited"
)

// AllowedUses is signed into the enrollment manifest. Mode is required.
// Count is the operator-defined finite cap and is required only for finite.
type AllowedUses struct {
	Mode  UseMode `json:"mode"`
	Count int     `json:"count,omitempty"`
}

func (a AllowedUses) Normalize() (AllowedUses, error) {
	switch a.Mode {
	case UseExactlyOne:
		if a.Count != 0 && a.Count != 1 {
			return AllowedUses{}, fmt.Errorf("exactly-one grants must not set a count other than 1")
		}
		a.Count = 1
		return a, nil
	case UseFinite:
		if a.Count < 1 {
			return AllowedUses{}, fmt.Errorf("finite grants require a positive operator-defined count")
		}
		return a, nil
	case UseUnlimited:
		if a.Count != 0 {
			return AllowedUses{}, fmt.Errorf("unlimited grants must not set a finite count")
		}
		return a, nil
	case "":
		return AllowedUses{}, fmt.Errorf("allowed-use mode is required (exactly-one, finite, or unlimited)")
	default:
		return AllowedUses{}, fmt.Errorf("unknown allowed-use mode %q", a.Mode)
	}
}

func (a AllowedUses) Allows(used int) error {
	n, err := a.Normalize()
	if err != nil {
		return err
	}
	switch n.Mode {
	case UseExactlyOne:
		if used >= 1 {
			return fmt.Errorf("grant %s exhausted (exactly-one)", UseExactlyOne)
		}
	case UseFinite:
		if used >= n.Count {
			return fmt.Errorf("grant exhausted (%s:%d)", UseFinite, n.Count)
		}
	case UseUnlimited:
		return nil
	}
	return nil
}

func (a AllowedUses) PolicyLine() string {
	n, err := a.Normalize()
	if err != nil {
		return "allowed uses: invalid"
	}
	switch n.Mode {
	case UseExactlyOne:
		return "Allowed uses: exactly-one"
	case UseFinite:
		return fmt.Sprintf("Allowed uses: finite %d", n.Count)
	case UseUnlimited:
		return "Allowed uses: unlimited"
	default:
		return "Allowed uses: unknown"
	}
}

// ParseUses accepts exactly-one, unlimited, finite:N, or a positive integer (finite).
func ParseUses(s string) (AllowedUses, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	switch s {
	case "", string(UseExactlyOne), "1", "one":
		return AllowedUses{Mode: UseExactlyOne, Count: 1}.Normalize()
	case string(UseUnlimited), "inf", "infinite":
		return AllowedUses{Mode: UseUnlimited}.Normalize()
	}
	if n, err := strconv.Atoi(s); err == nil {
		return AllowedUses{Mode: UseFinite, Count: n}.Normalize()
	}
	if rest, ok := strings.CutPrefix(s, "finite:"); ok {
		n, err := strconv.Atoi(rest)
		if err != nil {
			return AllowedUses{}, fmt.Errorf("finite count must be an integer")
		}
		return AllowedUses{Mode: UseFinite, Count: n}.Normalize()
	}
	return AllowedUses{}, fmt.Errorf("allowed uses must be exactly-one, finite:N, or unlimited")
}
