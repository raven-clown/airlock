// Package ratelimit parses rates and counts them. Store is the plug point for counters
// shared across replicas; MemoryStore counts in one process.
package ratelimit

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Rate is Count units per Period.
type Rate struct {
	Count  int64
	Period time.Duration
}

var units = []struct {
	name string
	d    time.Duration
}{{"s", time.Second}, {"m", time.Minute}, {"h", time.Hour}, {"d", 24 * time.Hour}}

// ParseRate parses a rate written as N/s, N/m, N/h or N/d, such as "30/m".
func ParseRate(s string) (Rate, error) {
	num, unit, ok := strings.Cut(s, "/")
	n, err := strconv.ParseInt(strings.TrimSpace(num), 10, 64)
	unit = strings.TrimSpace(unit)
	if ok && err == nil && n > 0 {
		for _, u := range units {
			if u.name == unit && u.d/time.Duration(n) > 0 {
				return Rate{Count: n, Period: u.d}, nil
			}
		}
	}
	return Rate{}, fmt.Errorf("rate %q must be a positive whole number per s, m, h or d, such as 30/m", s)
}

// String returns the rate in the form ParseRate reads.
func (r Rate) String() string {
	for _, u := range units {
		if u.d == r.Period {
			return strconv.FormatInt(r.Count, 10) + "/" + u.name
		}
	}
	return strconv.FormatInt(r.Count, 10) + "/" + r.Period.String()
}

// Interval is the time one unit takes to come back.
func (r Rate) Interval() time.Duration { return r.Period / time.Duration(r.Count) }

// MarshalText writes the rate as ParseRate reads it.
func (r Rate) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// UnmarshalText reads a rate with ParseRate.
func (r *Rate) UnmarshalText(b []byte) error {
	v, err := ParseRate(string(b))
	if err != nil {
		return err
	}
	*r = v
	return nil
}
