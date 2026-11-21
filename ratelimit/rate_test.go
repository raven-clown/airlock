package ratelimit

import (
	"strings"
	"testing"
	"time"
)

func TestParseRate(t *testing.T) {
	good := []struct {
		in   string
		want Rate
	}{
		{"5/s", Rate{5, time.Second}},
		{"30/m", Rate{30, time.Minute}},
		{"100/h", Rate{100, time.Hour}},
		{"1000/d", Rate{1000, 24 * time.Hour}},
		{" 30 / m ", Rate{30, time.Minute}},
	}
	for _, tc := range good {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseRate(tc.in)
			if err != nil || got != tc.want {
				t.Fatalf("ParseRate(%q) = %v, %v; want %v", tc.in, got, err, tc.want)
			}
		})
	}
	bad := []string{"", "30", "/m", "30/", "0/m", "-1/m", "x/m", "30/w", "30/mm", "30/m extra", "1/0"}
	for _, in := range bad {
		t.Run("bad "+in, func(t *testing.T) {
			_, err := ParseRate(in)
			if err == nil {
				t.Fatalf("ParseRate(%q) gave no error", in)
			}
			if !strings.Contains(err.Error(), `"`+in+`"`) {
				t.Fatalf("error %q does not quote the input", err)
			}
		})
	}
}

func TestRateRoundTrip(t *testing.T) {
	for _, in := range []string{"5/s", "30/m", "100/h", "7/d"} {
		r, err := ParseRate(in)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParseRate(r.String())
		if err != nil || back != r || r.String() != in {
			t.Fatalf("round trip of %q gave %q, %v", in, r.String(), err)
		}
	}
}

func TestRateInterval(t *testing.T) {
	r := Rate{Count: 60, Period: time.Minute}
	if r.Interval() != time.Second {
		t.Fatalf("interval %v", r.Interval())
	}
}
