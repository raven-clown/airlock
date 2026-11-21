package limits

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/raven-clown/airlock/ratelimit"
)

// Refusal codes, shared by every mothership project.
const (
	CodeRateLimited        = "rate_limited"
	CodeConcurrencyLimited = "concurrency_limited"
	CodeOverloaded         = "overloaded"
)

// Caller is who a call is counted against.
type Caller struct {
	// Subject is the identity's subject: the user, or key:<name> for an API key.
	Subject string
	// Key is the API key name, empty for a signed-in user.
	Key          string
	Groups       []string
	ClaimProfile string
}

// counter is the subject counts are kept under.
func (c Caller) counter() string {
	if c.Key != "" {
		return "key:" + c.Key
	}
	return "user:" + c.Subject
}

// Denied says why a call may not run.
type Denied struct {
	Status     int
	Code       string
	Message    string
	RetryAfter time.Duration
	policies   []policyState
}

// SetHeaders writes Retry-After and the rate headers.
func (d *Denied) SetHeaders(h http.Header) {
	if d.RetryAfter > 0 {
		h.Set("Retry-After", strconv.FormatInt(ceilSeconds(d.RetryAfter), 10))
	}
	writePolicies(h, d.policies)
}

// Limiter decides whether a request or a tool call may run. A nil *Limiter allows everything.
type Limiter struct {
	store    ratelimit.Store
	cfg      Config
	profiles map[string]Profile
	now      func() time.Time
}

// New returns a limiter for cfg counting in st.
func New(cfg Config, st ratelimit.Store, now func() time.Time) *Limiter {
	l := &Limiter{store: st, cfg: cfg, profiles: map[string]Profile{}, now: now}
	for _, p := range cfg.Profiles {
		l.profiles[p.Name] = p
	}
	return l
}

// WithConfig returns a limiter for cfg on the same counters, so a reload keeps what every
// caller has used.
func (l *Limiter) WithConfig(cfg Config) *Limiter { return New(cfg, l.store, l.now) }

// Profile returns the caller's profile: a binding on the key, then the user, then a group
// in the caller's order, then the profile claim, then the default.
func (l *Limiter) Profile(c Caller) (Profile, bool) {
	find := func(subject string) (Profile, bool) {
		for _, b := range l.cfg.Bindings {
			if b.Subject == subject {
				p, ok := l.profiles[b.Profile]
				return p, ok
			}
		}
		return Profile{}, false
	}
	candidates := make([]string, 0, len(c.Groups)+2)
	if c.Key != "" {
		candidates = append(candidates, "key:"+c.Key)
	} else {
		candidates = append(candidates, "user:"+c.Subject)
	}
	for _, g := range c.Groups {
		candidates = append(candidates, "group:"+g)
	}
	for _, s := range candidates {
		if p, ok := find(s); ok {
			return p, true
		}
	}
	if p, ok := l.profiles[c.ClaimProfile]; ok && c.ClaimProfile != "" {
		return p, true
	}
	p, ok := l.profiles[l.cfg.Default]
	return p, ok
}

// Request admits one HTTP request against the requests limit.
func (l *Limiter) Request(ctx context.Context, c Caller) (*Ticket, *Denied) {
	return l.admit(ctx, c, KeyRequests, func(p Profile) Limit { return p.Requests })
}

// ToolCall admits one tool call against the tools.calls limit.
func (l *Limiter) ToolCall(ctx context.Context, c Caller) (*Ticket, *Denied) {
	return l.admit(ctx, c, KeyToolCalls, func(p Profile) Limit { return p.ToolCalls })
}

type check struct {
	name, counter, who string
	limit              Limit
}

func (l *Limiter) admit(ctx context.Context, c Caller, kind string, pick func(Profile) Limit) (*Ticket, *Denied) {
	t := &Ticket{}
	if l == nil {
		return t, nil
	}
	var checks []check
	if p, ok := l.Profile(c); ok && !pick(p).empty() {
		checks = append(checks, check{name: kind, counter: c.counter(), who: c.counter(), limit: pick(p)})
	}
	if p, ok := l.profiles[l.cfg.Org]; ok && l.cfg.Org != "" && !pick(p).empty() {
		checks = append(checks, check{name: "org." + kind, counter: "org", who: "the organisation", limit: pick(p)})
	}
	now := l.now()
	for _, ch := range checks {
		if d := t.take(ctx, l, ch, kind, now); d != nil {
			t.Release()
			d.policies = t.policies
			return nil, d
		}
	}
	return t, nil
}

func (t *Ticket) take(ctx context.Context, l *Limiter, ch check, kind string, now time.Time) *Denied {
	if n := ch.limit.Concurrency; n > 0 {
		ok, release, err := l.store.Acquire(ctx, kind+"|conc|"+ch.counter, n)
		if err != nil {
			return overloaded()
		}
		if !ok {
			return &Denied{Status: http.StatusTooManyRequests, Code: CodeConcurrencyLimited,
				Message: fmt.Sprintf("%s allows %d at once for %s; retry when one ends", ch.name, n, ch.who)}
		}
		t.releases = append(t.releases, release)
	}
	if r := ch.limit.Rate; r != nil {
		b, err := l.store.Take(ctx, kind+"|rate|"+ch.counter, *r, now)
		if err != nil {
			return overloaded()
		}
		t.policies = append(t.policies, policyState{name: ch.name, rate: *r, remaining: b.Remaining, reset: b.Reset})
		if !b.OK {
			return &Denied{Status: http.StatusTooManyRequests, Code: CodeRateLimited, RetryAfter: b.RetryAfter,
				Message: fmt.Sprintf("%s allows %s for %s; retry in %ds", ch.name, r, ch.who, ceilSeconds(b.RetryAfter))}
		}
	}
	return nil
}

func overloaded() *Denied {
	return &Denied{Status: http.StatusServiceUnavailable, Code: CodeOverloaded, RetryAfter: time.Second,
		Message: "the limit counters cannot be reached; retry shortly"}
}

// Ticket is an admitted call. Release it when the call ends.
type Ticket struct {
	releases []func()
	policies []policyState
	once     sync.Once
}

type policyState struct {
	name      string
	rate      ratelimit.Rate
	remaining int64
	reset     time.Duration
}

// Release frees the concurrency slots. It is safe to call more than once and on nil.
func (t *Ticket) Release() {
	if t == nil {
		return
	}
	t.once.Do(func() {
		for _, r := range t.releases {
			r()
		}
	})
}

// SetHeaders adds the IETF RateLimit-Policy and RateLimit headers for the rates counted.
func (t *Ticket) SetHeaders(h http.Header) {
	if t != nil {
		writePolicies(h, t.policies)
	}
}

func writePolicies(h http.Header, ps []policyState) {
	if len(ps) == 0 {
		return
	}
	policies := make([]string, 0, len(ps))
	states := make([]string, 0, len(ps))
	for _, p := range ps {
		policies = append(policies, fmt.Sprintf("%q;q=%d;w=%d", p.name, p.rate.Count, int64(p.rate.Period/time.Second)))
		states = append(states, fmt.Sprintf("%q;r=%d;t=%d", p.name, p.remaining, ceilSeconds(p.reset)))
	}
	h.Set("RateLimit-Policy", strings.Join(policies, ", "))
	h.Set("RateLimit", strings.Join(states, ", "))
}

func ceilSeconds(d time.Duration) int64 { return int64(math.Ceil(d.Seconds())) }

// Inflight caps the requests one replica serves at once.
type Inflight struct {
	max int64
	n   atomic.Int64
}

// NewInflight returns a cap of limit. Zero or less means no cap.
func NewInflight(limit int64) *Inflight { return &Inflight{max: limit} }

// Enter admits a request, or reports that the replica is full. release may be called
// more than once.
func (in *Inflight) Enter() (release func(), ok bool) {
	if in.n.Add(1) > in.max && in.max > 0 {
		in.n.Add(-1)
		return func() {}, false
	}
	var once sync.Once
	return func() { once.Do(func() { in.n.Add(-1) }) }, true
}
