package limits

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/raven-clown/airlock/ratelimit"
)

func TestParseProfile(t *testing.T) {
	tests := []struct {
		name    string
		limits  map[string]any
		want    Profile
		wantErr string
	}{
		{
			name: "both kinds",
			limits: map[string]any{
				"requests":    map[string]any{"rate": "60/m", "concurrency": 4},
				"tools.calls": map[string]any{"rate": "30/m", "concurrency": float64(2)},
			},
			want: Profile{Name: "p", Requests: Limit{Rate: &ratelimit.Rate{Count: 60, Period: time.Minute}, Concurrency: 4},
				ToolCalls: Limit{Rate: &ratelimit.Rate{Count: 30, Period: time.Minute}, Concurrency: 2}},
		},
		{
			name: "other projects ignored",
			limits: map[string]any{
				"llm.tokens":           map[string]any{"per_day": 100000},
				"llm.max_input_tokens": 8192,
				"agent.runs":           map[string]any{"rate": "10/m"},
				"memory.bytes":         "10MB",
			},
			want: Profile{Name: "p"},
		},
		{name: "unknown key", limits: map[string]any{"foo": 1}, wantErr: `unknown limit "foo"`},
		{name: "unknown tools key", limits: map[string]any{"tools.bytes": 1}, wantErr: `unknown limit "tools.bytes"`},
		{name: "not a map", limits: map[string]any{"requests": "60/m"}, wantErr: "requests: must be a map"},
		{name: "unknown field", limits: map[string]any{"requests": map[string]any{"burst": 3}}, wantErr: `requests: unknown field "burst"`},
		{name: "bad rate", limits: map[string]any{"tools.calls": map[string]any{"rate": "fast"}}, wantErr: `tools.calls: rate: rate "fast"`},
		{name: "bad concurrency", limits: map[string]any{"requests": map[string]any{"concurrency": -1}}, wantErr: "requests: concurrency:"},
		{name: "fractional concurrency", limits: map[string]any{"requests": map[string]any{"concurrency": 1.5}}, wantErr: "requests: concurrency:"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseProfile(Spec{Name: "p", Limits: tc.limits})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !sameProfile(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func sameProfile(a, b Profile) bool {
	same := func(x, y Limit) bool {
		if (x.Rate == nil) != (y.Rate == nil) || x.Concurrency != y.Concurrency {
			return false
		}
		return x.Rate == nil || *x.Rate == *y.Rate
	}
	return a.Name == b.Name && same(a.Requests, b.Requests) && same(a.ToolCalls, b.ToolCalls)
}

func TestConfigValidate(t *testing.T) {
	profiles := []Profile{{Name: "free"}}
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{name: "ok", cfg: Config{Profiles: profiles, Bindings: []Binding{{Name: "b", Subject: "group:eng", Profile: "free"}}, Default: "free", Org: "free"}},
		{name: "unknown default", cfg: Config{Profiles: profiles, Default: "pro"}, wantErr: `default_profile: unknown profile "pro"`},
		{name: "unknown org", cfg: Config{Profiles: profiles, Org: "pro"}, wantErr: `org_profile: unknown profile "pro"`},
		{name: "binding profile", cfg: Config{Profiles: profiles, Bindings: []Binding{{Name: "b", Subject: "user:a", Profile: "pro"}}}, wantErr: `profile_bindings[0].profile: unknown profile "pro"`},
		{name: "binding subject", cfg: Config{Profiles: profiles, Bindings: []Binding{{Name: "b", Subject: "team:a", Profile: "free"}}}, wantErr: "profile_bindings[0].subject"},
		{name: "binding name", cfg: Config{Profiles: profiles, Bindings: []Binding{{Subject: "user:a", Profile: "free"}}}, wantErr: "profile_bindings[0].name"},
		{name: "duplicate binding", cfg: Config{Profiles: profiles, Bindings: []Binding{{Name: "b", Subject: "user:a", Profile: "free"}, {Name: "b", Subject: "user:c", Profile: "free"}}}, wantErr: `profile_bindings[1].name: duplicate "b"`},
		{name: "duplicate profile", cfg: Config{Profiles: []Profile{{Name: "a"}, {Name: "a"}}}, wantErr: `profiles[1].name: duplicate "a"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func rate(s string) *ratelimit.Rate {
	r, err := ratelimit.ParseRate(s)
	if err != nil {
		panic(err)
	}
	return &r
}

func TestProfileResolution(t *testing.T) {
	cfg := Config{
		Profiles: []Profile{{Name: "key"}, {Name: "user"}, {Name: "group"}, {Name: "claim"}, {Name: "default"}},
		Bindings: []Binding{
			{Name: "k", Subject: "key:ci", Profile: "key"},
			{Name: "u", Subject: "user:alice", Profile: "user"},
			{Name: "g", Subject: "group:eng", Profile: "group"},
		},
		Default: "default",
	}
	l := New(cfg, ratelimit.NewMemoryStore(), time.Now)
	tests := []struct {
		name   string
		caller Caller
		want   string
	}{
		{"key wins", Caller{Subject: "key:ci", Key: "ci", Groups: []string{"eng"}}, "key"},
		{"user over group", Caller{Subject: "alice", Groups: []string{"eng"}, ClaimProfile: "claim"}, "user"},
		{"group over claim", Caller{Subject: "bob", Groups: []string{"x", "eng"}, ClaimProfile: "claim"}, "group"},
		{"claim over default", Caller{Subject: "bob", ClaimProfile: "claim"}, "claim"},
		{"unknown claim falls to default", Caller{Subject: "bob", ClaimProfile: "gold"}, "default"},
		{"default", Caller{Subject: "bob"}, "default"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := l.Profile(tc.caller)
			if !ok || p.Name != tc.want {
				t.Fatalf("got %q %v, want %q", p.Name, ok, tc.want)
			}
		})
	}
	if _, ok := New(Config{}, ratelimit.NewMemoryStore(), time.Now).Profile(Caller{Subject: "a"}); ok {
		t.Fatal("no profiles but a profile was found")
	}
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestRequestRate(t *testing.T) {
	ctx := context.Background()
	c := &clock{t: time.Unix(1000, 0)}
	l := New(Config{Profiles: []Profile{{Name: "free", Requests: Limit{Rate: rate("2/m")}}}, Default: "free"}, ratelimit.NewMemoryStore(), c.now)
	alice := Caller{Subject: "alice"}
	for i := range 2 {
		tk, d := l.Request(ctx, alice)
		if d != nil {
			t.Fatalf("call %d denied: %+v", i, d)
		}
		tk.Release()
	}
	_, d := l.Request(ctx, alice)
	if d == nil || d.Status != http.StatusTooManyRequests || d.Code != "rate_limited" || d.RetryAfter != 30*time.Second {
		t.Fatalf("third call: %+v", d)
	}
	if !strings.Contains(d.Message, "requests allows 2/m for user:alice") {
		t.Fatalf("message %q", d.Message)
	}
	if _, d := l.ToolCall(ctx, alice); d != nil {
		t.Fatalf("tool calls share the requests counter: %+v", d)
	}
	if _, d := l.Request(ctx, Caller{Subject: "bob"}); d != nil {
		t.Fatalf("bob shares alice's counter: %+v", d)
	}
	c.t = c.t.Add(30 * time.Second)
	if _, d := l.Request(ctx, alice); d != nil {
		t.Fatalf("no refill: %+v", d)
	}
}

func TestToolCallConcurrency(t *testing.T) {
	ctx := context.Background()
	l := New(Config{Profiles: []Profile{{Name: "free", ToolCalls: Limit{Concurrency: 1}}}, Default: "free"}, ratelimit.NewMemoryStore(), time.Now)
	k := Caller{Subject: "key:ci", Key: "ci"}
	first, d := l.ToolCall(ctx, k)
	if d != nil {
		t.Fatal(d)
	}
	_, d = l.ToolCall(ctx, k)
	if d == nil || d.Code != "concurrency_limited" || d.Status != http.StatusTooManyRequests || d.RetryAfter != 0 {
		t.Fatalf("second call: %+v", d)
	}
	if !strings.Contains(d.Message, "key:ci") {
		t.Fatalf("message %q", d.Message)
	}
	first.Release()
	if _, d := l.ToolCall(ctx, k); d != nil {
		t.Fatalf("after release: %+v", d)
	}
}

func TestRateDenialReleasesConcurrency(t *testing.T) {
	ctx := context.Background()
	l := New(Config{Profiles: []Profile{{Name: "p", Requests: Limit{Rate: rate("1/h"), Concurrency: 1}}}, Default: "p"}, ratelimit.NewMemoryStore(), time.Now)
	tk, _ := l.Request(ctx, Caller{Subject: "a"})
	tk.Release()
	if _, d := l.Request(ctx, Caller{Subject: "a"}); d == nil || d.Code != "rate_limited" {
		t.Fatalf("want rate_limited, got %+v", d)
	}
	if _, d := l.Request(ctx, Caller{Subject: "a"}); d == nil || d.Code != "rate_limited" {
		t.Fatalf("the refused call kept its slot: %+v", d)
	}
}

func TestOrgProfile(t *testing.T) {
	ctx := context.Background()
	cfg := Config{
		Profiles: []Profile{{Name: "free", Requests: Limit{Rate: rate("10/m")}}, {Name: "org", Requests: Limit{Rate: rate("2/m")}}},
		Default:  "free",
		Org:      "org",
	}
	l := New(cfg, ratelimit.NewMemoryStore(), time.Now)
	l.Request(ctx, Caller{Subject: "a"})
	l.Request(ctx, Caller{Subject: "b"})
	_, d := l.Request(ctx, Caller{Subject: "c"})
	if d == nil || !strings.Contains(d.Message, "the organisation") {
		t.Fatalf("org limit not applied: %+v", d)
	}
}

func TestNilLimiter(t *testing.T) {
	var l *Limiter
	tk, d := l.Request(context.Background(), Caller{Subject: "a"})
	if d != nil {
		t.Fatal(d)
	}
	h := http.Header{}
	tk.SetHeaders(h)
	tk.Release()
	if len(h) != 0 {
		t.Fatalf("headers %v", h)
	}
}

func TestHeaders(t *testing.T) {
	cfg := Config{
		Profiles: []Profile{{Name: "free", Requests: Limit{Rate: rate("60/m")}}, {Name: "org", Requests: Limit{Rate: rate("600/m")}}},
		Default:  "free",
		Org:      "org",
	}
	l := New(cfg, ratelimit.NewMemoryStore(), func() time.Time { return time.Unix(0, 0) })
	tk, _ := l.Request(context.Background(), Caller{Subject: "a"})
	h := http.Header{}
	tk.SetHeaders(h)
	if got := h.Get("RateLimit-Policy"); got != `"requests";q=60;w=60, "org.requests";q=600;w=60` {
		t.Fatalf("policy %q", got)
	}
	if got := h.Get("RateLimit"); got != `"requests";r=59;t=1, "org.requests";r=599;t=1` {
		t.Fatalf("state %q", got)
	}
}

func TestDeniedHeaders(t *testing.T) {
	l := New(Config{Profiles: []Profile{{Name: "p", Requests: Limit{Rate: rate("1/m")}}}, Default: "p"}, ratelimit.NewMemoryStore(), func() time.Time { return time.Unix(0, 0) })
	l.Request(context.Background(), Caller{Subject: "a"})
	_, d := l.Request(context.Background(), Caller{Subject: "a"})
	h := http.Header{}
	d.SetHeaders(h)
	if h.Get("Retry-After") != "60" || h.Get("RateLimit") != `"requests";r=0;t=60` || h.Get("RateLimit-Policy") != `"requests";q=1;w=60` {
		t.Fatalf("headers %v", h)
	}
}

type failingStore struct{}

func (failingStore) Take(context.Context, string, ratelimit.Rate, time.Time) (ratelimit.Bucket, error) {
	return ratelimit.Bucket{}, errors.New("down")
}

func (failingStore) Acquire(context.Context, string, int64) (bool, func(), error) {
	return false, func() {}, errors.New("down")
}

func TestStoreError(t *testing.T) {
	for _, lim := range []Limit{{Rate: rate("1/s")}, {Concurrency: 1}} {
		l := New(Config{Profiles: []Profile{{Name: "p", Requests: lim}}, Default: "p"}, failingStore{}, time.Now)
		_, d := l.Request(context.Background(), Caller{Subject: "a"})
		if d == nil || d.Status != http.StatusServiceUnavailable || d.Code != "overloaded" || d.RetryAfter != time.Second {
			t.Fatalf("%+v", d)
		}
	}
}

func TestWithConfigKeepsCounts(t *testing.T) {
	cfg := Config{Profiles: []Profile{{Name: "p", Requests: Limit{Rate: rate("1/h")}}}, Default: "p"}
	l := New(cfg, ratelimit.NewMemoryStore(), time.Now)
	l.Request(context.Background(), Caller{Subject: "a"})
	if _, d := l.WithConfig(cfg).Request(context.Background(), Caller{Subject: "a"}); d == nil {
		t.Fatal("a reload gave a fresh allowance")
	}
}

func TestInflight(t *testing.T) {
	in := NewInflight(1)
	release, ok := in.Enter()
	if !ok {
		t.Fatal("first refused")
	}
	if _, ok := in.Enter(); ok {
		t.Fatal("second admitted")
	}
	release()
	release()
	if _, ok := in.Enter(); !ok {
		t.Fatal("not freed")
	}
	if _, ok := in.Enter(); ok {
		t.Fatal("double release freed two")
	}
	unlimited := NewInflight(0)
	for range 3 {
		if _, ok := unlimited.Enter(); !ok {
			t.Fatal("zero means no cap")
		}
	}
}
