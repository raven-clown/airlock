package oidc_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/auth/oidc"
	"github.com/raven-clown/airlock/auth/oidc/oidctest"
)

func newAuth(t *testing.T, p *oidctest.Issuer, change func(*oidc.Config)) *oidc.Authenticator {
	t.Helper()
	cfg := oidc.Config{Issuer: p.URL(), Audience: oidctest.Audience, Client: p.Client()}
	if change != nil {
		change(&cfg)
	}
	a, err := oidc.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func reason(err error) string {
	var inv *auth.InvalidError
	if errors.As(err, &inv) {
		return inv.Reason
	}
	return ""
}

func TestVerify(t *testing.T) {
	p := oidctest.New(t)
	a := newAuth(t, p, nil)
	now := time.Now()
	tests := []struct {
		name   string
		change func(map[string]any)
		reason string
	}{
		{name: "valid"},
		{name: "expired", change: func(c map[string]any) { c["exp"] = now.Add(-2 * time.Minute).Unix() }, reason: "expired"},
		{name: "within skew", change: func(c map[string]any) { c["exp"] = now.Add(-30 * time.Second).Unix() }},
		{name: "no exp", change: func(c map[string]any) { delete(c, "exp") }, reason: "claims"},
		{name: "not yet valid", change: func(c map[string]any) { c["nbf"] = now.Add(5 * time.Minute).Unix() }, reason: "not_yet_valid"},
		{name: "issued in the future", change: func(c map[string]any) { c["iat"] = now.Add(5 * time.Minute).Unix() }, reason: "not_yet_valid"},
		{name: "bad nbf", change: func(c map[string]any) { c["nbf"] = "soon" }, reason: "claims"},
		{name: "wrong audience", change: func(c map[string]any) { c["aud"] = "other" }, reason: "audience"},
		{name: "audience list", change: func(c map[string]any) { c["aud"] = []string{"other", oidctest.Audience} }},
		{name: "no subject", change: func(c map[string]any) { delete(c, "sub") }, reason: "claims"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := p.Claims()
			if tc.change != nil {
				tc.change(claims)
			}
			id, err := a.Verify(context.Background(), p.Token(claims))
			if tc.reason != "" {
				if reason(err) != tc.reason {
					t.Fatalf("err = %v, want reason %q", err, tc.reason)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if id.Subject != "alice@example.com" || !slices.Equal(id.Groups, []string{"eng", "ops"}) || id.Method != "oidc" {
				t.Fatalf("identity %+v", id)
			}
		})
	}
}

func TestWrongIssuerFetchesNothing(t *testing.T) {
	p := oidctest.New(t)
	a := newAuth(t, p, nil)
	claims := p.Claims()
	claims["iss"] = "https://evil.example"
	if _, err := a.Verify(context.Background(), p.Token(claims)); reason(err) != "issuer" {
		t.Fatalf("err = %v", err)
	}
	if p.Fetches() != 0 || p.Discovers() != 0 {
		t.Fatalf("fetched %d keys and %d discovery documents for a foreign token", p.Fetches(), p.Discovers())
	}
}

func TestUnknownKeyFetchesAtMostOnce(t *testing.T) {
	p := oidctest.New(t)
	var mu sync.Mutex
	now := time.Now()
	a := newAuth(t, p, func(c *oidc.Config) {
		c.Now = func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		}
	})
	ctx := context.Background()
	if _, err := a.Verify(ctx, p.Token(p.Claims())); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	now = now.Add(11 * time.Second)
	mu.Unlock()
	before := p.Fetches()
	stranger := oidctest.NewKey(t)
	for _, kid := range []string{"nope-1", "nope-2", "nope-3"} {
		tok := oidctest.Sign(t, jose.ES256, stranger, kid, p.Claims())
		if _, err := a.Verify(ctx, tok); reason(err) != "signature" {
			t.Fatalf("%s: err = %v", kid, err)
		}
	}
	if got := p.Fetches() - before; got != 1 {
		t.Fatalf("%d fetches for unknown keys within the refresh interval, want 1", got)
	}
}

func TestRotatedKey(t *testing.T) {
	p := oidctest.New(t)
	var mu sync.Mutex
	now := time.Now()
	a := newAuth(t, p, func(c *oidc.Config) {
		c.Now = func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		}
	})
	ctx := context.Background()
	if _, err := a.Verify(ctx, p.Token(p.Claims())); err != nil {
		t.Fatal(err)
	}
	p.Rotate("key-2")
	mu.Lock()
	now = now.Add(11 * time.Second)
	mu.Unlock()
	if _, err := a.Verify(ctx, p.Token(p.Claims())); err != nil {
		t.Fatalf("token with the rotated key: %v", err)
	}
}

func TestUnsignedAndSharedSecretRefused(t *testing.T) {
	p := oidctest.New(t)
	a := newAuth(t, p, nil)
	for _, header := range []string{`{"alg":"none","typ":"JWT"}`, `{"alg":"HS256","typ":"JWT"}`} {
		if _, err := a.Verify(context.Background(), oidctest.Handmade(t, header, p.Claims())); reason(err) != "malformed" {
			t.Fatalf("%s: err = %v", header, err)
		}
	}
}

func TestClaimShapes(t *testing.T) {
	p := oidctest.New(t)
	a := newAuth(t, p, func(c *oidc.Config) {
		c.GroupsClaim = "realm_access.roles"
		c.SubjectClaim = "email"
	})
	claims := p.Claims()
	claims["email"] = "bob@example.com"
	claims["realm_access"] = map[string]any{"roles": []string{"interns"}}
	claims["tier"] = "pro"
	id, err := a.Verify(context.Background(), p.Token(claims))
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "bob@example.com" || !slices.Equal(id.Groups, []string{"interns"}) || id.Profile != "pro" {
		t.Fatalf("identity %+v", id)
	}

	b := newAuth(t, p, nil)
	claims = p.Claims()
	claims["groups"] = "eng"
	id, err = b.Verify(context.Background(), p.Token(claims))
	if err != nil || !slices.Equal(id.Groups, []string{"eng"}) {
		t.Fatalf("string groups claim: %+v, %v", id, err)
	}
}

func TestIssuerDown(t *testing.T) {
	p := oidctest.New(t)
	tok := p.Token(p.Claims())
	p.SetStatus(http.StatusInternalServerError)
	a := newAuth(t, p, nil)
	if _, err := a.Verify(context.Background(), tok); !errors.Is(err, auth.ErrUnavailable) {
		t.Fatalf("err = %v, want ErrUnavailable", err)
	}
}

func TestAuthenticateClaimsOnlyJWTs(t *testing.T) {
	p := oidctest.New(t)
	a := newAuth(t, p, nil)
	for _, tok := range []string{"alk_a.b.c", "opaque-token", ""} {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", nil)
		if tok != "" {
			r.Header.Set("Authorization", "Bearer "+tok)
		}
		if _, err := a.Authenticate(context.Background(), r); !errors.Is(err, auth.ErrNotMine) {
			t.Fatalf("%q: err = %v, want ErrNotMine", tok, err)
		}
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+p.Token(p.Claims()))
	id, err := a.Authenticate(context.Background(), r)
	if err != nil || id.Token == "" {
		t.Fatalf("%+v, %v", id, err)
	}
}

func TestNewChecks(t *testing.T) {
	for _, cfg := range []oidc.Config{
		{Issuer: "idp", Audience: "a"},
		{Issuer: "https://idp"},
		{Issuer: "https://idp", Audience: "a", JWKSURL: "keys"},
	} {
		if _, err := oidc.New(cfg); err == nil {
			t.Fatalf("%+v accepted", cfg)
		}
	}
}

func TestRegistered(t *testing.T) {
	f, ok := auth.Lookup("oidc")
	if !ok {
		t.Fatal("oidc is not registered")
	}
	if _, err := f([]byte(`{"issuer":"https://idp","audience":"a"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := f([]byte(`{"issuer":"https://idp"}`)); err == nil {
		t.Fatal("a config with no audience was accepted")
	}
}

func TestSame(t *testing.T) {
	cfg := oidc.Config{Issuer: "https://idp", Audience: "a"}
	a, err := oidc.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !a.Same(oidc.Config{Issuer: "https://idp", Audience: "a", SubjectClaim: "sub"}) {
		t.Fatal("defaults count as different")
	}
	if a.Same(oidc.Config{Issuer: "https://idp", Audience: "b"}) || a.Issuer() != "https://idp" {
		t.Fatal("another audience counts as the same")
	}
}
