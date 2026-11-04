package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeAuth struct {
	id  *Identity
	err error
}

func (f fakeAuth) Authenticate(context.Context, *http.Request) (*Identity, error) {
	return f.id, f.err
}

func request(header string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", nil)
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	return r
}

func TestChain(t *testing.T) {
	alice := &Identity{Subject: "alice"}
	invalid := &InvalidError{Method: "apikey", Reason: "revoked"}
	tests := []struct {
		name    string
		chain   *Chain
		header  string
		want    *Identity
		wantErr error
	}{
		{
			name:   "skips not mine",
			chain:  NewChain(fakeAuth{err: ErrNotMine}, fakeAuth{id: alice}),
			header: "Bearer x",
			want:   alice,
		},
		{
			name:    "invalid stops the chain",
			chain:   NewChain(fakeAuth{err: invalid}, fakeAuth{id: alice}),
			header:  "Bearer x",
			wantErr: invalid,
		},
		{
			name:    "no header",
			chain:   NewChain(fakeAuth{id: alice}),
			wantErr: ErrNoCredentials,
		},
		{
			name:    "nobody claims it",
			chain:   NewChain(fakeAuth{err: ErrNotMine}, fakeAuth{err: ErrNotMine}),
			header:  "Bearer x",
			wantErr: ErrNoCredentials,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.chain.Authenticate(context.Background(), request(tt.header))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("identity = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInvalidErrorHidesToken(t *testing.T) {
	err := &InvalidError{Method: "apikey", Reason: "unknown"}
	if got := err.Error(); got != "apikey: invalid credential: unknown" {
		t.Errorf("Error() = %q", got)
	}
}

func TestBearerToken(t *testing.T) {
	tests := []struct {
		header string
		want   string
		ok     bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true},
		{"Basic x", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			got, ok := BearerToken(request(tt.header))
			if got != tt.want || ok != tt.ok {
				t.Errorf("BearerToken = %q, %v, want %q, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestContext(t *testing.T) {
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("empty context has an identity")
	}
	id := &Identity{Subject: "alice"}
	got, ok := FromContext(WithIdentity(context.Background(), id))
	if !ok || got != id {
		t.Fatalf("FromContext = %v, %v", got, ok)
	}
}

func TestIdentityLogValue(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("call", "identity", &Identity{Subject: "alice", Groups: []string{"eng"}, Method: "oidc", Token: "secret-token"})
	if strings.Contains(buf.String(), "secret-token") {
		t.Fatalf("log contains the token: %s", buf.String())
	}
	var line struct {
		Identity map[string]any `json:"identity"`
	}
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatal(err)
	}
	if line.Identity["subject"] != "alice" || line.Identity["method"] != "oidc" {
		t.Errorf("identity logged as %v", line.Identity)
	}
}

func TestRegister(t *testing.T) {
	f := func(json.RawMessage) (Authenticator, error) { return fakeAuth{}, nil }
	Register("test-kind", f)
	if _, ok := Lookup("test-kind"); !ok {
		t.Fatal("Lookup did not find test-kind")
	}
	if _, ok := Lookup("missing"); ok {
		t.Fatal("Lookup found an unregistered kind")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("registering twice did not panic")
		}
	}()
	Register("test-kind", f)
}
