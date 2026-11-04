package apikey

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/raven-clown/airlock/auth"
)

func TestAuthenticate(t *testing.T) {
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)
	plain := func(name string) string { return Prefix + "secret-" + name }
	keys := []Key{
		{Name: "ci-bot", SHA256: Hash(plain("ci-bot")), Groups: []string{"ci"}},
		{Name: "old", SHA256: Hash(plain("old")), Revoked: true},
		{Name: "expired", SHA256: Hash(plain("expired")), ExpiresAt: now.Add(-time.Minute)},
		{Name: "later", SHA256: Hash(plain("later")), ExpiresAt: now.Add(time.Minute)},
	}
	a := New(keys, func() time.Time { return now })

	tests := []struct {
		name       string
		token      string
		wantName   string
		wantErr    error
		wantReason string
	}{
		{name: "valid", token: plain("ci-bot"), wantName: "ci-bot"},
		{name: "expires later", token: plain("later"), wantName: "later"},
		{name: "not an api key", token: "header.payload.signature", wantErr: auth.ErrNotMine},
		{name: "unknown", token: plain("nobody"), wantReason: "unknown"},
		{name: "revoked", token: plain("old"), wantReason: "revoked"},
		{name: "expired", token: plain("expired"), wantReason: "expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", nil)
			r.Header.Set("Authorization", "Bearer "+tt.token)
			id, err := a.Authenticate(context.Background(), r)
			switch {
			case tt.wantReason != "":
				var inv *auth.InvalidError
				if !errors.As(err, &inv) || inv.Reason != tt.wantReason || inv.Method != "apikey" {
					t.Fatalf("error = %v, want invalid with reason %q", err, tt.wantReason)
				}
				if strings.Contains(err.Error(), tt.token) {
					t.Fatal("error contains the token")
				}
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
			default:
				if err != nil {
					t.Fatalf("Authenticate: %v", err)
				}
				if id.Subject != "key:"+tt.wantName || id.KeyName != tt.wantName || id.Method != "apikey" || id.Token != tt.token {
					t.Errorf("identity = %+v", id)
				}
			}
		})
	}
}

func TestAuthenticateGroups(t *testing.T) {
	a := New([]Key{{Name: "ci-bot", SHA256: Hash(Prefix + "x"), Groups: []string{"ci"}}}, time.Now)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+Prefix+"x")
	id, err := a.Authenticate(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(id.Groups, []string{"ci"}) {
		t.Errorf("groups = %v", id.Groups)
	}
}

func TestGenerate(t *testing.T) {
	plain, hash, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plain, Prefix) || len(plain) != len(Prefix)+43 {
		t.Errorf("key %q has the wrong shape", plain)
	}
	if Hash(plain) != hash {
		t.Error("Hash(plain) differs from the returned hash")
	}
	other, _, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if other == plain {
		t.Error("two keys are equal")
	}
}

func TestRegistered(t *testing.T) {
	f, ok := auth.Lookup("apikey")
	if !ok {
		t.Fatal("apikey is not registered")
	}
	if _, err := f([]byte(`{"keys":[{"name":"a","sha256":"00"}]}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := f([]byte(`{`)); err == nil {
		t.Fatal("bad JSON accepted")
	}
}
