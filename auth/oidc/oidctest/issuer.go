// Package oidctest is a local OpenID Connect provider for tests: a discovery document, a key
// set a test can change, and tokens signed in the test. It uses no outside network.
package oidctest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Audience is the audience of the tokens Claims describes.
const Audience = "airlock"

// Issuer is a local identity provider.
type Issuer struct {
	t   testing.TB
	srv *httptest.Server

	mu        sync.Mutex
	keys      []jose.JSONWebKey
	status    int
	signer    *ecdsa.PrivateKey
	signerKid string
	fetches   int
	discovers int
}

// New starts a provider with no keys. It stops when the test ends.
func New(t testing.TB) *Issuer {
	t.Helper()
	p := &Issuer{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		p.discovers++
		p.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": p.srv.URL, "jwks_uri": p.srv.URL + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		p.mu.Lock()
		p.fetches++
		status := p.status
		raw, _ := json.Marshal(jose.JSONWebKeySet{Keys: p.keys})
		p.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		_, _ = w.Write(raw)
	})
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

// URL is the issuer URL, as the iss claim and the config carry it.
func (p *Issuer) URL() string { return p.srv.URL }

// Client reaches the provider.
func (p *Issuer) Client() *http.Client { return p.srv.Client() }

// Close stops the provider before the test ends.
func (p *Issuer) Close() { p.srv.Close() }

// SetStatus makes the key set answer with status, or normally again with 0.
func (p *Issuer) SetStatus(status int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.status = status
}

// Fetches is how many times the key set was fetched.
func (p *Issuer) Fetches() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.fetches
}

// Discovers is how many times the discovery document was fetched.
func (p *Issuer) Discovers() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.discovers
}

// Rotate replaces every published key with a new one under kid, and signs with it from now on.
func (p *Issuer) Rotate(kid string) {
	priv := newKey(p.t)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys = []jose.JSONWebKey{{Key: &priv.PublicKey, KeyID: kid, Use: "sig"}}
	p.signer, p.signerKid = priv, kid
}

// Claims returns the claims of a token that passes every check: subject alice@example.com
// in groups eng and ops.
func (p *Issuer) Claims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":    p.srv.URL,
		"aud":    Audience,
		"sub":    "alice@example.com",
		"iat":    now.Unix(),
		"exp":    now.Add(5 * time.Minute).Unix(),
		"groups": []string{"eng", "ops"},
	}
}

// Token returns a token over claims, signed with the current key, which it makes when the
// provider has none.
func (p *Issuer) Token(claims map[string]any) string {
	p.t.Helper()
	p.mu.Lock()
	key, kid := p.signer, p.signerKid
	p.mu.Unlock()
	if key == nil {
		p.Rotate("key-1")
		p.mu.Lock()
		key, kid = p.signer, p.signerKid
		p.mu.Unlock()
	}
	return Sign(p.t, jose.ES256, key, kid, claims)
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// NewKey returns a key the provider does not publish, for tokens it must refuse.
func NewKey(t testing.TB) *ecdsa.PrivateKey { return newKey(t) }

// Sign returns a token over claims. An empty kid leaves the key id out of the header.
func Sign(t testing.TB, alg jose.SignatureAlgorithm, key any, kid string, claims map[string]any) string {
	t.Helper()
	signingKey := jose.SigningKey{Algorithm: alg, Key: key}
	if kid != "" {
		signingKey.Key = jose.JSONWebKey{Key: key, KeyID: kid}
	}
	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

// Handmade returns a token with the given header and a signature nobody made.
func Handmade(t testing.TB, header string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(header)) + "." + enc.EncodeToString(payload) + "." + enc.EncodeToString([]byte("signature"))
}
