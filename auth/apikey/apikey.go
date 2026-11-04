// Package apikey authenticates callers with static alk_ API keys stored as SHA-256 hashes.
package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/raven-clown/airlock/auth"
)

// Prefix starts every airlock API key.
const Prefix = "alk_"

const method = "apikey"

// Key is a stored API key. Only the hash of the key is kept.
type Key struct {
	Name      string    `json:"name" yaml:"name"`
	SHA256    string    `json:"sha256" yaml:"sha256"`
	Groups    []string  `json:"groups,omitempty" yaml:"groups"`
	ExpiresAt time.Time `json:"expires_at,omitzero" yaml:"expires_at"`
	Revoked   bool      `json:"revoked,omitempty" yaml:"revoked"`
}

// Authenticator checks bearer tokens that start with Prefix.
type Authenticator struct {
	byHash map[string]Key
	now    func() time.Time
}

// New returns an authenticator for keys. now is used for expiry checks.
func New(keys []Key, now func() time.Time) *Authenticator {
	m := make(map[string]Key, len(keys))
	for _, k := range keys {
		m[strings.ToLower(k.SHA256)] = k
	}
	return &Authenticator{byHash: m, now: now}
}

// Authenticate implements auth.Authenticator.
func (a *Authenticator) Authenticate(_ context.Context, r *http.Request) (*auth.Identity, error) {
	token, ok := auth.BearerToken(r)
	if !ok || !strings.HasPrefix(token, Prefix) {
		return nil, auth.ErrNotMine
	}
	k, ok := a.byHash[Hash(token)]
	switch {
	case !ok:
		return nil, &auth.InvalidError{Method: method, Reason: "unknown"}
	case k.Revoked:
		return nil, &auth.InvalidError{Method: method, Reason: "revoked"}
	case !k.ExpiresAt.IsZero() && !a.now().Before(k.ExpiresAt):
		return nil, &auth.InvalidError{Method: method, Reason: "expired"}
	}
	return &auth.Identity{
		Subject: "key:" + k.Name,
		Groups:  k.Groups,
		Method:  method,
		KeyName: k.Name,
		Token:   token,
	}, nil
}

// Generate returns a new random key and its hash.
func Generate() (plain, sha256hex string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("generating key: %w", err)
	}
	plain = Prefix + base64.RawURLEncoding.EncodeToString(b)
	return plain, Hash(plain), nil
}

// Hash returns the lowercase hex SHA-256 of a key.
func Hash(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

type config struct {
	Keys []Key `json:"keys"`
}

func init() {
	auth.Register(method, func(raw json.RawMessage) (auth.Authenticator, error) {
		var c config
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("apikey config: %w", err)
		}
		return New(c.Keys, time.Now), nil
	})
}
