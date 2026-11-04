// Package auth defines caller identities and the authenticators that produce them.
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
)

// Identity is an authenticated caller.
type Identity struct {
	Subject string
	Groups  []string
	Method  string
	KeyName string
	// Token is the raw bearer token, kept for forwarding. It is never logged.
	Token  string
	Claims map[string]any
}

// LogValue leaves the token and claims out of logs.
func (id *Identity) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("subject", id.Subject),
		slog.Any("groups", id.Groups),
		slog.String("method", id.Method),
	)
}

// Authenticator turns a request into an identity.
// It returns ErrNotMine when the credential is not one it handles.
type Authenticator interface {
	Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
}

var (
	// ErrNotMine means the authenticator does not handle this kind of credential.
	ErrNotMine = errors.New("auth: credential not handled")
	// ErrNoCredentials means the request has no credential any authenticator accepts.
	ErrNoCredentials = errors.New("auth: no credentials")
)

// InvalidError is a credential an authenticator recognised but rejected.
type InvalidError struct {
	Method string
	Reason string
}

func (e *InvalidError) Error() string {
	return fmt.Sprintf("%s: invalid credential: %s", e.Method, e.Reason)
}

// BearerToken returns the token from an "Authorization: Bearer" header.
func BearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "bearer") || token == "" {
		return "", false
	}
	return token, true
}

type ctxKey struct{}

// WithIdentity returns a context carrying id.
func WithIdentity(ctx context.Context, id *Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the identity stored by WithIdentity.
func FromContext(ctx context.Context) (*Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(*Identity)
	return id, ok && id != nil
}

// Factory builds an authenticator from its JSON config.
type Factory func(cfg json.RawMessage) (Authenticator, error)

var (
	registryMu sync.RWMutex
	registry   = map[string]Factory{}
)

// Register makes an authenticator kind available. It panics if kind is already registered.
func Register(kind string, f Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, dup := registry[kind]; dup {
		panic("auth: kind registered twice: " + kind)
	}
	registry[kind] = f
}

// Lookup returns the factory registered for kind.
func Lookup(kind string) (Factory, bool) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	f, ok := registry[kind]
	return f, ok
}
