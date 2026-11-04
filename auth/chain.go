package auth

import (
	"context"
	"errors"
	"net/http"
)

// Chain tries authenticators in order. The first one that claims the credential decides.
type Chain struct {
	auths []Authenticator
}

// NewChain returns a chain over a.
func NewChain(a ...Authenticator) *Chain {
	return &Chain{auths: a}
}

// Authenticate returns the identity from the first authenticator that claims the request.
func (c *Chain) Authenticate(ctx context.Context, r *http.Request) (*Identity, error) {
	if _, ok := BearerToken(r); !ok {
		return nil, ErrNoCredentials
	}
	for _, a := range c.auths {
		id, err := a.Authenticate(ctx, r)
		if errors.Is(err, ErrNotMine) {
			continue
		}
		return id, err
	}
	return nil, ErrNoCredentials
}
