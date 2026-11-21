// Package oidc signs callers in with JWTs from any OpenID Connect provider, checked locally
// against the provider's cached signing keys.
package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/raven-clown/airlock/auth"
	"github.com/raven-clown/airlock/auth/apikey"
)

// Method names this authenticator in identities, audit records and metrics.
const Method = "oidc"

// DefaultClockSkew is how far the clocks of airlock and the provider may differ.
const DefaultClockSkew = time.Minute

// Claim defaults.
const (
	DefaultSubjectClaim = "sub"
	DefaultGroupsClaim  = "groups"
	DefaultProfileClaim = "tier"
)

// signingAlgs are the signatures accepted. All are asymmetric, so a token signed with a
// shared secret, or not signed, is never accepted.
var signingAlgs = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.PS256, jose.PS384, jose.PS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.EdDSA,
}

// Config says which tokens are accepted and how their claims become an identity.
type Config struct {
	Issuer   string
	Audience string
	// JWKSURL is where the signing keys are. Empty means the issuer's discovery document.
	JWKSURL string
	// SubjectClaim, GroupsClaim and ProfileClaim name claims. A dotted name such as
	// realm_access.roles is read as a path when no claim has that exact name.
	SubjectClaim, GroupsClaim, ProfileClaim string
	// ClockSkew is the allowance on exp, nbf and iat. Zero means DefaultClockSkew.
	ClockSkew time.Duration
	// Client fetches the discovery document and the keys. Nil means http.DefaultClient.
	Client *http.Client
	Now    func() time.Time
}

// Authenticator checks tokens from one issuer.
type Authenticator struct {
	cfg  Config
	keys *keySet
}

// New returns an authenticator for cfg. It does not reach the issuer: the keys are fetched
// when the first token arrives.
func New(cfg Config) (*Authenticator, error) {
	if err := checkHTTPURL(cfg.Issuer); err != nil {
		return nil, fmt.Errorf("oidc issuer %q: %w", cfg.Issuer, err)
	}
	if cfg.Audience == "" {
		return nil, errors.New("oidc needs an audience")
	}
	if cfg.JWKSURL != "" {
		if err := checkHTTPURL(cfg.JWKSURL); err != nil {
			return nil, fmt.Errorf("oidc jwks url %q: %w", cfg.JWKSURL, err)
		}
	}
	if cfg.SubjectClaim == "" {
		cfg.SubjectClaim = DefaultSubjectClaim
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = DefaultGroupsClaim
	}
	if cfg.ProfileClaim == "" {
		cfg.ProfileClaim = DefaultProfileClaim
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = DefaultClockSkew
	}
	if cfg.Client == nil {
		cfg.Client = http.DefaultClient
	}
	cfg.Client = noDowngrade(cfg.Client)
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Authenticator{cfg: cfg, keys: &keySet{issuer: cfg.Issuer, jwksURL: cfg.JWKSURL, client: cfg.Client, now: cfg.Now}}, nil
}

// Issuer returns the issuer tokens must come from.
func (a *Authenticator) Issuer() string { return a.cfg.Issuer }

// Same reports whether cfg would build the same authenticator, so a reload can keep this
// one and its cached keys.
func (a *Authenticator) Same(cfg Config) bool {
	b, err := New(cfg)
	if err != nil {
		return false
	}
	x, y := a.cfg, b.cfg
	return x.Issuer == y.Issuer && x.Audience == y.Audience && x.JWKSURL == y.JWKSURL &&
		x.SubjectClaim == y.SubjectClaim && x.GroupsClaim == y.GroupsClaim && x.ProfileClaim == y.ProfileClaim &&
		x.ClockSkew == y.ClockSkew
}

// Authenticate implements auth.Authenticator. A bearer token that is not an airlock API key
// and has the three parts of a JWT is this authenticator's.
func (a *Authenticator) Authenticate(ctx context.Context, r *http.Request) (*auth.Identity, error) {
	token, ok := auth.BearerToken(r)
	if !ok || strings.HasPrefix(token, apikey.Prefix) || strings.Count(token, ".") != 2 {
		return nil, auth.ErrNotMine
	}
	return a.Verify(ctx, token)
}

// Verify checks a token's signature, issuer, audience and validity, and returns its caller.
func (a *Authenticator) Verify(ctx context.Context, token string) (*auth.Identity, error) {
	jws, err := jose.ParseSignedCompact(token, signingAlgs)
	if err != nil {
		return nil, reject("malformed", "malformed token or unsupported signature")
	}
	// The issuer is read before the signature is checked, so a token from somewhere else
	// never causes a key fetch. Nothing else is trusted until the signature holds.
	var peek struct {
		Issuer string `json:"iss"`
	}
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &peek); err != nil || peek.Issuer != a.cfg.Issuer {
		return nil, reject("issuer", fmt.Sprintf("issuer is %q, want %q", peek.Issuer, a.cfg.Issuer))
	}
	header := jws.Signatures[0].Protected
	verify := func(keys []jose.JSONWebKey) ([]byte, bool) {
		for _, k := range keys {
			if k.Algorithm != "" && k.Algorithm != header.Algorithm {
				continue
			}
			if payload, err := jws.Verify(k.Key); err == nil {
				return payload, true
			}
		}
		return nil, false
	}
	keys, err := a.keys.lookup(ctx, header.KeyID, false)
	if err != nil {
		return nil, err
	}
	payload, verified := verify(keys)
	// A token without kid names no key to look for, so a key missing from the cached set is
	// only found by reading the set again, as for an unknown kid.
	if !verified && header.KeyID == "" {
		if keys, err = a.keys.lookup(ctx, "", true); err != nil {
			return nil, err
		}
		payload, verified = verify(keys)
	}
	if !verified {
		return nil, reject("signature", fmt.Sprintf("no key of the issuer verifies the signature (kid %q)", header.KeyID))
	}

	var claims map[string]any
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&claims); err != nil {
		return nil, reject("claims", "claims are not a JSON object")
	}
	if err := a.checkClaims(claims); err != nil {
		return nil, err
	}
	subject, _ := lookupClaim(claims, a.cfg.SubjectClaim).(string)
	if subject == "" {
		return nil, reject("claims", fmt.Sprintf("claim %q is missing or not a string", a.cfg.SubjectClaim))
	}
	// API key callers have the subject key:<name>, so a token naming one could pass for
	// that key wherever subjects are compared, such as a session's owner.
	if strings.HasPrefix(subject, "key:") {
		return nil, reject("claims", fmt.Sprintf("claim %q starts with key:, which only API keys may use", a.cfg.SubjectClaim))
	}
	profile, _ := lookupClaim(claims, a.cfg.ProfileClaim).(string)
	return &auth.Identity{
		Subject: subject,
		Groups:  claimStrings(lookupClaim(claims, a.cfg.GroupsClaim)),
		Method:  Method,
		Token:   token,
		Claims:  claims,
		Profile: profile,
	}, nil
}

func (a *Authenticator) checkClaims(claims map[string]any) error {
	found := false
	for _, aud := range claimStrings(claims["aud"]) {
		if aud == a.cfg.Audience {
			found = true
			break
		}
	}
	if !found {
		return reject("audience", fmt.Sprintf("audience does not include %q", a.cfg.Audience))
	}
	now := a.cfg.Now()
	exp, ok := claimTime(claims["exp"])
	if !ok {
		return reject("claims", "claim exp is missing")
	}
	if !now.Before(exp.Add(a.cfg.ClockSkew)) {
		return reject("expired", "token expired at "+exp.UTC().Format(time.RFC3339))
	}
	// nbf and iat are optional, but one that is present has to be a time and not ahead of now.
	for _, name := range []string{"nbf", "iat"} {
		v, present := claims[name]
		if !present {
			continue
		}
		at, ok := claimTime(v)
		if !ok {
			return reject("claims", "claim "+name+" is not a time")
		}
		if now.Add(a.cfg.ClockSkew).Before(at) {
			return reject("not_yet_valid", "token is not valid before "+at.UTC().Format(time.RFC3339))
		}
	}
	return nil
}

func reject(reason, detail string) error {
	return &auth.InvalidError{Method: Method, Reason: reason, Detail: detail}
}

// lookupClaim returns the claim called name, or when there is none and name has dots, the
// value at that path into nested objects, as in Keycloak's realm_access.roles.
func lookupClaim(claims map[string]any, name string) any {
	if v, ok := claims[name]; ok {
		return v
	}
	var cur any = claims
	for part := range strings.SplitSeq(name, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = obj[part]
	}
	return cur
}

// claimStrings reads a claim that is one string or a list of strings.
func claimStrings(v any) []string {
	switch v := v.(type) {
	case string:
		if v != "" {
			return []string{v}
		}
	case []any:
		var out []string
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// claimTime reads a claim that is a number of seconds since 1970.
func claimTime(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	secs, err := n.Float64()
	// The upper bound keeps the conversion to whole seconds from overflowing.
	if err != nil || secs < 0 || secs > 1e12 {
		return time.Time{}, false
	}
	return time.Unix(int64(secs), 0), true
}

type registryConfig struct {
	Issuer       string `json:"issuer"`
	Audience     string `json:"audience"`
	JWKSURL      string `json:"jwks_url"`
	SubjectClaim string `json:"subject_claim"`
	GroupsClaim  string `json:"groups_claim"`
	ProfileClaim string `json:"profile_claim"`
}

func init() {
	auth.Register(Method, func(raw json.RawMessage) (auth.Authenticator, error) {
		var c registryConfig
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, fmt.Errorf("oidc config: %w", err)
		}
		return New(Config{Issuer: c.Issuer, Audience: c.Audience, JWKSURL: c.JWKSURL,
			SubjectClaim: c.SubjectClaim, GroupsClaim: c.GroupsClaim, ProfileClaim: c.ProfileClaim})
	})
}

// checkHTTPURL accepts https, and plain http only on a loopback address: whoever can change
// the keys on the way can sign any token.
func checkHTTPURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	switch {
	case u.Host == "" || (u.Scheme != "http" && u.Scheme != "https"):
		return errors.New("must be an https URL")
	case u.Scheme == "http" && !Loopback(u.Hostname()):
		return errors.New("must be https; plain http is only allowed on a loopback address")
	}
	return nil
}

// Loopback reports whether host is localhost or a loopback IP.
func Loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// noDowngrade wraps c so a redirect cannot move a fetch from https to http.
func noDowngrade(c *http.Client) *http.Client {
	out := *c
	next := c.CheckRedirect
	out.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
			return errors.New("refusing a redirect from https to http")
		}
		if next != nil {
			return next(req, via)
		}
		if len(via) >= 10 {
			return errors.New("stopped after 10 redirects")
		}
		return nil
	}
	return &out
}
