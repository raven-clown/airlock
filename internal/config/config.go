// Package config loads airlock's YAML config file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/backend"
	"github.com/raven-clown/airlock/internal/limits"
	"github.com/raven-clown/airlock/internal/naming"
	"github.com/raven-clown/airlock/policy/rules"
)

// Config is the whole config file.
type Config struct {
	ListenAddr string `yaml:"listen_addr"`
	// OpsListenAddr, when set, serves /healthz, /readyz and /metrics there instead of on
	// listen_addr, so they can stay off the public port.
	OpsListenAddr   string           `yaml:"ops_listen_addr"`
	Storage         Storage          `yaml:"storage"`
	Stdio           StdioConfig      `yaml:"stdio"`
	Audit           Audit            `yaml:"audit"`
	Telemetry       Telemetry        `yaml:"telemetry"`
	Limits          LimitsConfig     `yaml:"limits"`
	Settings        Settings         `yaml:"settings"`
	APIKeys         []apikey.Key     `yaml:"api_keys"`
	Servers         []backend.Config `yaml:"servers"`
	Rules           []rules.Rule     `yaml:"rules"`
	RoleBindings    []RoleBinding    `yaml:"role_bindings"`
	Profiles        []limits.Spec    `yaml:"profiles"`
	ProfileBindings []limits.Binding `yaml:"profile_bindings"`
}

// Storage selects the database.
type Storage struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

// Telemetry says where traces go.
type Telemetry struct {
	// OTLPEndpoint is the base URL of an OTLP/HTTP collector. Empty turns tracing off.
	OTLPEndpoint string            `yaml:"otlp_endpoint"`
	OTLPHeaders  map[string]string `yaml:"otlp_headers"`
	// SampleRatio is the share of new traces recorded, from 0 to 1. Zero means all.
	SampleRatio float64 `yaml:"sample_ratio"`
}

// LimitsConfig holds the per-replica limits that are not part of a profile.
type LimitsConfig struct {
	// MaxInflight caps the requests one replica serves at once. Zero means no cap.
	MaxInflight int64 `yaml:"max_inflight"`
}

// Settings are stored in the settings table, one row per top-level key.
type Settings struct {
	AllowedOrigins []string `json:"allowed_origins,omitempty" yaml:"allowed_origins"`
	// PublicURL is where clients reach airlock, used in the protected resource metadata.
	// Empty means the scheme and host of each request.
	PublicURL      string `json:"public_url,omitempty" yaml:"public_url"`
	OIDC           *OIDC  `json:"oidc,omitempty" yaml:"oidc"`
	DefaultProfile string `json:"default_profile,omitempty" yaml:"default_profile"`
	OrgProfile     string `json:"org_profile,omitempty" yaml:"org_profile"`
}

// OIDC says which tokens are accepted and how their claims become an identity.
type OIDC struct {
	Issuer   string `json:"issuer" yaml:"issuer"`
	Audience string `json:"audience" yaml:"audience"`
	// JWKSURL is where the signing keys are. Empty means the issuer's discovery document.
	JWKSURL      string `json:"jwks_url,omitempty" yaml:"jwks_url"`
	SubjectClaim string `json:"subject_claim,omitempty" yaml:"subject_claim"`
	GroupsClaim  string `json:"groups_claim,omitempty" yaml:"groups_claim"`
	ProfileClaim string `json:"profile_claim,omitempty" yaml:"profile_claim"`
}

// Claim defaults.
const (
	DefaultSubjectClaim = "sub"
	DefaultGroupsClaim  = "groups"
	DefaultProfileClaim = "tier"
)

// Admin API roles.
const (
	RoleAdmin  = "admin"
	RoleMember = "member"
	RoleViewer = "viewer"
)

// RoleBinding gives an admin API role to the subjects matching its patterns.
type RoleBinding struct {
	Name     string   `json:"name" yaml:"name"`
	Subjects []string `json:"subjects" yaml:"subjects"`
	Role     string   `json:"role" yaml:"role"`
}

// StdioConfig holds settings for serve --stdio.
type StdioConfig struct {
	Identity        string   `yaml:"identity"`
	Groups          []string `yaml:"groups"`
	AllowedCommands []string `yaml:"allowed_commands"`
}

// Audit configures audit records.
type Audit struct {
	Sinks       []Sink        `yaml:"sinks"`
	IncludeArgs bool          `yaml:"include_args"`
	BufferSize  int           `yaml:"buffer_size"`
	OnOverflow  string        `yaml:"on_overflow"`
	Retention   time.Duration `yaml:"retention"`
}

// Sink is one audit destination.
type Sink struct {
	Kind string `yaml:"kind"`
	Path string `yaml:"path"`
}

// Env holds environment variables by name.
type Env map[string]string

// Lookup returns the value of name.
func (e Env) Lookup(name string) (string, bool) {
	v, ok := e[name]
	return v, ok
}

// OSEnv returns the process environment.
func OSEnv() Env {
	env := Env{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	return env
}

// processKeys are expanded at load time. The rest are resources whose ${VAR} references are kept.
var processKeys = map[string]bool{
	"listen_addr": true, "ops_listen_addr": true, "storage": true, "stdio": true, "audit": true, "settings": true, "telemetry": true, "limits": true,
}

// Default returns the config used when no file is given.
func Default() *Config {
	return &Config{
		ListenAddr: "127.0.0.1:8080",
		Storage:    Storage{Driver: "sqlite", DSN: "file:airlock.db"},
		Stdio:      StdioConfig{Identity: "local"},
		Audit: Audit{
			Sinks:      []Sink{{Kind: "stdout"}},
			BufferSize: 4096,
			OnOverflow: "drop",
			Retention:  720 * time.Hour,
		},
	}
}

// Load reads and parses the file at path.
func Load(path string, env Env) (*Config, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	return Parse(data, env)
}

// Parse parses a config document, applies env overrides and validates the result.
func Parse(data []byte, env Env) (*Config, error) {
	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	if err := strict.Decode(Default()); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	doc := &root
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		doc = root.Content[0]
	}
	if doc.Kind == 0 {
		doc = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	}
	if doc.Kind != yaml.MappingNode {
		return nil, errors.New("parsing config: the document must be a mapping")
	}
	if err := applyEnv(doc, env); err != nil {
		return nil, err
	}
	if err := expandProcess(doc, env.Lookup); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := yaml.NewEncoder(&buf).Encode(doc); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	cfg := Default()
	dec := yaml.NewDecoder(&buf)
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func expandProcess(doc *yaml.Node, lookup func(string) (string, bool)) error {
	for i := 0; i+1 < len(doc.Content); i += 2 {
		key := doc.Content[i].Value
		if !processKeys[key] {
			continue
		}
		if err := expandNode(doc.Content[i+1], lookup); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
	}
	return nil
}

func expandNode(n *yaml.Node, lookup func(string) (string, bool)) error {
	if n.Kind == yaml.ScalarNode {
		v, err := Expand(n.Value, lookup)
		if err != nil {
			return err
		}
		n.Value = v
		return nil
	}
	for _, c := range n.Content {
		if err := expandNode(c, lookup); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) normalize() error {
	seen := map[string]bool{}
	for i := range c.Servers {
		s := &c.Servers[i]
		at := fmt.Sprintf("servers[%d]", i)
		switch {
		case !naming.ValidServerName(s.Name):
			return fmt.Errorf("%s.name: invalid server name %q", at, s.Name)
		case seen[s.Name]:
			return fmt.Errorf("%s.name: duplicate %q", at, s.Name)
		}
		seen[s.Name] = true
		switch s.Transport {
		case backend.TransportStdio:
			if s.Command == "" {
				return fmt.Errorf("%s.command: required for stdio", at)
			}
		case backend.TransportStreamable:
			if s.URL == "" {
				return fmt.Errorf("%s.url: required for streamable_http", at)
			}
		default:
			return fmt.Errorf("%s.transport: must be stdio or streamable_http", at)
		}
		if s.Auth.Mode == "" {
			s.Auth.Mode = backend.AuthNone
		}
		switch s.Auth.Mode {
		case backend.AuthNone, backend.AuthStatic, backend.AuthForward:
		default:
			return fmt.Errorf("%s.auth.mode: must be none, static or forward", at)
		}
		if s.CallTimeout == 0 {
			s.CallTimeout = backend.DefaultCallTimeout
		}
	}
	keys := map[string]bool{}
	for i, k := range c.APIKeys {
		at := fmt.Sprintf("api_keys[%d]", i)
		switch {
		case k.Name == "":
			return fmt.Errorf("%s.name: required", at)
		case keys[k.Name]:
			return fmt.Errorf("%s.name: duplicate %q", at, k.Name)
		case !isHex64(k.SHA256):
			return fmt.Errorf("%s.sha256: must be 64 hex characters", at)
		}
		keys[k.Name] = true
	}
	if _, err := rules.New(c.Rules); err != nil {
		return fmt.Errorf("rules: %w", err)
	}
	for i, s := range c.Audit.Sinks {
		at := fmt.Sprintf("audit.sinks[%d]", i)
		switch s.Kind {
		case "stdout":
		case "file":
			if s.Path == "" {
				return fmt.Errorf("%s.path: required for file", at)
			}
		default:
			return fmt.Errorf("%s.kind: unknown sink %q", at, s.Kind)
		}
	}
	if c.Audit.OnOverflow != "drop" && c.Audit.OnOverflow != "block" {
		return errors.New("audit.on_overflow: must be drop or block")
	}
	if c.Audit.BufferSize <= 0 {
		return errors.New("audit.buffer_size: must be positive")
	}
	if c.Audit.Retention <= 0 {
		return errors.New("audit.retention: must be positive")
	}
	if c.Storage.Driver != "sqlite" && c.Storage.Driver != "postgres" {
		return errors.New("storage.driver: must be sqlite or postgres")
	}
	if c.Storage.DSN == "" {
		return errors.New("storage.dsn: required")
	}
	if r := c.Telemetry.SampleRatio; r < 0 || r > 1 {
		return errors.New("telemetry.sample_ratio: must be from 0 to 1")
	}
	if c.Telemetry.OTLPEndpoint != "" && !isHTTPURL(c.Telemetry.OTLPEndpoint) {
		// The value is not repeated, since it can hold a collector's key.
		return errors.New("telemetry.otlp_endpoint: must be an http or https URL of an OTLP/HTTP collector")
	}
	if c.Limits.MaxInflight < 0 {
		return errors.New("limits.max_inflight: must be zero or more")
	}
	if err := c.checkSettings(); err != nil {
		return err
	}
	if _, err := c.LimitsConfig(); err != nil {
		return err
	}
	return c.checkRoleBindings()
}

// Validate checks a config built from the store the way Parse checks a file, filling in
// the same defaults.
func Validate(c *Config) error { return c.normalize() }

func (c *Config) checkSettings() error {
	if c.Settings.PublicURL != "" && !isHTTPURL(c.Settings.PublicURL) {
		return fmt.Errorf("settings.public_url: %q must be an http or https URL", c.Settings.PublicURL)
	}
	o := c.Settings.OIDC
	if o == nil {
		return nil
	}
	switch {
	case !isHTTPURL(o.Issuer):
		return fmt.Errorf("settings.oidc.issuer: %q must be an http or https URL", o.Issuer)
	case o.Audience == "":
		return errors.New("settings.oidc.audience: required")
	case o.JWKSURL != "" && !isHTTPURL(o.JWKSURL):
		return fmt.Errorf("settings.oidc.jwks_url: %q must be an http or https URL", o.JWKSURL)
	}
	return nil
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// LimitsConfig parses the profiles and checks the bindings and the default and org profiles.
func (c *Config) LimitsConfig() (limits.Config, error) {
	out := limits.Config{Bindings: c.ProfileBindings, Default: c.Settings.DefaultProfile, Org: c.Settings.OrgProfile}
	for i, s := range c.Profiles {
		p, err := limits.ParseProfile(s)
		if err != nil {
			return limits.Config{}, fmt.Errorf("profiles[%d]: %w", i, err)
		}
		out.Profiles = append(out.Profiles, p)
	}
	if err := out.Validate(); err != nil {
		if strings.HasPrefix(err.Error(), "default_profile") || strings.HasPrefix(err.Error(), "org_profile") {
			return limits.Config{}, fmt.Errorf("settings.%w", err)
		}
		return limits.Config{}, err
	}
	return out, nil
}

func (c *Config) checkRoleBindings() error {
	seen := map[string]bool{}
	for i, b := range c.RoleBindings {
		at := fmt.Sprintf("role_bindings[%d]", i)
		switch {
		case b.Name == "":
			return fmt.Errorf("%s.name: required", at)
		case seen[b.Name]:
			return fmt.Errorf("%s.name: duplicate %q", at, b.Name)
		case len(b.Subjects) == 0:
			return fmt.Errorf("%s.subjects: required", at)
		}
		switch b.Role {
		case RoleAdmin, RoleMember, RoleViewer:
		default:
			return fmt.Errorf("%s.role: must be admin, member or viewer", at)
		}
		seen[b.Name] = true
	}
	return nil
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
