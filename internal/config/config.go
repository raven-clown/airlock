// Package config loads airlock's YAML config file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/backend"
	"github.com/raven-clown/airlock/internal/naming"
	"github.com/raven-clown/airlock/policy/rules"
)

// Config is the whole config file.
type Config struct {
	ListenAddr     string           `yaml:"listen_addr"`
	AllowedOrigins []string         `yaml:"allowed_origins"`
	Stdio          StdioConfig      `yaml:"stdio"`
	APIKeys        []apikey.Key     `yaml:"api_keys"`
	Servers        []backend.Config `yaml:"servers"`
	Rules          []rules.Rule     `yaml:"rules"`
	Audit          Audit            `yaml:"audit"`
}

// StdioConfig holds settings for serve --stdio.
type StdioConfig struct {
	Identity        string   `yaml:"identity"`
	Groups          []string `yaml:"groups"`
	AllowedCommands []string `yaml:"allowed_commands"`
}

// Audit configures audit records.
type Audit struct {
	Sinks       []Sink `yaml:"sinks"`
	IncludeArgs bool   `yaml:"include_args"`
	BufferSize  int    `yaml:"buffer_size"`
	OnOverflow  string `yaml:"on_overflow"`
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
var processKeys = map[string]bool{"listen_addr": true, "allowed_origins": true, "stdio": true, "audit": true}

// Default returns the config used when no file is given.
func Default() *Config {
	return &Config{
		ListenAddr: "127.0.0.1:8080",
		Stdio:      StdioConfig{Identity: "local"},
		Audit: Audit{
			Sinks:      []Sink{{Kind: "stdout"}},
			BufferSize: 4096,
			OnOverflow: "drop",
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
