// Package backend connects airlock to the MCP servers behind it.
package backend

import "time"

// Config describes one backend MCP server.
type Config struct {
	Name        string            `json:"name" yaml:"name"`
	Transport   string            `json:"transport" yaml:"transport"`
	Command     string            `json:"command,omitempty" yaml:"command"`
	Args        []string          `json:"args,omitempty" yaml:"args"`
	Env         map[string]string `json:"env,omitempty" yaml:"env"`
	Dir         string            `json:"dir,omitempty" yaml:"dir"`
	URL         string            `json:"url,omitempty" yaml:"url"`
	Auth        HTTPAuth          `json:"auth,omitzero" yaml:"auth"`
	CallTimeout time.Duration     `json:"call_timeout,omitempty" yaml:"call_timeout"`
	Required    bool              `json:"required,omitempty" yaml:"required"`
}

// HTTPAuth sets how a Streamable HTTP backend is called.
type HTTPAuth struct {
	Mode               string            `json:"mode,omitempty" yaml:"mode"`
	Headers            map[string]string `json:"headers,omitempty" yaml:"headers"`
	DiscoveryHeaders   map[string]string `json:"discovery_headers,omitempty" yaml:"discovery_headers"`
	SessionIdleTimeout time.Duration     `json:"session_idle_timeout,omitempty" yaml:"session_idle_timeout"`
	MaxSessions        int               `json:"max_sessions,omitempty" yaml:"max_sessions"`
}

// Transports and HTTP auth modes known to the built-in backends.
const (
	TransportStdio      = "stdio"
	TransportStreamable = "streamable_http"
	AuthNone            = "none"
	AuthStatic          = "static"
	AuthForward         = "forward"
)

// DefaultCallTimeout applies when a backend sets no call_timeout.
const DefaultCallTimeout = 60 * time.Second
