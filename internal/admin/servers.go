package admin

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/raven-clown/airlock/backend"
	"github.com/raven-clown/airlock/internal/store"
	"github.com/raven-clown/airlock/policy/glob"
)

// serverWrite is a server as the API takes it: durations as Go strings such as 60s.
type serverWrite struct {
	Name        string            `json:"name"`
	Transport   string            `json:"transport"`
	Command     string            `json:"command,omitempty"`
	Args        []string          `json:"args,omitempty"`
	Env         map[string]string `json:"env,omitempty"`
	Dir         string            `json:"dir,omitempty"`
	URL         string            `json:"url,omitempty"`
	Auth        *authWrite        `json:"auth,omitempty"`
	CallTimeout string            `json:"call_timeout,omitempty"`
	Required    bool              `json:"required,omitempty"`
}

type authWrite struct {
	Mode               string            `json:"mode,omitempty"`
	Headers            map[string]string `json:"headers,omitempty"`
	DiscoveryHeaders   map[string]string `json:"discovery_headers,omitempty"`
	SessionIdleTimeout string            `json:"session_idle_timeout,omitempty"`
	MaxSessions        int               `json:"max_sessions,omitempty"`
}

var reference = regexp.MustCompile(`\$\{[A-Za-z_][A-Za-z0-9_]*\}`)

// secretHeader reports whether a header's value is likely a credential.
func secretHeader(name string) bool {
	n := strings.ToLower(name)
	if n == "authorization" || n == "proxy-authorization" || n == "cookie" {
		return true
	}
	for _, word := range []string{"key", "token", "secret", "auth", "password"} {
		if strings.Contains(n, word) {
			return true
		}
	}
	return false
}

func parseDuration(field, s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, invalid(field, "%s must be a duration such as 60s, not %q", field, s)
	}
	return d, nil
}

func formatDuration(d time.Duration) string {
	if d == 0 {
		return ""
	}
	return d.String()
}

func (h *handler) decodeServer(raw []byte, _ json.RawMessage) (string, json.RawMessage, error) {
	var in serverWrite
	if err := decodeStrict(raw, &in); err != nil {
		return "", nil, err
	}
	cfg := backend.Config{Name: in.Name, Transport: in.Transport, Command: in.Command, Args: in.Args, Env: in.Env,
		Dir: in.Dir, URL: in.URL, Required: in.Required}
	var err error
	if cfg.CallTimeout, err = parseDuration("call_timeout", in.CallTimeout); err != nil {
		return "", nil, err
	}
	if in.Auth != nil {
		cfg.Auth = backend.HTTPAuth{Mode: in.Auth.Mode, Headers: in.Auth.Headers, DiscoveryHeaders: in.Auth.DiscoveryHeaders, MaxSessions: in.Auth.MaxSessions}
		if cfg.Auth.SessionIdleTimeout, err = parseDuration("auth.session_idle_timeout", in.Auth.SessionIdleTimeout); err != nil {
			return "", nil, err
		}
	}
	for k, v := range cfg.Env {
		if !reference.MatchString(v) {
			return "", nil, invalid("env."+k, "env values must be ${VAR} references to airlock's environment, so no secret is stored")
		}
	}
	for field, headers := range map[string]map[string]string{"auth.headers": cfg.Auth.Headers, "auth.discovery_headers": cfg.Auth.DiscoveryHeaders} {
		for k, v := range headers {
			if secretHeader(k) && !reference.MatchString(v) {
				return "", nil, invalid(field+"."+k, "the value of %s must use a ${VAR} reference to airlock's environment, so no secret is stored", k)
			}
		}
	}
	if allowed := h.d.Process.Stdio.AllowedCommands; cfg.Transport == backend.TransportStdio && len(allowed) > 0 &&
		!slices.ContainsFunc(allowed, func(p string) bool { return glob.Match(p, cfg.Command) }) {
		return "", nil, invalid("command", "command %q is not in stdio.allowed_commands", cfg.Command)
	}
	spec, err := json.Marshal(cfg)
	return cfg.Name, spec, err
}

func serverWriteForm(spec json.RawMessage) (json.RawMessage, error) {
	var cfg backend.Config
	if err := json.Unmarshal(spec, &cfg); err != nil {
		return nil, err
	}
	out := serverWrite{Name: cfg.Name, Transport: cfg.Transport, Command: cfg.Command, Args: cfg.Args, Env: cfg.Env,
		Dir: cfg.Dir, URL: cfg.URL, CallTimeout: formatDuration(cfg.CallTimeout), Required: cfg.Required}
	if a := cfg.Auth; a.Mode != "" || len(a.Headers) > 0 || len(a.DiscoveryHeaders) > 0 || a.SessionIdleTimeout != 0 || a.MaxSessions != 0 {
		out.Auth = &authWrite{Mode: a.Mode, Headers: a.Headers, DiscoveryHeaders: a.DiscoveryHeaders,
			SessionIdleTimeout: formatDuration(a.SessionIdleTimeout), MaxSessions: a.MaxSessions}
	}
	return json.Marshal(out)
}

// secretValues shows each value as its reference, as a plain value when it cannot be a
// secret, or only as set.
func secretValues(m map[string]string, plainOK func(string) bool) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		switch {
		case reference.MatchString(v):
			out[k] = map[string]any{"ref": v}
		case plainOK(k):
			out[k] = map[string]any{"value": v}
		default:
			out[k] = map[string]any{"set": true}
		}
	}
	return out
}

func (h *handler) viewServer(row store.Row) (map[string]any, error) {
	var cfg backend.Config
	if err := json.Unmarshal(row.Spec, &cfg); err != nil {
		return nil, err
	}
	v := map[string]any{"name": cfg.Name, "transport": cfg.Transport}
	set := func(k string, val any, present bool) {
		if present {
			v[k] = val
		}
	}
	set("command", cfg.Command, cfg.Command != "")
	set("args", cfg.Args, len(cfg.Args) > 0)
	set("env", secretValues(cfg.Env, func(string) bool { return false }), len(cfg.Env) > 0)
	set("dir", cfg.Dir, cfg.Dir != "")
	set("url", cfg.URL, cfg.URL != "")
	set("call_timeout", formatDuration(cfg.CallTimeout), cfg.CallTimeout != 0)
	set("required", cfg.Required, cfg.Required)
	notSecret := func(k string) bool { return !secretHeader(k) }
	a := map[string]any{}
	if cfg.Auth.Mode != "" {
		a["mode"] = cfg.Auth.Mode
	}
	if len(cfg.Auth.Headers) > 0 {
		a["headers"] = secretValues(cfg.Auth.Headers, notSecret)
	}
	if len(cfg.Auth.DiscoveryHeaders) > 0 {
		a["discovery_headers"] = secretValues(cfg.Auth.DiscoveryHeaders, notSecret)
	}
	if cfg.Auth.SessionIdleTimeout != 0 {
		a["session_idle_timeout"] = formatDuration(cfg.Auth.SessionIdleTimeout)
	}
	if cfg.Auth.MaxSessions != 0 {
		a["max_sessions"] = cfg.Auth.MaxSessions
	}
	set("auth", a, len(a) > 0)
	if h.d.Backends != nil {
		if b, ok := h.d.Backends.Get(cfg.Name); ok {
			v["status"] = backendStatus(b)
		}
	}
	return v, nil
}

func backendStatus(b backend.Backend) map[string]any {
	st := b.Status()
	out := map[string]any{"name": b.Name(), "state": st.State, "tools": st.Tools}
	if st.Err != "" {
		out["error"] = st.Err
	}
	if !st.Since.IsZero() {
		out["since"] = formatTime(st.Since)
	}
	if len(st.Stderr) > 0 {
		out["stderr"] = st.Stderr
	}
	return out
}
