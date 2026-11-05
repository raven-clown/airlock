package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func envOf(m map[string]string) Env {
	return Env(m)
}

func TestParseDefaults(t *testing.T) {
	got, err := Parse(nil, envOf(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, Default()) {
		t.Errorf("Parse(empty) = %+v, want %+v", got, Default())
	}
	if got.ListenAddr != "127.0.0.1:8080" || got.Stdio.Identity != "local" || got.Audit.BufferSize != 4096 || got.Audit.OnOverflow != "drop" {
		t.Errorf("defaults = %+v", got)
	}
	if len(got.Audit.Sinks) != 1 || got.Audit.Sinks[0].Kind != "stdout" {
		t.Errorf("default sinks = %+v", got.Audit.Sinks)
	}
	if got.Storage.Driver != "sqlite" || got.Storage.DSN != "file:airlock.db" {
		t.Errorf("default storage = %+v", got.Storage)
	}
}

func TestSettings(t *testing.T) {
	got, err := Parse([]byte("settings:\n  allowed_origins: [\"http://localhost:*\"]\n"), envOf(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Settings.AllowedOrigins, []string{"http://localhost:*"}) {
		t.Errorf("settings = %+v", got.Settings)
	}
	if _, err := Parse([]byte("allowed_origins: [x]\n"), envOf(nil)); err == nil || !strings.Contains(err.Error(), "allowed_origins") {
		t.Errorf("top-level allowed_origins: error = %v", err)
	}
}

func TestRoleBindings(t *testing.T) {
	got, err := Parse([]byte("role_bindings:\n  - {name: admins, subjects: [\"group:ops\"], role: admin}\n"), envOf(nil))
	if err != nil {
		t.Fatal(err)
	}
	want := []RoleBinding{{Name: "admins", Subjects: []string{"group:ops"}, Role: RoleAdmin}}
	if !reflect.DeepEqual(got.RoleBindings, want) {
		t.Errorf("role bindings = %+v", got.RoleBindings)
	}
}

func TestEnvOverride(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		check   func(*Config) bool
		wantErr string
	}{
		{name: "top level", env: map[string]string{"AIRLOCK_LISTEN_ADDR": "0.0.0.0:9"}, check: func(c *Config) bool { return c.ListenAddr == "0.0.0.0:9" }},
		{name: "nested", env: map[string]string{"AIRLOCK_STDIO__IDENTITY": "me"}, check: func(c *Config) bool { return c.Stdio.Identity == "me" }},
		{name: "bool", env: map[string]string{"AIRLOCK_AUDIT__INCLUDE_ARGS": "true"}, check: func(c *Config) bool { return c.Audit.IncludeArgs }},
		{name: "storage", env: map[string]string{"AIRLOCK_STORAGE__DSN": "file:x.db"}, check: func(c *Config) bool { return c.Storage.DSN == "file:x.db" && c.Storage.Driver == "sqlite" }},
		{name: "int", env: map[string]string{"AIRLOCK_AUDIT__BUFFER_SIZE": "10"}, check: func(c *Config) bool { return c.Audit.BufferSize == 10 }},
		{name: "other prefix ignored", env: map[string]string{"LISTEN_ADDR": "x", "AIRLOCKX": "y"}, check: func(c *Config) bool { return c.ListenAddr == "127.0.0.1:8080" }},
		{name: "unknown", env: map[string]string{"AIRLOCK_NOPE": "1"}, wantErr: "AIRLOCK_NOPE: unknown key nope"},
		{name: "unknown nested", env: map[string]string{"AIRLOCK_STDIO__NOPE": "1"}, wantErr: "unknown key stdio.nope"},
		{name: "list", env: map[string]string{"AIRLOCK_SERVERS": "x"}, wantErr: "cannot override list key servers"},
		{name: "section", env: map[string]string{"AIRLOCK_STDIO": "x"}, wantErr: "cannot override section stdio"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse([]byte("listen_addr: 127.0.0.1:8080\n"), envOf(tt.env))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !tt.check(got) {
				t.Errorf("override not applied: %+v", got)
			}
		})
	}
}

func TestEnvOverrideWithoutFileKey(t *testing.T) {
	got, err := Parse(nil, envOf(map[string]string{"AIRLOCK_STDIO__IDENTITY": "me"}))
	if err != nil {
		t.Fatal(err)
	}
	if got.Stdio.Identity != "me" || got.ListenAddr != "127.0.0.1:8080" {
		t.Errorf("config = %+v", got)
	}
}

func TestUnknownKey(t *testing.T) {
	_, err := Parse([]byte("listen_adr: x\n"), envOf(nil))
	if err == nil || !strings.Contains(err.Error(), "listen_adr") || !strings.Contains(err.Error(), "line 1") {
		t.Fatalf("error = %v", err)
	}
}

func TestExpand(t *testing.T) {
	env := envOf(map[string]string{"A": "1", "B": "two"}).Lookup
	tests := []struct {
		in, want, wantErr string
	}{
		{in: "${A}", want: "1"},
		{in: "x${A}-${B}y", want: "x1-twoy"},
		{in: "plain", want: "plain"},
		{in: "$A", want: "$A"},
		{in: "${MISSING}", wantErr: "variable MISSING is not set"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := Expand(tt.in, env)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("Expand = %q, %v, want %q", got, err, tt.want)
			}
		})
	}
}

func TestProcessSettingsExpanded(t *testing.T) {
	doc := `
listen_addr: ${ADDR}
servers:
  - name: github
    transport: stdio
    command: gh-mcp
    env:
      TOKEN: ${GH}
`
	got, err := Parse([]byte(doc), envOf(map[string]string{"ADDR": "127.0.0.1:1"}))
	if err != nil {
		t.Fatal(err)
	}
	if got.ListenAddr != "127.0.0.1:1" {
		t.Errorf("listen_addr = %q", got.ListenAddr)
	}
	if got.Servers[0].Env["TOKEN"] != "${GH}" {
		t.Errorf("server env was expanded: %q", got.Servers[0].Env["TOKEN"])
	}
}

func TestProcessSettingMissingVar(t *testing.T) {
	_, err := Parse([]byte("listen_addr: ${NOPE}\n"), envOf(nil))
	if err == nil || !strings.Contains(err.Error(), "variable NOPE is not set") {
		t.Fatalf("error = %v", err)
	}
}

func TestServerDefaults(t *testing.T) {
	doc := `
servers:
  - name: a
    transport: streamable_http
    url: http://x/mcp
  - name: b
    transport: stdio
    command: b
    call_timeout: 5s
`
	got, err := Parse([]byte(doc), envOf(nil))
	if err != nil {
		t.Fatal(err)
	}
	if got.Servers[0].Auth.Mode != "none" || got.Servers[0].CallTimeout != 60*time.Second {
		t.Errorf("server a = %+v", got.Servers[0])
	}
	if got.Servers[1].CallTimeout != 5*time.Second {
		t.Errorf("server b timeout = %v", got.Servers[1].CallTimeout)
	}
}

func TestValidate(t *testing.T) {
	hexA := strings.Repeat("a", 64)
	hexB := strings.Repeat("b", 64)
	tests := []struct {
		name, doc, wantErr string
	}{
		{"bad server name", "servers:\n  - {name: ok, transport: stdio, command: x}\n  - {name: Bad, transport: stdio, command: x}\n", `servers[1].name: invalid server name "Bad"`},
		{"duplicate server", "servers:\n  - {name: a, transport: stdio, command: x}\n  - {name: a, transport: stdio, command: x}\n", `servers[1].name: duplicate "a"`},
		{"transport", "servers:\n  - {name: a, transport: sse, url: x}\n", "servers[0].transport: must be stdio or streamable_http"},
		{"stdio command", "servers:\n  - {name: a, transport: stdio}\n", "servers[0].command: required for stdio"},
		{"http url", "servers:\n  - {name: a, transport: streamable_http}\n", "servers[0].url: required for streamable_http"},
		{"auth mode", "servers:\n  - {name: a, transport: streamable_http, url: x, auth: {mode: magic}}\n", "servers[0].auth.mode: must be none, static or forward"},
		{"sink kind", "audit:\n  sinks: [{kind: kafka}]\n", `audit.sinks[0].kind: unknown sink "kafka"`},
		{"file sink path", "audit:\n  sinks: [{kind: file}]\n", "audit.sinks[0].path: required for file"},
		{"overflow", "audit:\n  on_overflow: maybe\n", "audit.on_overflow: must be drop or block"},
		{"key name", "api_keys:\n  - {sha256: " + hexA + "}\n", "api_keys[0].name: required"},
		{"key hash", "api_keys:\n  - {name: k, sha256: abc}\n", "api_keys[0].sha256: must be 64 hex characters"},
		{"duplicate key", "api_keys:\n  - {name: k, sha256: " + hexA + "}\n  - {name: k, sha256: " + hexB + "}\n", `api_keys[1].name: duplicate "k"`},
		{"rules", "rules:\n  - {name: r}\n", `rules: rule "r": no subjects`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.doc), envOf(nil))
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "airlock.yaml")
	if err := os.WriteFile(path, []byte("listen_addr: 127.0.0.1:7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path, envOf(nil))
	if err != nil || got.ListenAddr != "127.0.0.1:7" {
		t.Fatalf("Load = %+v, %v", got, err)
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml"), envOf(nil)); err == nil {
		t.Fatal("missing file loaded")
	}
}
