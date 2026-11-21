package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/raven-clown/airlock/auth/apikey"
	"github.com/raven-clown/airlock/auth/oidc/oidctest"
	"github.com/raven-clown/airlock/internal/config"
)

var keyPattern = regexp.MustCompile(`alk_[A-Za-z0-9_-]{43}`)

// startServe runs serve on doc and returns its address, stdout and stderr.
func startServe(t *testing.T, doc string) (string, *syncBuffer, *syncBuffer) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "airlock.yaml")
	dsn := "file:" + filepath.ToSlash(filepath.Join(dir, "airlock.db"))
	full := fmt.Sprintf("listen_addr: 127.0.0.1:0\nstorage:\n  dsn: '%s'\n", dsn) + doc
	if err := os.WriteFile(path, []byte(full), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stdout, stderr := &syncBuffer{}, &syncBuffer{}
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, []string{"serve", "--config", path}, strings.NewReader(""), stdout, stderr, config.Env{})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return listeningAddr(t, stdout), stdout, stderr
}

func call(t *testing.T, method, url, token string, body any) (int, map[string]any, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var v map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&v)
	return resp.StatusCode, v, resp.Header
}

func mcpClient(ctx context.Context, t *testing.T, addr, token string) *client.Client {
	t.Helper()
	tr, err := transport.NewStreamableHTTP("http://"+addr+"/mcp", transport.WithHTTPHeaders(map[string]string{"Authorization": "Bearer " + token}))
	if err != nil {
		t.Fatal(err)
	}
	c := client.NewClient(tr)
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	init := mcp.InitializeRequest{}
	init.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	if _, err := c.Initialize(ctx, init); err != nil {
		t.Fatal(err)
	}
	return c
}

func echo(ctx context.Context, t *testing.T, c *client.Client) {
	t.Helper()
	req := mcp.CallToolRequest{}
	req.Params.Name = "demo__echo"
	req.Params.Arguments = map[string]any{"text": "hi"}
	res, err := c.CallTool(ctx, req)
	if err != nil || res.IsError {
		t.Fatalf("demo__echo: %+v, %v", res, err)
	}
}

// TestServeAdmin sets airlock up from an empty store through the admin API alone.
func TestServeAdmin(t *testing.T) {
	ctx := context.Background()
	addr, stdout, stderr := startServe(t, "")
	waitFor(t, "the bootstrap key", func() bool { return keyPattern.MatchString(stderr.String()) })
	boot := keyPattern.FindString(stderr.String())
	if strings.Contains(stdout.String(), boot) {
		t.Fatal("the bootstrap key reached the JSON log")
	}
	base := "http://" + addr + "/admin/v1"
	if code, v, _ := call(t, http.MethodPost, base+"/servers", boot, map[string]any{"name": "demo", "transport": "stdio", "command": serverPath}); code != http.StatusCreated {
		t.Fatalf("create server: %d %v", code, v)
	}
	if code, v, _ := call(t, http.MethodPost, base+"/rules", boot, map[string]any{"name": "ci", "subjects": []string{"key:ci"}, "allow": []string{"demo__*"}}); code != http.StatusCreated {
		t.Fatalf("create rule: %d %v", code, v)
	}
	code, created, _ := call(t, http.MethodPost, base+"/api-keys", boot, map[string]any{"name": "ci"})
	if code != http.StatusCreated {
		t.Fatalf("create key: %d %v", code, created)
	}
	c := mcpClient(ctx, t, addr, created["key"].(string))
	waitFor(t, "demo__echo listed", func() bool { return slices.Contains(names(t, c), "demo__echo") })
	echo(ctx, t, c)

	code, page, _ := call(t, http.MethodGet, base+"/audit?kind=admin", boot, nil)
	if code != http.StatusOK || len(page["items"].([]any)) < 3 {
		t.Fatalf("admin audit: %d %v", code, page)
	}
	waitFor(t, "the tool call in the audit log", func() bool {
		_, page, _ := call(t, http.MethodGet, base+"/audit?kind=tool&subject=key:ci", boot, nil)
		items, _ := page["items"].([]any)
		return len(items) == 1
	})
	code, status, _ := call(t, http.MethodGet, base+"/status", boot, nil)
	if code != http.StatusOK || status["storage"] != "sqlite" || len(status["backends"].([]any)) != 1 {
		t.Fatalf("status: %d %v", code, status)
	}
	if code, _, _ := call(t, http.MethodGet, base+"/status", created["key"].(string), nil); code != http.StatusOK {
		// Every caller is a member, and members may not read the status.
		if code != http.StatusForbidden {
			t.Fatalf("member status: %d", code)
		}
	}
}

func TestServeMetrics(t *testing.T) {
	ctx := context.Background()
	doc := fmt.Sprintf(`
api_keys:
  - {name: ci, sha256: %s, groups: [eng]}
role_bindings:
  - {name: ops, subjects: ["key:nobody"], role: admin}
servers:
  - {name: demo, transport: stdio, command: '%s'}
rules:
  - {name: eng, subjects: ["group:eng"], allow: ["demo__*"]}
profiles:
  - name: free
    limits:
      requests: {rate: 1000/m}
settings:
  default_profile: free
`, apikey.Hash(testKey), serverPath)
	addr, _, _ := startServe(t, doc)
	c := mcpClient(ctx, t, addr, testKey)
	waitFor(t, "demo__echo listed", func() bool { return slices.Contains(names(t, c), "demo__echo") })
	echo(ctx, t, c)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/metrics", nil)
	var body string
	waitFor(t, "the tool call in the metrics", func() bool {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		body = string(raw)
		return strings.Contains(body, `airlock_tool_calls_total{server="demo",tool="echo",outcome="ok"} 1`)
	})
	for _, want := range []string{`airlock_requests_total{route="/mcp",code="200"}`, "airlock_inflight_requests", "airlock_revision", `airlock_build_info{version="dev"} 1`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	code, _, h := call(t, http.MethodGet, "http://"+addr+"/admin/v1/me", testKey, nil)
	if code != http.StatusForbidden || h.Get("RateLimit-Policy") != `"requests";q=1000;w=60` {
		t.Fatalf("admin answer %d, headers %v", code, h)
	}
}

func TestServeOIDC(t *testing.T) {
	ctx := context.Background()
	p := oidctest.New(t)
	doc := fmt.Sprintf(`
settings:
  oidc: {issuer: %q, audience: %s}
role_bindings:
  - {name: ops, subjects: ["group:ops"], role: admin}
servers:
  - {name: demo, transport: stdio, command: '%s'}
rules:
  - {name: eng, subjects: ["group:eng"], allow: ["demo__echo"]}
`, p.URL(), oidctest.Audience, serverPath)
	addr, _, _ := startServe(t, doc)
	c := mcpClient(ctx, t, addr, p.Token(p.Claims()))
	waitFor(t, "demo__echo listed", func() bool { return slices.Contains(names(t, c), "demo__echo") })
	echo(ctx, t, c)
	code, me, _ := call(t, http.MethodGet, "http://"+addr+"/admin/v1/me", p.Token(p.Claims()), nil)
	if code != http.StatusOK || me["subject"] != "alice@example.com" || me["role"] != "admin" {
		t.Fatalf("me: %d %v", code, me)
	}
	expired := p.Claims()
	expired["exp"] = 1
	code, _, h := call(t, http.MethodPost, "http://"+addr+"/mcp", p.Token(expired), map[string]any{})
	want := `Bearer resource_metadata="http://` + addr + `/.well-known/oauth-protected-resource"`
	if code != http.StatusUnauthorized || h.Get("WWW-Authenticate") != want {
		t.Fatalf("expired token: %d %q", code, h.Get("WWW-Authenticate"))
	}
	code, meta, _ := call(t, http.MethodGet, "http://"+addr+"/.well-known/oauth-protected-resource", "", nil)
	if code != http.StatusOK || meta["authorization_servers"].([]any)[0] != p.URL() {
		t.Fatalf("metadata: %d %v", code, meta)
	}
}

func TestKeysNew(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"keys", "new", "--name", "ci-bot", "--group", "eng", "--group", "ops"}, nil, &stdout, &stderr, config.Env{}); code != 0 {
		t.Fatalf("code %d: %s", code, stderr.String())
	}
	key := keyPattern.FindString(stdout.String())
	_, entry, ok := strings.Cut(stdout.String(), "config file:\n\n")
	if key == "" || !ok {
		t.Fatalf("output %q", stdout.String())
	}
	cfg, err := config.Parse([]byte("api_keys:\n"+entry), config.Env{})
	if err != nil {
		t.Fatalf("the entry does not load: %v\n%s", err, entry)
	}
	k := cfg.APIKeys[0]
	if k.Name != "ci-bot" || k.SHA256 != apikey.Hash(key) || !slices.Equal(k.Groups, []string{"eng", "ops"}) {
		t.Fatalf("entry %+v", k)
	}
	for _, args := range [][]string{{"keys"}, {"keys", "old"}, {"keys", "new"}} {
		if code := run(context.Background(), args, nil, &stdout, &stderr, config.Env{}); code != 2 {
			t.Errorf("%v: code %d", args, code)
		}
	}
}

func TestBootstrapKeyCommand(t *testing.T) {
	path := writeTestConfig(t)
	var keys []string
	for range 2 {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), []string{"bootstrap-key", "--config", path}, nil, &stdout, &stderr, config.Env{}); code != 0 {
			t.Fatalf("code %d: %s", code, stderr.String())
		}
		keys = append(keys, strings.TrimSpace(stdout.String()))
	}
	if !keyPattern.MatchString(keys[0]) || keys[0] == keys[1] {
		t.Fatalf("keys %v", keys)
	}
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"bootstrap-key", "--config", filepath.Join(t.TempDir(), "missing.yaml")}, nil, io.Discard, &stderr, config.Env{}); code != 1 {
		t.Fatalf("missing config: code %d", code)
	}
}
