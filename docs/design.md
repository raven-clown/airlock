# airlock design

Status: draft for review
Date: 2026-11-04

airlock is an MCP gateway. Clients connect to one MCP endpoint. Behind it sit many MCP servers, reached over stdio or Streamable HTTP. airlock adds login (OIDC and API keys), per-user and per-group tool permissions, an audit log, rate limits, and tool lists filtered to what each caller may use.

It follows the shared contract in `mothership/CONTRACT.md`. Where this document and the contract disagree, the contract wins and this document gets fixed.

## Goals

- One binary, one YAML file, running in under five minutes with no database and no Docker.
- Works with any OIDC provider (IdpForge, Keycloak, Entra ID, Auth0, Dex) through plain discovery and JWKS. No provider-specific code.
- A permission model you can explain in one sentence, and a CLI that tells you why a call was allowed or denied.
- Clear plugin points so outside contributors can add auth providers, policy engines, backends, audit sinks and rate limiters without touching the core.
- Small enough to ship as v0.1.0 and demo in a short screen recording.

## Non-goals for v1

- A web UI. The CLI covers inspection. A UI is a good first contribution later.
- A database or admin API. Config is a file, reloaded when it changes.
- Running MCP servers in containers. airlock starts stdio commands as given, and connects to HTTP servers by URL.
- Prompts and resources. v1 aggregates tools only.
- Forwarding sampling, elicitation and roots requests from backends back to clients.
- A2A, ACP, AG-UI or LLM traffic. That is `rosetta` and `transponder`.

## How airlock compares

The three closest projects, as described in their READMEs. This is a summary of what they say, not a benchmark.

| | docker/mcp-gateway | MCPJungle | agentgateway | airlock |
|---|---|---|---|---|
| Language | Go | Go | Rust | Go |
| Runs servers | in Docker containers | registered by URL or command | stdio, HTTP, SSE | stdio and Streamable HTTP |
| Client identity | shared local gateway, no per-user model | client tokens, "simple access control" | JWT, API keys, OAuth | OIDC users and groups, API keys |
| Permissions | per-profile tool allowlist | tool groups per client | CEL policy engine | allow and deny rules on users, groups, keys |
| Explain a decision | no | no | no | `airlock check` |
| Audit log | logging and call tracing | observability hooks | OpenTelemetry | structured audit events, pluggable sinks |
| Rate limits | not mentioned | not mentioned | yes | per user, group or key, per tool |
| State | Docker Desktop config | database | YAML, Kubernetes controller | one YAML file |

Where airlock is better:

- Against docker/mcp-gateway: it is built for a team, not one desktop. Each person logs in through the company's OIDC provider and sees only their tools. It does not need Docker.
- Against MCPJungle: permissions come from the identity provider's groups instead of per-client tokens, deny rules exist, every call is audited, and rate limits are built in. Everything lives in a file you can review in a pull request, with no database to run.
- Against agentgateway: it does one job. A Go developer can read the whole codebase in an afternoon, and the config for a typical setup fits on one screen. agentgateway covers far more ground (A2A, LLM routing, Kubernetes) with Rust and CEL, which is more to learn. In the mothership set, `rosetta` and `transponder` cover that ground instead.
- Against all three: `airlock check` answers "can alice call `github__delete_repo`, and which rule decided it" without making the call. Permission bugs in a gateway are security bugs, and being able to test them from the shell matters.

## SDK choice: mark3labs/mcp-go

airlock builds on `github.com/mark3labs/mcp-go` (v1.x), not the official `github.com/modelcontextprotocol/go-sdk`.

Reasons:

- `server.WithToolFilter` is applied on both `tools/list` and `tools/call`, so a hidden tool cannot be called. That is exactly airlock's access boundary, and it already exists and is tested upstream.
- `server.WithToolHandlerMiddleware` gives an ordered chain around every call, which is where rate limits, audit and metrics go.
- `server.WithHTTPContextFunc` puts the caller's identity into the request context once per HTTP request.
- `server.NewProtectedResourceMetadataHandler` serves the RFC 9728 document that MCP clients use to find the OIDC issuer and start login.
- The client side has stdio and Streamable HTTP transports, and `transport.WithHTTPHeaderFunc` sets headers per request from the context, which covers token forwarding and `traceparent`.
- The maintainer of airlock knows mcp-go internals well, so gaps found while building airlock can be fixed upstream instead of worked around.

The go-sdk is a fine choice too. It is official, follows the spec closely, and has `auth.RequireBearerToken`. With it, airlock would need its own middleware on `tools/list` and `tools/call` to filter and enforce, which is the part most likely to have security bugs. mcp-go types appear only in the gateway and backend packages. Policy, audit, auth and rate limit plugins use airlock's own small types, so a later SDK switch would not break those plugins.

## Approaches considered

1. **One aggregating server with per-caller filtering (chosen).** airlock runs a single mcp-go server whose tool set is the union of all backend tools, renamed with prefixes. A tool filter hides what the caller may not use, and middleware enforces limits and writes audit events. Simple, cheap per session, and reload only touches one tool set.
2. **One virtual server per downstream session.** Build a new mcp-go server for each session holding only that caller's tools. Easy to reason about, but every reload has to rebuild every live session, and memory grows with sessions.
3. **Raw JSON-RPC proxy.** Forward messages and rewrite names in flight. Passes every protocol feature through, including sampling, but airlock would reimplement session handling and break every time the spec changes.

Approach 1 gives the smallest, safest v1. If sampling passthrough becomes important, approach 3's ideas can be added for those methods only.

## Architecture

```
 MCP client (editor, agent, rosetta)
      | Streamable HTTP /mcp          or  stdio (airlock serve --stdio)
      v
 +--------------------------------------------------------------+
 | listener: Origin check, X-Request-ID, traceparent             |
 | authn: Authenticator chain (oidc, apikey)  -> Identity        |
 | mcp-go server                                                 |
 |   ToolFilter: policy.Decide for each tool  (list and call)    |
 |   middleware: ratelimit -> audit -> metrics/trace -> router   |
 | catalog: prefixed tools from every backend                    |
 +--------------------------------------------------------------+
      |                    |                         |
  backend "github"    backend "files"          backend "logbook"
  stdio process        stdio process            Streamable HTTP, forwards token
```

### Request flow for `tools/call`

1. The listener checks `Origin` against `allowed_origins`, keeps or generates `X-Request-ID`, and extracts `traceparent`.
2. The authenticator chain reads `Authorization: Bearer <token>`. Each authenticator says "mine, valid", "mine, invalid" or "not mine". The first "mine" wins. No match means 401 with a `WWW-Authenticate` header pointing at the protected resource metadata.
3. The identity goes into the context. A request on an existing MCP session must carry the same subject that opened the session, or it gets 403. This stops a stolen session ID from being used with a different login.
4. mcp-go runs the tool filter. Policy denies mean the tool does not exist for this caller.
5. Middleware runs in order: rate limit, audit (records the start), metrics and tracing, then the router.
6. The router splits `github__create_issue` at the first `__`, finds backend `github`, and calls `create_issue` with the original arguments.
7. The result goes back unchanged. The audit event is finished with outcome and duration.

### Tool names

- Exposed name: `<server>__<tool>`, as in the contract.
- Server names match `^[a-z0-9][a-z0-9-]{0,31}$`. No underscores, so the first `__` always splits cleanly.
- MCP limits tool names to 128 characters from `A-Z a-z 0-9 _ - .`. An upstream tool whose prefixed name breaks this is skipped with a warning log and a metric.
- Descriptions, input schemas, output schemas and annotations pass through unchanged.

## Components

Public packages are the plugin surface. Everything else is under `internal/`.

| Package | Job |
|---|---|
| `cmd/airlock` | CLI: `serve`, `validate`, `check`, `tools`, `keys new`, `version` |
| `internal/config` | Load YAML, expand `${VAR}`, apply env overrides, validate, watch for changes |
| `internal/gateway` | mcp-go server, catalog, router, session-to-identity binding |
| `internal/httpx` | Listener, Origin check, request ID, health, readiness, metrics routes |
| `auth` | `Authenticator` interface, `Identity` type, registry; built-ins in `auth/oidc`, `auth/apikey` |
| `policy` | `Policy` interface, registry; built-in `policy/rules` |
| `backend` | `Backend` interface, registry; built-ins in `backend/stdio`, `backend/streamable` |
| `audit` | `Event` type, `Sink` interface, registry; built-ins `stdout`, `file` |
| `ratelimit` | `Limiter` interface, registry; built-in in-memory token bucket |
| `telemetry` | Prometheus metrics, OTLP tracing setup |

### Plugin interfaces

Plugins are compiled in, the same way Caddy and CoreDNS do it. A contributor writes a package that calls `Register` in `init`, and a custom build imports it. No dynamic loading.

```go
package auth

type Identity struct {
    Subject string
    Groups  []string
    Method  string
    Token   string
    Claims  map[string]any
}

type Authenticator interface {
    Authenticate(ctx context.Context, r *http.Request) (*Identity, error)
}

var ErrNotMine = errors.New("auth: credential not handled")

func Register(kind string, f func(cfg yaml.Node) (Authenticator, error))
```

```go
package policy

type Request struct {
    Identity *auth.Identity
    Server   string
    Tool     string
    Args     map[string]any
}

type Decision struct {
    Allow  bool
    Rule   string
    Reason string
}

type Policy interface {
    Decide(ctx context.Context, req Request) Decision
}
```

`Args` is nil when filtering `tools/list` and set on `tools/call`, so a policy plugin such as CEL can check arguments at call time.

```go
package backend

type Backend interface {
    Name() string
    Start(ctx context.Context) error
    Tools() []mcp.Tool
    Call(ctx context.Context, id *auth.Identity, req mcp.CallToolRequest) (*mcp.CallToolResult, error)
    Status() Status
    Close() error
    OnToolsChanged(func())
}
```

```go
package audit

type Sink interface {
    Write(ctx context.Context, e Event) error
    Close() error
}
```

```go
package ratelimit

type Limiter interface {
    Allow(ctx context.Context, key string) (ok bool, retryAfter time.Duration)
}
```

## Authentication

### OIDC (`auth/oidc`)

- Discovery from `issuer`, JWKS fetched and cached, keys refreshed when an unknown `kid` shows up.
- Checks signature, `iss`, `exp`, `nbf`, and `aud` against `audience`.
- `subject_claim` defaults to `sub`. Setting it to `email` or `preferred_username` makes policies easier to read.
- `groups_claim` defaults to `groups` and accepts a dotted path such as `realm_access.roles`. A string value becomes a one-item list.
- airlock serves `/.well-known/oauth-protected-resource` naming the issuer, so MCP clients that support MCP authorization can log in through IdpForge or any other provider on their own. airlock does not run an authorization server.
- Uses `github.com/coreos/go-oidc/v3` for discovery and verification.

### API keys (`auth/apikey`)

- Keys look like `alk_` followed by 32 random bytes in base64url. `airlock keys new --name ci-bot` prints a new key once, plus the config line to paste.
- Config stores only the SHA-256 hash. The keys are random and long, so a slow hash adds nothing.
- Each key has a `name` (becomes the subject `key:<name>`) and optional `groups`.
- A bearer token that starts with `alk_` is handled by the API key authenticator. Anything else goes to OIDC.

### stdio mode

`airlock serve --stdio` serves one local client over stdin and stdout. There is no HTTP request to read a token from, so the identity comes from `stdio.identity` in config (default subject `local`). Policies still apply, which makes stdio mode handy for trying out a policy.

## Authorization

The built-in `rules` policy:

```yaml
policy:
  kind: rules
  rules:
    - name: eng-github
      subjects: ["group:eng"]
      allow: ["github__*", "files__*"]
      deny: ["github__delete_*"]
    - name: interns-read
      subjects: ["group:interns"]
      allow: ["files__read_*", "files__list_*"]
    - name: ci-bot
      subjects: ["key:ci-bot"]
      allow: ["github__create_issue"]
    - name: everyone-memory
      subjects: ["*"]
      allow: ["logbook__*"]
```

- Subjects: `user:<subject>`, `group:<name>`, `key:<name>`, or `*` for any logged-in caller.
- Tool patterns are globs on the prefixed name (`*` matches any run of characters).
- Evaluation: take every rule whose subjects match the caller. If any of them denies the tool, it is denied. Otherwise, if any allows it, it is allowed. Otherwise it is denied. Order does not matter, deny always wins, and the default is deny.
- The decision records the rule that decided it, or `default-deny`. Audit events and `airlock check` show it.

```
$ airlock check --config airlock.yaml --user alice --group eng github__delete_repo
DENY  github__delete_repo  rule=eng-github  reason="denied by pattern github__delete_*"
```

## Backends

### stdio (`backend/stdio`)

- `command`, `args`, `env` (with `${VAR}` expansion) and `dir` from config. One process per backend, shared by every caller.
- stderr goes to the airlock log, tagged with the backend name.
- If the process exits, it restarts with exponential backoff (1s up to 60s).
- The caller's identity is not passed to the process. Per-user processes are an open choice below.

### Streamable HTTP (`backend/streamable`)

- `url`, plus `auth.mode`:
  - `forward`: sends the caller's own bearer token, as the contract requires. Upstream sessions are pooled per (subject, token hash), so a backend never sees two users on one session. Idle sessions close after `session_idle_timeout` (default 10m), and the pool has a `max_sessions` cap (default 256) with least-recently-used eviction.
  - `static`: sends fixed `headers` from config. One shared session.
  - `none`: no credentials. One shared session.
- `discovery_headers` are used for the session that lists tools at startup and on `list_changed`, since there is no caller at that point. For `logbook`, this is an API key that airlock holds.
- `traceparent`, `tracestate` and `X-Request-ID` are forwarded on every call.

### Shared backend behavior

- Each backend lists its tools at start, and again on `notifications/tools/list_changed`. The catalog updates and mcp-go tells connected clients.
- When a backend goes down, its tools stay listed with the last known definitions. Calls fail fast with a tool error saying the server is unavailable. This avoids tools flickering in and out of the client during short outages.
- `call_timeout` per backend, default 60s. Client cancellation cancels the backend call through the context.

## Rate limits

```yaml
rate_limits:
  - name: interns
    subjects: ["group:interns"]
    tools: ["*"]
    rate: 30/m
    burst: 10
  - name: github-writes
    subjects: ["*"]
    tools: ["github__create_*"]
    rate: 60/h
```

- Each rule keeps a token bucket per caller subject. A call has to pass every rule that matches it.
- Rates are written `N/s`, `N/m` or `N/h`. `burst` defaults to N.
- An over-limit call returns a tool result with `isError: true` and text such as `rate limit "interns" exceeded, retry in 12s`, so the model can see what happened. The audit outcome is `rate_limited`.
- The built-in limiter is in memory, so limits are per airlock instance. A Redis limiter is a natural plugin.

## Audit log

Every `tools/call` writes one event, including denied and rate-limited ones. Tool list requests do not, to keep volume down.

```json
{"time":"2026-11-04T10:15:02.114Z","request_id":"8f2c...","trace_id":"4bf9...","session_id":"a1b2...","subject":"alice@example.com","groups":["eng"],"auth":"oidc","server":"github","tool":"create_issue","decision":"allow","rule":"eng-github","outcome":"ok","duration_ms":412}
```

- `outcome` is one of `ok`, `tool_error`, `denied`, `rate_limited`, `backend_unavailable`, `timeout`, `canceled`.
- Arguments are left out by default. `audit.include_args: true` adds them, and keys listed in `audit.redact` (default `password`, `token`, `secret`, `api_key`, `authorization`) are replaced with `"[redacted]"` at any depth.
- Tokens are never written to audit events or logs.
- Sinks: `stdout` writes JSON lines tagged `"log":"audit"` so they can be split from normal logs, and `file` appends JSON lines to a path. Several sinks can be active at once.
- Events go through a buffered channel (default 1024). If a sink falls behind, events are dropped and `airlock_audit_dropped_total` goes up. A gateway that blocks tool calls because a log disk is slow does more harm than one that counts its drops. `audit.on_overflow: block` is available for setups that must not lose events.

## Config

```yaml
listen_addr: 127.0.0.1:8080
allowed_origins: ["http://localhost:*"]

auth:
  oidc:
    issuer: https://idp.example.com
    audience: airlock
    subject_claim: email
    groups_claim: groups
  api_keys:
    - name: ci-bot
      sha256: 3b5d...e1
      groups: [ci]

backends:
  - name: github
    transport: stdio
    command: github-mcp-server
    args: [stdio]
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: ${GITHUB_TOKEN}
  - name: files
    transport: stdio
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem", "/srv/shared"]
  - name: logbook
    transport: streamable_http
    url: http://logbook:8090/mcp
    auth:
      mode: forward
      discovery_headers:
        Authorization: Bearer ${LOGBOOK_DISCOVERY_KEY}

policy:
  kind: rules
  rules:
    - name: eng
      subjects: ["group:eng"]
      allow: ["*"]
      deny: ["github__delete_*"]

rate_limits:
  - name: default
    subjects: ["*"]
    tools: ["*"]
    rate: 120/m

audit:
  sinks:
    - kind: file
      path: /var/log/airlock/audit.jsonl
  include_args: false

telemetry:
  otlp_endpoint: ""
```

- `--config` is required for `serve`.
- `${VAR}` in any string value is replaced from the environment at load time. This is how secrets get in.
- Any scalar key can be overridden by an environment variable: `AIRLOCK_` plus the key path in upper case, with `__` between levels. `AIRLOCK_LISTEN_ADDR` sets `listen_addr` and `AIRLOCK_AUTH__OIDC__ISSUER` sets `auth.oidc.issuer`. Lists cannot be overridden this way.
- Unknown keys are an error, so typos fail loudly.
- Reload: airlock checks the file's modification time every 2 seconds (this works the same on Windows, Linux and macOS) and also reloads on SIGHUP where that exists. A new config is fully validated before it replaces the old one. If it is invalid, the old one stays, the error is logged, and `airlock_config_reload_errors_total` goes up. Policies, keys, rate limits and audit settings swap at once. Added backends start, removed ones stop, and changed ones restart.

## Operations

- `/mcp`: the MCP endpoint (Streamable HTTP, stateful sessions).
- `/healthz`: 200 when the process is up.
- `/readyz`: 200 when config is loaded and every backend marked `required: true` is connected. The body is JSON with each backend's status. `required` defaults to false, so one broken optional backend does not take the gateway out of a load balancer.
- `/metrics`: Prometheus. Main series: `airlock_tool_calls_total{server,tool,outcome}`, `airlock_tool_call_duration_seconds{server}`, `airlock_backend_up{server}`, `airlock_auth_failures_total{method,reason}`, `airlock_audit_dropped_total`, `airlock_config_reload_errors_total`.
- Traces over OTLP when `telemetry.otlp_endpoint` is set: one span per `tools/call` with a child span for the backend call.
- Logs: JSON on stdout through `log/slog`.
- Default `listen_addr` is `127.0.0.1:8080`. The Docker image sets `0.0.0.0:8080`.

## CLI

| Command | What it does |
|---|---|
| `airlock serve --config f` | Run the gateway over HTTP |
| `airlock serve --config f --stdio` | Serve one local client over stdio |
| `airlock validate --config f` | Check config and exit non-zero on errors |
| `airlock check --config f --user u [--group g] [--key k] TOOL...` | Print the decision and deciding rule for each tool, without calling anything |
| `airlock tools --config f [--user u] [--group g]` | Connect to the backends and print the tool list a caller would see |
| `airlock keys new --name n [--group g]` | Print a new API key and its config entry |
| `airlock version` | Print version and build info |

## Errors

- Auth failure: HTTP 401 with `WWW-Authenticate: Bearer resource_metadata="..."`. A valid token on another user's session: 403.
- Unknown or hidden tool: the MCP "tool not found" error, the same for both. A caller cannot tell a denied tool from one that does not exist.
- Rate limited, backend unavailable, timeout: a tool result with `isError: true` and a short message. The model can read it and the client does not treat it as a protocol failure.
- Backend tool errors pass through unchanged.
- A panic in a handler or plugin is recovered, logged with the request ID, and returned as an internal error. It does not take down the process.

## Testing

- Test-driven, unit tests next to each package. No `-race` in local runs on Windows (no gcc). CI runs `-race` on Linux.
- Policy and rate limit logic: table tests, including deny-wins, default-deny, and glob edge cases.
- OIDC: an in-test issuer on `httptest` serving discovery and JWKS, signing tokens with a generated RSA key. Covers expired, wrong audience, wrong issuer, unknown `kid` and rotated keys.
- Backends: Streamable HTTP tests use in-process mcp-go servers on `httptest`. stdio tests build a tiny test MCP server from `internal/testserver` in `TestMain` and run it as a real process, so they work on Windows too.
- Gateway end to end: start airlock from a test config, connect with the mcp-go client as alice, bob and ci-bot, then check visible tools, denied calls, rate limits, audit lines, `list_changed` propagation, and session hijack rejection.
- `airlock check` and `airlock validate` get golden-output tests.

## Demo

`examples/quickstart` holds a config and a small Go demo MCP server (`examples/demo-server` with `echo`, `time` and `notes_*` tools), so the demo needs only Go, with no Node or Docker. The recording shows:

1. `airlock serve` with two backends.
2. alice in group `eng` lists tools and sees both servers. bob in `interns` sees only the read tools.
3. bob calls a write tool and gets "tool not found". bob hits the rate limit.
4. `airlock check` explains both results.
5. The audit file shows every call, including the denied one.

## Contributor entry points

Good first pieces, each behind an existing interface: CEL or OPA policy, Redis rate limiter, webhook / Kafka / OpenSearch audit sinks, legacy SSE backend, a backend that runs servers in Docker, OAuth 2.0 token exchange (RFC 8693) for HTTP backends, a read-only web UI, Helm chart, and a config store backed by a database.

## Decisions made

1. Config is YAML only, with hot reload. No database, no admin API.
2. No web UI in v1. The CLI (`check`, `tools`, `validate`, `keys new`) covers inspection.
3. Built on mark3labs/mcp-go v1.x.
4. One aggregating server with a per-caller tool filter (approach 1).
5. Tools only in v1. No prompts, resources, sampling, elicitation or roots passthrough.
6. Deny wins, default is deny, rule order does not matter.
7. Hidden and missing tools look the same to the caller.
8. API keys use the `alk_` prefix and are stored as SHA-256 hashes.
9. HTTP backends in `forward` mode get one upstream session per caller and token.
10. stdio backends run one shared process per backend.
11. Down backends keep their last known tools listed and fail calls fast.
12. Rate limit and availability errors are tool results with `isError`, not JSON-RPC errors.
13. Audit drops events instead of blocking calls, unless `on_overflow: block` is set.
14. Environment override nesting uses `__`, as in `AIRLOCK_AUTH__OIDC__ISSUER`.
15. Plugins are compiled in through `Register` functions in public packages.
16. Module `github.com/raven-clown/airlock`, Apache-2.0, `go 1.26` in go.mod, first release v0.1.0.

## Open choices

1. **Token forwarding and the MCP spec.** The contract says a component forwards the caller's token unchanged. The MCP authorization spec warns against token passthrough, because a token meant for airlock then works at the backend too. For the mothership set this is fine if `logbook` accepts the same audience as airlock. For third-party HTTP backends, `forward` should not be the default. A later `exchange` mode (RFC 8693) would fix this properly. This may need a line in the contract.
2. **Env override nesting.** The contract shows `AIRLOCK_LISTEN_ADDR` but does not say how nested keys work. This spec uses `__`. The other three projects should agree on the same rule, so it may belong in the contract.
3. **Per-user stdio processes.** Some stdio servers act as one account. A `per_user: true` option could start one process per caller with that caller's identity in its env. It costs a process per user, so it is left out of v1.
4. **Prompts and resources.** Prompts can use the same prefix scheme. Resources need URI rewriting and are harder. Planned for v0.2.
5. **Sampling and elicitation passthrough.** Needs routing a backend's request back to the right client session. Worth doing once a real backend needs it.
6. **Rate limit errors.** Tool results with `isError` are friendlier to models. Some clients may prefer a JSON-RPC error they can retry on. Easy to change before v1.0.
7. **Should `tools/list` be audited?** Off for now to keep volume down. Could be a config flag.
