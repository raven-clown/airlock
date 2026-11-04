# airlock design

Status: draft for review
Date: 2026-11-04

airlock is an MCP gateway. Clients connect to one MCP endpoint. Behind it sit many MCP servers, reached over stdio or Streamable HTTP. airlock adds login (OIDC and API keys), per-user and per-group tool permissions, an audit log, rate limits, and tool lists filtered to what each caller may use.

It follows the shared contract in `mothership/CONTRACT.md`. Where this document and the contract disagree, the contract wins and this document gets fixed.

## Goals

- One binary that runs with no setup: embedded SQLite by default, Postgres for teams and replicas. No Docker needed.
- Everything a future web console needs is in a JSON admin API under `/admin/v1/`. A new user can go from a fresh start to a working gateway without editing YAML, and every common task (adding a server, giving someone access, reading the audit log) is one or two API calls.
- Teams that prefer GitOps can still declare servers, rules and keys in YAML, and airlock keeps the database in step with the file.
- Works with any OIDC provider (IdpForge, Keycloak, Entra ID, Auth0, Dex) through plain discovery and JWKS. No provider-specific code.
- A permission model you can explain in one sentence, and a way (CLI and API) to see why a call was allowed or denied.
- Clear plugin points so outside contributors can add auth providers, policy engines, backends, audit sinks and rate limiters without touching the core.
- Every feature ships in the Apache-2.0 build. There is no paid edition, and the README says so.
- Small enough to ship as v0.1.0 and demo in a short screen recording.

## Non-goals for v1

- A web UI. The contract plans a separate console. airlock ships the admin API and an OpenAPI file for it.
- Running MCP servers in containers. airlock starts stdio commands as given, and connects to HTTP servers by URL.
- Prompts and resources. v1 aggregates tools only.
- Forwarding sampling, elicitation and roots requests from backends back to clients.
- Multi-tenancy. v1 has one tenant per instance (see open choices).
- A2A, ACP, AG-UI or LLM traffic. That is `rosetta` and `transponder`.

## How airlock compares

The three closest projects, as described in their READMEs. This is a summary of what they say, not a benchmark.

| | docker/mcp-gateway | MCPJungle | agentgateway | airlock |
|---|---|---|---|---|
| Language | Go | Go | Rust | Go |
| Runs servers | in Docker containers | registered by URL or command | stdio, HTTP, SSE | stdio and Streamable HTTP |
| Client identity | shared local gateway, no per-user model | client tokens, "simple access control" | JWT, API keys, OAuth | OIDC users and groups, API keys |
| Permissions | per-profile tool allowlist | tool groups per client | CEL policy engine | allow and deny rules on users, groups, keys |
| Explain a decision | no | no | no | `airlock check` and `POST /admin/v1/check` |
| Audit log | logging and call tracing | observability hooks | OpenTelemetry | audit records in SQL, queryable over the API |
| Rate limits | not mentioned | not mentioned | yes | per user, group or key, per tool |
| State | Docker Desktop config | database | YAML, Kubernetes controller | embedded SQLite or Postgres, plus optional YAML |

Where airlock is better:

- Against docker/mcp-gateway: it is built for a team, not one desktop. Each person logs in through the company's OIDC provider and sees only their tools. It does not need Docker.
- Against MCPJungle: permissions come from the identity provider's groups instead of per-client tokens, deny rules exist, every call is audited and queryable, and rate limits are built in. SQLite is embedded, so there is still nothing extra to run, and YAML provisioning lets a team review changes in a pull request.
- Against agentgateway: it does one job. A Go developer can read the whole codebase in an afternoon, and a typical setup is a handful of API calls or one short file. agentgateway covers far more ground (A2A, LLM routing, Kubernetes) with Rust and CEL, which is more to learn. In the mothership set, `rosetta` and `transponder` cover that ground instead.
- Against all three: airlock answers "can alice call `github__delete_repo`, and which rule decided it" without making the call. Permission bugs in a gateway are security bugs, and being able to test them matters.

### What the others charge for

airlock has no paid edition and no license key. SSO, roles and permissions, audit logs, multi-tenancy, clustering and the admin API are all in the Apache-2.0 build, and the README says so. Here is what the other projects keep for a paid product, limited to what their own pages say (checked 2026-11-04):

- **Docker.** The open-source MCP Gateway has no per-user model. Docker sells a separate MCP Enterprise Gateway, through "Contact sales" with no public price, whose product page lists sign-in through your identity provider with policy following your groups, per-tool allow and deny rules, and "a structured event per evaluation" streamed to a SIEM. That is close to airlock's core feature set. ([product page](https://www.docker.com/products/mcp-enterprise-gateway/))
- **agentgateway.** The open-source project has JWT auth, CEL-based RBAC and rate limiting. Solo.io sells Solo Enterprise for agentgateway under a separate license, which its launch post says adds automatic token exchange, "cryptographically verifiable" audit trails, tool server fingerprinting and versioning, secure elicitation, a hardened distribution and 24x7 support. ([launch post](https://solo.io/blog/introducing-solo-enterprise-for-agentgateway), [docs](https://docs.solo.io/gateway/2.0.x/ai/about/)) Solo's related agentregistry product lists SSO, RBAC, audit logging and rate limiting as enterprise-only in its own comparison. ([agentregistry comparison](https://docs.solo.io/agentregistry/latest/about/oss-enterprise/))
- **MCPJungle.** Its README describes a self-hosted gateway and mentions no paid edition, hosted offering or pricing. Nothing to compare on price, so the comparison above is on features only. ([README](https://github.com/mcpjungle/MCPJungle))

Token exchange and SIEM-grade audit, which both vendors sell, are on airlock's roadmap as free features (see contributor entry points and open choices).

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

### Gateway shape

1. **One aggregating server with per-caller filtering (chosen).** airlock runs a single mcp-go server whose tool set is the union of all backend tools, renamed with prefixes. A tool filter hides what the caller may not use, and middleware enforces limits and writes audit events. Simple, cheap per session, and a config change only touches one tool set.
2. **One virtual server per downstream session.** Build a new mcp-go server for each session holding only that caller's tools. Easy to reason about, but every change has to rebuild every live session, and memory grows with sessions.
3. **Raw JSON-RPC proxy.** Forward messages and rewrite names in flight. Passes every protocol feature through, including sampling, but airlock would reimplement session handling and break every time the spec changes.

### Where state lives

1. **The database is the source of truth, YAML provisions into it (chosen).** Servers, rules, keys, rate limits and settings live in SQL and are managed through the admin API. Anything declared in the YAML file is written into the database at startup and on change, marked as owned by the file, and is read-only through the API. This is how Grafana provisioning works. The console gets full control, and GitOps users keep their file.
2. **YAML is the source of truth, SQL only holds audit records.** Simple, but the console could not add a server or grant access, which the contract requires.
3. **Database only.** Clean, but teams lose the ability to review permission changes in a pull request.

## Architecture

```
 MCP client (editor, agent, rosetta)        console / scripts
      | Streamable HTTP /mcp  or stdio            | JSON /admin/v1/
      v                                           v
 +--------------------------------------------------------------+
 | listener: Origin check, X-Request-ID, traceparent             |
 | authn: Authenticator chain (oidc, apikey)  -> Identity        |
 +-------------------------------+------------------------------+
 | mcp-go server                 | admin API (role check)       |
 |   ToolFilter: policy.Decide   |   servers, rules, keys,      |
 |   middleware: ratelimit ->    |   rate limits, settings,     |
 |     audit -> metrics -> router|   audit, usage, check        |
 +-------------------------------+------------------------------+
 | runtime snapshot (immutable, swapped on every revision)       |
 +--------------------------------------------------------------+
 | store: SQLite or Postgres  <-  provisioner (YAML file)        |
 +--------------------------------------------------------------+
      |                    |                         |
  backend "github"    backend "files"          backend "logbook"
  stdio process        stdio process            Streamable HTTP, forwards token
```

### The runtime snapshot

Every request reads from one immutable snapshot: the compiled policy, rate limit rules, API key hashes, settings and backend set. Any write to the store bumps a `revision` counter in the same transaction. Each airlock instance checks the revision every 2 seconds and, when it moves, loads a new snapshot and swaps it in atomically. Backends that were added start, removed ones stop, changed ones restart. This keeps the hot path free of database reads and lets several replicas share one Postgres.

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
| `cmd/airlock` | CLI: `serve`, `validate`, `migrate`, `check`, `tools`, `keys new`, `bootstrap-key`, `version` |
| `internal/config` | Load YAML, expand `${VAR}`, apply env overrides, validate, watch for changes |
| `internal/store` | `Store` interface, SQLite and Postgres implementations, migrations |
| `internal/provision` | Sync file-declared resources into the store |
| `internal/runtime` | Build and swap the immutable snapshot when the revision changes |
| `internal/gateway` | mcp-go server, catalog, router, session-to-identity binding |
| `internal/admin` | Admin API handlers, generated from `api/openapi.yaml` |
| `internal/secrets` | Encrypt and decrypt secret fields at rest |
| `internal/httpx` | Listener, Origin check, request ID, health, readiness, metrics routes |
| `auth` | `Authenticator` interface, `Identity` type, registry; built-ins in `auth/oidc`, `auth/apikey` |
| `policy` | `Policy` interface, registry; built-in `policy/rules` |
| `backend` | `Backend` interface, registry; built-ins in `backend/stdio`, `backend/streamable` |
| `audit` | `Event` type, `Sink` interface, registry; built-ins `sql`, `stdout`, `file` |
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

func Register(kind string, f func(cfg json.RawMessage) (Authenticator, error))
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
    Write(ctx context.Context, events []Event) error
    Close() error
}
```

```go
package ratelimit

type Limiter interface {
    Allow(ctx context.Context, key string) (ok bool, retryAfter time.Duration)
}
```

Plugin config arrives as JSON, whether it came from YAML or from the API, so a plugin is configured the same way in both places.

## Storage

- Drivers: `modernc.org/sqlite` and `github.com/jackc/pgx/v5` through `database/sql`. Both are pure Go, so builds need no cgo.
- Config: `storage.driver` is `sqlite` (default) or `postgres`, and `storage.dsn` defaults to `file:airlock.db` in the working directory.
- Queries are hand-written SQL kept to what both engines support. Every store test runs against SQLite, and against Postgres too under the `integration` build tag.
- Migrations are numbered SQL files embedded in the binary, one folder per engine, applied at startup inside a transaction and tracked in `schema_migrations`. On Postgres, an advisory lock stops two replicas from migrating at once. `airlock migrate` runs them without starting the server. A binary refuses to start against a schema newer than it knows.
- SQLite runs in WAL mode with a busy timeout, and airlock keeps a single writer connection.

### Tables

| Table | Holds |
|---|---|
| `servers` | Backend definitions: name, transport, command/args/env or url/auth, timeouts, `required`, `enabled` |
| `rules` | Policy rules: name, subjects, allow, deny |
| `rate_limits` | Rate limit rules |
| `api_keys` | Name, SHA-256 hash, groups, created, expires, last used, revoked |
| `role_bindings` | Admin API roles: subject pattern and role |
| `settings` | Key-value settings: OIDC, allowed origins, audit options |
| `audit_events` | One row per tool call |
| `revision` | One row, bumped on every write |

Every managed row has `source` (`file` or `api`), `version` (for optimistic concurrency), `created_at` and `updated_at`.

### Secrets at rest

Server `env` values and HTTP `headers` often hold tokens. A secret field is stored either as a `${VAR}` reference, resolved from airlock's environment when the backend starts, or as a literal encrypted with AES-256-GCM. The key comes from `AIRLOCK_SECRET_KEY`. With SQLite and no key set, airlock creates `airlock.key` next to the database on first start, so the quickstart needs no setup. With Postgres, a key must be set before literals are accepted, since replicas must share it. The admin API never returns a secret value. It returns `{"set": true}` instead, and a write that omits the field keeps the old value.

### Provisioning from YAML

Resources declared in the config file (`servers`, `rules`, `rate_limits`, `api_keys`, `role_bindings`, `settings`) are written to the store at startup and whenever the file changes. They get `source: file`. Rows that disappear from the file are deleted, but only if they were `source: file`. The admin API refuses to change or delete them, with a 409 that says the resource is managed by the config file. Resources created through the API get `source: api` and the file never touches them. A name used by both sides is a validation error at load time.

## Authentication

### OIDC (`auth/oidc`)

- Discovery from `issuer`, JWKS fetched and cached, keys refreshed when an unknown `kid` shows up.
- Checks signature, `iss`, `exp`, `nbf`, and `aud` against `audience`.
- `subject_claim` defaults to `sub`. Setting it to `email` or `preferred_username` makes rules easier to read.
- `groups_claim` defaults to `groups` and accepts a dotted path such as `realm_access.roles`. A string value becomes a one-item list.
- airlock serves `/.well-known/oauth-protected-resource` naming the issuer, so MCP clients that support MCP authorization can log in through IdpForge or any other provider on their own. airlock does not run an authorization server.
- The OIDC settings live in the `settings` table, so they can be set from the console. They can also come from the file.
- Uses `github.com/coreos/go-oidc/v3` for discovery and verification.

### API keys (`auth/apikey`)

- Keys look like `alk_` followed by 32 random bytes in base64url.
- Only the SHA-256 hash is stored. The keys are random and long, so a slow hash adds nothing.
- Each key has a `name` (the subject becomes `key:<name>`), optional `groups` and an optional expiry. `last_used_at` is updated at most once a minute per key.
- Created through `POST /admin/v1/api-keys`, which returns the key once. For file-provisioned keys, `airlock keys new --name ci-bot` prints a key and the hash line to paste.
- A bearer token that starts with `alk_` is handled by the API key authenticator. Anything else goes to OIDC.

### First start

When the store has no role bindings at all, airlock creates an API key named `bootstrap` with the `admin` role and prints it once to stderr as plain text, outside the JSON log stream so it does not end up in log storage. The console uses it to set up OIDC and the first real admin binding, then the bootstrap key can be revoked. If it is lost before that, `airlock bootstrap-key` (run on the host, with direct access to the store) issues a new one. The file can instead declare `role_bindings`, which skips the bootstrap key.

### stdio mode

`airlock serve --stdio` serves one local client over stdin and stdout. There is no HTTP request to read a token from, so the identity comes from `stdio.identity` in config (default subject `local`). Policies still apply, which makes stdio mode handy for trying out a policy.

## Authorization

### Tool rules

The built-in `rules` policy, shown here as YAML. The same shape is used by the admin API.

```yaml
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
- The decision records the rule that decided it, or `default-deny`. Audit records and the check endpoint show it.

```
$ airlock check --user alice --group eng github__delete_repo
DENY  github__delete_repo  rule=eng-github  reason="denied by pattern github__delete_*"
```

### Admin roles

The admin API uses the same identities as `/mcp`. Access to it comes from `role_bindings`, which map a subject pattern (same syntax as rules) to a role:

- `viewer`: every `GET` endpoint, including audit and usage, plus `POST /check`.
- `admin`: everything.

A caller with no binding gets 403 on every admin route. MCP tool rules and admin roles are separate, so being allowed to call tools never grants admin access.

An admin can create stdio servers, which means running commands on the airlock host. The docs say this plainly: the `admin` role is as strong as a shell on that machine. `stdio.allowed_commands` (a list of globs, empty means any) narrows what can be started, and it can only be set in the file, never through the API.

## Admin API

JSON under `/admin/v1/`, described by `api/openapi.yaml` (OpenAPI 3.0.3). The file is the source of truth: request and response types and the server interface are generated from it with `oapi-codegen` in its `net/http` mode, the generated code is committed, and CI fails if regenerating changes anything. The OpenAPI file is also served at `/admin/v1/openapi.yaml` so a console can read it.

### Endpoints

| Method and path | Does |
|---|---|
| `GET /status` | Version, uptime, revision, storage driver, each backend's state and tool count |
| `GET /servers`, `POST /servers` | List and add backends |
| `GET /servers/{name}`, `PATCH /servers/{name}`, `DELETE /servers/{name}` | Read, change, remove a backend |
| `POST /servers/{name}/restart` | Restart a backend |
| `POST /servers/test` | Try a server definition without saving it: connect, list tools, report errors |
| `GET /tools` | The full catalog with prefixed names, filterable by `server` |
| `GET /rules`, `POST /rules`, `GET/PATCH/DELETE /rules/{name}` | Tool rules |
| `GET /rate-limits`, `POST /rate-limits`, `GET/PATCH/DELETE /rate-limits/{name}` | Rate limit rules |
| `GET /api-keys`, `POST /api-keys`, `GET/PATCH /api-keys/{name}`, `POST /api-keys/{name}/revoke` | API keys. The key value is only in the `POST` response |
| `GET /role-bindings`, `POST /role-bindings`, `DELETE /role-bindings/{id}` | Admin roles |
| `GET /settings`, `PATCH /settings` | OIDC, allowed origins, audit options |
| `POST /check` | Decisions for a subject, groups and a list of tools (or every tool), with the deciding rule |
| `GET /audit` | Audit records, newest first, filterable by `subject`, `server`, `tool`, `outcome`, `since`, `until` |
| `GET /usage` | Call counts, error counts and latency, grouped by `subject`, `server` or `tool` over a time range |
| `GET /sessions` | Live MCP sessions on this instance: subject, client name, started, last seen |
| `GET /export` | Every `source: api` resource as YAML, ready to move into the config file |

`POST /servers/test` and `POST /check` are there so a console can offer "test connection" and "who can see what" screens without guessing.

### Conventions

- Lists take `cursor` and `limit` (default 50, max 500) and return `{"items": [...], "next_cursor": "..."}`. `next_cursor` is empty on the last page. Cursors are opaque base64 of the sort key and id, so new rows never shift a page.
- Errors are `{"error": {"code": "not_found", "message": "...", "field": "..."}}`, with codes `invalid`, `not_found`, `conflict`, `managed_by_file`, `version_mismatch`, `forbidden`, `unauthorized`.
- Every resource has `version`. `PATCH` and `DELETE` accept `If-Match: <version>` and return 412 when it is stale, so two console tabs cannot silently overwrite each other.
- `PATCH` uses JSON merge patch (RFC 7396).
- Every write is validated with the same code the file loader uses, then committed with a revision bump. Running instances pick it up within 2 seconds.
- Admin writes are audited too, as events with `kind: admin`, the route, the resource name and the caller. Secret values are never included.

## Backends

### stdio (`backend/stdio`)

- `command`, `args`, `env` and `dir`. One process per backend, shared by every caller.
- stderr goes to the airlock log, tagged with the backend name. The last 100 lines are kept and shown in `GET /servers/{name}` so a console can show why a server fails to start.
- If the process exits, it restarts with exponential backoff (1s up to 60s).
- The caller's identity is not passed to the process. Per-user processes are an open choice below.

### Streamable HTTP (`backend/streamable`)

- `url`, plus `auth.mode`:
  - `forward`: sends the caller's own bearer token, as the contract requires. Upstream sessions are pooled per (subject, token hash), so a backend never sees two users on one session. Idle sessions close after `session_idle_timeout` (default 10m), and the pool has a `max_sessions` cap (default 256) with least-recently-used eviction.
  - `static`: sends fixed `headers`. One shared session.
  - `none`: no credentials. One shared session.
- `discovery_headers` are used for the session that lists tools at startup and on `list_changed`, since there is no caller at that point. For `logbook`, this is an API key that airlock holds.
- `traceparent`, `tracestate` and `X-Request-ID` are forwarded on every call.

### Shared backend behavior

- Each backend lists its tools at start, and again on `notifications/tools/list_changed`. The catalog updates and mcp-go tells connected clients.
- When a backend goes down, its tools stay listed with the last known definitions. Calls fail fast with a tool error saying the server is unavailable. This avoids tools flickering in and out of the client during short outages.
- `call_timeout` per backend, default 60s. Client cancellation cancels the backend call through the context.
- `enabled: false` keeps a server's definition but stops it and removes its tools.

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
- The built-in limiter is in memory, so with several replicas each one counts on its own. A Postgres or Redis limiter is a natural plugin.

## Audit log

Every `tools/call` writes one record, including denied and rate-limited ones, and so does every admin API write. Tool list requests are not recorded, to keep volume down.

```json
{"time":"2026-11-04T10:15:02.114Z","kind":"tool","request_id":"8f2c...","trace_id":"4bf9...","session_id":"a1b2...","instance":"airlock-7d9f","subject":"alice@example.com","groups":["eng"],"auth":"oidc","server":"github","tool":"create_issue","decision":"allow","rule":"eng-github","outcome":"ok","duration_ms":412}
```

- `outcome` is one of `ok`, `tool_error`, `denied`, `rate_limited`, `backend_unavailable`, `timeout`, `canceled`.
- Arguments are left out by default. The `audit.include_args` setting adds them, and keys in `audit.redact` (default `password`, `token`, `secret`, `api_key`, `authorization`) are replaced with `"[redacted]"` at any depth.
- Tokens are never written to audit records or logs.
- The `sql` sink is always on, because `GET /audit` and `GET /usage` read from it. It inserts in batches (up to 200 rows or every 500ms). `audit.retention` (default 30 days) controls how long rows are kept, and an hourly job deletes older ones.
- Extra sinks: `stdout` writes JSON lines tagged `"log":"audit"` so they can be split from normal logs, and `file` appends JSON lines to a path.
- Records go through a buffered channel (default 4096). If a sink falls behind, records are dropped and `airlock_audit_dropped_total` goes up. A gateway that blocks tool calls because a disk is slow does more harm than one that counts its drops. `audit.on_overflow: block` is there for setups that must not lose records.

## Config file

The file holds process settings, and optionally resources to provision. Everything below `servers` can be left out and managed through the admin API instead.

```yaml
listen_addr: 127.0.0.1:8080

storage:
  driver: sqlite
  dsn: file:/var/lib/airlock/airlock.db

stdio:
  identity: local
  allowed_commands: []

telemetry:
  otlp_endpoint: ""

settings:
  allowed_origins: ["http://localhost:*"]
  oidc:
    issuer: https://idp.example.com
    audience: airlock
    subject_claim: email
    groups_claim: groups

role_bindings:
  - subjects: ["group:airlock-admins"]
    role: admin

servers:
  - name: github
    transport: stdio
    command: github-mcp-server
    args: [stdio]
    env:
      GITHUB_PERSONAL_ACCESS_TOKEN: ${GITHUB_TOKEN}
  - name: logbook
    transport: streamable_http
    url: http://logbook:8090/mcp
    auth:
      mode: forward
      discovery_headers:
        Authorization: Bearer ${LOGBOOK_DISCOVERY_KEY}

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
```

- `--config` points at the file. Without it, airlock runs on defaults (SQLite in the working directory, bootstrap key on first start), which is the zero-setup quickstart.
- `${VAR}` in a string value is resolved from the environment. In process settings this happens at load time. In provisioned resources the reference itself is stored and resolved when the backend starts, so the secret never lands in the database.
- Any scalar key can be overridden by an environment variable: `AIRLOCK_` plus the key path in upper case, with `__` between levels. `AIRLOCK_LISTEN_ADDR` sets `listen_addr` and `AIRLOCK_STORAGE__DSN` sets `storage.dsn`. Lists cannot be overridden this way.
- Unknown keys are an error, so typos fail loudly.
- airlock checks the file's modification time every 2 seconds (this works the same on Windows, Linux and macOS) and also reloads on SIGHUP where that exists. A new file is fully validated before it is provisioned. If it is invalid, nothing changes, the error is logged, and `airlock_config_reload_errors_total` goes up. Process settings such as `listen_addr` and `storage` need a restart, and airlock logs a warning when they change.

## Running several replicas

With Postgres, any number of airlock instances can share one database. Config changes reach every instance through the revision check. Audit records carry the `instance` name. Two limits apply in v1: MCP sessions live in the memory of the instance that opened them, so the load balancer needs sticky sessions on the `Mcp-Session-Id` header, and rate limits are counted per instance. `GET /sessions` shows only the instance that answers.

## Operations

- `/mcp`: the MCP endpoint (Streamable HTTP, stateful sessions).
- `/admin/v1/`: the admin API.
- `/healthz`: 200 when the process is up.
- `/readyz`: 200 when the store is reachable, migrations are current, and every backend marked `required: true` is connected. The body is JSON with each check's status. `required` defaults to false, so one broken optional backend does not take the gateway out of a load balancer.
- `/metrics`: Prometheus. Main series: `airlock_tool_calls_total{server,tool,outcome}`, `airlock_tool_call_duration_seconds{server}`, `airlock_backend_up{server}`, `airlock_auth_failures_total{method,reason}`, `airlock_admin_requests_total{route,code}`, `airlock_audit_dropped_total`, `airlock_config_reload_errors_total`, `airlock_revision`.
- Traces over OTLP when `telemetry.otlp_endpoint` is set: one span per `tools/call` with a child span for the backend call, and one span per admin request.
- Logs: JSON on stdout through `log/slog`.
- Default `listen_addr` is `127.0.0.1:8080`. The Docker image sets `0.0.0.0:8080` and keeps the SQLite file in a `/data` volume.

## CLI

Commands that need a running gateway talk to its admin API using `--url` and `--token` (or `AIRLOCK_URL` and `AIRLOCK_TOKEN`). Offline commands use `--config` and open the store directly.

| Command | What it does |
|---|---|
| `airlock serve [--config f]` | Run the gateway over HTTP |
| `airlock serve [--config f] --stdio` | Serve one local client over stdio |
| `airlock validate --config f` | Check the file and exit non-zero on errors (offline) |
| `airlock migrate [--config f]` | Apply database migrations and exit (offline) |
| `airlock bootstrap-key [--config f]` | Issue a new bootstrap admin key (offline) |
| `airlock keys new --name n [--group g]` | Print a new API key and its hash line for the file (offline) |
| `airlock check --user u [--group g] [--key k] [TOOL...]` | Show decisions and deciding rules, through `POST /check` |
| `airlock tools [--user u] [--group g]` | Show the tool list a caller would see, through `POST /check` and `GET /tools` |
| `airlock version` | Print version and build info |

## Errors

- MCP auth failure: HTTP 401 with `WWW-Authenticate: Bearer resource_metadata="..."`. A valid token on another user's session: 403.
- Unknown or hidden tool: the MCP "tool not found" error, the same for both. A caller cannot tell a denied tool from one that does not exist.
- Rate limited, backend unavailable, timeout: a tool result with `isError: true` and a short message. The model can read it and the client does not treat it as a protocol failure.
- Backend tool errors pass through unchanged.
- Admin API errors use the error shape above with the right HTTP status.
- Store unreachable: tool calls keep working from the current snapshot. Audit records queue and then drop as described, admin writes fail with 503, and `/readyz` reports the store as down.
- A panic in a handler or plugin is recovered, logged with the request ID, and returned as an internal error. It does not take down the process.

## Testing

- Test-driven, unit tests next to each package, table-driven where it fits, following CONTRIBUTING.md. No network in unit tests and no bare `time.Sleep`.
- CI runs tests on Linux, macOS and Windows (`-race` on the first two), lint, CodeQL and dependency review, and fails below 80% total coverage. Local runs on Windows skip `-race` because there is no C compiler.
- Policy and rate limit logic: table tests, including deny-wins, default-deny, and glob edge cases.
- OIDC: an in-test issuer on `httptest` serving discovery and JWKS, signing tokens with a generated RSA key. Covers expired, wrong audience, wrong issuer, unknown `kid` and rotated keys.
- Store: one shared test suite run against every driver. SQLite always. Postgres runs behind the `integration` build tag, using `AIRLOCK_TEST_POSTGRES_DSN`, and CI runs it with a Postgres service container. Migrations are tested from empty and from each earlier version.
- Provisioning: file-owned rows appear, update, disappear, refuse API edits, and never touch API-owned rows.
- Admin API: a test walks every operation in `api/openapi.yaml` and fails if a route is missing, and request and response bodies are checked against the schema. Pagination, `If-Match`, merge patch, role checks and secret masking each get their own tests.
- Backends: Streamable HTTP tests use in-process mcp-go servers on `httptest`. stdio tests build a tiny test MCP server from `internal/testutil/mcpserver` in `TestMain` and run it as a real process, so they work on Windows too.
- Gateway end to end: start airlock with an empty SQLite store, set it up only through the admin API with the bootstrap key, connect with the mcp-go client as alice, bob and ci-bot, then check visible tools, denied calls, rate limits, audit records over the API, `list_changed` propagation, and session hijack rejection. A second run sets up the same state from a YAML file and checks the results match.
- Two instances on one Postgres (integration tag): a rule added through one is enforced by the other within a few seconds.
- `airlock check` and `airlock validate` get golden-output tests.

## Demo

`examples/demo-server` is a small Go MCP server with `echo`, `time` and `notes_*` tools, so the demo needs only Go, with no Node or Docker. `examples/quickstart` has a shell script that drives the admin API with `curl`. The recording shows:

1. `airlock serve` with no config prints a bootstrap key.
2. Three `curl` calls add two servers and a rule. No YAML is touched.
3. alice in group `eng` lists tools and sees both servers. bob in `interns` sees only the read tools.
4. bob calls a write tool and gets "tool not found", then hits the rate limit.
5. `airlock check` explains both results.
6. `GET /admin/v1/audit?subject=bob` shows every call, including the denied one.

## Contributor entry points

Good first pieces, each behind an existing interface: CEL or OPA policy, Postgres or Redis rate limiter, webhook / Kafka / OpenSearch audit sinks, legacy SSE backend, a backend that runs servers in Docker, OAuth 2.0 token exchange (RFC 8693) for HTTP backends, Postgres `LISTEN/NOTIFY` for faster change pickup, a Helm chart, and client libraries generated from the OpenAPI file.

## Repository

The repository root carries the shared files from `mothership/contributing/`: CONTRIBUTING.md, AGENTS.md (with CLAUDE.md, GEMINI.md and `.github/copilot-instructions.md` pointing to it), SECURITY.md, CODE_OF_CONDUCT.md, CHANGELOG.md, LICENSE, issue and pull request templates, CODEOWNERS, CI workflows, Dependabot, `.golangci.yml`, `.testcoverage.yml`, the Makefile and `.gitattributes`. airlock adds to them and never loosens them. Every change is committed right away with a Conventional Commits message, and AGENTS.md changes in the same commit whenever commands, layout or rules change. The first milestone's issues are drafted in `docs/issues.md` once this spec is approved.

## Decisions made

1. State lives in SQL: embedded SQLite by default, Postgres for teams and replicas, pure-Go drivers, migrations at startup. This replaces the earlier YAML-only plan, following the contract change in mothership commit 144dc5a.
2. The database is the source of truth. YAML provisions into it, file-owned rows are read-only through the API.
3. No UI in this repository. The admin API under `/admin/v1/` covers every common task, with `api/openapi.yaml` as the source of truth and generated handlers.
4. Built on mark3labs/mcp-go v1.x.
5. One aggregating server with a per-caller tool filter, reading from an immutable snapshot swapped on each revision.
6. Tools only in v1. No prompts, resources, sampling, elicitation or roots passthrough.
7. Deny wins, default is deny, rule order does not matter.
8. Hidden and missing tools look the same to the caller.
9. Two admin roles, `viewer` and `admin`, bound to subject patterns. Tool permissions never grant admin access.
10. A bootstrap admin key is printed once on first start when no role bindings exist.
11. API keys use the `alk_` prefix and are stored as SHA-256 hashes.
12. Secret fields are `${VAR}` references or AES-GCM encrypted literals, and are never returned by the API.
13. HTTP backends in `forward` mode get one upstream session per caller and token.
14. stdio backends run one shared process per backend.
15. Down backends keep their last known tools listed and fail calls fast.
16. Rate limit and availability errors are tool results with `isError`, not JSON-RPC errors.
17. The SQL audit sink is always on, with 30-day retention by default. Records drop instead of blocking calls, unless `on_overflow: block` is set.
18. Environment override nesting uses `__`, as in `AIRLOCK_STORAGE__DSN`.
19. Optimistic concurrency with `version` and `If-Match`, updates with JSON merge patch.
20. Plugins are compiled in through `Register` functions in public packages, configured with JSON.
21. Module `github.com/raven-clown/airlock`, Apache-2.0, `go 1.26` in go.mod, first release v0.1.0.
22. No paid edition. Every feature, including SSO, roles, audit, multi-tenancy, clustering and the admin API, ships in the Apache-2.0 build.

## Open choices

1. **Token forwarding and the MCP spec.** The contract says a component forwards the caller's token unchanged. The MCP authorization spec warns against token passthrough, because a token meant for airlock then works at the backend too. For the mothership set this is fine if `logbook` accepts the same audience as airlock. For third-party HTTP backends, `forward` should not be the default. A later `exchange` mode (RFC 8693) would fix this properly. This may need a line in the contract.
2. **Env override nesting.** The contract shows `AIRLOCK_LISTEN_ADDR` but does not say how nested keys work. This spec uses `__`. The other three projects should agree on the same rule, so it may belong in the contract.
3. **stdio servers from the API.** Letting admins add stdio servers is what makes "add a server in a few clicks" work, but it means admin equals shell on the host. The current plan allows it, with `stdio.allowed_commands` in the file as the brake. The other option is to allow it only when the file turns it on.
4. **Multi-tenancy.** The contract lists it among features that stay free. v1 has one tenant per instance. Adding a `tenant_id` column to every table now costs little and avoids a painful migration later, but it adds a concept nobody uses yet. Leaning towards adding the column with a single default tenant.
5. **Per-user stdio processes.** Some stdio servers act as one account. A `per_user: true` option could start one process per caller with that caller's identity in its env. It costs a process per user, so it is left out of v1.
6. **Prompts and resources.** Prompts can use the same prefix scheme. Resources need URI rewriting and are harder. Planned for v0.2.
7. **Sampling and elicitation passthrough.** Needs routing a backend's request back to the right client session. Worth doing once a real backend needs it.
8. **Rate limit errors.** Tool results with `isError` are friendlier to models. Some clients may prefer a JSON-RPC error they can retry on. Easy to change before v1.0.
9. **Shared MCP sessions across replicas.** v1 needs sticky sessions. Storing session state in Postgres would remove that, at the cost of a store read on every request.
