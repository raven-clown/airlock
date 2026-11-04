# Milestone v0.1.0: issues

The first release, as described in [design.md](design.md). Each issue below is posted to GitHub under the `v0.1.0` milestone. The `good first issue` items are small standalone packages that the core will import, so they can be built before the rest exists. If one is still unclaimed when the core needs it, a maintainer picks it up.

Posted on 2026-11-04 as [#1 to #28](https://github.com/raven-clown/airlock/milestone/1), in the order below. GitHub is now the place to discuss them.

---

### Glob matching for tool patterns

Labels: enhancement, good first issue

**Why:** Rules and rate limits match tool names with patterns like `github__*` or `files__read_*`. `path.Match` treats `/` specially and supports more syntax than we want, so airlock needs its own small matcher.

**Proposed API:**

```go
package glob

// Match reports whether name matches pattern, where * matches any run of characters, including none.
func Match(pattern, name string) bool
```

**Behavior:**
- `*` matches any run of characters, including an empty one. Every other character matches itself.
- No other special characters. `?`, `[` and `\` are literal.
- Matching is case-sensitive.
- An empty pattern matches only an empty name.
- Must not backtrack exponentially: `Match("*a*a*a*a*a*b", strings.Repeat("a", 10000))` returns quickly.

**Tests:** A table test covering exact match, leading, trailing and middle `*`, several `*`, `**`, empty pattern, empty name, literal `?` and `[`, case differences, and the long input above finishing in well under a second.

**Where:** New package `policy/glob`: `policy/glob/glob.go` and `policy/glob/glob_test.go`.

---

### Parse rate limit strings

Labels: enhancement, good first issue

**Why:** Rate limits are written as `30/m` in YAML and in the admin API. Both need the same parser with clear error messages.

**Proposed API:**

```go
package ratelimit

type Rate struct {
    Count  int
    Period time.Duration
}

// ParseRate parses strings like "30/m", "5/s" or "100/h".
func ParseRate(s string) (Rate, error)

func (r Rate) String() string
```

**Behavior:**
- Accepts `N/s`, `N/m` and `N/h`, where N is a positive integer. Spaces around the parts are allowed.
- Rejects zero, negative numbers, missing parts, unknown units and anything after the unit, with an error that quotes the input.
- `String()` returns the canonical form, so `ParseRate(r.String())` gives back `r`.

**Tests:** A table test with valid inputs for each unit, inputs with spaces, and each kind of invalid input. A round-trip test for `String()`.

**Where:** New file `ratelimit/rate.go` and `ratelimit/rate_test.go`.

---

### Redact secrets in audit arguments

Labels: enhancement, good first issue

**Why:** When `audit.include_args` is on, tool arguments go into audit records. Keys like `password` or `token` must be replaced before they are stored, at any depth.

**Proposed API:**

```go
package audit

// Redact returns a deep copy of args with the values of matching keys replaced by "[redacted]".
func Redact(args map[string]any, keys []string) map[string]any
```

**Behavior:**
- Key matching is case-insensitive: `Password`, `PASSWORD` and `password` all match `password`.
- Walks nested maps and slices of any depth. A matching key's value is replaced whatever its type.
- Never changes the input map.
- A nil map returns nil.

**Tests:** A table test with flat maps, nested maps, maps inside slices, mixed case keys, a matching key whose value is a map, an empty key list, and a check that the input is unchanged afterwards.

**Where:** New files `audit/redact.go` and `audit/redact_test.go`.

---

### Validate prefixed tool names

Labels: enhancement, good first issue

**Why:** airlock exposes tools as `<server>__<tool>`. The MCP spec limits tool names to 1 to 128 characters from `A-Z a-z 0-9 _ - .`, and server names have their own rule. Tools that would break the limit must be skipped with a clear reason.

**Proposed API:**

```go
package naming

const Separator = "__"

// ValidServerName reports whether s matches ^[a-z0-9][a-z0-9-]{0,31}$.
func ValidServerName(s string) bool

// Join returns server + "__" + tool, or an error saying why the result is not a valid MCP tool name.
func Join(server, tool string) (string, error)

// Split splits at the first "__". ok is false when there is no separator.
func Split(name string) (server, tool string, ok bool)
```

**Behavior:**
- `Join` fails if the server name is invalid, the tool name is empty, the result is longer than 128 characters, or it contains a character outside `A-Z a-z 0-9 _ - .`.
- `Split("github__create__issue")` returns `github` and `create__issue`.

**Tests:** Table tests for valid and invalid server names (uppercase, underscore, leading dash, 33 characters), `Join` at exactly 128 and at 129 characters, bad characters, and `Split` with zero, one and several separators.

**Where:** New package `internal/naming`: `internal/naming/naming.go` and `internal/naming/naming_test.go`.

---

### Show build info in `airlock version`

Labels: enhancement, good first issue

**Why:** Bug reports ask for the output of `airlock version`. Today it prints only `airlock dev`, which doesn't say which commit or Go version was used.

**Proposed API:** `airlock version` prints:

```
airlock dev
commit: 958fded (modified)
go: go1.27.2
```

**Behavior:**
- The version line is unchanged.
- Commit and the modified flag come from `runtime/debug.ReadBuildInfo()` (`vcs.revision`, shortened to 7 characters, and `vcs.modified`). If they are missing, the commit line is left out.
- The Go line comes from `runtime.Version()`.

**Tests:** Extend `TestRun` in `cmd/airlock/main_test.go`. Move the build info lookup behind a function variable so the test can fake it, and cover: full info, info without VCS settings, and `ReadBuildInfo` returning false.

**Where:** `cmd/airlock/main.go` and `cmd/airlock/main_test.go`.

---

### Config loading with env overrides

Labels: enhancement

**Why:** Every project loads one YAML file with `--config`, expands `${VAR}`, and lets env vars override any scalar key, with `__` between levels (contract, Operations).

**Proposed API:** `internal/config`: `Load(path string, env func(string) (string, bool)) (*Config, error)`, plus `Default() *Config` for running with no file. Keys from design.md, Config file section.

**Behavior:**
- Unknown keys are an error naming the key and line.
- `${VAR}` in process settings is expanded at load. In provisioned resources the reference is kept as written.
- `AIRLOCK_LISTEN_ADDR` sets `listen_addr`, `AIRLOCK_STORAGE__DSN` sets `storage.dsn`. Lists can't be overridden.
- Validation errors name the field path.

**Tests:** Table tests for overrides at each depth, unknown keys, missing `${VAR}`, invalid values, and an empty file giving the defaults.

---

### SQL store, migrations and SQLite

Labels: enhancement

**Why:** All state lives in SQL (contract, Storage). SQLite is the default.

**Proposed API:** `internal/store`: a `Store` interface with methods per table in design.md, Storage section. `Open(ctx, driver, dsn string) (Store, error)` runs migrations. Embedded migrations per engine, tracked in `schema_migrations`.

**Behavior:**
- Every table has `org_id`, and every query filters by it.
- Every write bumps the org's `revision` in the same transaction.
- Refuses to start against a schema newer than the binary knows.
- SQLite in WAL mode, busy timeout, one writer connection.

**Tests:** A shared store test suite in `internal/store/storetest` that any driver runs, covering CRUD for every table, `version` checks, revision bumps and migrations from empty.

---

### Postgres store

Labels: enhancement, adapter

**Why:** Teams and replicas use Postgres (contract, Storage).

**Proposed API:** `storage.driver: postgres` with a pgx DSN.

**Behavior:** Same as SQLite, plus an advisory lock around migrations so two replicas don't migrate at once.

**Tests:** The shared store suite behind the `integration` build tag, using `AIRLOCK_TEST_POSTGRES_DSN`. A CI job with a Postgres service container.

---

### Identity, authenticator chain and API keys

Labels: enhancement

**Why:** Every request to `/mcp` and `/admin/v1/` carries `Authorization: Bearer`, and the same identity rules apply to both.

**Proposed API:** Package `auth` with `Identity`, `Authenticator`, `ErrNotMine` and `Register`, from design.md. Built-in `auth/apikey` for `alk_` keys stored as SHA-256 hashes, service and personal.

**Behavior:**
- First authenticator that claims the token decides. None claiming it means 401 with `WWW-Authenticate`.
- Revoked and expired keys are rejected. `last_used_at` is written at most once a minute per key.
- Tokens never appear in logs or errors.

**Tests:** Chain order, valid, unknown, revoked and expired keys, personal keys acting as their owner, and a log capture check that no token leaks.

---

### OIDC authenticator and protected resource metadata

Labels: enhancement

**Why:** People log in through their company's identity provider, and MCP clients find it through RFC 9728 metadata.

**Proposed API:** `auth/oidc` with `issuer`, `audience`, `subject_claim`, `groups_claim` (dotted paths allowed). `/.well-known/oauth-protected-resource` served from the settings.

**Behavior:** Checks signature, `iss`, `aud`, `exp`, `nbf`. Refreshes JWKS on an unknown `kid`. A string groups claim becomes a one-item list.

**Tests:** An in-test issuer on `httptest` with a generated RSA key. Expired, wrong audience, wrong issuer, unknown and rotated `kid`, nested groups claim, string groups claim.

---

### Rules policy with deny-wins and explanations

Labels: enhancement

**Why:** The core permission model: allow and deny rules on users, groups and keys.

**Proposed API:** `policy` package with `Policy`, `Request`, `Decision` and `Register`. Built-in `policy/rules`, using the glob matcher.

**Behavior:** Every rule matching the caller is considered. Any deny wins, then any allow, then `default-deny`. The decision names the rule and the pattern that decided.

**Tests:** Table tests for user, group, key and `*` subjects, deny-wins across rules, default deny, order independence, and decisions carrying the right rule and reason.

---

### stdio backend

Labels: enhancement

**Why:** Most MCP servers today run as local commands.

**Proposed API:** `backend` package with `Backend`, `Status` and `Register`. Built-in `backend/stdio` with `command`, `args`, `env`, `dir`.

**Behavior:** One process per backend. stderr goes to the log tagged with the backend name, and the last 100 lines are kept for the admin API. Restarts with backoff from 1s to 60s. Lists tools at start and on `list_changed`. Down backends keep their last known tools and fail calls fast.

**Tests:** A test MCP server built from `internal/testutil/mcpserver` in `TestMain` and run as a real process, so tests pass on Windows. Start, call, crash and restart, `list_changed`, timeout, cancellation.

---

### Streamable HTTP backend

Labels: enhancement

**Why:** Remote MCP servers, including logbook, speak Streamable HTTP.

**Proposed API:** `backend/streamable` with `url`, `auth.mode` (`none` by default, `static`, `forward`), `headers`, `discovery_headers`, `session_idle_timeout`, `max_sessions`.

**Behavior:** `forward` keeps one upstream session per subject and token hash, with idle timeout and LRU eviction. `traceparent`, `tracestate`, `X-Request-ID` and `X-Project` are set on every call.

**Tests:** In-process mcp-go servers on `httptest`. Each auth mode, two users never sharing a session, idle eviction, header forwarding.

---

### Gateway: catalog, router and tool filter

Labels: enhancement

**Why:** The heart of airlock: one MCP server that shows each caller only their tools and routes calls to the right backend.

**Proposed API:** `internal/gateway` on mcp-go, using `WithToolFilter`, tool middleware and `WithHTTPContextFunc`. Streamable HTTP at `/mcp` and `airlock serve --stdio`.

**Behavior:** Tools prefixed as `<server>__<tool>`, invalid names skipped with a warning. Hidden and missing tools give the same "tool not found". A request on a session opened by a different subject gets 403. In stdio mode all logs go to stderr.

**Tests:** End-to-end with the mcp-go client as two users with different rules: listed tools, denied calls, `list_changed` reaching the client, session hijack rejected.

---

### Rate limits

Labels: enhancement

**Why:** Stop one caller or one runaway agent from hammering a backend.

**Proposed API:** `ratelimit` package with `Limiter` and `Register`, built-in in-memory token buckets per rule and subject.

**Behavior:** A call must pass every matching rule. Over the limit returns a tool result with `isError: true` and a retry hint, and the audit outcome is `rate_limited`.

**Tests:** Table tests with a fake clock: burst, refill, several matching rules, different subjects not sharing buckets.

---

### Audit pipeline and sinks

Labels: enhancement

**Why:** Every tool call and every admin write leaves a record (contract, Admin API).

**Proposed API:** `audit` package with `Event`, `Sink` and `Register`. Built-in `sql` (always on), `stdout` and `file` sinks. Settings `include_args`, `redact`, `retention`, `on_overflow`.

**Behavior:** Buffered channel, batch inserts, drops counted in `airlock_audit_dropped_total` unless `on_overflow: block`. Hourly retention job. Tokens never recorded.

**Tests:** Each outcome produces the right record, drops are counted, block mode blocks, retention deletes old rows only, redaction applied.

---

### Runtime snapshot and revision polling

Labels: enhancement

**Why:** Requests must not read the database. Config changes, from the API or another replica, must still reach every instance within seconds.

**Proposed API:** `internal/runtime` building an immutable snapshot (policy, limits, keys, settings, backends) and swapping it when the revision moves.

**Behavior:** Polls every 2 seconds. Added backends start, removed ones stop, changed ones restart. A failed rebuild keeps the old snapshot and logs the error.

**Tests:** Snapshot swaps on revision change, backend diffing, a failed rebuild leaving the old one in place, concurrent readers during a swap.

---

### Provision resources from the YAML file

Labels: enhancement

**Why:** GitOps users declare servers, rules and keys in the file, and the console must not edit those.

**Proposed API:** `internal/provision` syncing the file's resources into the store with `source: file`.

**Behavior:** Rows removed from the file are deleted only if they came from the file. The API refuses edits to them with 409 `managed_by_file`. A name used by both the file and the API is a load error. The file is checked every 2 seconds and on SIGHUP.

**Tests:** Add, change and remove in the file, API edits refused, API rows untouched, invalid file changes nothing.

---

### Admin API foundation and OpenAPI

Labels: enhancement

**Why:** The console works only through the admin API, and every project shares its conventions (contract, Admin API).

**Proposed API:** `api/openapi.yaml` as the source, handlers generated with `oapi-codegen` into `internal/admin`, a CI check that regenerating changes nothing. `GET /status` and `GET /audit`.

**Behavior:** Error shape `{"error": {"code", "message", "field"}}`. Cursor pagination with `limit` default 50, max 500, `next_cursor` absent on the last page. Integer `version` with `If-Match`, 409 `version_conflict`. Roles `member`, `viewer`, `admin`. Every write audited.

**Tests:** A test that walks every operation in the OpenAPI file and fails on a missing route. Pagination, `If-Match`, role checks and the error shape.

---

### Admin API: servers and tools

Labels: enhancement

**Why:** Adding a server is the first thing a new user does in the console.

**Proposed API:** `GET/POST /servers`, `GET/PATCH/DELETE /servers/{name}`, `POST /servers/{name}/restart`, `POST /servers/test`, `GET /tools`.

**Behavior:** Secret fields return `{"set": true}`, never the value. `POST /servers/test` connects and lists tools without saving. stdio commands are checked against `stdio.allowed_commands`.

**Tests:** CRUD, secret masking, test connection success and failure, allowed commands enforced, file-managed servers read-only.

---

### Admin API: rules, rate limits, bindings, settings and check

Labels: enhancement

**Why:** Giving someone access must be a few clicks.

**Proposed API:** CRUD for `/rules`, `/rate-limits`, `/role-bindings`, `/project-bindings`. `GET/PATCH /settings`. `POST /check`. `GET /me`, `GET /me/tools`.

**Behavior:** Writes are validated with the same code as the file loader. `POST /check` returns each tool's decision and deciding rule. `/me/tools` shows the caller's own view.

**Tests:** CRUD with validation errors naming the field, `check` results matching the gateway's real decisions, member versus viewer access.

---

### Admin API: API keys, usage, sessions and export

Labels: enhancement

**Why:** Services need keys, and admins need to see who uses what.

**Proposed API:** `/api-keys` (service keys), `/me/api-keys` (personal keys), `GET /usage`, `GET /sessions`, `GET /export`.

**Behavior:** The key value appears only in the create response. Usage is grouped by subject, server or tool over a time range. Export returns API-created resources as YAML the file loader accepts.

**Tests:** Key shown once, revoke works at once, usage sums match audit records, export output loads back through the file loader.

---

### First start: bootstrap key and default member binding

Labels: enhancement

**Why:** A new user must reach a working setup without YAML (contract, Operations).

**Proposed API:** On a store with no role bindings, create an `admin` API key named `bootstrap`, print it once to stderr, and bind `*` to `member`. `airlock bootstrap-key` issues a new one offline.

**Behavior:** Not printed again on later starts. Skipped when the file declares role bindings. The key never enters the JSON log stream.

**Tests:** First start prints once, second start doesn't, file bindings skip it, the printed key works on `/admin/v1/status`.

---

### Encrypted secret fields

Labels: enhancement

**Why:** Server env values and headers hold tokens, and the console needs to store them.

**Proposed API:** `internal/secrets` with AES-256-GCM, key from `AIRLOCK_SECRET_KEY`, or `airlock.key` created next to a SQLite database.

**Behavior:** A secret is either a `${VAR}` reference or an encrypted literal. With Postgres and no key, literals are refused with a clear error.

**Tests:** Round trip, wrong key fails, tampered ciphertext fails, key file created once with tight permissions, Postgres without a key refused.

---

### Health, readiness, metrics and tracing

Labels: enhancement

**Why:** Operators need the same endpoints in every project (contract, Operations).

**Proposed API:** `/healthz`, `/readyz`, `/metrics`, OTLP traces when `telemetry.otlp_endpoint` is set. `X-Request-ID` kept or generated, `Origin` checked against `allowed_origins`.

**Behavior:** `/readyz` checks the store, migrations and every `required: true` backend, with a JSON body per check. Metric names from design.md, Operations.

**Tests:** Readiness for each failing check, request ID kept and generated, bad Origin rejected, metric names present after a tool call.

---

### CLI commands

Labels: enhancement

**Why:** Operators and the demo need `serve`, `validate`, `migrate`, `check`, `tools`, `keys new` and `bootstrap-key`.

**Proposed API:** As in design.md, CLI. Online commands use `--url` and `--token` or `AIRLOCK_URL` and `AIRLOCK_TOKEN`.

**Behavior:** Non-zero exit codes on errors. `check` prints one line per tool with the decision, rule and reason.

**Tests:** Golden-output tests for `check` and `validate`, `keys new` output loading back into the config.

---

### Demo server and quickstart

Labels: docs, help wanted

**Why:** A visitor should see airlock working in a few minutes with only Go installed.

**Proposed API:** `examples/demo-server` (an MCP server with `echo`, `time` and `notes_*` tools) and `examples/quickstart` (a script that sets airlock up through the admin API with `curl`).

**Behavior:** Follows the six steps in design.md, Demo.

**Tests:** The quickstart runs in CI against a fresh build and checks each step's output.

---

### Release builds and container image

Labels: help wanted

**Why:** Users want a binary for their platform and a container image.

**Proposed API:** GoReleaser config for Linux, macOS and Windows on amd64 and arm64, a distroless image with SQLite data in `/data` and `listen_addr` set to `0.0.0.0:8080`, a release workflow on tags.

**Behavior:** Binaries are static (no cgo). The image runs as a non-root user.

**Tests:** A snapshot build in CI on pull requests that touch the release config.
