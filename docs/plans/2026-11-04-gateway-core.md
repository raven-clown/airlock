# Gateway core implementation plan

Plan 1 of 4 for v0.1.0. Plan 2 adds the store, provisioning and revision polling. Plan 3 adds the admin API. Plan 4 adds OIDC, rate limits, the remaining CLI commands, metrics, the demo and release builds.

**Goal:** `airlock serve --config airlock.yaml` fronts stdio and Streamable HTTP MCP servers on one `/mcp` endpoint, with API key login, rules-based tool filtering, and audit records on stdout or in a file. `airlock serve --stdio` serves one local client.

**Architecture:** One mcp-go server holds every backend tool under a prefixed name. A tool filter asks the policy in the current runtime snapshot whether the caller may see each tool, and a middleware chain writes audit records before routing the call to its backend. In this plan the snapshot is built from the YAML file. Plan 2 swaps in a store-backed source behind the same `runtime.Source` interface.

**Tech stack:** Go 1.26 (`go 1.26` in go.mod), `github.com/mark3labs/mcp-go` v1.4.0, `go.yaml.in/yaml/v3`, standard library for everything else.

**Spec:** [docs/design.md](../design.md)

## Global constraints

- Module `github.com/raven-clown/airlock`. No cgo.
- Tool names are `<server>__<tool>`. Server names match `^[a-z0-9][a-z0-9-]{0,31}$`. Prefixed names are 1 to 128 characters from `A-Z a-z 0-9 _ - .`.
- Deny wins, default is deny, rule order does not matter.
- Hidden and missing tools give the same "tool not found" error.
- Bearer tokens never appear in logs, errors or audit records.
- Logs are JSON on stdout through `log/slog`. In stdio mode all logs go to stderr.
- Env overrides: `AIRLOCK_` plus the upper-case key path, `__` between levels. Unknown config keys are errors.
- Tests: table-driven, no network beyond `httptest` and local child processes, no bare `time.Sleep`. Must pass without `-race` on Windows and with `-race` in CI. Total coverage at least 80%.
- Comments short and about why. Every exported name has a doc comment. No em-dashes anywhere.
- Commit after every task with a Conventional Commits message and push. Update AGENTS.md (Layout) in the same commit when a package appears. Add a CHANGELOG line under Unreleased for user-visible features.

## Review focus

1. **A stdio command that does not exist or exits at once.** airlock still starts, the backend shows `down` with the error, it retries with backoff, and other backends work. Test in Task 7.
2. **`${VAR}` in a server's `env` that is not set.** That backend fails to start with an error naming the variable, other backends start. Test in Task 7.
3. **A call to a tool whose backend just went down.** The call returns an `isError` result within the call timeout, never hangs, and the audit outcome is `backend_unavailable`. Test in Task 11.
4. **The tool list changes while calls are in flight.** In-flight calls finish, new calls see the new list, nothing panics. Test in Task 11.
5. **Upstream tool names that contain `__` or invalid characters.** `a__b` from server `s` becomes `s__a__b` and routes back to `a__b`. A name with a space is skipped with a warning and the rest of the server's tools still appear. Test in Task 11.

---

### Task 1: Tool and server naming

Closes #4.

**Files:**
- Create: `internal/naming/naming.go`, `internal/naming/naming_test.go`

**Interfaces:**
- Produces: `const Separator = "__"`, `ValidServerName(s string) bool`, `Join(server, tool string) (string, error)`, `Split(name string) (server, tool string, ok bool)`

- [ ] **Step 1: Write the failing tests**

`TestValidServerName`: `github`, `a`, `my-server-2` and a 32-character name are valid. Empty, `GitHub`, `my_server`, `-lead`, a 33-character name and `a__b` are not.
`TestJoin`: `Join("github","create_issue")` is `github__create_issue`. A result of exactly 128 characters passes, 129 fails. A tool with a space fails, an empty tool fails, an invalid server fails. Error messages contain the offending name.
`TestSplit`: `github__create__issue` gives `github`, `create__issue`, true. `nosep` gives false. `__x` gives `""`, `x`, true.

- [ ] **Step 2: Run** `go test ./internal/naming/` and see it fail to compile.
- [ ] **Step 3: Implement** with a precompiled regexp for server names and a byte loop for tool characters.
- [ ] **Step 4: Run** `go test ./internal/naming/` and see PASS.
- [ ] **Step 5: Commit** `feat(naming): validate, join and split prefixed tool names` with `Closes #4`, and push.

### Task 2: Glob matching

Closes #1.

**Files:**
- Create: `policy/glob/glob.go`, `policy/glob/glob_test.go`

**Interfaces:**
- Produces: `glob.Match(pattern, name string) bool`

- [ ] **Step 1: Write the failing tests** from issue #1: exact, leading, trailing and middle `*`, several `*`, `**`, empty pattern against empty and non-empty name, literal `?` and `[`, case sensitivity. `TestMatchNoBacktracking` checks `Match("*a*a*a*a*a*b", strings.Repeat("a", 10000))` is false and finishes before a 1 second deadline using a goroutine and `time.After`.
- [ ] **Step 2: Run** `go test ./policy/glob/` and see it fail.
- [ ] **Step 3: Implement** the linear two-pointer wildcard match (remember the last `*` position and the name position after it, backtrack only there).
- [ ] **Step 4: Run** and see PASS.
- [ ] **Step 5: Commit** `feat(policy): add glob matching for tool patterns` with `Closes #1`, and push.

### Task 3: Identity and the authenticator chain

**Files:**
- Create: `auth/auth.go`, `auth/chain.go`, `auth/auth_test.go`

**Interfaces:**
- Produces:
  - `type Identity struct { Subject string; Groups []string; Method string; KeyName string; Token string; Claims map[string]any }`. `Token` is never logged: `Identity` implements `slog.LogValuer` returning subject, groups and method only.
  - `type Authenticator interface { Authenticate(ctx context.Context, r *http.Request) (*Identity, error) }`
  - `var ErrNotMine`, `var ErrNoCredentials`, `type InvalidError struct{ Method, Reason string }` (its `Error()` never includes the token)
  - `func NewChain(a ...Authenticator) *Chain`, `func (c *Chain) Authenticate(ctx, r) (*Identity, error)`
  - `func WithIdentity(ctx context.Context, id *Identity) context.Context`, `func FromContext(ctx context.Context) (*Identity, bool)`
  - `func BearerToken(r *http.Request) (string, bool)`
  - `func Register(kind string, f Factory)`, `type Factory func(cfg json.RawMessage) (Authenticator, error)`, `func Lookup(kind string) (Factory, bool)`

- [ ] **Step 1: Write the failing tests**

`TestChain`: with fakes, the first authenticator returning `ErrNotMine` is skipped and the second's identity is returned. An authenticator returning `*InvalidError` stops the chain with that error. No header gives `ErrNoCredentials`. All `ErrNotMine` gives `ErrNoCredentials`.
`TestBearerToken`: `Bearer abc` and `bearer abc` give `abc`. `Basic x`, `Bearer` and an empty header give false.
`TestIdentityLogValue`: logging an identity with `Token: "secret-token"` through a JSON slog handler into a buffer does not contain `secret-token`.
`TestRegister`: registering the same kind twice panics. `Lookup` finds a registered kind.

- [ ] **Step 2: Run** `go test ./auth/` and see it fail.
- [ ] **Step 3: Implement.** The registry is a package-level map guarded by a mutex, filled from `init` functions only.
- [ ] **Step 4: Run** and see PASS.
- [ ] **Step 5: Commit** `feat(auth): add identity, authenticator chain and registry` and push.

### Task 4: API key authenticator

**Files:**
- Create: `auth/apikey/apikey.go`, `auth/apikey/apikey_test.go`

**Interfaces:**
- Consumes: Task 3.
- Produces:
  - `const Prefix = "alk_"`
  - `type Key struct { Name string; SHA256 string; Groups []string; ExpiresAt time.Time; Revoked bool }`
  - `func New(keys []Key, now func() time.Time) *Authenticator`
  - `func Generate() (plain string, sha256hex string, err error)`: `alk_` plus 32 random bytes in unpadded base64url.
  - `func Hash(plain string) string`: lowercase hex SHA-256.

- [ ] **Step 1: Write the failing tests**

Table `TestAuthenticate`: a valid key gives `Subject: "key:ci-bot"`, `KeyName: "ci-bot"`, `Method: "apikey"`, its groups. A token without `alk_` gives `ErrNotMine`. An unknown `alk_` key, a revoked key and a key with `ExpiresAt` before `now()` give `*auth.InvalidError` with reasons `unknown`, `revoked`, `expired`. A zero `ExpiresAt` never expires.
`TestGenerate`: prefix is `alk_`, length is 4 + 43, `Hash(plain)` equals the returned hash, two calls differ.

- [ ] **Step 2: Run** `go test ./auth/apikey/` and see it fail.
- [ ] **Step 3: Implement** with a `map[string]Key` keyed by hash. Register kind `apikey` in `init`.
- [ ] **Step 4: Run** and see PASS.
- [ ] **Step 5: Commit** `feat(auth): add API key authenticator` and push.

### Task 5: Rules policy

**Files:**
- Create: `policy/policy.go`, `policy/rules/rules.go`, `policy/rules/rules_test.go`, `policy/policy_test.go`

**Interfaces:**
- Consumes: `auth.Identity` (Task 3), `glob.Match` (Task 2).
- Produces:
  - `policy.Request{ Identity *auth.Identity; Server, Tool string; Args map[string]any }`, where `Tool` is the prefixed name.
  - `policy.Decision{ Allow bool; Rule, Reason string }`
  - `policy.Policy` interface with `Decide(ctx, Request) Decision`
  - `policy.Register(kind string, f Factory)`, `policy.Lookup`
  - `policy.Subjects(id *auth.Identity) []string`: `user:<subject>` for non-key identities, `key:<name>` for keys, `group:<g>` for each group, and `*`.
  - `rules.Rule{ Name string; Subjects, Allow, Deny []string }`, `rules.New(rs []Rule) (*Policy, error)`
  - `const rules.DefaultDeny = "default-deny"`

- [ ] **Step 1: Write the failing tests**

Using the four rules from design.md (Authorization), table `TestDecide`:
- alice in `eng`, `github__create_issue`: allow, rule `eng-github`.
- alice in `eng`, `github__delete_repo`: deny, rule `eng-github`, reason `denied by pattern github__delete_*`.
- bob in `interns`, `github__create_issue`: deny, rule `default-deny`.
- bob in `interns`, `files__read_file`: allow, rule `interns-read`.
- `key:ci-bot`, `github__create_issue`: allow. `key:ci-bot`, `files__read_file`: deny.
- anyone, `logbook__recall`: allow, rule `everyone-memory`.
- A deny in one rule beats an allow in another rule that also matches.
`TestDecideOrderIndependent`: every permutation of the rule list gives the same decisions for the cases above.
`TestNewValidation`: empty name, duplicate names, a rule with no subjects, and a subject without a known prefix (`team:x`) are errors naming the rule.

- [ ] **Step 2: Run** `go test ./policy/...` and see it fail.
- [ ] **Step 3: Implement.** For a deny, `Rule` is the first matching rule by name order so the output is stable. Register kind `rules` in `init`.
- [ ] **Step 4: Run** and see PASS.
- [ ] **Step 5: Commit** `feat(policy): add rules policy with deny-wins decisions` and push.

### Task 6: Config loading

Part of #6. Covers the keys this plan needs: `listen_addr`, `allowed_origins`, `stdio.identity`, `api_keys`, `servers`, `rules`, `audit`. Plan 2 adds `storage`, `role_bindings`, `settings`.

**Files:**
- Create: `backend/config.go`, `internal/config/config.go`, `internal/config/env.go`, `internal/config/expand.go`, `internal/config/config_test.go`, `internal/config/testdata/*.yaml`

**Interfaces:**
- Produces:
  - `type Config struct { ListenAddr string; AllowedOrigins []string; Stdio StdioConfig; APIKeys []APIKey; Servers []backend.Config; Rules []rules.Rule; Audit Audit }` with yaml tags in snake_case. Server definitions use the public `backend.Config` from Task 7, so plugins outside the module can read them. Define `backend.Config` in this task (only the struct, in `backend/config.go`).
  - `backend.Config{ Name, Transport, Command string; Args []string; Env map[string]string; Dir, URL string; Auth backend.HTTPAuth; CallTimeout time.Duration; Required bool }` and `backend.HTTPAuth{ Mode string; Headers, DiscoveryHeaders map[string]string; SessionIdleTimeout time.Duration; MaxSessions int }`, with yaml and json tags in snake_case. yaml.v3 decodes `60s` into `time.Duration` on its own.
  - `type Audit struct { Sinks []Sink; IncludeArgs bool; BufferSize int; OnOverflow string }`, `type Sink struct { Kind, Path string }`
  - `func Default() *Config`: `listen_addr: 127.0.0.1:8080`, `stdio.identity: local`, one `stdout` audit sink, buffer 4096, overflow `drop`, call timeout 60s.
  - `func Load(path string, env func(string) (string, bool)) (*Config, error)`
  - `func Parse(data []byte, env func(string) (string, bool)) (*Config, error)`
  - `func Expand(s string, env func(string) (string, bool)) (string, error)`: replaces `${NAME}`, errors with `variable NAME is not set`.

- [ ] **Step 1: Write the failing tests**

`TestParseDefaults`: an empty document gives `Default()`.
`TestEnvOverride` table: `AIRLOCK_LISTEN_ADDR=0.0.0.0:9` sets `ListenAddr`. `AIRLOCK_STDIO__IDENTITY=me` sets `Stdio.Identity`. `AIRLOCK_AUDIT__INCLUDE_ARGS=true` sets a bool. `AIRLOCK_NOPE=1` is an error `unknown key nope`. Env vars without the prefix are ignored.
`TestUnknownKey`: `listen_adr: x` fails with an error containing `listen_adr` and `line 1`.
`TestExpand` table: `${A}` with A set, two variables, no variables, unset variable error, `$A` without braces left as is.
`TestProcessSettingsExpanded`: `listen_addr: ${ADDR}` is expanded at load. `servers[0].env.TOKEN: ${GH}` is kept as the literal `${GH}`.
`TestValidate` table: bad server name, duplicate server names, transport not `stdio` or `streamable_http`, stdio without command, HTTP without url, `auth.mode` outside `none|static|forward`, unknown audit sink kind. Each error message names the field path, such as `servers[1].name`.

- [ ] **Step 2: Run** `go test ./internal/config/` and see it fail.
- [ ] **Step 3: Implement.** Decode into a `yaml.Node`, apply env overrides by walking mapping nodes (creating missing scalar keys, refusing sequences), expand `${VAR}` in the process-setting subtrees, then decode with `KnownFields(true)` and validate. Rule validation reuses `rules.New`.
- [ ] **Step 4: Run** and see PASS.
- [ ] **Step 5: Commit** `feat(config): load YAML with env overrides and validation` and push. Add `go.yaml.in/yaml/v3` to go.mod.

### Task 7: Test MCP server and stdio backend

Covers #12.

**Files:**
- Create: `internal/testutil/mcpserver/mcpserver.go`, `internal/testutil/mcpserver/mcpserver_test.go`, `internal/testutil/mcpserver/cmd/testserver/main.go`, `internal/testutil/build.go`
- Create: `backend/backend.go`, `backend/set.go`, `backend/backend_test.go`
- Create: `backend/stdio/stdio.go`, `backend/stdio/stdio_test.go`

**Interfaces:**
- Consumes: `auth.Identity`, `backend.Config` (Task 6), `config.Expand`.
- Produces:
  - `mcpserver.New(name string) *server.MCPServer` with tools: `echo` (returns its `text` argument), `fail` (tool error result `failed on purpose`), `crash` (exits the process with code 3), `wait` (blocks until the context ends, then returns `canceled`), `add_tool` (adds a tool named by `name`, which triggers `list_changed`), `env` (returns the value of env var `name`), `bad name` (a tool with a space in its name).
  - `testutil.BuildTestServer(dir string) (path string, err error)`: runs `go build` on `cmd/testserver` into `dir`, adding `.exe` on Windows.
  - `backend.Backend` interface as in design.md, plus `backend.Status{ State string; Err string; Tools int; Since time.Time; Stderr []string }` with states `starting`, `up`, `down`.
  - `backend.ErrUnavailable`
  - `backend.Register(transport string, f Factory)`, `type Factory func(cfg Config, deps Deps) (Backend, error)`, `type Deps struct { Logger *slog.Logger; Env func(string) (string, bool) }`
  - `backend.NewSet(deps Deps) *Set`, `(*Set).Apply(ctx, []backend.Config) error` (start new, stop removed, restart changed), `(*Set).Get(name) (Backend, bool)`, `(*Set).All() []Backend`, `(*Set).OnChange(func())`, `(*Set).Close() error`
  - `stdio.New(cfg backend.Config, deps backend.Deps, opts stdio.Options) *stdio.Backend`, `stdio.Options{ BackoffBase, BackoffMax time.Duration }` (defaults 1s and 60s). The registered factory for transport `stdio` uses the defaults.

- [ ] **Step 1: Write the failing tests**

`TestMCPServer` (in-process client from `client.NewInProcessClient`): each tool behaves as listed.
Stdio tests share one built binary from `TestMain` (build into `os.MkdirTemp`, remove after).
- `TestStdioListAndCall`: after `Start`, `Status().State` becomes `up` (poll with deadline), `Tools()` contains `echo`, calling `echo` with `{"text":"hi"}` returns `hi`.
- `TestStdioToolError`: `fail` returns a result with `IsError` true and no Go error.
- `TestStdioCrashRestarts`: calling `crash` returns an error, state goes `down` then back to `up`, and `echo` works again. Tests build it with `stdio.New` and `Options{BackoffBase: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond}`.
- `TestStdioListChanged`: calling `add_tool` with `{"name":"new"}` fires the `OnToolsChanged` callback and `Tools()` then contains `new`.
- `TestStdioCancel`: calling `wait` with a context canceled after the call starts returns within 2 seconds with a context error.
- `TestStdioMissingCommand` (review focus 1): command `does-not-exist-airlock` makes `Start` return nil, state becomes `down` with an error mentioning the command, and retries continue.
- `TestStdioUnsetEnv` (review focus 2): env `TOKEN: ${AIRLOCK_TEST_UNSET}` gives state `down` with error `variable AIRLOCK_TEST_UNSET is not set`.
- `TestStdioEnvResolved`: env `X: ${Y}` with Y set to `z` makes the `env` tool return `z`.
- `TestStdioStderrKept`: the last stderr lines appear in `Status().Stderr`, at most 100.
- `TestSetApply`: applying two servers starts both, applying one stops the other, changing a field restarts it, `OnChange` fires.

- [ ] **Step 2: Run** `go test ./backend/... ./internal/testutil/...` and see it fail.
- [ ] **Step 3: Implement.** Use `transport.NewStdioWithOptions` and `client.NewClient`, register `OnNotification` for `notifications/tools/list_changed`, keep tools in an `atomic.Pointer[[]mcp.Tool]`. A supervisor goroutine restarts on transport close with backoff doubling from `BackoffBase` (1s) to 60s. `Call` returns `ErrUnavailable` immediately when not `up`, and applies `CallTimeout` with `context.WithTimeout`. Stderr is read line by line into a 100-line ring and logged with `backend` set to the name.
- [ ] **Step 4: Run** and see PASS.
- [ ] **Step 5: Commit** `feat(backend): add backend set and stdio backend` and push. Update AGENTS.md layout.

### Task 8: Streamable HTTP backend

Covers #13 except `X-Project`, which plan 3 adds with project bindings.

**Files:**
- Create: `backend/streamable/streamable.go`, `backend/streamable/pool.go`, `backend/streamable/streamable_test.go`

**Interfaces:**
- Consumes: Task 7's `backend` package, `auth.FromContext`.
- Produces: transport `streamable_http` registered in `init`. Header forwarding reads `traceparent`, `tracestate` and `X-Request-ID` from the context through `httpx.HeadersFromContext(ctx) http.Header`, so this task also creates `internal/httpx/headers.go` with `WithForwardHeaders(ctx, h http.Header) context.Context` and `HeadersFromContext`.

- [ ] **Step 1: Write the failing tests** against `mcpserver.New` served by `server.NewStreamableHTTPServer` on `httptest.NewServer`, with a recording handler wrapper that captures request headers.
- `TestHTTPNone`: no `Authorization` header reaches the server, tools are listed, `echo` works.
- `TestHTTPStatic`: `headers: {X-Key: abc}` reaches every request.
- `TestHTTPForward`: calls as alice (token `ta`) and bob (token `tb`) arrive with their own bearer tokens and different `Mcp-Session-Id` values. A second alice call reuses alice's session.
- `TestHTTPForwardDiscovery`: the listing session uses `discovery_headers`, not a caller token.
- `TestHTTPPoolEviction`: with `max_sessions: 1`, a call as bob closes alice's session. With `session_idle_timeout` of 50ms and a fake clock advanced past it, the idle session is closed on the next sweep.
- `TestHTTPTraceHeaders`: `traceparent` and `X-Request-ID` from the context reach the server.
- `TestHTTPServerDown`: closing the `httptest` server makes calls return `ErrUnavailable` or a transport error, and state becomes `down`.

- [ ] **Step 2: Run** `go test ./backend/streamable/` and see it fail.
- [ ] **Step 3: Implement.** `transport.NewStreamableHTTP` with `WithHTTPHeaderFunc` reading forward headers from the context. In `forward` mode, the pool key is `subject + "\x00" + sha256(token)`, the pool is an LRU with `max_sessions` (default 256) and `session_idle_timeout` (default 10m).
- [ ] **Step 4: Run** and see PASS.
- [ ] **Step 5: Commit** `feat(backend): add Streamable HTTP backend with token forwarding` and push.

### Task 9: Audit pipeline with stdout and file sinks

Part of #16. The `sql` sink comes in plan 2, argument redaction is #3.

**Files:**
- Create: `audit/audit.go`, `audit/pipeline.go`, `audit/stdout.go`, `audit/file.go`, `audit/audit_test.go`

**Interfaces:**
- Produces:
  - `audit.Event` with JSON fields exactly as in design.md (Audit log): `time`, `kind`, `request_id`, `trace_id`, `session_id`, `instance`, `subject`, `groups`, `auth`, `project`, `server`, `tool`, `decision`, `rule`, `outcome`, `duration_ms`, `args`, `error`. `omitempty` on optional fields.
  - Outcome constants: `OutcomeOK = "ok"`, `OutcomeToolError = "tool_error"`, `OutcomeDenied = "denied"`, `OutcomeRateLimited = "rate_limited"`, `OutcomeBackendUnavailable = "backend_unavailable"`, `OutcomeTimeout = "timeout"`, `OutcomeCanceled = "canceled"`.
  - `audit.Sink` with `Write(ctx, []Event) error` and `Close() error`. `audit.RegisterSink(kind string, f SinkFactory)`.
  - `audit.NewPipeline(sinks []Sink, opts PipelineOptions) *Pipeline`, `PipelineOptions{ BufferSize int; Block bool; BatchSize int; FlushEvery time.Duration; Logger *slog.Logger }`, `(*Pipeline).Record(Event)`, `(*Pipeline).Dropped() uint64`, `(*Pipeline).Close(ctx) error` (flushes).
  - `audit.NewStdoutSink(w io.Writer) Sink` writes one JSON object per line with `"log":"audit"` first. `audit.NewFileSink(path string) (Sink, error)` appends JSON lines, creating the file with mode 0600.

- [ ] **Step 1: Write the failing tests**
- `TestStdoutSink`: one event becomes one line starting with `{"log":"audit",` and round-trips through `json.Unmarshal`.
- `TestFileSinkAppends`: two pipelines writing to the same path leave both lines.
- `TestPipelineFlushOnClose`: 10 recorded events reach a fake sink after `Close`.
- `TestPipelineDrops`: with buffer 1, a sink that blocks on a channel, and 5 records, `Dropped()` is at least 3 and `Record` never blocks (each call returns before a 1 second deadline).
- `TestPipelineBlockMode`: with `Block: true`, the sixth `Record` waits until the sink is released.
- `TestPipelineSinkError`: a sink returning an error is logged and the pipeline keeps going.

- [ ] **Step 2: Run** `go test ./audit/` and see it fail.
- [ ] **Step 3: Implement** one goroutine reading the channel, batching up to `BatchSize` (200) or `FlushEvery` (500ms), writing to every sink.
- [ ] **Step 4: Run** and see PASS.
- [ ] **Step 5: Commit** `feat(audit): add audit pipeline with stdout and file sinks` and push.

### Task 10: Runtime snapshot from the config file

Part of #17. Revision polling comes in plan 2.

**Files:**
- Create: `internal/runtime/snapshot.go`, `internal/runtime/file.go`, `internal/runtime/runtime_test.go`

**Interfaces:**
- Consumes: `config.Config`, `rules.New`, `apikey.New`.
- Produces:
  - `runtime.Snapshot{ Policy policy.Policy; Authenticator *auth.Chain; Servers []backend.Config; AllowedOrigins []string; Audit config.Audit }`
  - `runtime.Source` interface: `Load(ctx context.Context) (*Snapshot, error)`
  - `runtime.NewFileSource(path string, env func(string) (string, bool)) Source`
  - `runtime.Holder` with `Current() *Snapshot` (atomic) and `Swap(*Snapshot)`
  - `runtime.Watch(ctx, src Source, h *Holder, every time.Duration, onSwap func(*Snapshot), log *slog.Logger)`: reloads when the file's mtime changes. A failed load keeps the old snapshot and logs `config reload failed`.

- [ ] **Step 1: Write the failing tests**
- `TestFileSourceBuildsSnapshot`: a file with one rule and one API key gives a snapshot whose policy allows the rule's tool and whose chain accepts the key.
- `TestWatchSwaps`: rewriting the file with a new rule swaps the snapshot (poll `Current()` with a deadline, interval 10ms).
- `TestWatchKeepsOldOnError`: writing invalid YAML leaves `Current()` unchanged and logs one error.
- `TestHolderConcurrent`: readers calling `Current()` while a writer swaps 1000 times see only complete snapshots.

- [ ] **Step 2: Run** `go test ./internal/runtime/` and see it fail.
- [ ] **Step 3: Implement.** On Unix, a SIGHUP also triggers a reload, in a file with a `//go:build !windows` tag.
- [ ] **Step 4: Run** and see PASS.
- [ ] **Step 5: Commit** `feat(runtime): build the runtime snapshot from the config file` and push.

### Task 11: Gateway

Covers #14.

**Files:**
- Create: `internal/gateway/gateway.go`, `internal/gateway/catalog.go`, `internal/gateway/sessions.go`, `internal/gateway/gateway_test.go`

**Interfaces:**
- Consumes: `backend.Set`, `runtime.Holder`, `audit.Pipeline`, `naming`, `auth.FromContext`, `policy.Request`.
- Produces:
  - `gateway.New(opts Options) *Gateway`, `Options{ Backends *backend.Set; Runtime *runtime.Holder; Audit *audit.Pipeline; Logger *slog.Logger; Instance string; Version string }`
  - `(*Gateway).MCPServer() *server.MCPServer`
  - `(*Gateway).HTTPHandler() http.Handler`: the Streamable HTTP endpoint with authentication and session binding in front.
  - `(*Gateway).ServeStdio(ctx context.Context, in io.Reader, out io.Writer, id *auth.Identity) error`
  - `(*Gateway).Refresh()`: rebuilds the catalog from every backend's tools and calls `SetTools`.

- [ ] **Step 1: Write the failing tests.** Two backends (`alpha` and `beta`, both `mcpserver.New` over in-process HTTP) behind a gateway, the rules from design.md adapted to `alpha__*` and `beta__*`, and two API keys. Clients are mcp-go Streamable HTTP clients against `httptest.NewServer(g.HTTPHandler())`.
- `TestListFiltered`: the `eng` key sees `alpha__echo` and `beta__echo`, the `interns` key sees only `beta__echo`.
- `TestCallRouted`: `alpha__echo` returns the text and the audit sink got one record with `server: alpha`, `tool: echo`, `decision: allow`, `outcome: ok`, the rule name and a `request_id`.
- `TestHiddenLooksMissing`: the interns key calling `alpha__echo` and calling `nope__x` gives the same error code and message. The first is audited as `denied` with `rule: default-deny`.
- `TestToolErrorPassesThrough`: `alpha__fail` returns `IsError` with the backend's text, audited as `tool_error`.
- `TestNoTokenIs401`: a request without a token gets 401 with a `WWW-Authenticate: Bearer` header.
- `TestSessionHijack`: a request carrying the eng client's `Mcp-Session-Id` but the interns key gets 403.
- `TestListChangedReachesClient`: calling `alpha__add_tool` makes the eng client receive `notifications/tools/list_changed`, and the next list contains `alpha__new`.
- `TestBackendDown` (review focus 3): after alpha's server closes, `alpha__echo` returns an `IsError` result saying `server alpha is unavailable` before the call timeout, audited as `backend_unavailable`, and `alpha__echo` is still listed.
- `TestConcurrentRefresh` (review focus 4): 20 goroutines call `beta__echo` while another calls `Refresh` 50 times. Every call succeeds.
- `TestNameMapping` (review focus 5): a backend tool `a__b` is exposed as `alpha__a__b` and the call reaches `a__b`. The `bad name` tool is skipped, a warning naming it is logged, and `alpha__echo` is still listed.
- `TestStdioDownstream`: `ServeStdio` over `io.Pipe` with identity `user:local` in group `eng` lists the eng tools.

- [ ] **Step 2: Run** `go test ./internal/gateway/` and see it fail.
- [ ] **Step 3: Implement.**
  - The mcp-go server uses `WithToolCapabilities(true)`, `WithToolFilter` calling the current policy for each tool (with `Args` nil), and `WithToolHandlerMiddleware` for audit and timing.
  - Each catalog entry's handler re-checks the policy with arguments, calls the backend with the original tool name, and maps `backend.ErrUnavailable` to `mcp.NewToolResultError("server <name> is unavailable")`, `context.DeadlineExceeded` to outcome `timeout`, and `context.Canceled` to `canceled`.
  - `HTTPHandler` authenticates with the snapshot's chain, stores the identity and forward headers in the request context, generates `X-Request-ID` when missing, and uses `WithHTTPContextFunc` to carry them into mcp-go. Session binding: an `OnRegisterSession` hook records `session ID -> subject`, `OnUnregisterSession` removes it, and the handler returns 403 when the `Mcp-Session-Id` header belongs to another subject.
  - `Refresh` runs on every backend `OnToolsChanged` and on `Set.OnChange`.
- [ ] **Step 4: Run** `go test ./internal/gateway/` and see PASS.
- [ ] **Step 5: Commit** `feat(gateway): serve one filtered, audited MCP endpoint for all backends` and push. Update AGENTS.md layout and add a CHANGELOG line.

### Task 12: HTTP listener and `serve`

Part of #25 and #26.

**Files:**
- Create: `internal/httpx/server.go`, `internal/httpx/origin.go`, `internal/httpx/httpx_test.go`
- Create: `cmd/airlock/serve.go`, `cmd/airlock/serve_test.go`
- Modify: `cmd/airlock/main.go` (add `serve` to the switch and usage)

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `httpx.NewMux(mcp http.Handler, ready func() error) *http.ServeMux` with `/mcp`, `/healthz` (200 `ok`) and `/readyz` (200 with `{"status":"ok"}`, or 503 with the failing check).
  - `httpx.CheckOrigin(allowed []string, next http.Handler) http.Handler`: requests with no `Origin` pass. An `Origin` that matches none of the globs (`http://localhost:*` style, using `glob.Match`) gets 403.
  - `serve(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, env func(string) (string, bool)) int`

- [ ] **Step 1: Write the failing tests**
- `TestCheckOrigin` table: no Origin passes, `http://localhost:3000` passes `http://localhost:*`, `https://evil.example` gets 403.
- `TestReadyz`: 200 when the check returns nil, 503 with the error text in JSON when it does not.
- `TestServeHTTP`: `serve` with a temp config on `127.0.0.1:0` (the bound address is written to stderr as a JSON log line `listening` with `addr`), backed by the built test server binary from `internal/testutil`. An mcp-go client with an API key lists `demo__echo` and calls it. Canceling the context makes `serve` return 0.
- `TestServeStdio`: `serve --stdio` with stdin and stdout pipes answers `initialize` and `tools/list`, and nothing but JSON-RPC appears on stdout.
- `TestServeBadConfig`: an invalid file makes `serve` return 1 and print the validation error to stderr.

- [ ] **Step 2: Run** `go test ./internal/httpx/ ./cmd/airlock/` and see it fail.
- [ ] **Step 3: Implement.** `serve` loads the file source, builds the backend set and the audit pipeline from the snapshot, starts `runtime.Watch` (calling `Set.Apply` on swap), and runs `http.Server` until the context ends, then shuts down with a 10 second timeout. `main` passes a context canceled on SIGINT and SIGTERM. The logger writes JSON to stdout in HTTP mode and to stderr in stdio mode. `/readyz` fails while any `required: true` backend is not `up`.
- [ ] **Step 4: Run** `go test ./...` and see PASS. Run `golangci-lint run ./...` and see 0 issues.
- [ ] **Step 5: Commit** `feat(cli): add airlock serve over HTTP and stdio` and push. Update README's "A taste" to say the file-based flow works, add the CHANGELOG line, update AGENTS.md commands.

### Task 13: Coverage and branch check

- [ ] **Step 1:** Run `go test -coverprofile=cover.out ./...` then `go run github.com/vladopajic/go-test-coverage/v2@v2.21.0 --config=.testcoverage.yml`. Expected: total at least 80%. If below, add tests for the uncovered branches the report names, not for trivial getters.
- [ ] **Step 2:** Run `gh run list --limit 3` after the last push and confirm `ci` and `codeql` are green. If a job fails, read its log with `gh run view --log-failed` and fix the cause.
- [ ] **Step 3: Commit** any test additions as `test: raise coverage for the gateway core` and push.
