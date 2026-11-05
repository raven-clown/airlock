# Store and provisioning implementation plan

Plan 2 of 4 for v0.1.0. Plan 1 built the gateway core on a YAML-only snapshot. This plan moves state into SQL. Plan 3 adds the admin API, first start and encrypted secrets. Plan 4 adds OIDC, rate limits, the remaining CLI commands, metrics, the demo and release builds.

**Goal:** `airlock serve` keeps servers, rules, API keys, role bindings and settings in SQLite (default) or Postgres. The YAML file provisions into the store, every instance reloads when the store's revision moves, and every tool call lands in the `audit_events` table.

**Architecture:** `internal/store` holds one table per resource kind with the same columns (`org_id`, `name`, `source`, `version`, `spec` as JSON, timestamps), plus `audit_events` and `revision`. Every write runs in a transaction that locks the org's revision row first and bumps it when something changed. `internal/provision` turns the parsed file into rows and replaces the `source: file` rows in one transaction, and watches the file. `runtime.StoreSource` uses the revision as its version and rebuilds the snapshot from the rows, so `runtime.Watch` from plan 1 does the polling unchanged.

**Tech stack:** Go 1.26, `modernc.org/sqlite`, `github.com/jackc/pgx/v5/stdlib`, `database/sql`, `embed`, plus what plan 1 uses.

**Spec:** [docs/design.md](../design.md), sections Storage, Provisioning from YAML, The runtime snapshot, Audit log, Config file.

## Global constraints

- Everything from plan 1's Global constraints still holds.
- No cgo: both drivers are pure Go.
- Every table has `org_id`, and every query filters by it. The org is `default` until organisations ship.
- Hand-written SQL that runs on both engines. Queries are written with `?` and rewritten to `$n` for Postgres.
- Migrations are embedded, numbered, one folder per engine, applied in a transaction, tracked in `schema_migrations`. A schema newer than the binary is a startup error.
- SQLite: WAL mode, busy timeout 5000 ms, one open connection.
- Default `storage.driver` is `sqlite`, default `storage.dsn` is `file:airlock.db`.
- Writes through the store bump the org's revision in the same transaction. Audit inserts do not.
- Rows from the file have `source: file`. Store updates and deletes refuse them with `ErrManagedByFile`. The file never touches `source: api` rows. A name on both sides fails provisioning and changes nothing.
- Times are stored as Unix milliseconds in integer columns.
- Tests: every store test runs on SQLite, and on Postgres under the `integration` build tag with `AIRLOCK_TEST_POSTGRES_DSN`.

## Review focus

1. **Two replicas provision the same file at once on Postgres.** Both succeed, there is one row per name, and the revision moves once. Test in Task 3, run under the integration tag too.
2. **A database migrated by a newer airlock.** Startup fails with an error that names both schema versions, and nothing is written. Test in Task 2.
3. **The file declares a server whose name an admin already created through the API.** Provisioning fails with an error naming the kind and the name, and no row changes, including rows for other kinds in the same file. Test in Task 3.
4. **Restarting with an unchanged file.** Provisioning reports no change and the revision stays put, so replicas do not reload for nothing. Test in Task 3.
5. **Starting without `--config` after a file was used before.** The old file rows are removed, API rows stay. Test in Task 3.

---

### Task 1: Storage, settings and role bindings in the config file

Part of #6.

**Files:**
- Modify: `internal/config/config.go`, `internal/config/config_test.go`

**Interfaces:**
- Produces:
  - `Config` gains `Storage Storage` (`storage`), `Settings Settings` (`settings`) and `RoleBindings []RoleBinding` (`role_bindings`). The top-level `allowed_origins` key moves to `settings.allowed_origins`.
  - `type Storage struct { Driver, DSN string }` with yaml `driver`, `dsn`. Defaults `sqlite`, `file:airlock.db`.
  - `type Settings struct { AllowedOrigins []string }` with yaml and json tag `allowed_origins`. Each top-level settings key is one row in the store.
  - `type RoleBinding struct { Name string; Subjects []string; Role string }` with yaml and json tags in snake_case.
  - Roles: `RoleAdmin = "admin"`, `RoleMember = "member"`, `RoleViewer = "viewer"`.
  - `storage` and `settings` are expanded at load like the other process keys.

- [ ] **Step 1: Write the failing tests.** Extend `TestParseDefaults` with the storage defaults. `TestEnvOverride` gains `AIRLOCK_STORAGE__DSN=file:x.db`. `TestValidate` gains: driver `mysql` (error at `storage.driver`), role binding without a name, duplicate role binding names, role `owner` (error at `role_bindings[0].role`), role binding without subjects. `TestSettings`: `settings.allowed_origins` parses, top-level `allowed_origins` is now an unknown key.
- [ ] **Step 2: Run** `go test ./internal/config/` and see the new cases fail.
- [ ] **Step 3: Implement** the types, defaults and checks in `normalize`. Update `runtime.Build` and `serve.go` to read `Settings.AllowedOrigins`.
- [ ] **Step 4: Run** `go test ./...` and see PASS.
- [ ] **Step 5: Commit** `feat(config): add storage, settings and role bindings` and push.

### Task 2: SQL store on SQLite

Covers #7.

**Files:**
- Create: `internal/store/store.go`, `internal/store/resources.go`, `internal/store/migrate.go`, `internal/store/dialect.go`, `internal/store/migrations/sqlite/0001_init.sql`, `internal/store/migrations/postgres/0001_init.sql`
- Create: `internal/store/storetest/storetest.go`, `internal/store/sqlite_test.go`, `internal/store/dialect_test.go`

**Interfaces:**
- Produces:
  - `const DefaultOrg = "default"`
  - `type Kind string` with `KindServers`, `KindRules`, `KindAPIKeys`, `KindRoleBindings`, `KindSettings` (table names `servers`, `rules`, `api_keys`, `role_bindings`, `settings`). Table names come only from this list.
  - `const SourceFile = "file"`, `SourceAPI = "api"`
  - `type Row struct { Name, Source string; Version int64; Spec json.RawMessage; CreatedAt, UpdatedAt time.Time }`
  - Errors: `ErrNotFound`, `ErrExists`, `ErrVersionConflict`, `ErrManagedByFile`, `ErrSchemaTooNew`.
  - `func Open(ctx context.Context, driver, dsn string) (*Store, error)`: opens, migrates, returns. Driver `sqlite` or `postgres`.
  - `(*Store).Close() error`, `Ping(ctx) error`, `SchemaVersion(ctx) (int, error)`
  - `Get(ctx, org string, k Kind, name string) (Row, error)`
  - `List(ctx, org string, k Kind, after string, limit int) ([]Row, error)`: sorted by name, names greater than `after`, `limit <= 0` means all.
  - `Create(ctx, org string, k Kind, name string, spec json.RawMessage) (Row, error)`: `source: api`, version 1.
  - `Update(ctx, org string, k Kind, name string, version int64, spec json.RawMessage) (Row, error)`: version must match, then +1.
  - `Delete(ctx, org string, k Kind, name string, version int64) error`
  - `Revision(ctx, org string) (int64, error)`: 0 for an org that never had a write.
  - `storetest.Run(t *testing.T, open func(t *testing.T) *store.Store)`: the shared suite. Each subtest uses its own random org, so one database serves the whole run.

The `0001_init.sql` files create `schema_migrations(version, applied_at)`, the five resource tables with primary key `(org_id, name)`, `api_keys.last_used_at` (nullable, for plan 3), `revision(org_id primary key, value)`, and `audit_events` with one column per `audit.Event` field (`groups` and `args` as JSON text, `time` as Unix ms) and an index on `(org_id, time)`.

- [ ] **Step 1: Write the failing tests.** `storetest.Run` subtests:
  - `CreateGet`: create then get returns the spec, source `api`, version 1, timestamps set. Create again gives `ErrExists`.
  - `List`: five rows, `after` and `limit` page through them in name order. Another org's rows never show.
  - `Update`: right version bumps to 2 and changes `updated_at`; stale version gives `ErrVersionConflict`; missing name gives `ErrNotFound`.
  - `Delete`: stale version gives `ErrVersionConflict`, right version removes, second delete gives `ErrNotFound`.
  - `Revision`: starts at 0, each create, update and delete adds 1, failed writes add nothing, other orgs are separate.
  - `AllKinds`: create, get and delete work for every kind.
  `sqlite_test.go`: `TestSQLite` runs the suite on a file in `t.TempDir()`. `TestSchemaTooNew` (review focus 2): insert version 999 into `schema_migrations`, reopen, get `ErrSchemaTooNew` with `999` and the known version in the message. `TestReopenKeepsData`. `TestWAL`: `PRAGMA journal_mode` returns `wal`. `TestUnknownDriver`.
  `dialect_test.go`: `rebind("a = ? AND b = ?")` gives `a = $1 AND b = $2` for Postgres and is unchanged for SQLite, `?` inside quotes untouched.
- [ ] **Step 2: Run** `go test ./internal/store/...` and see it fail.
- [ ] **Step 3: Implement.** SQLite DSN gets `_pragma=journal_mode(WAL)` and `_pragma=busy_timeout(5000)` appended, and `SetMaxOpenConns(1)`. Each write transaction first runs `INSERT INTO revision (org_id, value) VALUES (?, 0) ON CONFLICT DO NOTHING` and `UPDATE revision SET value = value WHERE org_id = ?`, which takes the row lock on Postgres, then does its work, then bumps the revision if it changed a row. Add `modernc.org/sqlite` to go.mod.
- [ ] **Step 4: Run** and see PASS. Run `golangci-lint run ./...`.
- [ ] **Step 5: Commit** `feat(store): add the SQL store with SQLite and migrations` and push. AGENTS.md Layout lists `internal/store`.

### Task 3: Provisioning from the file

Covers #18.

**Files:**
- Create: `internal/store/provision.go` (store side), `internal/provision/provision.go`, `internal/provision/watch.go`, `internal/provision/provision_test.go`
- Move: `internal/runtime/signal_unix.go`, `internal/runtime/signal_windows.go` to `internal/provision`
- Modify: `internal/store/storetest/storetest.go`

**Interfaces:**
- Consumes: `config.Config` (Task 1), `store.Store` (Task 2).
- Produces:
  - `(*Store).Provision(ctx, org string, want map[Kind]map[string]json.RawMessage) (changed bool, err error)`: in one transaction, for every kind in `want`, upserts the named rows as `source: file` (version +1 only when the spec differs), deletes `source: file` rows of that kind not named, and bumps the revision once if anything changed. A name held by a `source: api` row returns `*NameTakenError{Kind Kind; Name string}` and rolls back everything. Every kind is always present in `want`, possibly empty.
  - `provision.Rows(cfg *config.Config) (map[store.Kind]map[string]json.RawMessage, error)`: servers by name, rules by name, API keys by name, role bindings by name, and one settings row per top-level key of `Settings` marshalled to JSON.
  - `provision.Apply(ctx, st *store.Store, org string, cfg *config.Config) (bool, error)`
  - `provision.Watch(ctx, path string, env config.Env, st *store.Store, org string, opts WatchOptions)`, `type WatchOptions struct { Every time.Duration; Logger *slog.Logger; Ready chan<- struct{}; Process *config.Config }`. Checks the file's SHA-256 every `Every` and on SIGHUP. On change it loads and applies the file. A load or apply error logs `config reload failed` and changes nothing. When process keys (`listen_addr`, `storage`, `stdio`, `audit`) differ from `Process`, it logs a warning `restart airlock to apply` naming the keys.

- [ ] **Step 1: Write the failing tests.** Add storetest subtests:
  - `ProvisionAddChangeRemove`: add two servers, change one (version 2), drop one; API rows of the same kind stay.
  - `ProvisionUnchanged` (review focus 4): the same input twice, second call `changed == false` and the revision is unchanged.
  - `ProvisionNameTaken` (review focus 3): an API server `github`, then a file with rule `r1` and server `github` returns `*NameTakenError{KindServers, "github"}`, and rule `r1` does not exist afterwards.
  - `ProvisionConcurrent` (review focus 1): eight goroutines provision the same input at once; all succeed, one row per name, the revision moved by exactly 1.
  - `ManagedByFile`: a provisioned row refuses `Update` and `Delete` with `ErrManagedByFile`, and `Create` with its name gives `ErrExists`.
  - `ProvisionEmpty` (review focus 5): file rows of every kind are removed by an empty input, API rows stay.
  `provision_test.go`: `TestRows` checks the keys and that `${VAR}` in a server env stays literal in the spec. `TestWatchApplies`: rewrite the file, the store gets the new server. `TestWatchBadFile`: a broken file logs `config reload failed` and the rows stay. `TestWatchProcessWarning`: changing `listen_addr` logs the warning naming `listen_addr`.
- [ ] **Step 2: Run** `go test ./internal/store/... ./internal/provision/` and see it fail.
- [ ] **Step 3: Implement.** The error text for `NameTakenError` is `servers "github" was created through the admin API; rename one of them`.
- [ ] **Step 4: Run** and see PASS.
- [ ] **Step 5: Commit** `feat(provision): sync file resources into the store` and push. AGENTS.md lists `internal/provision`.

### Task 4: SQL audit sink and retention

Part of #16.

**Files:**
- Create: `internal/store/audit.go`, `internal/store/storetest/audit.go`
- Modify: `internal/config/config.go` (`audit.retention`), `internal/config/config_test.go`

**Interfaces:**
- Consumes: `audit.Event`, `audit.Sink`.
- Produces:
  - `(*Store).InsertAudit(ctx, org string, events []audit.Event) error`: one transaction, one prepared insert per event, no revision bump.
  - `(*Store).ListAudit(ctx, org string, limit int) ([]audit.Event, error)`: newest first. Plan 3 adds filters and cursors.
  - `(*Store).DeleteAuditBefore(ctx, org string, before time.Time) (int64, error)`
  - `(*Store).AuditSink(org string) audit.Sink`
  - `config.Audit` gains `Retention time.Duration` (`retention`), default `720h`, must be positive.

- [ ] **Step 1: Write the failing tests.** storetest subtests: `AuditRoundTrip` writes one event with every field set and reads back an equal event (time at ms precision). `AuditRetention` deletes only rows older than the cutoff and only in its org. `AuditNoRevision`: inserting events leaves the revision alone. `AuditSink` writes through the `audit.Sink` interface. Config: default retention, `retention: 0s` is an error at `audit.retention`.
- [ ] **Step 2: Run** and see it fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** and see PASS.
- [ ] **Step 5: Commit** `feat(store): store audit records in SQL with retention` and push.

### Task 5: Postgres

Covers #8.

**Files:**
- Create: `internal/store/postgres.go`, `internal/store/postgres_integration_test.go` (build tag `integration`)
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Produces: `Open(ctx, "postgres", dsn)` through the `pgx` driver. Migrations hold `pg_advisory_lock(7413020)` on one connection while they run.

- [ ] **Step 1: Write the failing test.** `TestPostgres` skips when `AIRLOCK_TEST_POSTGRES_DSN` is empty, otherwise runs `storetest.Run`. `TestPostgresConcurrentOpen`: four `Open` calls at once on a fresh schema all succeed and `SchemaVersion` is the latest.
- [ ] **Step 2: Add the CI job** `postgres` on ubuntu with a `postgres:17` service and `go test -race -tags integration ./internal/store/...`, and push to see it fail.
- [ ] **Step 3: Implement.** Add `github.com/jackc/pgx/v5` to go.mod.
- [ ] **Step 4: Run** `go build -tags integration ./...` and `go vet -tags integration ./internal/store/` locally, and confirm the CI job passes.
- [ ] **Step 5: Commit** `feat(store): add Postgres` and push.

### Task 6: Snapshot from the store

Covers #17.

**Files:**
- Create: `internal/runtime/store.go`
- Modify: `internal/runtime/snapshot.go`, `internal/runtime/runtime_test.go`
- Delete: `internal/runtime/file.go`

**Interfaces:**
- Consumes: `store.Store`, `provision.Rows` keys and spec shapes (Task 3).
- Produces:
  - `Snapshot` gains `Settings config.Settings`, `RoleBindings []config.RoleBinding`, `Revision int64`, and loses `AllowedOrigins`.
  - `runtime.NewStoreSource(st *store.Store, org string, process *config.Config) *StoreSource`. `Load` reads every kind, decodes the specs into a copy of `process`, and calls `Build`. `Version` is the revision as a decimal string.
  - `Build` copies `Settings` and `RoleBindings`.

- [ ] **Step 1: Write the failing tests.** `TestStoreSourceBuildsSnapshot`: provision a config, load, check policy, keys, servers and settings. `TestWatchStoreSwaps`: an API write (`st.Create` of a rule) swaps the snapshot within the deadline. `TestStoreSourceBadRow`: a rule row with invalid JSON makes `Load` fail and `Watch` keep the old snapshot. `TestConcurrentReaders`: readers call `Current()` in a loop while ten swaps happen, every read sees a complete snapshot.
- [ ] **Step 2: Run** `go test ./internal/runtime/` and see it fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `go test ./...` and see PASS.
- [ ] **Step 5: Commit** `feat(runtime): build snapshots from the store and poll its revision` and push.

### Task 7: Wire the store into `serve` and add `migrate`

Closes #7, #17, #18. Part of #16, #26.

**Files:**
- Modify: `cmd/airlock/serve.go`, `cmd/airlock/serve_test.go`, `cmd/airlock/main.go`, `cmd/airlock/main_test.go`
- Create: `cmd/airlock/migrate.go`, `cmd/airlock/retention.go`, `cmd/airlock/retention_test.go`
- Modify: `README.md`, `CHANGELOG.md`, `AGENTS.md`, `docs/design.md` (role binding `name`, settings rows)

**Interfaces:**
- Consumes: everything above.
- Produces:
  - `serve`: parse config, `store.Open`, `provision.Apply` (an error exits 1), `NewStoreSource`, then backends and gateway as before. Two loops: `provision.Watch` for the file and `runtime.Watch` on the store, both every 2 seconds. The SQL audit sink is always first in the sink list. `/readyz` also fails when `st.Ping` fails, with check name `store`.
  - `runRetention(ctx, st *store.Store, org string, every time.Duration, retention time.Duration, now func() time.Time, log *slog.Logger)`: deletes old audit rows at start and then every `every` (an hour in `serve`).
  - `airlock migrate [--config f]`: opens the store, prints `schema version N` and exits 0.

- [ ] **Step 1: Write the failing tests.** Serve tests pass `AIRLOCK_STORAGE__DSN` pointing into `t.TempDir()`. `TestServeHTTP` also checks that the tool call shows up in `ListAudit`. `TestServeReloadsFromStore`: while serving, `st.Create` a rule through a second `store.Open` on the same file; the tool becomes callable within the deadline. `TestServeNameTaken`: an API row and a file row with the same name make `serve` exit 1 with the error on stderr. `TestMigrate` prints the version. `TestRetention` deletes old rows on the first tick.
- [ ] **Step 2: Run** `go test ./cmd/airlock/` and see it fail.
- [ ] **Step 3: Implement**, then update README (storage section and the `settings.allowed_origins` move), CHANGELOG (store, Postgres, provisioning, SQL audit, `migrate`), AGENTS.md Layout and Commands, and design.md.
- [ ] **Step 4: Run** `make check` (or `go test ./...` plus lint and coverage on Windows) and see PASS with coverage at least 80%.
- [ ] **Step 5: Commit** `feat: keep state in the store and add airlock migrate` and push.
