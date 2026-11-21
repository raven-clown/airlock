# AGENTS.md

Instructions for coding agents working in this repository. Keep this file current: when a command, a package layout or a rule changes, update it in the same commit.

## Project

airlock is an MCP gateway. Clients connect to one MCP endpoint and reach many MCP servers behind it, over stdio or Streamable HTTP. airlock adds OIDC and API key login, per-user and per-group tool permissions, an audit log, rate limits and filtered tool lists, and serves a JSON admin API under `/admin/v1/` for a future console. Teams run it in front of their MCP servers, and agents in the mothership set call tools through it. The design is in `docs/design.md`.

It is one of four projects described in the shared contract at https://github.com/raven-clown/mothership/blob/main/CONTRACT.md. Follow the contract. A change to how the projects connect goes to the contract first.

## Commands

```shell
go build ./...
go test -race ./...
golangci-lint run ./...
make check   # lint plus tests with the 80% coverage check
```

Run it locally with `go run ./cmd/airlock serve --config airlock.yaml`, or `--stdio` for one local client.

On Windows without a C compiler, run `go test ./...` locally. CI runs `-race` on Linux and macOS.

The store suite and the two-replica test also run on Postgres: `AIRLOCK_TEST_POSTGRES_DSN=postgres://... go test -tags integration ./internal/store/... ./internal/admin/...`. CI does this in the `postgres` job. Store changes go through `internal/store/storetest`, so both engines get the same tests. A migration after `0001` only adds tables and columns that are nullable or have a default; `TestMigrationsExpandOnly` fails otherwise, unless the file says `-- contract:` and why.

## Layout

Only packages that exist are listed. `internal/secrets` (encrypted secret fields) and the `validate`, `check` and `tools` commands are planned in `docs/design.md`.

- `cmd/airlock`: the CLI (`serve`, `migrate`, `bootstrap-key`, `keys new`, `version`, `help`). `serve` wires everything: provisioning, the first-start key, the reloader, metrics, the tracer, the gateway, the admin API and the listeners
- `auth`, `auth/apikey`, `auth/oidc`: identities and the authenticator chain. `auth/oidc` checks JWTs against a cached JWKS; `auth/oidc/oidctest` is a local issuer for tests
- `policy`, `policy/glob`, `policy/rules`: the policy interface, `*` matching and the built-in allow and deny rules
- `backend`, `backend/stdio`, `backend/streamable`: the backend interface and the two transports
- `audit`: records, the pipeline and the stdout and file sinks
- `ratelimit`: rates (`30/m`) and the counter `Store` interface, with an in-memory GCRA store. A shared store for replicas goes behind the same interface
- `telemetry`: the Prometheus registry and airlock's metrics, and the tracer with its OTLP/HTTP exporter. No label or span attribute may hold a subject, a key, a token or tool arguments
- `internal/limits`: the shared profiles (`requests`, `tools.calls`), profile resolution and the limiter
- `internal/naming`: building, checking and splitting `<server>__<tool>` names
- `internal/config`: YAML loading, env overrides and `Validate`, which the admin API uses too
- `internal/store`: SQLite and Postgres stores and migrations. `Create`, `Update` and `Delete` take audit events that commit in the same transaction
- `internal/provision`: syncing file-declared resources into the store, and watching the file
- `internal/runtime`: the immutable snapshot (policy, authenticators, roles, limiter), `StoreSource.ConfigWith` to check a change before it is written, and the `Reloader` that swaps snapshots every 2 seconds and right after an admin write
- `internal/httpx`: forwarded headers, the mux, the Origin check, and `Front`, which every authenticated route goes through (request id, span, metrics, `max_inflight`, sign-in, the `requests` limit)
- `internal/gateway`: the mcp-go server, catalog and router, with the `tools.calls` limit, tool metrics and spans
- `internal/admin`: the `/admin/v1/` handlers and the first-start bootstrap. `spec_test.go` checks that the served routes and `api/openapi.yaml` match both ways and validates every response the tests get against the file, so a new endpoint goes in the file first
- `internal/testutil`: test fakes and the test MCP server
- `api/openapi.yaml`: the admin API description, embedded by package `api`
- `docs/`: design, milestone issues, and implementation plans in `docs/plans/`

## Rules

- Follow CONTRIBUTING.md: tests with every change, a failing test first for a bug fix, table-driven tests, no network in unit tests, no bare `time.Sleep`.
- Work on a branch off main named `feat/<topic>`, `fix/<topic>`, `ci/<topic>`, `docs/<topic>` or `deps/<topic>`. Never commit straight to main and never force-push it.
- Commit after every change, with a Conventional Commits message, and push the branch.
- When the work is done, open a PR with a Conventional Commits title and a plain English description. Wait for every required check to pass: the three test jobs, coverage, lint, analyze, dependency review and pr title. A macOS job cancelled while waiting for a runner gets `gh run rerun <id> --failed` and is not a failure. Never merge a red PR.
- Merge your own green PR with `gh pr merge <n> --squash --delete-branch --admin --subject "<pr title> (#<n>)" --body ""` (the explicit subject and empty body keep a co-author trailer off the squash commit), then `git switch main && git pull && git branch -D <branch>`.
- Fill in `.github/PULL_REQUEST_TEMPLATE.md`, including the project checks. Issues use the forms in `.github/ISSUE_TEMPLATE/`: bug report, feature request, new adapter and docs.
- Release after every finished plan, at the latest main: a `chore(release): vX.Y.Z` pull request moves the Unreleased entries in CHANGELOG.md under the version, and once it merges, `gh release create vX.Y.Z --target <merge commit>` tags that commit. A plan bumps the minor version, a fix-only release the patch. Check that no release pull request is open before merging anything else.
- A bug or a missing feature in mcp-go gets a reproduction, an issue and a PR on mark3labs/mcp-go, after checking for existing ones. Work around it here with the issue link next to the workaround. Never point go.mod at a fork.
- Never mention AI, assistants or code generation in code, comments, docs, commit messages, pull requests or issues.
- Never add `Co-Authored-By`, `Generated with` or similar trailers.
- No em-dashes. Keep comments short and about why.
- Every feature ships in the free build. Never add a license check or a paid-only code path.
- Update CHANGELOG.md under Unreleased for anything users will notice, and update README.md when usage changes.
