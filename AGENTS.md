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

The store suite also runs on Postgres: `AIRLOCK_TEST_POSTGRES_DSN=postgres://... go test -tags integration ./internal/store/...`. CI does this in the `postgres` job. Store changes go through `internal/store/storetest`, so both engines get the same tests.

## Layout

Built so far: `cmd/airlock` (`serve`, `migrate`, `version`, `help`), `internal/naming`, `policy`, `policy/glob`, `policy/rules`, `auth`, `auth/apikey`, `backend`, `backend/stdio`, `backend/streamable`, `audit` (pipeline, stdout and file sinks), `internal/config`, `internal/httpx` (forwarded headers, mux, Origin check), `internal/runtime` (snapshots from the store), `internal/store` (SQLite and Postgres), `internal/provision`, `internal/gateway` and `internal/testutil`. The rest is the planned layout from `docs/design.md`:

- `cmd/airlock`: the CLI (`serve`, `validate`, `migrate`, `check`, `tools`, `keys new`, `bootstrap-key`, `version`)
- `auth`, `policy`, `backend`, `audit`, `ratelimit`: public plugin interfaces and registries, with built-ins in subpackages
- `policy/glob`: `*` wildcard matching for tool patterns
- `telemetry`: Prometheus metrics and OTLP tracing
- `internal/naming`: building, checking and splitting `<server>__<tool>` names
- `internal/config`: YAML loading, env overrides, file watching
- `internal/store`: SQLite and Postgres stores and migrations
- `internal/provision`: syncing file-declared resources into the store
- `internal/runtime`: the immutable snapshot swapped on each revision
- `internal/gateway`: the mcp-go server, catalog and router
- `internal/admin`: admin API handlers generated from `api/openapi.yaml`
- `internal/secrets`: encryption of secret fields at rest
- `internal/httpx`: listener, health, readiness and metrics routes
- `internal/testutil`: test fakes and the test MCP server
- `api/openapi.yaml`: the admin API description, source of truth for its handlers
- `docs/`: design, milestone issues, and implementation plans in `docs/plans/`

## Rules

- Follow CONTRIBUTING.md: tests with every change, a failing test first for a bug fix, table-driven tests, no network in unit tests, no bare `time.Sleep`.
- Work on a branch off main named `feat/<topic>`, `fix/<topic>`, `ci/<topic>`, `docs/<topic>` or `deps/<topic>`. Never commit straight to main and never force-push it.
- Commit after every change, with a Conventional Commits message, and push the branch.
- When the work is done, open a PR with a Conventional Commits title and a plain English description. Wait for every required check to pass: the three test jobs, coverage, lint, analyze, dependency review and pr title. A macOS job cancelled while waiting for a runner gets `gh run rerun <id> --failed` and is not a failure. Never merge a red PR.
- Merge your own green PR with `gh pr merge <n> --squash --delete-branch --admin`, then `git switch main && git pull && git branch -D <branch>`.
- A bug or a missing feature in mcp-go gets a reproduction, an issue and a PR on mark3labs/mcp-go, after checking for existing ones. Work around it here with the issue link next to the workaround. Never point go.mod at a fork.
- Never mention AI, assistants or code generation in code, comments, docs, commit messages, pull requests or issues.
- Never add `Co-Authored-By`, `Generated with` or similar trailers.
- No em-dashes. Keep comments short and about why.
- Every feature ships in the free build. Never add a license check or a paid-only code path.
- Update CHANGELOG.md under Unreleased for anything users will notice, and update README.md when usage changes.
