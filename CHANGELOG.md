# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- OIDC sign-in from any provider through discovery and a cached JWKS, set in `settings.oidc` (`issuer`, `audience`, `jwks_url`, `subject_claim`, `groups_claim`, `profile_claim`). A 401 points MCP clients at `/.well-known/oauth-protected-resource`, and an issuer that cannot be reached answers 503 `auth_unavailable`.
- The `admin`, `viewer` and `member` roles from `role_bindings`.
- The admin API under `/admin/v1/`, described in `api/openapi.yaml` and served at `/admin/v1/openapi.yaml`: status, tools, servers, rules, API keys (with revoke), role bindings, settings, profiles, profile bindings, `/me`, `/me/tools`, `/check` and `/audit` with filters. Lists page with `cursor` and `limit`, writes take `If-Match`, PATCH is a JSON merge patch, items from the file are read-only, and every write is checked against the whole config, stored with its audit record and live on that instance before the answer. Server `env` values and secret-looking header values must be `${VAR}` references, so the API never stores a secret.
- On a store with no role bindings, `airlock serve` prints an admin API key once to stderr. `airlock bootstrap-key` makes a new one, and `airlock keys new` prints a key with its config file entry.
- Limits from the shared mothership profiles: `profiles`, `profile_bindings`, `settings.default_profile` and `settings.org_profile`, with `requests` and `tools.calls` (`rate`, `concurrency`). Requests over the limit get 429 with `Retry-After`, every response sends `RateLimit-Policy` and `RateLimit`, and `limits.max_inflight` answers 503 `overloaded` past a per-instance cap.
- `/metrics` with `airlock_requests_total`, `airlock_request_duration_seconds`, `airlock_inflight_requests`, `airlock_limited_total`, `airlock_events_dropped_total` and airlock's own tool, backend, auth and reload series. `ops_listen_addr` moves `/metrics`, `/healthz` and `/readyz` to their own port.
- OTLP/HTTP traces with `telemetry.otlp_endpoint`, `otlp_headers` and `sample_ratio`, and a `traceparent` sent to backends under airlock's own span.

### Changed

- Errors from `/mcp` before the MCP layer, such as a missing token, use the shared `{"error": {"code", "message"}}` shape.

### Fixed

- `${VAR}` references in `auth.headers` and `auth.discovery_headers` of Streamable HTTP servers are resolved from airlock's environment instead of being sent as written.

## [0.1.0] - 2026-11-05

### Added

- One MCP endpoint in front of stdio and Streamable HTTP servers, with tools prefixed as `<server>__<tool>`.
- API key login, allow and deny rules per user, group and key, and tool lists filtered to what each caller may use.
- Audit records for every tool call, including denied ones, on stdout or in a file.
- `airlock serve --config file` over HTTP at `/mcp`, and `airlock serve --stdio` for one local client, with `/healthz`, `/readyz`, an `Origin` check and config reload when the file changes.
- State in SQL: embedded SQLite by default, Postgres for teams and replicas (`storage.driver`, `storage.dsn`), with migrations at startup and `airlock migrate`.
- Resources in the config file are provisioned into the database, and every instance reloads within two seconds of any change.
- Audit records always go to the `audit_events` table and are kept for `audit.retention` (30 days by default).
- `role_bindings` and `settings` in the config file. `allowed_origins` moved to `settings.allowed_origins`.

[Unreleased]: https://github.com/raven-clown/airlock/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/raven-clown/airlock/releases/tag/v0.1.0
