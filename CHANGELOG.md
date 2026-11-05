# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- One MCP endpoint in front of stdio and Streamable HTTP servers, with tools prefixed as `<server>__<tool>`.
- API key login, allow and deny rules per user, group and key, and tool lists filtered to what each caller may use.
- Audit records for every tool call, including denied ones, on stdout or in a file.
- `airlock serve --config file` over HTTP at `/mcp`, and `airlock serve --stdio` for one local client, with `/healthz`, `/readyz`, an `Origin` check and config reload when the file changes.
- State in SQL: embedded SQLite by default, Postgres for teams and replicas (`storage.driver`, `storage.dsn`), with migrations at startup and `airlock migrate`.
- Resources in the config file are provisioned into the database, and every instance reloads within two seconds of any change.
- Audit records always go to the `audit_events` table and are kept for `audit.retention` (30 days by default).
- `role_bindings` and `settings` in the config file. `allowed_origins` moved to `settings.allowed_origins`.
