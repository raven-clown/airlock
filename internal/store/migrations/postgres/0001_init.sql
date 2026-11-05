CREATE TABLE servers (
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    version BIGINT NOT NULL,
    spec TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, name)
);

CREATE TABLE rules (
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    version BIGINT NOT NULL,
    spec TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, name)
);

CREATE TABLE api_keys (
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    version BIGINT NOT NULL,
    spec TEXT NOT NULL,
    last_used_at BIGINT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, name)
);

CREATE TABLE role_bindings (
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    version BIGINT NOT NULL,
    spec TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, name)
);

CREATE TABLE settings (
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    version BIGINT NOT NULL,
    spec TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, name)
);

CREATE TABLE revision (
    org_id TEXT PRIMARY KEY,
    value BIGINT NOT NULL
);

INSERT INTO revision (org_id, value) VALUES ('default', 0);

CREATE TABLE audit_events (
    id BIGSERIAL PRIMARY KEY,
    org_id TEXT NOT NULL,
    occurred_at BIGINT NOT NULL,
    kind TEXT NOT NULL,
    request_id TEXT NOT NULL,
    trace_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    instance TEXT NOT NULL,
    subject TEXT NOT NULL,
    groups_json TEXT NOT NULL,
    auth TEXT NOT NULL,
    project TEXT NOT NULL,
    server TEXT NOT NULL,
    tool TEXT NOT NULL,
    decision TEXT NOT NULL,
    rule TEXT NOT NULL,
    outcome TEXT NOT NULL,
    duration_ms BIGINT NOT NULL,
    args_json TEXT NOT NULL,
    error TEXT NOT NULL
);

CREATE INDEX audit_events_org_time ON audit_events (org_id, occurred_at);
