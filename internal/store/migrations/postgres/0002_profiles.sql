CREATE TABLE profiles (
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    version BIGINT NOT NULL,
    spec TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, name)
);

CREATE TABLE profile_bindings (
    org_id TEXT NOT NULL,
    name TEXT NOT NULL,
    source TEXT NOT NULL,
    version BIGINT NOT NULL,
    spec TEXT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    PRIMARY KEY (org_id, name)
);

ALTER TABLE audit_events ADD COLUMN action TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN resource TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN route TEXT NOT NULL DEFAULT '';
