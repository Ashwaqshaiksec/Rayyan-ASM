-- 002_users.sql
-- Users table with MFA, lockout, and preferences support.

CREATE TABLE users (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at     TIMESTAMPTZ,
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email          TEXT NOT NULL,
    username       TEXT NOT NULL,
    password_hash  TEXT NOT NULL,
    first_name     TEXT NOT NULL DEFAULT '',
    last_name      TEXT NOT NULL DEFAULT '',
    role           TEXT NOT NULL DEFAULT 'viewer',
    mfa_enabled    BOOL NOT NULL DEFAULT FALSE,
    mfa_secret     TEXT NOT NULL DEFAULT '',
    active         BOOL NOT NULL DEFAULT TRUE,
    last_login_at  TIMESTAMPTZ,
    login_attempts INT  NOT NULL DEFAULT 0,
    locked_until   TIMESTAMPTZ,
    avatar_url     TEXT NOT NULL DEFAULT '',
    preferences    JSONB NOT NULL DEFAULT '{}'
);

CREATE UNIQUE INDEX idx_users_email    ON users (email)    WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_users_username ON users (username) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_org_id     ON users (org_id);
CREATE INDEX idx_users_deleted_at ON users (deleted_at);

CREATE TABLE api_keys (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at   TIMESTAMPTZ,
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    key_hash     TEXT NOT NULL,
    key_prefix   TEXT NOT NULL,
    scopes       TEXT[] NOT NULL DEFAULT '{}',
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    active       BOOL NOT NULL DEFAULT TRUE
);

CREATE UNIQUE INDEX idx_api_keys_key_hash ON api_keys (key_hash) WHERE deleted_at IS NULL;
CREATE INDEX idx_api_keys_org_id     ON api_keys (org_id);
CREATE INDEX idx_api_keys_user_id    ON api_keys (user_id);
CREATE INDEX idx_api_keys_deleted_at ON api_keys (deleted_at);
