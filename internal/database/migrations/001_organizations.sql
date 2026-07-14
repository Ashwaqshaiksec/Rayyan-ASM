-- 001_organizations.sql
-- Foundational org/tenant table. All other tables reference org_id.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    logo_url    TEXT NOT NULL DEFAULT '',
    plan        TEXT NOT NULL DEFAULT 'free',
    max_assets  INT  NOT NULL DEFAULT 1000,
    active      BOOL NOT NULL DEFAULT TRUE,
    settings    JSONB NOT NULL DEFAULT '{}'
);

CREATE UNIQUE INDEX idx_organizations_name ON organizations (name) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_organizations_slug ON organizations (slug) WHERE deleted_at IS NULL;
CREATE INDEX idx_organizations_deleted_at ON organizations (deleted_at);
