-- 005_services.sql
-- Open ports / running services discovered on hosts and subdomains.

CREATE TABLE services (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at       TIMESTAMPTZ,
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    host_id          UUID REFERENCES hosts(id) ON DELETE SET NULL,
    host_ref         TEXT NOT NULL DEFAULT '',
    port             INT  NOT NULL,
    protocol         TEXT NOT NULL,
    service          TEXT NOT NULL DEFAULT '',
    product          TEXT NOT NULL DEFAULT '',
    version          TEXT NOT NULL DEFAULT '',
    banner           TEXT NOT NULL DEFAULT '',
    state            TEXT NOT NULL DEFAULT 'open',
    tunnel           TEXT NOT NULL DEFAULT '',
    cpe              TEXT NOT NULL DEFAULT '',
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    content_hash     TEXT NOT NULL DEFAULT '',
    last_changed_at  TIMESTAMPTZ,
    discovery_job_id UUID
);

CREATE INDEX idx_services_org_id     ON services (org_id);
CREATE INDEX idx_services_host_id    ON services (host_id);
CREATE INDEX idx_services_host_ref   ON services (host_ref);
CREATE INDEX idx_services_deleted_at ON services (deleted_at);

CREATE TABLE technologies (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    service_id UUID REFERENCES services(id) ON DELETE SET NULL,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL DEFAULT '',
    category   TEXT NOT NULL DEFAULT '',
    confidence INT  NOT NULL DEFAULT 0,
    source     TEXT NOT NULL DEFAULT '',
    cpe        TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_technologies_org_id     ON technologies (org_id);
CREATE INDEX idx_technologies_service_id ON technologies (service_id);
CREATE INDEX idx_technologies_deleted_at ON technologies (deleted_at);
