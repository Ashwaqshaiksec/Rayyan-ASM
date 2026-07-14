-- 004_hosts.sql
-- IP-centric asset table.

CREATE TABLE hosts (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at       TIMESTAMPTZ,
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    ip               TEXT NOT NULL,
    ip_version       INT  NOT NULL DEFAULT 4,
    hostname         TEXT NOT NULL DEFAULT '',
    reverse_dns      TEXT NOT NULL DEFAULT '',
    asn              TEXT NOT NULL DEFAULT '',
    asn_org          TEXT NOT NULL DEFAULT '',
    cidr             TEXT NOT NULL DEFAULT '',
    country          TEXT NOT NULL DEFAULT '',
    city             TEXT NOT NULL DEFAULT '',
    isp              TEXT NOT NULL DEFAULT '',
    provider         TEXT NOT NULL DEFAULT '',
    host_type        TEXT NOT NULL DEFAULT '',
    status           TEXT NOT NULL DEFAULT 'active',
    os               TEXT NOT NULL DEFAULT '',
    os_version       TEXT NOT NULL DEFAULT '',
    tags             TEXT[] NOT NULL DEFAULT '{}',
    notes            TEXT NOT NULL DEFAULT '',
    owner            TEXT NOT NULL DEFAULT '',
    business_unit    TEXT NOT NULL DEFAULT '',
    environment      TEXT NOT NULL DEFAULT 'production',
    monitored        BOOL NOT NULL DEFAULT TRUE,
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_scanned_at  TIMESTAMPTZ,
    risk_score       FLOAT NOT NULL DEFAULT 0,
    risk_tier        TEXT NOT NULL DEFAULT 'low',
    risk_factors     JSONB NOT NULL DEFAULT '{}',
    risk_scored_at   TIMESTAMPTZ,
    discovery_job_id UUID
);

CREATE INDEX idx_hosts_org_id     ON hosts (org_id);
CREATE INDEX idx_hosts_ip         ON hosts (ip);
CREATE INDEX idx_hosts_deleted_at ON hosts (deleted_at);
