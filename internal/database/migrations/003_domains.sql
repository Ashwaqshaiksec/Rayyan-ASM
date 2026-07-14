-- 003_domains.sql
-- Domains, subdomains, and DNS records.

CREATE TABLE domains (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at        TIMESTAMPTZ,
    org_id            UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    registrar         TEXT NOT NULL DEFAULT '',
    registration_date TIMESTAMPTZ,
    expiry_date       TIMESTAMPTZ,
    nameservers       TEXT[] NOT NULL DEFAULT '{}',
    status            TEXT NOT NULL DEFAULT 'active',
    tags              TEXT[] NOT NULL DEFAULT '{}',
    notes             TEXT NOT NULL DEFAULT '',
    owner             TEXT NOT NULL DEFAULT '',
    business_unit     TEXT NOT NULL DEFAULT '',
    environment       TEXT NOT NULL DEFAULT 'production',
    monitored         BOOL NOT NULL DEFAULT TRUE,
    last_scanned_at   TIMESTAMPTZ,
    scan_cron         TEXT NOT NULL DEFAULT '',
    scan_depth        TEXT NOT NULL DEFAULT 'full',
    risk_score        FLOAT NOT NULL DEFAULT 0,
    risk_tier         TEXT NOT NULL DEFAULT 'low',
    risk_factors      JSONB NOT NULL DEFAULT '{}',
    risk_scored_at    TIMESTAMPTZ,
    discovery_job_id  UUID
);

CREATE INDEX idx_domains_org_id     ON domains (org_id);
CREATE INDEX idx_domains_deleted_at ON domains (deleted_at);

CREATE TABLE subdomains (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at            TIMESTAMPTZ,
    org_id                UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain_id             UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    name                  TEXT NOT NULL,
    fqdn                  TEXT NOT NULL,
    ips                   TEXT[] NOT NULL DEFAULT '{}',
    status                TEXT NOT NULL DEFAULT 'active',
    source                TEXT NOT NULL DEFAULT '',
    tags                  TEXT[] NOT NULL DEFAULT '{}',
    first_seen_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_scanned_at       TIMESTAMPTZ,
    consecutive_failures  INT  NOT NULL DEFAULT 0,
    last_checked_at       TIMESTAMPTZ,
    dead                  BOOL NOT NULL DEFAULT FALSE,
    risk_score            FLOAT NOT NULL DEFAULT 0,
    risk_tier             TEXT NOT NULL DEFAULT 'low',
    risk_factors          JSONB NOT NULL DEFAULT '{}',
    risk_scored_at        TIMESTAMPTZ,
    discovery_job_id      UUID
);

CREATE UNIQUE INDEX idx_subdomains_fqdn       ON subdomains (fqdn) WHERE deleted_at IS NULL;
CREATE INDEX idx_subdomains_org_id            ON subdomains (org_id);
CREATE INDEX idx_subdomains_domain_id         ON subdomains (domain_id);
CREATE INDEX idx_subdomains_deleted_at        ON subdomains (deleted_at);

CREATE TABLE dns_records (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain_id  UUID NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,
    value      TEXT NOT NULL,
    ttl        INT  NOT NULL DEFAULT 0,
    priority   INT  NOT NULL DEFAULT 0,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_dns_records_org_id     ON dns_records (org_id);
CREATE INDEX idx_dns_records_domain_id  ON dns_records (domain_id);
CREATE INDEX idx_dns_records_deleted_at ON dns_records (deleted_at);
