-- Migration 025: External Attack Surface Discovery Engine
--
-- Adds job tracking, a discovery-scoped event feed, and risk-indicator
-- flags for the external discovery pipeline. Discovered assets themselves
-- continue to live in the existing domains / subdomains / hosts / services /
-- certificates / dns_records tables — this migration only adds the
-- orchestration layer on top.

-- Discovery Jobs
-- One row per discovery pipeline run against a set of seed domains.
CREATE TABLE IF NOT EXISTS discovery_jobs (
    id                UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at        TIMESTAMPTZ,
    org_id            UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by        UUID        REFERENCES users(id) ON DELETE SET NULL,
    seed_domains      TEXT[]      NOT NULL DEFAULT '{}',
    status            TEXT        NOT NULL DEFAULT 'pending',
    stage             TEXT        NOT NULL DEFAULT '',
    progress          INTEGER     NOT NULL DEFAULT 0,
    cadence           TEXT        NOT NULL DEFAULT 'manual',
    depth             INTEGER     NOT NULL DEFAULT 2,
    options           JSONB       NOT NULL DEFAULT '{}',
    assets_found      INTEGER     NOT NULL DEFAULT 0,
    new_assets        INTEGER     NOT NULL DEFAULT 0,
    domains_found     INTEGER     NOT NULL DEFAULT 0,
    subdomains_found  INTEGER     NOT NULL DEFAULT 0,
    ips_found         INTEGER     NOT NULL DEFAULT 0,
    certs_found       INTEGER     NOT NULL DEFAULT 0,
    services_found    INTEGER     NOT NULL DEFAULT 0,
    started_at        TIMESTAMPTZ,
    completed_at      TIMESTAMPTZ,
    error             TEXT        NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_discovery_jobs_org      ON discovery_jobs(org_id);
CREATE INDEX IF NOT EXISTS idx_discovery_jobs_status   ON discovery_jobs(status);
CREATE INDEX IF NOT EXISTS idx_discovery_jobs_deleted  ON discovery_jobs(deleted_at);
CREATE INDEX IF NOT EXISTS idx_discovery_jobs_created  ON discovery_jobs(org_id, created_at DESC);

-- Discovery Events
-- Append-only narrative feed of pipeline activity: stage transitions,
-- individual asset discoveries, and risk-flag raises. Powers the
-- discovery dashboard's live feed and the WebSocket broadcast stream.
CREATE TABLE IF NOT EXISTS discovery_events (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    org_id       UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    job_id       UUID        REFERENCES discovery_jobs(id) ON DELETE CASCADE,
    event_type   TEXT        NOT NULL,
    asset_type   TEXT        NOT NULL DEFAULT '',
    asset_label  TEXT        NOT NULL DEFAULT '',
    source       TEXT        NOT NULL DEFAULT '',
    severity     TEXT        NOT NULL DEFAULT '',
    message      TEXT        NOT NULL DEFAULT '',
    detected_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_discovery_events_org      ON discovery_events(org_id);
CREATE INDEX IF NOT EXISTS idx_discovery_events_job      ON discovery_events(job_id);
CREATE INDEX IF NOT EXISTS idx_discovery_events_type     ON discovery_events(event_type);
CREATE INDEX IF NOT EXISTS idx_discovery_events_detected ON discovery_events(org_id, detected_at DESC);

-- Discovery Risk Flags
-- Risk indicators surfaced directly from discovered asset metadata
-- (exposed admin panels, VPN portals, expired certs, shadow IT, unknown
-- assets) — distinct from the generic findings table, which is populated
-- by active vulnerability scanning rather than passive discovery.
CREATE TABLE IF NOT EXISTS discovery_risk_flags (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at   TIMESTAMPTZ,
    org_id       UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_type   TEXT        NOT NULL,
    asset_id     UUID        NOT NULL,
    asset_label  TEXT        NOT NULL DEFAULT '',
    flag_type    TEXT        NOT NULL,
    severity     TEXT        NOT NULL DEFAULT 'medium',
    evidence     TEXT        NOT NULL DEFAULT '',
    status       TEXT        NOT NULL DEFAULT 'open',
    detected_at  TIMESTAMPTZ NOT NULL,
    resolved_at  TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_discovery_risk_flags_org    ON discovery_risk_flags(org_id);
CREATE INDEX IF NOT EXISTS idx_discovery_risk_flags_asset  ON discovery_risk_flags(asset_type, asset_id);
CREATE INDEX IF NOT EXISTS idx_discovery_risk_flags_type   ON discovery_risk_flags(flag_type);
CREATE INDEX IF NOT EXISTS idx_discovery_risk_flags_status ON discovery_risk_flags(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_discovery_risk_flags_unique
    ON discovery_risk_flags(org_id, asset_type, asset_id, flag_type);

-- Discovery provenance on existing asset tables.
-- discovery_job_id traces which pipeline run first surfaced the asset;
-- nullable since most assets also arrive via manual entry / regular scans.
ALTER TABLE domains      ADD COLUMN IF NOT EXISTS discovery_job_id UUID REFERENCES discovery_jobs(id) ON DELETE SET NULL;
ALTER TABLE subdomains   ADD COLUMN IF NOT EXISTS discovery_job_id UUID REFERENCES discovery_jobs(id) ON DELETE SET NULL;
ALTER TABLE hosts        ADD COLUMN IF NOT EXISTS discovery_job_id UUID REFERENCES discovery_jobs(id) ON DELETE SET NULL;
ALTER TABLE services     ADD COLUMN IF NOT EXISTS discovery_job_id UUID REFERENCES discovery_jobs(id) ON DELETE SET NULL;
ALTER TABLE certificates ADD COLUMN IF NOT EXISTS discovery_job_id UUID REFERENCES discovery_jobs(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_domains_discovery_job      ON domains(discovery_job_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_discovery_job   ON subdomains(discovery_job_id);
CREATE INDEX IF NOT EXISTS idx_hosts_discovery_job        ON hosts(discovery_job_id);
CREATE INDEX IF NOT EXISTS idx_services_discovery_job     ON services(discovery_job_id);
CREATE INDEX IF NOT EXISTS idx_certificates_discovery_job ON certificates(discovery_job_id);
