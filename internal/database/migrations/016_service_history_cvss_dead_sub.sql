-- Migration 015: service history, CVSS vector on findings, dead subdomain detection

-- Service History
-- Tracks port open/closed events over time for a given host/port/protocol.
CREATE TABLE IF NOT EXISTS service_history (
    id           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    org_id       UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    host_id      UUID        REFERENCES hosts(id) ON DELETE CASCADE,
    host_ref     TEXT        NOT NULL,
    port         INT         NOT NULL,
    protocol     TEXT        NOT NULL DEFAULT 'tcp',
    service      TEXT,
    product      TEXT,
    version      TEXT,
    state        TEXT        NOT NULL DEFAULT 'open',  -- open | closed | filtered
    banner       TEXT,
    scan_job_id  UUID        REFERENCES scan_jobs(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_service_history_org      ON service_history(org_id);
CREATE INDEX IF NOT EXISTS idx_service_history_host_ref ON service_history(host_ref, port, protocol);
CREATE INDEX IF NOT EXISTS idx_service_history_host_id  ON service_history(host_id) WHERE host_id IS NOT NULL;

-- CVSS vector on findings
-- findings.cvss (float) already exists; add cvss_vector and cvss_version.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_vector  TEXT    DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS cvss_version TEXT    DEFAULT 'CVSS:3.1';

-- Dead subdomain tracking
ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS consecutive_failures INT     NOT NULL DEFAULT 0;
ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS last_checked_at      TIMESTAMPTZ;
ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS dead                 BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX IF NOT EXISTS idx_subdomains_dead ON subdomains(org_id, dead) WHERE deleted_at IS NULL;
