-- Migration 024: Security hardening, performance indexes, password reset tokens

-- Password reset tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_prt_user_id ON password_reset_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_prt_expires ON password_reset_tokens(expires_at) WHERE used_at IS NULL;

-- Dead-letter queue for failed jobs
CREATE TABLE IF NOT EXISTS failed_jobs (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_type    TEXT NOT NULL,
    payload     JSONB NOT NULL,
    error       TEXT NOT NULL,
    attempts    INTEGER NOT NULL DEFAULT 0,
    org_id      UUID,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_failed_jobs_created ON failed_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_failed_jobs_type ON failed_jobs(job_type);

-- api_keys: key_prefix column for O(1) lookup (prefix = first 12 chars of plaintext key)
-- This column may already exist from AutoMigrate on newer deployments; IF NOT EXISTS guards it.
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_prefix VARCHAR(12);
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix, active) WHERE active = true;

-- Performance indexes on high-query-volume tables
CREATE INDEX IF NOT EXISTS idx_findings_org_status   ON findings(org_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_org_severity ON findings(org_id, severity);
CREATE INDEX IF NOT EXISTS idx_findings_org_created  ON findings(org_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_hosts_org_created     ON hosts(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_hosts_org_risk        ON hosts(org_id, risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_alerts_org_status     ON alerts(org_id, status);
CREATE INDEX IF NOT EXISTS idx_alerts_org_severity   ON alerts(org_id, severity);

CREATE INDEX IF NOT EXISTS idx_audit_org_created     ON audit_logs(org_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_subdomains_org_domain ON subdomains(org_id, domain_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_org_risk   ON subdomains(org_id, risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_services_org_host     ON services(org_id, host_id);
CREATE INDEX IF NOT EXISTS idx_services_org_port     ON services(org_id, port);

CREATE INDEX IF NOT EXISTS idx_exposure_org_level    ON asset_exposure_scores(org_id, exposure_level);
CREATE INDEX IF NOT EXISTS idx_exposure_org_score    ON asset_exposure_scores(org_id, exposure_score DESC);

CREATE INDEX IF NOT EXISTS idx_dns_org_domain        ON dns_records(org_id, domain_id);
CREATE INDEX IF NOT EXISTS idx_certs_org_expiry      ON certificates(org_id, not_after);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_org_status  ON scan_jobs(org_id, status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_org_created ON scan_jobs(org_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_changes_org_created   ON asset_change_events(org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_attack_paths_org      ON attack_paths(org_id, risk_score DESC);
