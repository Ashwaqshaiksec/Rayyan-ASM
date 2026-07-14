-- 008_scan_jobs.sql
-- Scan jobs and scan results (basic queue tracking pre-tool-registry).

CREATE TABLE scan_jobs (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at   TIMESTAMPTZ,
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by   UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name         TEXT NOT NULL,
    type         TEXT NOT NULL,
    workflow     TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'pending',
    priority     INT  NOT NULL DEFAULT 5,
    targets      JSONB NOT NULL DEFAULT '{}',
    options      JSONB NOT NULL DEFAULT '{}',
    progress     INT  NOT NULL DEFAULT 0,
    total_items  INT  NOT NULL DEFAULT 0,
    done_items   INT  NOT NULL DEFAULT 0,
    error        TEXT NOT NULL DEFAULT '',
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    scheduled_at TIMESTAMPTZ,
    cron_expr    TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_scan_jobs_org_id     ON scan_jobs (org_id);
CREATE INDEX idx_scan_jobs_created_by ON scan_jobs (created_by);
CREATE INDEX idx_scan_jobs_status     ON scan_jobs (status);
CREATE INDEX idx_scan_jobs_deleted_at ON scan_jobs (deleted_at);

CREATE TABLE scan_results (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    job_id      UUID NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    asset_type  TEXT NOT NULL,
    asset_id    UUID,
    status      TEXT NOT NULL DEFAULT 'new',
    data        JSONB NOT NULL DEFAULT '{}',
    raw         TEXT NOT NULL DEFAULT '',
    error       TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_scan_results_org_id     ON scan_results (org_id);
CREATE INDEX idx_scan_results_job_id     ON scan_results (job_id);
CREATE INDEX idx_scan_results_deleted_at ON scan_results (deleted_at);
