-- Migration: 011_findings.sql
-- Ensures indexes exist on the findings table (GORM AutoMigrate creates the
-- table; this migration adds performance indexes and an update trigger).

-- Partial index for fast "open findings" dashboard count
CREATE INDEX IF NOT EXISTS idx_findings_org_status
    ON findings (org_id, status)
    WHERE deleted_at IS NULL;

-- Partial index for severity-filtered queries
CREATE INDEX IF NOT EXISTS idx_findings_org_severity
    ON findings (org_id, severity)
    WHERE deleted_at IS NULL;

-- Index for looking up findings by scan job
CREATE INDEX IF NOT EXISTS idx_findings_scan_job_id
    ON findings (scan_job_id)
    WHERE scan_job_id IS NOT NULL AND deleted_at IS NULL;

-- Index for host-scoped findings
CREATE INDEX IF NOT EXISTS idx_findings_host_id
    ON findings (host_id)
    WHERE host_id IS NOT NULL AND deleted_at IS NULL;

-- Reuse the set_updated_at trigger function created in 010_tool_registry.sql
-- (CREATE OR REPLACE means it's safe to declare again if run in isolation)
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_findings_updated_at ON findings;
CREATE TRIGGER trg_findings_updated_at
    BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
