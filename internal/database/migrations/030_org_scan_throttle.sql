-- Migration 030: real, DB-backed concurrent-scan throttling per org
--
-- Replaces the old in-memory OrgScanThrottleMap (which was never written to,
-- reset on every restart, and not shared across instances) with a column on
-- organizations plus counting active rows in scan_jobs/discovery_jobs.

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS max_concurrent_scans INTEGER NOT NULL DEFAULT 0;
-- 0 means "use the plan default" (see defaultMaxConcurrentScans in admin_ops.go)

-- Index already exists for scan_jobs(org_id, status) from migration 024.
CREATE INDEX IF NOT EXISTS idx_discovery_jobs_org_status ON discovery_jobs(org_id, status);
