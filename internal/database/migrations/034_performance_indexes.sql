-- 034_performance_indexes.sql
--
-- Composite indexes for query patterns that appear frequently in handler code
-- but were not covered by earlier migrations. All use IF NOT EXISTS so the
-- migration is safe to apply on databases that already have some of these
-- (e.g. created manually on a dev instance).

-- findings: lookup by scan job within an org (scan compare, export by job)
CREATE INDEX IF NOT EXISTS idx_findings_org_scan_job
    ON findings (org_id, scan_job_id)
    WHERE deleted_at IS NULL;

-- findings: SLA dashboard — open findings with a due date within an org
CREATE INDEX IF NOT EXISTS idx_findings_org_sla_due
    ON findings (org_id, sla_due_at)
    WHERE sla_due_at IS NOT NULL
      AND status NOT IN ('fixed', 'false_positive')
      AND deleted_at IS NULL;

-- scan_results: primary access pattern is always (org_id, job_id)
CREATE INDEX IF NOT EXISTS idx_scan_results_org_job
    ON scan_results (org_id, job_id)
    WHERE deleted_at IS NULL;

-- web_assets: screenshot gallery queries filter on (org_id, screenshotted)
CREATE INDEX IF NOT EXISTS idx_web_assets_org_screenshotted
    ON web_assets (org_id, screenshotted)
    WHERE screenshotted = true AND deleted_at IS NULL;

-- findings: deduplication check on (org_id, title, target) used during scan ingest
CREATE INDEX IF NOT EXISTS idx_findings_org_title_target
    ON findings (org_id, title, target)
    WHERE deleted_at IS NULL;

-- hosts: cloud asset inventory filtered by provider within org
CREATE INDEX IF NOT EXISTS idx_cloud_assets_org_provider
    ON cloud_assets (org_id, provider)
    WHERE deleted_at IS NULL;

-- discovery_risk_flags: status dashboard (org + status is the primary filter)
CREATE INDEX IF NOT EXISTS idx_risk_flags_org_status_type
    ON discovery_risk_flags (org_id, status, flag_type);

-- audit_logs: admin delivery history — org + sent_at DESC is the paging query
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_org_sent
    ON webhook_deliveries (org_id, sent_at DESC);
