-- Migration: 012_scan_job_workflow.sql
-- Adds the workflow column to scan_jobs for Feature 1 (Workflow → Dispatcher wiring).

ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS workflow TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_scan_jobs_workflow
    ON scan_jobs (workflow)
    WHERE workflow != '';
