-- Migration 032: Add request_id to audit_logs for X-Request-ID correlation.
-- This allows tracing an audit event back to the specific HTTP request in access logs.

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS request_id VARCHAR(64) DEFAULT '' NOT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs (request_id)
    WHERE request_id != '';

COMMENT ON COLUMN audit_logs.request_id IS 'X-Request-ID header value; correlates with access log entries.';
