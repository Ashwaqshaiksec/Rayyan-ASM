-- 035_finding_frameworks_email_security.sql
--
-- 1. Add the `frameworks` text-array column to findings so each finding can be
--    tagged with one or more compliance/threat-framework identifiers
--    (e.g. "OWASP:A01", "MITRE:T1190", "CWE-89", "PCI-DSS:6.3").
--
-- 2. No separate email_security_results table is needed — results are returned
--    live from the /domains/:id/email-security endpoint and not persisted
--    (they are cheap DNS lookups). This migration is therefore only about the
--    findings frameworks column.
--
-- All statements use IF NOT EXISTS / safe guards so re-applying is harmless.

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS frameworks text[] NOT NULL DEFAULT '{}';

-- GIN index for efficient containment queries such as
-- WHERE frameworks @> ARRAY['OWASP:A01'] on Postgres.
-- SQLite ignores this silently (no GIN support) but the column is still usable.
CREATE INDEX IF NOT EXISTS idx_findings_frameworks
    ON findings USING GIN (frameworks);
