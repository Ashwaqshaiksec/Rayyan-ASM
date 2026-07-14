-- NOTE: This codebase's actual schema is managed by GORM AutoMigrate
-- (see internal/database/database.go Migrate()), not by these .sql files.
-- This file is kept for reference/documentation of intended schema changes;
-- the corresponding Go struct tags in internal/models/models.go are the
-- canonical source and have been updated to match.

-- Batch 10 migrations (reference only)

-- 1. Finding SLA fields
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS sla_due_at        TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS sla_breached      BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS sla_breach_at     TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS risk_accepted      BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS risk_accepted_by   UUID,
    ADD COLUMN IF NOT EXISTS risk_accepted_at   TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS risk_accept_reason TEXT;

-- 2. ASN range table — enumerates CIDRs belonging to an ASN
CREATE TABLE IF NOT EXISTS asn_ranges (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asn         TEXT        NOT NULL,
    asn_org     TEXT,
    cidr        TEXT        NOT NULL,
    country     TEXT,
    rir         TEXT,           -- ARIN, RIPE, APNIC, AFRINIC, LACNIC
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, asn, cidr)
);
CREATE INDEX IF NOT EXISTS idx_asn_ranges_org ON asn_ranges(org_id);
CREATE INDEX IF NOT EXISTS idx_asn_ranges_asn ON asn_ranges(asn);

-- 3. WHOIS history — snapshot per domain per scan
CREATE TABLE IF NOT EXISTS whois_history (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    domain          TEXT        NOT NULL,
    registrar       TEXT,
    registrant      TEXT,
    registration_date TIMESTAMPTZ,
    expiry_date     TIMESTAMPTZ,
    nameservers     TEXT[],
    raw             TEXT,
    snapped_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_whois_history_org_domain ON whois_history(org_id, domain);

-- 4. Outbound webhook delivery log
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    notif_config_id UUID        REFERENCES notification_configs(id) ON DELETE SET NULL,
    alert_id        UUID        REFERENCES alerts(id) ON DELETE SET NULL,
    channel         TEXT        NOT NULL,
    endpoint        TEXT        NOT NULL,
    status_code     INT,
    success         BOOLEAN     NOT NULL DEFAULT FALSE,
    error_message   TEXT,
    attempt         INT         NOT NULL DEFAULT 1,
    sent_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_org ON webhook_deliveries(org_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_alert ON webhook_deliveries(alert_id);

-- 5. Per-domain scan cadence (cron expression per domain)
ALTER TABLE domains
    ADD COLUMN IF NOT EXISTS scan_cron   TEXT,           -- e.g. "0 2 * * *"
    ADD COLUMN IF NOT EXISTS scan_depth  TEXT DEFAULT 'full';  -- full, quick, passive

-- 6. Service diff view helper — store last content hash per service to detect changes
ALTER TABLE services
    ADD COLUMN IF NOT EXISTS content_hash   TEXT,
    ADD COLUMN IF NOT EXISTS last_changed_at TIMESTAMPTZ;

-- NOTE: Screenshots are NOT a separate table — they're stored as fields
-- (screenshotted, screenshot_path) directly on the existing web_assets table.
-- No additional migration needed for the screenshot gallery feature.
