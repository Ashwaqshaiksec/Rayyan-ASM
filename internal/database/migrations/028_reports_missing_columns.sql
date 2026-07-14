-- 028_reports_missing_columns.sql
-- The reports table created in 009_alerts.sql was missing columns that the
-- Go model (models.Report) defines. GORM AutoMigrate adds them on startup,
-- but raw SQL migrations must also be explicit. This migration is idempotent.

ALTER TABLE reports
    ADD COLUMN IF NOT EXISTS file_size    BIGINT       NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS generated_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS expires_at   TIMESTAMPTZ;
