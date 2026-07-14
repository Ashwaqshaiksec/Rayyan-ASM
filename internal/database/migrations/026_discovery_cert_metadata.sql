-- Migration 026: Certificate.Metadata (discovery engine TLS validation findings)
--
-- Certificate.Metadata (internal/models/models.go) was added during the
-- External Attack Surface Discovery hardening pass to store the second
-- TLS-chain-validation pass's findings ("tls_valid" bool,
-- "tls_validation_error" string — see persistCertificate in
-- internal/modules/discovery/engine.go) without a dedicated column. This
-- migration adds the matching SQL column for any deployment that
-- provisions its schema from these numbered files directly.
--
-- Application note: as of this migration, internal/database.Migrate()
-- (internal/database/database.go) provisions the schema via GORM's
-- AutoMigrate against the model structs, not by executing these numbered
-- .sql files — AutoMigrate already adds this column automatically because
-- Certificate.Metadata is a struct field with a `gorm:"type:jsonb"` tag.
-- This file exists so the numbered migration history stays complete and
-- so any tooling, review process, or future migration runner that does
-- read these files (rather than the Go structs) sees the same schema.
ALTER TABLE certificates
    ADD COLUMN IF NOT EXISTS metadata jsonb NOT NULL DEFAULT '{}';
