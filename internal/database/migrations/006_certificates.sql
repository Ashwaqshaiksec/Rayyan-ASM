-- 006_certificates.sql
-- TLS/SSL certificate records linked to services.

CREATE TABLE certificates (
    id                UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at        TIMESTAMPTZ,
    org_id            UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    service_id        UUID REFERENCES services(id) ON DELETE SET NULL,
    fingerprint       TEXT NOT NULL,
    subject           TEXT NOT NULL DEFAULT '',
    issuer            TEXT NOT NULL DEFAULT '',
    subject_alt_names TEXT[] NOT NULL DEFAULT '{}',
    serial_number     TEXT NOT NULL DEFAULT '',
    not_before        TIMESTAMPTZ NOT NULL,
    not_after         TIMESTAMPTZ NOT NULL,
    is_expired        BOOL NOT NULL DEFAULT FALSE,
    is_wildcard       BOOL NOT NULL DEFAULT FALSE,
    is_self_signed    BOOL NOT NULL DEFAULT FALSE,
    signature_alg     TEXT NOT NULL DEFAULT '',
    key_alg           TEXT NOT NULL DEFAULT '',
    key_bits          INT  NOT NULL DEFAULT 0,
    version           INT  NOT NULL DEFAULT 3,
    discovery_job_id  UUID
);

CREATE UNIQUE INDEX idx_certificates_fingerprint ON certificates (fingerprint) WHERE deleted_at IS NULL;
CREATE INDEX idx_certificates_org_id             ON certificates (org_id);
CREATE INDEX idx_certificates_service_id         ON certificates (service_id);
CREATE INDEX idx_certificates_not_after          ON certificates (not_after);
CREATE INDEX idx_certificates_deleted_at         ON certificates (deleted_at);
