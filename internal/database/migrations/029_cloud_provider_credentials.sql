-- 029_cloud_provider_credentials.sql
-- Stores per-org, per-provider encrypted cloud credentials used by the
-- scheduler for automatic daily cloud asset synchronisation (AWS/Azure/GCP).
-- Credentials are AES-256-GCM encrypted with RAYYAN_AUTH_CREDENTIALKEY,
-- same key as tool_credentials. Never expose encrypted_creds via the API.

CREATE TABLE IF NOT EXISTS cloud_provider_credentials (
    id               UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ,

    org_id           UUID         NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider         TEXT         NOT NULL CHECK (provider IN ('aws','azure','gcp')),
    label            TEXT         NOT NULL DEFAULT '',
    encrypted_creds  TEXT         NOT NULL,
    sync_enabled     BOOLEAN      NOT NULL DEFAULT TRUE,
    last_sync_at     TIMESTAMPTZ,
    created_by       UUID         REFERENCES users(id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_cloud_provider_credentials_org_provider_label
    ON cloud_provider_credentials (org_id, provider, label)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_cloud_provider_credentials_org_id
    ON cloud_provider_credentials (org_id)
    WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_cloud_provider_credentials_sync
    ON cloud_provider_credentials (sync_enabled, last_sync_at)
    WHERE deleted_at IS NULL AND sync_enabled = TRUE;
