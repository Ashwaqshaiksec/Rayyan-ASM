-- Migration: 013_tool_credentials.sql
-- Stores AES-256-GCM encrypted credential material for external tools that
-- support authenticated scans (e.g. smbclient, enum4linux-ng, crackmapexec).
--
-- The encrypted_secret column holds a base64-encoded AES-256-GCM ciphertext
-- of a JSON-marshalled toolrunner/types.ToolCredentials struct. The
-- encryption key is derived from RAYYAN_AUTH_CREDENTIAL_KEY (32-byte key,
-- base64 or hex encoded) and is never stored in the database. Plaintext
-- credentials are never logged.

CREATE TABLE IF NOT EXISTS tool_credentials (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    tool_name        TEXT        NOT NULL,
    label            TEXT        NOT NULL DEFAULT '',
    encrypted_secret TEXT        NOT NULL,
    created_by       UUID        NOT NULL,

    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at       TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_tool_credentials_org_id   ON tool_credentials(org_id);
CREATE INDEX IF NOT EXISTS idx_tool_credentials_tool_name ON tool_credentials(tool_name);
CREATE INDEX IF NOT EXISTS idx_tool_credentials_deleted_at ON tool_credentials(deleted_at);
