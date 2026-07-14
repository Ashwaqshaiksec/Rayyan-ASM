-- 027_email_verification.sql
-- Adds email_verified flag to users and a single-use verification token table.
-- New registrations are blocked from login until email is confirmed.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS email_verified BOOL NOT NULL DEFAULT FALSE;

-- Existing users (created before this migration) are grandfathered as verified
-- so they are not locked out. Set to TRUE only for rows that predate this run.
UPDATE users SET email_verified = TRUE WHERE created_at < NOW();

CREATE TABLE email_verification_tokens (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    user_id    UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT        NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_email_verify_token_hash ON email_verification_tokens (token_hash)
    WHERE deleted_at IS NULL;
CREATE INDEX idx_email_verify_user_id ON email_verification_tokens (user_id);
CREATE INDEX idx_email_verify_expires ON email_verification_tokens (expires_at);
