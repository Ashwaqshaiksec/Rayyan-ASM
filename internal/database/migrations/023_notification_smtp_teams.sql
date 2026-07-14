-- Migration 023: SMTP/email and Microsoft Teams support for notification_configs
--
-- Slack, Discord, and Telegram all reuse the existing webhook_url / bot_token /
-- chat_id columns. Teams also delivers over an incoming webhook URL, so it
-- needs no new columns — it reuses webhook_url. Email has no webhook at all;
-- it needs SMTP connection details plus a destination address. The SMTP
-- password is encrypted at rest with the same AES-256-GCM scheme as
-- tool_credentials.encrypted_secret (see internal/crypto), keyed by
-- RAYYAN_AUTH_CREDENTIALKEY, and is never returned by the API.
ALTER TABLE notification_configs ADD COLUMN IF NOT EXISTS smtp_host TEXT;
ALTER TABLE notification_configs ADD COLUMN IF NOT EXISTS smtp_port INTEGER NOT NULL DEFAULT 587;
ALTER TABLE notification_configs ADD COLUMN IF NOT EXISTS smtp_username TEXT;
ALTER TABLE notification_configs ADD COLUMN IF NOT EXISTS smtp_password_encrypted TEXT;
ALTER TABLE notification_configs ADD COLUMN IF NOT EXISTS smtp_from TEXT;
ALTER TABLE notification_configs ADD COLUMN IF NOT EXISTS smtp_to TEXT[] DEFAULT '{}';
ALTER TABLE notification_configs ADD COLUMN IF NOT EXISTS smtp_use_tls BOOLEAN NOT NULL DEFAULT TRUE;

-- channel now also accepts 'email' and 'teams' alongside slack/discord/telegram.
-- No CHECK constraint exists today on this column, so no constraint change
-- is needed — validation happens in the API handler.
