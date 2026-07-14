-- 037_siem_notification_channel.sql
--
-- Adds support for a "siem" notification channel: a generic authenticated
-- HTTP webhook for SIEM/SOAR ingest endpoints (Splunk HEC, generic
-- collectors, Tines/Torq webhooks, etc). Unlike Slack/Discord/Teams
-- incoming webhooks — which authenticate via the secrecy of the URL
-- itself — SIEM/SOAR collectors almost universally require an auth
-- token/header, so two new columns are needed on notification_configs:
--
--   auth_header          - which HTTP header carries the token
--                           (e.g. "Authorization" or "X-Splunk-Token")
--   auth_token_encrypted - AES-256-GCM ciphertext (base64) of the token,
--                          encrypted with the same RAYYAN_AUTH_CREDENTIALKEY
--                          already used for SMTP passwords and tool
--                          credentials. Never exposed via JSON.
--
-- All statements use IF NOT EXISTS so re-applying is harmless.

ALTER TABLE notification_configs
    ADD COLUMN IF NOT EXISTS auth_header text NOT NULL DEFAULT '';

ALTER TABLE notification_configs
    ADD COLUMN IF NOT EXISTS auth_token_encrypted text NOT NULL DEFAULT '';
