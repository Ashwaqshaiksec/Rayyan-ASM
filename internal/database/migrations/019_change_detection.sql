-- Migration 018: unified change detection

-- Asset State Snapshots
-- One row per (org, asset_type, asset_key) holding the last known watched
-- fields for that asset. Overwritten on every detection run — this is the
-- "current baseline" compared against, not a history log.
CREATE TABLE IF NOT EXISTS asset_state_snapshots (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_type  TEXT        NOT NULL,  -- domain | subdomain | host | service | certificate | dns_record | technology
    asset_key   TEXT        NOT NULL,
    label       TEXT,
    fields      JSONB       NOT NULL DEFAULT '{}',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, asset_type, asset_key)
);

-- Asset Change Events
-- Append-only timeline. Every detection run inserts zero or more rows here;
-- existing rows are never updated or deleted.
CREATE TABLE IF NOT EXISTS asset_change_events (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    org_id      UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_type  TEXT        NOT NULL,
    asset_key   TEXT        NOT NULL,
    asset_label TEXT,
    change_type TEXT        NOT NULL,  -- new | removed | changed
    field       TEXT,
    old_value   TEXT,
    new_value   TEXT,
    detected_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_asset_change_org      ON asset_change_events(org_id);
CREATE INDEX IF NOT EXISTS idx_asset_change_type     ON asset_change_events(asset_type);
CREATE INDEX IF NOT EXISTS idx_asset_change_key      ON asset_change_events(asset_key);
CREATE INDEX IF NOT EXISTS idx_asset_change_detected ON asset_change_events(detected_at);
