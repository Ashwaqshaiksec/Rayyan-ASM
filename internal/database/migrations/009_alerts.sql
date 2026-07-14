-- 009_alerts.sql
-- Alert table and reports stub (pre-module additions).

CREATE TABLE alerts (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    type        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    message     TEXT NOT NULL DEFAULT '',
    asset_id    UUID,
    asset_type  TEXT NOT NULL DEFAULT '',
    data        JSONB NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'open',
    acked_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    acked_at    TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ
);

CREATE INDEX idx_alerts_org_id     ON alerts (org_id);
CREATE INDEX idx_alerts_status     ON alerts (status);
CREATE INDEX idx_alerts_severity   ON alerts (severity);
CREATE INDEX idx_alerts_deleted_at ON alerts (deleted_at);

CREATE TABLE reports (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL,
    format     TEXT NOT NULL DEFAULT 'pdf',
    status     TEXT NOT NULL DEFAULT 'pending',
    file_path  TEXT NOT NULL DEFAULT '',
    options    JSONB NOT NULL DEFAULT '{}',
    error      TEXT NOT NULL DEFAULT '',
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

CREATE INDEX idx_reports_org_id     ON reports (org_id);
CREATE INDEX idx_reports_created_by ON reports (created_by);
CREATE INDEX idx_reports_status     ON reports (status);
CREATE INDEX idx_reports_deleted_at ON reports (deleted_at);
