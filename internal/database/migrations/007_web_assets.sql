-- 007_web_assets.sql
-- Web-layer assets (screenshots, HTTP metadata) linked to services.

CREATE TABLE web_assets (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at       TIMESTAMPTZ,
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    service_id       UUID REFERENCES services(id) ON DELETE SET NULL,
    url              TEXT NOT NULL,
    title            TEXT NOT NULL DEFAULT '',
    status_code      INT  NOT NULL DEFAULT 0,
    content_type     TEXT NOT NULL DEFAULT '',
    content_length   INT  NOT NULL DEFAULT 0,
    screenshot_path  TEXT NOT NULL DEFAULT '',
    headers          JSONB NOT NULL DEFAULT '{}',
    response_time_ms INT  NOT NULL DEFAULT 0,
    last_crawled_at  TIMESTAMPTZ,
    discovery_job_id UUID
);

CREATE INDEX idx_web_assets_org_id     ON web_assets (org_id);
CREATE INDEX idx_web_assets_service_id ON web_assets (service_id);
CREATE INDEX idx_web_assets_deleted_at ON web_assets (deleted_at);
