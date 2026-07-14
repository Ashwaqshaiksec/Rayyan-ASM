-- Migration 017: asset correlation graph

-- Asset Relationships
-- One row per edge in the asset correlation graph. Fully rebuilt by the
-- correlation engine on each recompute (existing org rows are deleted and
-- reinserted), so no update path is needed — only insert/delete.
CREATE TABLE IF NOT EXISTS asset_relationships (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    org_id        UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    from_type     TEXT        NOT NULL,  -- domain | subdomain | host | service | certificate | asn | registrant
    from_id       UUID        NOT NULL,
    from_label    TEXT,
    to_type       TEXT        NOT NULL,
    to_id         UUID        NOT NULL,
    to_label      TEXT,
    relation_type TEXT        NOT NULL,  -- parent_child | resolves_to | cert_san_match | shared_asn | shared_registrant
    confidence    FLOAT8      NOT NULL DEFAULT 1,
    evidence      TEXT,
    computed_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_asset_rel_org        ON asset_relationships(org_id);
CREATE INDEX IF NOT EXISTS idx_asset_rel_from        ON asset_relationships(from_type, from_id);
CREATE INDEX IF NOT EXISTS idx_asset_rel_to          ON asset_relationships(to_type, to_id);
CREATE INDEX IF NOT EXISTS idx_asset_rel_relation    ON asset_relationships(relation_type);
