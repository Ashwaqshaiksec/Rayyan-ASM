-- Migration 021: exposure prioritization engine

-- Asset Exposure Scores
-- One row per scored asset (host, subdomain, or domain) per org, capturing
-- the multi-factor Exposure Score produced by the exposure engine. This is
-- additive to, and never overwrites, the existing CVSS-driven Risk Score —
-- risk_score here is carried as a read-only reference column copied from
-- the asset at calculation time. Rebuilt in full on each recompute: existing
-- rows for the org are dropped and replaced, same lifecycle as
-- asset_relationships and attack_paths.
CREATE TABLE IF NOT EXISTS asset_exposure_scores (
    id                 UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    org_id             UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    asset_type         TEXT        NOT NULL,
    asset_id           UUID        NOT NULL,
    asset_label        TEXT,
    risk_score         DOUBLE PRECISION NOT NULL DEFAULT 0,
    exposure_score     DOUBLE PRECISION NOT NULL DEFAULT 0,
    exposure_level     TEXT        NOT NULL DEFAULT 'informational',
    internet_exposed   BOOLEAN     NOT NULL DEFAULT FALSE,
    attack_path_count  INTEGER     NOT NULL DEFAULT 0,
    critical_findings  INTEGER     NOT NULL DEFAULT 0,
    criticality        TEXT        NOT NULL DEFAULT 'standard',
    factors            JSONB       NOT NULL DEFAULT '{}',
    calculated_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_exposure_scores_org        ON asset_exposure_scores(org_id);
CREATE INDEX IF NOT EXISTS idx_exposure_scores_asset      ON asset_exposure_scores(asset_type, asset_id);
CREATE INDEX IF NOT EXISTS idx_exposure_scores_score      ON asset_exposure_scores(exposure_score DESC);
CREATE INDEX IF NOT EXISTS idx_exposure_scores_level      ON asset_exposure_scores(exposure_level);
-- one current row per asset; a recompute deletes-and-reinserts per org but
-- this guards against any future partial-update path producing duplicates
CREATE UNIQUE INDEX IF NOT EXISTS idx_exposure_scores_unique ON asset_exposure_scores(org_id, asset_type, asset_id);
