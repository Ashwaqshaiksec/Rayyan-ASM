-- Migration 019: attack path analysis

-- Attack Paths
-- One row per ranked exposure chain from an internet-facing entry asset to a
-- sensitive internal target, weighted by the lowest risk score among the
-- hops on the chain (the "weakest link"). Rebuilt in full on each recompute,
-- same lifecycle as asset_relationships — existing rows for the org are
-- dropped and replaced.
CREATE TABLE IF NOT EXISTS attack_paths (
    id                    UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    org_id                UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    entry_type            TEXT        NOT NULL,
    entry_id              UUID        NOT NULL,
    entry_label           TEXT,
    target_type           TEXT        NOT NULL,
    target_id             UUID        NOT NULL,
    target_label          TEXT,
    weakest_score         DOUBLE PRECISION,
    weakest_type          TEXT,
    weakest_id            UUID,
    weakest_label         TEXT,
    hop_count             INTEGER     NOT NULL DEFAULT 0,
    hops                  JSONB       NOT NULL DEFAULT '[]',
    chokepoint_service_id UUID,
    finding_severity      TEXT,
    computed_at           TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attack_paths_org      ON attack_paths(org_id);
CREATE INDEX IF NOT EXISTS idx_attack_paths_entry    ON attack_paths(entry_type, entry_id);
CREATE INDEX IF NOT EXISTS idx_attack_paths_target   ON attack_paths(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_attack_paths_weakest  ON attack_paths(weakest_score);
