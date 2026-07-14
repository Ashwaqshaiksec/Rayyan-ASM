-- Executive Dashboard: daily KPI snapshots per org, backing historical
-- trend charts (daily/weekly/monthly/quarterly) for the Exposure
-- Management Platform's executive reporting surface.

CREATE TABLE IF NOT EXISTS executive_kpi_snapshots (
    id                          UUID PRIMARY KEY,
    org_id                      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    date                        DATE NOT NULL,

    total_assets                INTEGER NOT NULL DEFAULT 0,
    total_domains               INTEGER NOT NULL DEFAULT 0,
    total_hosts                 INTEGER NOT NULL DEFAULT 0,
    total_services              INTEGER NOT NULL DEFAULT 0,
    total_cloud_assets          INTEGER NOT NULL DEFAULT 0,
    internet_facing_assets      INTEGER NOT NULL DEFAULT 0,

    new_assets                  INTEGER NOT NULL DEFAULT 0,
    removed_assets              INTEGER NOT NULL DEFAULT 0,
    modified_assets             INTEGER NOT NULL DEFAULT 0,

    avg_risk_score              DOUBLE PRECISION NOT NULL DEFAULT 0,
    exposure_score              DOUBLE PRECISION NOT NULL DEFAULT 0,
    critical_findings           INTEGER NOT NULL DEFAULT 0,
    high_findings                INTEGER NOT NULL DEFAULT 0,
    medium_findings              INTEGER NOT NULL DEFAULT 0,
    low_findings                 INTEGER NOT NULL DEFAULT 0,
    open_findings                INTEGER NOT NULL DEFAULT 0,
    risk_accepted_count          INTEGER NOT NULL DEFAULT 0,

    attack_path_count           INTEGER NOT NULL DEFAULT 0,
    critical_attack_path_count  INTEGER NOT NULL DEFAULT 0,
    avg_chokepoint_score        DOUBLE PRECISION NOT NULL DEFAULT 0,

    sla_total                   INTEGER NOT NULL DEFAULT 0,
    sla_breached                INTEGER NOT NULL DEFAULT 0,
    sla_compliance_pct          DOUBLE PRECISION NOT NULL DEFAULT 100,

    critical_assets_exposed     INTEGER NOT NULL DEFAULT 0,

    computed_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_exec_kpi_org_date ON executive_kpi_snapshots (org_id, date);
CREATE INDEX IF NOT EXISTS idx_exec_kpi_date ON executive_kpi_snapshots (date);
