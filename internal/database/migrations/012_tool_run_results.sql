-- Migration: 011_tool_run_results.sql
-- Persists per-tool output rows for every workflow/scan run.
-- result_data holds the full JSON payload for the tool's output regardless of category.

CREATE TABLE IF NOT EXISTS tool_run_results (
    id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id       UUID        NOT NULL,
    tool_name     TEXT        NOT NULL,
    category      TEXT        NOT NULL DEFAULT '',

    -- Unified result payload; the shape varies by tool category.
    result_data   JSONB       NOT NULL DEFAULT '[]',

    -- Execution metadata
    result_count  INT         NOT NULL DEFAULT 0,
    duration_ms   BIGINT      NOT NULL DEFAULT 0,
    status        TEXT        NOT NULL DEFAULT 'ok'
                              CHECK (status IN ('ok', 'error', 'skipped')),
    error_message TEXT        NOT NULL DEFAULT '',
    truncated     BOOLEAN     NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tool_run_results_scan_id   ON tool_run_results (scan_id);
CREATE INDEX IF NOT EXISTS idx_tool_run_results_tool_name ON tool_run_results (tool_name);
CREATE INDEX IF NOT EXISTS idx_tool_run_results_created   ON tool_run_results (created_at DESC);
