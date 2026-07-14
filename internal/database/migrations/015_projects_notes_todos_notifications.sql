-- Projects
CREATE TABLE IF NOT EXISTS projects (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by  UUID NOT NULL REFERENCES users(id),
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    description TEXT,
    type        TEXT NOT NULL DEFAULT 'general',
    scope       TEXT[] DEFAULT '{}',
    out_of_scope TEXT[] DEFAULT '{}',
    color       TEXT DEFAULT '#6366f1',
    active      BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_projects_org_id ON projects(org_id);

-- Notes
CREATE TABLE IF NOT EXISTS notes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at  TIMESTAMPTZ,
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id  UUID REFERENCES projects(id) ON DELETE SET NULL,
    created_by  UUID NOT NULL REFERENCES users(id),
    title       TEXT NOT NULL,
    content     TEXT NOT NULL,
    target      TEXT,
    tags        TEXT[] DEFAULT '{}',
    pinned      BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS idx_notes_org_id     ON notes(org_id);
CREATE INDEX IF NOT EXISTS idx_notes_project_id ON notes(project_id);

-- Todos
CREATE TABLE IF NOT EXISTS todos (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at   TIMESTAMPTZ,
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    project_id   UUID REFERENCES projects(id) ON DELETE SET NULL,
    created_by   UUID NOT NULL REFERENCES users(id),
    assigned_to  UUID REFERENCES users(id) ON DELETE SET NULL,
    title        TEXT NOT NULL,
    notes        TEXT,
    status       TEXT NOT NULL DEFAULT 'open',
    priority     TEXT NOT NULL DEFAULT 'medium',
    target       TEXT,
    due_at       TIMESTAMPTZ,
    done_at      TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_todos_org_id     ON todos(org_id);
CREATE INDEX IF NOT EXISTS idx_todos_project_id ON todos(project_id);

-- Notification configs
CREATE TABLE IF NOT EXISTS notification_configs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at   TIMESTAMPTZ,
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by   UUID NOT NULL REFERENCES users(id),
    channel      TEXT NOT NULL,
    name         TEXT NOT NULL,
    webhook_url  TEXT,
    bot_token    TEXT,
    chat_id      TEXT,
    alert_types  TEXT[] DEFAULT '{}',
    min_severity TEXT NOT NULL DEFAULT 'info',
    active       BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE INDEX IF NOT EXISTS idx_notification_configs_org_id ON notification_configs(org_id);
