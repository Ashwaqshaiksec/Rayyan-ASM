-- Migration 031: unique constraint on cloud_assets(org_id, provider, resource_id)
-- Required for ON CONFLICT upsert in the cloud_enum workflow dispatcher.
-- GORM AutoMigrate creates the index from the model tag; this file keeps the
-- migration changelog complete for direct readers.

CREATE UNIQUE INDEX IF NOT EXISTS idx_cloud_asset_key
    ON cloud_assets (org_id, provider, resource_id);
