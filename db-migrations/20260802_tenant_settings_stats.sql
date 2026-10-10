-- Existing-volume counterpart of db-init/04-tenant-settings-migration.sql.
-- The fresh-install schema and upgraded pre-tenancy schema must converge.
ALTER TABLE radius_stats ADD COLUMN IF NOT EXISTS tenant_id INT NULL;
ALTER TABLE radius_stats ADD KEY IF NOT EXISTS idx_radius_stats_tenant_time (tenant_id, collected_at);
ALTER TABLE settings MODIFY COLUMN setting_value TEXT;
ALTER TABLE tenant_settings MODIFY COLUMN setting_value TEXT NOT NULL;
