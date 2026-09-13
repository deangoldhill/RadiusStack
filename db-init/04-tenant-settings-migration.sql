-- Online upgrade for existing RadiusStack databases.
ALTER TABLE radius_stats ADD COLUMN IF NOT EXISTS tenant_id INT NULL, ADD KEY idx_radius_stats_tenant_time (tenant_id, collected_at);

-- Preserve existing values while allowing structured custom attribute JSON beyond 255 bytes.
ALTER TABLE settings MODIFY COLUMN setting_value TEXT;
ALTER TABLE tenant_settings MODIFY COLUMN setting_value TEXT NOT NULL;
