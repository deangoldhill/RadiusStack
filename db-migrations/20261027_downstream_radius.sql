-- Downstream RADIUS destinations and routing; no secrets are exposed by API reads.
CREATE TABLE IF NOT EXISTS schema_migrations (migration_name VARCHAR(128) NOT NULL PRIMARY KEY, applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS downstream_radius_destinations (
  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  tenant_id INT NULL,
  name VARCHAR(100) NOT NULL,
  ipv4 VARCHAR(15) NOT NULL,
  auth_port SMALLINT UNSIGNED NOT NULL DEFAULT 1812,
  accounting_port SMALLINT UNSIGNED NOT NULL DEFAULT 1813,
  shared_secret VARCHAR(253) NOT NULL,
  UNIQUE KEY uq_downstream_tenant_id (tenant_id,id),
  KEY idx_downstream_tenant_name (tenant_id,name),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);
ALTER TABLE nas ADD COLUMN IF NOT EXISTS downstream_destination_id INT NULL;
ALTER TABLE nas ADD COLUMN IF NOT EXISTS downstream_mode ENUM('duplicate','proxy-only') NULL;
ALTER TABLE nas ADD COLUMN IF NOT EXISTS downstream_validate_response BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE nas ADD CONSTRAINT fk_nas_downstream_destination FOREIGN KEY (downstream_destination_id) REFERENCES downstream_radius_destinations(id) ON DELETE SET NULL;
CREATE TABLE IF NOT EXISTS profile_downstream_routes (
  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  tenant_id INT NULL,
  profile_name VARCHAR(64) NOT NULL,
  destination_id INT NOT NULL,
  mode ENUM('duplicate','proxy-only') NOT NULL,
  validate_response BOOLEAN NOT NULL DEFAULT FALSE,
  KEY idx_profile_downstream_tenant_name (tenant_id,profile_name),
  KEY idx_profile_downstream_tenant_destination (tenant_id,destination_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (destination_id) REFERENCES downstream_radius_destinations(id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,destination_id) REFERENCES downstream_radius_destinations(tenant_id,id) ON DELETE CASCADE
);
INSERT IGNORE INTO schema_migrations (migration_name) VALUES ('20261027_downstream_radius');
