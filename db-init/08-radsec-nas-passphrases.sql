-- Encrypted, tenant-bound recovery for newly generated RadSec NAS certificate passphrases.
-- The composite parent key prevents a passphrase from being attached to a NAS in a different tenant.
CREATE TABLE IF NOT EXISTS schema_migrations (migration_name VARCHAR(128) NOT NULL PRIMARY KEY, applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP);
ALTER TABLE nas ADD UNIQUE KEY IF NOT EXISTS uq_nas_tenant_id (tenant_id,id);
CREATE TABLE IF NOT EXISTS radsec_nas_passphrases (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  tenant_id INT NOT NULL,
  nas_id INT NOT NULL,
  ciphertext TEXT NOT NULL,
  iv VARCHAR(64) NOT NULL,
  auth_tag VARCHAR(64) NOT NULL,
  key_version TINYINT UNSIGNED NOT NULL DEFAULT 1,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_radsec_nas_passphrase_tenant_nas (tenant_id,nas_id),
  KEY idx_radsec_nas_passphrases_tenant (tenant_id),
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id,nas_id) REFERENCES nas(tenant_id,id) ON DELETE CASCADE
);
-- Existing RadSec certificates intentionally receive no row: their prior one-time passphrases are unavailable and must be regenerated.
INSERT IGNORE INTO schema_migrations (migration_name) VALUES ('20260929_radsec_nas_passphrases');
