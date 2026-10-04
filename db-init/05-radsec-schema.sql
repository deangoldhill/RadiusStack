-- Idempotent production migration: RadSec metadata for an existing MariaDB volume.
-- DDL is intentionally safe to re-run; record is written only after schema exists.
CREATE TABLE IF NOT EXISTS schema_migrations (
  migration_name VARCHAR(128) NOT NULL PRIMARY KEY,
  applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE nas ADD COLUMN IF NOT EXISTS radsec_enabled TINYINT(1) NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS radsec_clients (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  tenant_id INT NOT NULL,
  nas_id INT NOT NULL,
  serial VARCHAR(64) NOT NULL,
  common_name VARCHAR(128) NOT NULL,
  certificate_path VARCHAR(255) NOT NULL,
  issued_at DATETIME NOT NULL,
  revoked_at DATETIME NULL,
  UNIQUE KEY uq_radsec_client_serial (serial),
  KEY idx_radsec_clients_tenant_nas (tenant_id,nas_id),
  CONSTRAINT fk_radsec_clients_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  CONSTRAINT fk_radsec_clients_nas FOREIGN KEY (nas_id) REFERENCES nas(id) ON DELETE CASCADE
);

INSERT IGNORE INTO schema_migrations (migration_name) VALUES ('20260918_radsec');
