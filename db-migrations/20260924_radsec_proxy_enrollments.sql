-- Idempotent production migration: revocable SaaS RadSec proxy enrollments.
CREATE TABLE IF NOT EXISTS schema_migrations (
  migration_name VARCHAR(128) NOT NULL PRIMARY KEY,
  applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS radsec_proxy_enrollments (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  tenant_id INT NOT NULL,
  nas_id INT NOT NULL,
  radsec_client_id BIGINT NOT NULL,
  display_name VARCHAR(128) NOT NULL,
  observed_ip VARCHAR(45) NOT NULL,
  issued_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  revoked_at DATETIME NULL,
  revoked_reason VARCHAR(255) NULL,
  KEY idx_radsec_proxy_enrollments_tenant_active (tenant_id, revoked_at),
  UNIQUE KEY uq_radsec_proxy_enrollments_client (radsec_client_id),
  CONSTRAINT fk_radsec_proxy_enrollments_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  CONSTRAINT fk_radsec_proxy_enrollments_nas FOREIGN KEY (nas_id) REFERENCES nas(id) ON DELETE CASCADE,
  CONSTRAINT fk_radsec_proxy_enrollments_client FOREIGN KEY (radsec_client_id) REFERENCES radsec_clients(id) ON DELETE CASCADE
);

INSERT IGNORE INTO schema_migrations (migration_name) VALUES ('20260924_radsec_proxy_enrollments');
