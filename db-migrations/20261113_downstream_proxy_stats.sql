-- Per-destination UTC minute counters for routed downstream auth/accounting attempts.
-- Rows older than 366 days are pruned in bounded batches by the API maintenance worker.
CREATE TABLE IF NOT EXISTS downstream_proxy_stats_minutes (
  destination_id INT NOT NULL,
  tenant_id INT NULL,
  bucket_start DATETIME NOT NULL,
  route_mode ENUM('proxy-only','duplicate','validated') NOT NULL,
  auth_requests BIGINT UNSIGNED NOT NULL DEFAULT 0,
  accounting_requests BIGINT UNSIGNED NOT NULL DEFAULT 0,
  PRIMARY KEY (destination_id,bucket_start,route_mode),
  KEY idx_downstream_proxy_stats_tenant_time (tenant_id,destination_id,bucket_start),
  KEY idx_downstream_proxy_stats_retention (bucket_start),
  CONSTRAINT fk_downstream_proxy_stats_destination FOREIGN KEY (destination_id)
    REFERENCES downstream_radius_destinations(id) ON DELETE CASCADE
);
