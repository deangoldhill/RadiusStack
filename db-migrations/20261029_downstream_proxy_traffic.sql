-- Existing 6.0.2 destinations retain the previous Auth+Accounting behavior.
ALTER TABLE downstream_radius_destinations ADD COLUMN IF NOT EXISTS proxy_traffic ENUM('auth','accounting','both') NOT NULL DEFAULT 'both';
INSERT IGNORE INTO schema_migrations (migration_name) VALUES ('20261029_downstream_proxy_traffic');
