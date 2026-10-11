-- The worker seeds this checkpoint once from the current max auth ID on first initialization.
-- Never reset it on restart: events after that boundary must be retried until delivered.
CREATE TABLE IF NOT EXISTS syslog_auth_checkpoint (
  id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
  last_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
);
