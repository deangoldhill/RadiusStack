CREATE TABLE IF NOT EXISTS backup_jobs (
  id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  frequency ENUM('hourly','daily','weekly','interval_hours') NOT NULL,
  interval_hours SMALLINT UNSIGNED NULL,
  type ENUM('full','partial') NOT NULL,
  acct BOOLEAN NOT NULL DEFAULT FALSE,
  auth BOOLEAN NOT NULL DEFAULT FALSE,
  audit BOOLEAN NOT NULL DEFAULT FALSE,
  keep_count TINYINT UNSIGNED NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  next_run DATETIME(6) NOT NULL,
  last_run DATETIME(6) NULL,
  last_error VARCHAR(500) NULL,
  lease_until DATETIME(6) NULL,
  lease_token CHAR(32) NULL,
  KEY idx_backup_jobs_due (enabled,next_run)
);
CREATE TABLE IF NOT EXISTS local_backups (
  id CHAR(32) PRIMARY KEY,
  job_id BIGINT UNSIGNED NULL,
  type ENUM('full','partial') NOT NULL,
  size BIGINT UNSIGNED NOT NULL,
  created_at DATETIME(6) NOT NULL,
  checksum CHAR(64) NOT NULL,
  KEY idx_local_backups_job_time (job_id,created_at),
  CONSTRAINT fk_local_backups_job FOREIGN KEY (job_id) REFERENCES backup_jobs(id) ON DELETE SET NULL
);
