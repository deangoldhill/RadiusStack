-- Former API startup ALTERs are managed centrally and run whether HA is
-- currently enabled or not, so enabling HA never mutates schema at runtime.
ALTER TABLE ha_queue ADD COLUMN IF NOT EXISTS insert_id BIGINT DEFAULT NULL;
ALTER TABLE ha_sync_state ADD COLUMN IF NOT EXISTS last_time VARCHAR(30) DEFAULT '1970-01-01 00:00:00.000000';
ALTER TABLE radacct ADD COLUMN IF NOT EXISTS ha_updated_at TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6);
