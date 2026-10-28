-- Existing databases can have the HA cursor table without its fresh-install seed rows.
-- Keep any existing progress: never reset an already-present cursor.
INSERT IGNORE INTO ha_sync_state (table_name, last_time, last_id)
VALUES ('radacct', '1970-01-01 00:00:00.000000', 0),
       ('radpostauth', '1970-01-01 00:00:00.000000', 0);
