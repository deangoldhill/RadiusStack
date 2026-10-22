
CREATE TABLE IF NOT EXISTS ha_queue (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    query TEXT,
    values_json MEDIUMTEXT,
    insert_id BIGINT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS ha_sync_state (
    table_name VARCHAR(50) PRIMARY KEY,
    last_time VARCHAR(30) DEFAULT '1970-01-01 00:00:00.000000',
    last_id BIGINT DEFAULT 0
);
INSERT IGNORE INTO ha_sync_state (table_name, last_time, last_id) VALUES ('radacct', '1970-01-01 00:00:00.000000', 0), ('radpostauth', '1970-01-01 00:00:00.000000', 0);
CREATE TABLE IF NOT EXISTS ha_replay_state (
    source_peer VARCHAR(45) PRIMARY KEY,
    last_queue_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
    radsec_restart_pending TINYINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
