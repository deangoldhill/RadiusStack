-- Durable primary HA delivery control. Existing queues and accounting cursors are unchanged.
CREATE TABLE IF NOT EXISTS ha_control_state (
    id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
    paused TINYINT(1) NOT NULL DEFAULT 0,
    paused_at DATETIME(6) NULL,
    reason VARCHAR(255) NULL,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
);
INSERT IGNORE INTO ha_control_state (id, paused) VALUES (1, 0);
CREATE TABLE IF NOT EXISTS ha_log_reconcile_state (
    id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
    run_id CHAR(32) NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'idle',
    detail VARCHAR(255) NULL,
    error VARCHAR(255) NULL,
    expected_radacct BIGINT UNSIGNED NULL,
    expected_radpostauth BIGINT UNSIGNED NULL,
    expected_admin_audit_log BIGINT UNSIGNED NULL,
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
);
INSERT IGNORE INTO ha_log_reconcile_state (id, status) VALUES (1, 'idle');
