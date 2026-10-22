-- A single durable cursor per authenticated HA source makes ordered bulk replay
-- safe when the receiver commits but its HTTP response is lost.
CREATE TABLE IF NOT EXISTS ha_replay_state (
    source_peer VARCHAR(45) PRIMARY KEY,
    last_queue_id BIGINT UNSIGNED NOT NULL DEFAULT 0,
    radsec_restart_pending TINYINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
