-- Add a sealed transfer count for the primary-authoritative plan enforcement snapshot.
ALTER TABLE ha_log_reconcile_state ADD COLUMN IF NOT EXISTS expected_plan_pod_enforcements BIGINT UNSIGNED NULL;
