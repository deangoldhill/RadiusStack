-- A stable processing-member identity for new auth logs. Existing rows stay NULL:
-- offset/parity alone cannot reliably identify historical single-node records.
ALTER TABLE radpostauth ADD COLUMN IF NOT EXISTS origin_node TINYINT UNSIGNED NULL DEFAULT NULL;
