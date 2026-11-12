-- Existing installs: persist the manufacturer resolved locally when a MAC device is created.
-- Legacy rows are filled incrementally by the API's bounded backfill worker.
ALTER TABLE mac_auth_devices ADD COLUMN IF NOT EXISTS vendor_name VARCHAR(255) NULL;
