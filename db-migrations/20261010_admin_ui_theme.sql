-- A nullable per-administrator preference: existing accounts use the blue default.
ALTER TABLE admins ADD COLUMN IF NOT EXISTS ui_theme VARCHAR(16) NULL DEFAULT NULL;
