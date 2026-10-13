-- Persist only completed administrator sign-ins. Backfill existing accounts from
-- completed password-only and successful second-factor audit events; password
-- validation by itself does not mean an administrator logged in.
ALTER TABLE admins ADD COLUMN IF NOT EXISTS last_login_at DATETIME(6) NULL AFTER permissions;
UPDATE admins a
JOIN (
    SELECT admin_username, MAX(`timestamp`) AS last_login_at
    FROM admin_audit_log
    WHERE origin = 'webui' AND result = 'success'
      AND action IN ('Login completed', '2FA verification')
    GROUP BY admin_username
) completed ON completed.admin_username = a.username
SET a.last_login_at = completed.last_login_at
WHERE a.last_login_at IS NULL;
