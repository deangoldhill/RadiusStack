module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const syslog = require('../utils/syslog');
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily, apiDebugLog, setApiDebugMode } = dependencies;

// --- SETTINGS ---
app.get('/api/settings', requireApiAuth('settings', 'read-only'), async (req, res) => {
    const [rows] = await pool.query('SELECT * FROM settings');
    res.json(rows.reduce((acc, row) => ({ ...acc, [row.setting_key]: row.setting_value }), {}));
});

app.post('/api/settings', requireApiAuth('settings', 'read-write'), async (req, res) => {
  try {
    const { enforce_2fa, radius_debug, custom_reply_attributes, ui_theme, totp_enrollment_hours, mask_user_passwords, mac_auth_autocreate, mac_auth_autocreate_plan, mac_auth_autocreate_profile, mac_auth_autocreate_interval, authlogs_purge_enabled, authlogs_purge_days, authlogs_purge_interval, clear_stale_sessions, stale_session_threshold, stale_session_interval, api_debug, radius_stats_retention_days, radius_stats_purge_interval, radius_stats_poll_interval,
      syslog_enabled, syslog_host, syslog_port, syslog_protocol, syslog_send_audit, syslog_send_authlogs
    } = req.body;

    if (enforce_2fa !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('enforce_2fa', ?) ON DUPLICATE KEY UPDATE setting_value=?", [enforce_2fa, enforce_2fa]);
    if (radius_debug !== undefined) {
        await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('radius_debug', ?) ON DUPLICATE KEY UPDATE setting_value=?", [radius_debug, radius_debug]);
        exec('docker restart radius_server');
    }
    if (custom_reply_attributes !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('custom_reply_attributes', ?) ON DUPLICATE KEY UPDATE setting_value=?", [custom_reply_attributes, custom_reply_attributes]);
    if (ui_theme !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('ui_theme', ?) ON DUPLICATE KEY UPDATE setting_value=?", [ui_theme, ui_theme]);
    if (totp_enrollment_hours !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('totp_enrollment_hours', ?) ON DUPLICATE KEY UPDATE setting_value=?", [totp_enrollment_hours, totp_enrollment_hours]);
    if (mask_user_passwords !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('mask_user_passwords', ?) ON DUPLICATE KEY UPDATE setting_value=?", [mask_user_passwords, mask_user_passwords]);
  if (mac_auth_autocreate !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('mac_auth_autocreate', ?) ON DUPLICATE KEY UPDATE setting_value=?", [mac_auth_autocreate, mac_auth_autocreate]);
  if (mac_auth_autocreate_plan !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('mac_auth_autocreate_plan', ?) ON DUPLICATE KEY UPDATE setting_value=?", [mac_auth_autocreate_plan, mac_auth_autocreate_plan]);
  if (mac_auth_autocreate_profile !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('mac_auth_autocreate_profile', ?) ON DUPLICATE KEY UPDATE setting_value=?", [mac_auth_autocreate_profile, mac_auth_autocreate_profile]);
    if (mac_auth_autocreate_interval !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('mac_auth_autocreate_interval', ?) ON DUPLICATE KEY UPDATE setting_value=?", [mac_auth_autocreate_interval, mac_auth_autocreate_interval]);
    if (authlogs_purge_enabled !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('authlogs_purge_enabled', ?) ON DUPLICATE KEY UPDATE setting_value=?", [authlogs_purge_enabled, authlogs_purge_enabled]);
    if (authlogs_purge_days !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('authlogs_purge_days', ?) ON DUPLICATE KEY UPDATE setting_value=?", [authlogs_purge_days, authlogs_purge_days]);
    if (authlogs_purge_interval !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('authlogs_purge_interval', ?) ON DUPLICATE KEY UPDATE setting_value=?", [authlogs_purge_interval, authlogs_purge_interval]);

    if (clear_stale_sessions !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('clear_stale_sessions', ?) ON DUPLICATE KEY UPDATE setting_value=?", [clear_stale_sessions, clear_stale_sessions]);
    if (stale_session_threshold !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('stale_session_threshold', ?) ON DUPLICATE KEY UPDATE setting_value=?", [stale_session_threshold, stale_session_threshold]);
    if (stale_session_interval !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('stale_session_interval', ?) ON DUPLICATE KEY UPDATE setting_value=?", [stale_session_interval, stale_session_interval]);
    if (api_debug !== undefined) {
        await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('api_debug', ?) ON DUPLICATE KEY UPDATE setting_value=?", [api_debug, api_debug]);
        setApiDebugMode(api_debug === 'true');
    }

    if (radius_stats_retention_days !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('radius_stats_retention_days', ?) ON DUPLICATE KEY UPDATE setting_value=?", [radius_stats_retention_days, radius_stats_retention_days]);
    if (radius_stats_purge_interval !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('radius_stats_purge_interval', ?) ON DUPLICATE KEY UPDATE setting_value=?", [radius_stats_purge_interval, radius_stats_purge_interval]);
    if (radius_stats_poll_interval !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('radius_stats_poll_interval', ?) ON DUPLICATE KEY UPDATE setting_value=?", [radius_stats_poll_interval, radius_stats_poll_interval]);
    if (syslog_enabled !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('syslog_enabled', ?) ON DUPLICATE KEY UPDATE setting_value=?", [syslog_enabled, syslog_enabled]);
    if (syslog_host !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('syslog_host', ?) ON DUPLICATE KEY UPDATE setting_value=?", [syslog_host, syslog_host]);
    if (syslog_port !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('syslog_port', ?) ON DUPLICATE KEY UPDATE setting_value=?", [syslog_port, syslog_port]);
    if (syslog_protocol !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('syslog_protocol', ?) ON DUPLICATE KEY UPDATE setting_value=?", [syslog_protocol, syslog_protocol]);
    if (syslog_send_audit !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('syslog_send_audit', ?) ON DUPLICATE KEY UPDATE setting_value=?", [syslog_send_audit, syslog_send_audit]);
    if (syslog_send_authlogs !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('syslog_send_authlogs', ?) ON DUPLICATE KEY UPDATE setting_value=?", [syslog_send_authlogs, syslog_send_authlogs]);

    syslog.invalidateCache();


    await auditLog(req.admin.username, req.origin, `Updated settings (2FA:${enforce_2fa}, Debug:${radius_debug}, MacAutoCreate:${mac_auth_autocreate})`, 'success', '', req.ip);
    res.json({ success: true });
  } catch (err) {
    console.error('Settings save error:', err);
    res.status(500).json({ error: err.message });
  }
});


};
