const TENANT_SETTING_KEYS = new Set([
  'enforce_2fa', 'mask_user_passwords',
  'mac_auth_autocreate', 'mac_auth_autocreate_plan', 'mac_auth_autocreate_profile', 'mac_auth_autocreate_interval',
  'clear_stale_sessions', 'stale_session_threshold', 'stale_session_interim_threshold_minutes', 'stale_session_interval',
  'radius_stats_retention_days', 'radius_stats_purge_interval', 'radius_stats_poll_interval', 'custom_reply_attributes'
]);
const GLOBAL_SETTING_KEYS = new Set([
  'multi_tenant_enabled', 'radius_debug', 'api_debug', 'ui_theme', 'totp_enrollment_hours',
  'authlogs_purge_enabled', 'authlogs_purge_days', 'authlogs_purge_interval',
  'syslog_enabled', 'syslog_host', 'syslog_port', 'syslog_protocol', 'syslog_send_audit', 'syslog_send_authlogs'
]);

function asMap(rows) { return rows.reduce((result, row) => ({ ...result, [row.setting_key]: row.setting_value }), {}); }
function truthy(value) { return ['true', '1', true, 1].includes(value); }
const { STANDARD_REPLY_ATTRIBUTES, normalizeCustomReplyAttributes } = require('../custom_attributes');

module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
  const syslog = require('../utils/syslog');
  const { exec, setApiDebugMode } = dependencies;

  app.get('/api/settings', requireApiAuth('settings', 'read-only'), async (req, res) => {
    try {
      if (req.tenantScope.enabled) {
        const [rows] = await pool.query('SELECT setting_key, setting_value FROM tenant_settings WHERE tenant_id = ?', [req.tenantScope.tenantId]);
        return res.json(asMap(rows));
      }
      if (req.tenantScope.globalContext && Number(req.admin.is_super_admin) !== 1) return res.status(403).json({ error: 'Global settings require a super administrator' });
      const [rows] = await pool.query('SELECT setting_key, setting_value FROM settings');
      return res.json(asMap(rows));
    } catch (err) { return res.status(500).json({ error: err.message }); }
  });

  app.get('/api/settings/reply-attribute-catalogue', requireApiAuth('settings', 'read-only'), (req, res) => {
    return res.json({ attributes: STANDARD_REPLY_ATTRIBUTES });
  });

  app.post('/api/settings', requireApiAuth('settings', 'read-write'), async (req, res) => {
    try {
      const entries = Object.entries(req.body || {}).filter(([, value]) => value !== undefined);
      if (entries.some(([key]) => key === 'multi_tenant_enabled') && Number(req.admin.is_super_admin) === 1) req.tenantScope = { enabled: false, globalContext: true, superAdmin: true };
      const customEntry = entries.find(([key]) => key === 'custom_reply_attributes');
      let regenerateVsaDictionary = false;
      if (customEntry) {
        try { customEntry[1] = JSON.stringify(normalizeCustomReplyAttributes(customEntry[1])); regenerateVsaDictionary = true; }
        catch (err) { return res.status(400).json({ error: err.message }); }
      }
      const allowed = req.tenantScope.enabled ? TENANT_SETTING_KEYS : GLOBAL_SETTING_KEYS;
      const unexpected = entries.map(([key]) => key).filter(key => !allowed.has(key));
      if (unexpected.length && !(req.tenantScope.globalContext && Number(req.admin.is_super_admin) === 1)) return res.status(400).json({ error: 'Unexpected settings for selected scope', keys: unexpected });
      if (unexpected.length) entries.splice(0, entries.length, ...entries.filter(([key]) => allowed.has(key)));
      if (!req.tenantScope.enabled && req.tenantScope.globalContext && Number(req.admin.is_super_admin) !== 1) return res.status(403).json({ error: 'Global settings require a super administrator' });

      if (req.tenantScope.enabled) {
        for (const [key, value] of entries) {
          await pool.query(
            'INSERT INTO tenant_settings (tenant_id, setting_key, setting_value) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)',
            [req.tenantScope.tenantId, key, String(value)]
          );
        }
      } else {
        for (const [key, rawValue] of entries) {
          const value = key === 'multi_tenant_enabled' ? (truthy(rawValue) ? 'true' : 'false') : String(rawValue);
          await pool.query('INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)', [key, value]);
          if (key === 'radius_debug') exec('docker restart radius_server');
          if (key === 'api_debug') setApiDebugMode(value === 'true');
        }
        syslog.invalidateCache();
      }
      if (regenerateVsaDictionary) exec('docker restart radius_server');
      const scopeLabel = req.tenantScope.enabled ? `tenant ${req.tenantScope.tenantId}` : 'global platform';
      await auditLog(req.admin.username, req.origin, `Updated ${scopeLabel} settings`, 'success', '', req.ip, req.tenantScope);
      return res.json({ success: true });
    } catch (err) {
      console.error('Settings save error:', err);
      return res.status(500).json({ error: err.message });
    }
  });
};

module.exports.TENANT_SETTING_KEYS = TENANT_SETTING_KEYS;
module.exports.GLOBAL_SETTING_KEYS = GLOBAL_SETTING_KEYS;
