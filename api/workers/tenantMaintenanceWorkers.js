'use strict';

const MAC_SETTING_KEYS = ['mac_auth_autocreate', 'mac_auth_autocreate_plan', 'mac_auth_autocreate_profile', 'mac_auth_autocreate_interval'];
const STALE_SETTING_KEYS = ['clear_stale_sessions', 'stale_session_threshold', 'stale_session_interval'];
const ALL_SETTING_KEYS = [...MAC_SETTING_KEYS, ...STALE_SETTING_KEYS];

function settingMap(rows) {
  return rows.reduce((result, row) => {
    result[row.setting_key] = row.setting_value;
    return result;
  }, {});
}

function enabled(value) {
  return value === 'true' || value === '1' || value === true || value === 1;
}

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

async function loadScopes(pool) {
  const [[setting]] = await pool.query("SELECT setting_value FROM settings WHERE setting_key = 'multi_tenant_enabled'");
  const multiTenant = enabled(setting?.setting_value);
  if (!multiTenant) {
    const [rows] = await pool.query(
      "SELECT setting_key, setting_value FROM settings WHERE setting_key IN ('mac_auth_autocreate', 'mac_auth_autocreate_plan', 'mac_auth_autocreate_profile', 'mac_auth_autocreate_interval', 'clear_stale_sessions', 'stale_session_threshold', 'stale_session_interval')"
    );
    return [{ tenantId: null, config: settingMap(rows), multiTenant: false }];
  }

  const [rows] = await pool.query(
    "SELECT t.id AS tenant_id, ts.setting_key, ts.setting_value FROM tenants t LEFT JOIN tenant_settings ts ON ts.tenant_id = t.id AND ts.setting_key IN ('mac_auth_autocreate', 'mac_auth_autocreate_plan', 'mac_auth_autocreate_profile', 'mac_auth_autocreate_interval', 'clear_stale_sessions', 'stale_session_threshold', 'stale_session_interval')"
  );
  const scopes = new Map();
  for (const row of rows) {
    const tenantId = Number(row.tenant_id);
    if (!scopes.has(tenantId)) scopes.set(tenantId, { tenantId, config: {}, multiTenant: true });
    if (row.setting_key) scopes.get(tenantId).config[row.setting_key] = row.setting_value;
  }
  return [...scopes.values()];
}

function createTenantMaintenanceWorkers({ pool, auditLog, apiDebugLog = () => {}, logger = console, now = () => Date.now() }) {
  const lastAutoCreateRuns = new Map();
  const lastStaleSessionRuns = new Map();

  async function processAutoCreateMacs() {
    try {
      const scopes = await loadScopes(pool);
      for (const scope of scopes) {
        const { tenantId, config, multiTenant } = scope;
        if (!enabled(config.mac_auth_autocreate)) continue;
        const intervalSeconds = positiveInt(config.mac_auth_autocreate_interval, 5);
        const current = now();
        if (current - (lastAutoCreateRuns.get(tenantId) || 0) < intervalSeconds * 1000) continue;
        lastAutoCreateRuns.set(tenantId, current);

        const rejectedSql = multiTenant
          ? `SELECT DISTINCT p.username FROM radpostauth p LEFT JOIN radcheck r ON LOWER(REPLACE(REPLACE(r.username, ':', ''), '-', '')) = LOWER(REPLACE(REPLACE(p.username, ':', ''), '-', '')) AND r.tenant_id = ? WHERE p.tenant_id = ? AND p.reply = 'Access-Reject' AND p.username REGEXP '^([0-9a-fA-F]{12}|([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})$' AND r.username IS NULL AND p.authdate > DATE_SUB(NOW(), INTERVAL 1 MINUTE)`
          : `SELECT DISTINCT p.username FROM radpostauth p LEFT JOIN radcheck r ON LOWER(REPLACE(REPLACE(r.username, ':', ''), '-', '')) = LOWER(REPLACE(REPLACE(p.username, ':', ''), '-', '')) AND r.tenant_id IS NULL WHERE p.tenant_id IS NULL AND p.reply = 'Access-Reject' AND p.username REGEXP '^([0-9a-fA-F]{12}|([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})$' AND r.username IS NULL AND p.authdate > DATE_SUB(NOW(), INTERVAL 1 MINUTE)`;
        const [rejectedRows] = await pool.query(rejectedSql, multiTenant ? [tenantId, tenantId] : []);

        for (const row of rejectedRows) {
          const macAddress = row.username.trim().toLowerCase().replace(/-/g, ':');
          const [existing] = await pool.query(
            multiTenant ? 'SELECT username FROM radcheck WHERE username = ? AND tenant_id = ?' : 'SELECT username FROM radcheck WHERE username = ? AND tenant_id IS NULL',
            multiTenant ? [macAddress, tenantId] : [macAddress]
          );
          if (existing.length) continue;

          const conn = await pool.getConnection();
          try {
            await conn.beginTransaction();
            if (multiTenant) {
              await conn.query('INSERT IGNORE INTO mac_auth_devices (mac_address, mac_id, tenant_id) VALUES (?, ?, ?)', [macAddress, macAddress, tenantId]);
              await conn.query("DELETE FROM radcheck WHERE username = ? AND attribute = 'Cleartext-Password' AND tenant_id = ?", [macAddress, tenantId]);
              await conn.query("INSERT INTO radcheck (username, attribute, op, value, tenant_id) VALUES (?, 'Cleartext-Password', ':=', ?, ?)", [macAddress, macAddress, tenantId]);
              await conn.query('DELETE FROM radusergroup WHERE username = ? AND tenant_id = ?', [macAddress, tenantId]);
              if (config.mac_auth_autocreate_profile) await conn.query('INSERT INTO radusergroup (username, groupname, priority, tenant_id) VALUES (?, ?, 1, ?)', [macAddress, config.mac_auth_autocreate_profile, tenantId]);
              await conn.query('DELETE FROM user_plans WHERE username = ? AND tenant_id = ?', [macAddress, tenantId]);
              if (config.mac_auth_autocreate_plan) await conn.query('INSERT INTO user_plans (username, plan_id, tenant_id) VALUES (?, ?, ?)', [macAddress, config.mac_auth_autocreate_plan, tenantId]);
            } else {
              await conn.query('INSERT IGNORE INTO mac_auth_devices (mac_address, mac_id) VALUES (?, ?)', [macAddress, macAddress]);
              await conn.query("DELETE FROM radcheck WHERE username = ? AND attribute = 'Cleartext-Password' AND tenant_id IS NULL", [macAddress]);
              await conn.query("INSERT INTO radcheck (username, attribute, op, value) VALUES (?, 'Cleartext-Password', ':=', ?)", [macAddress, macAddress]);
              await conn.query('DELETE FROM radusergroup WHERE username = ? AND tenant_id IS NULL', [macAddress]);
              if (config.mac_auth_autocreate_profile) await conn.query('INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)', [macAddress, config.mac_auth_autocreate_profile]);
              await conn.query('DELETE FROM user_plans WHERE username = ? AND tenant_id IS NULL', [macAddress]);
              if (config.mac_auth_autocreate_plan) await conn.query('INSERT INTO user_plans (username, plan_id) VALUES (?, ?)', [macAddress, config.mac_auth_autocreate_plan]);
            }
            await conn.commit();
            logger.log(`[MAC Auto-Create Worker] Registered new MAC for ${multiTenant ? `tenant ${tenantId}` : 'global'}: ${macAddress}`);
          } catch (error) {
            await conn.rollback();
            logger.error(`[MAC Auto-Create Worker] Error registering MAC for ${multiTenant ? `tenant ${tenantId}` : 'global'}:`, error);
          } finally {
            conn.release();
          }
        }
      }
    } catch (error) {
      logger.error('[MAC Auto-Create Worker] Error:', error);
    }
  }

  async function processStaleSessions() {
    try {
      const scopes = await loadScopes(pool);
      for (const scope of scopes) {
        const { tenantId, config, multiTenant } = scope;
        if (!enabled(config.clear_stale_sessions)) continue;
        const intervalMinutes = positiveInt(config.stale_session_interval, 10);
        const current = now();
        if (current - (lastStaleSessionRuns.get(tenantId) || 0) < intervalMinutes * 60000) {
          apiDebugLog(`Stale session worker skipped for ${multiTenant ? `tenant ${tenantId}` : 'global'}: throttled`);
          continue;
        }
        lastStaleSessionRuns.set(tenantId, current);
        const thresholdDays = positiveInt(config.stale_session_threshold, 3);
        const tenantPredicate = multiTenant ? 'AND tenant_id = ?' : 'AND tenant_id IS NULL';
        const [staleSessions] = await pool.query(
          `SELECT radacctid FROM radacct WHERE acctstoptime IS NULL ${tenantPredicate} AND ((TIMESTAMPDIFF(HOUR, acctstarttime, NOW()) >= 3 AND TIMESTAMPDIFF(MINUTE, acctstarttime, acctupdatetime) > 10 AND TIMESTAMPDIFF(HOUR, acctupdatetime, NOW()) >= 1) OR (TIMESTAMPDIFF(DAY, acctstarttime, NOW()) >= ? AND (acctupdatetime IS NULL OR TIMESTAMPDIFF(SECOND, acctstarttime, acctupdatetime) <= 30)))`,
          multiTenant ? [tenantId, thresholdDays] : [thresholdDays]
        );
        if (!staleSessions.length) continue;
        const ids = staleSessions.map(row => row.radacctid);
        const placeholders = ids.map(() => '?').join(',');
        const updateSql = multiTenant
          ? `UPDATE radacct SET acctstoptime = NOW() WHERE tenant_id = ? AND radacctid IN (${placeholders})`
          : `UPDATE radacct SET acctstoptime = NOW() WHERE tenant_id IS NULL AND radacctid IN (${placeholders})`;
        await pool.query(updateSql, multiTenant ? [tenantId, ...ids] : ids);
        await auditLog('system', 'system', `Cleared ${ids.length} stale sessions`, 'success', `Background process auto-clear for ${multiTenant ? `tenant ${tenantId}` : 'global'}`, '127.0.0.1', multiTenant ? { enabled: true, tenantId } : { enabled: false });
        logger.log(`[Background Task] Auto-cleared ${ids.length} stale sessions for ${multiTenant ? `tenant ${tenantId}` : 'global'}.`);
      }
    } catch (error) {
      logger.error('[Background Task] Error auto-clearing stale sessions:', error);
    }
  }

  return { processAutoCreateMacs, processStaleSessions };
}

module.exports = { ALL_SETTING_KEYS, createTenantMaintenanceWorkers, loadScopes };
