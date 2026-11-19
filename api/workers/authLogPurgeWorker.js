// Global retention keeps the legacy all-rows behavior; tenant retention is explicitly tenant-scoped.
function createAuthLogPurgeWorker({pool, auditLog, now = Date.now}) {
  let lastGlobalRun = 0;
  const lastTenantRun = new Map();
  const settingKeys = "('multi_tenant_enabled', 'authlogs_purge_enabled', 'authlogs_purge_days', 'authlogs_purge_interval')";
  const tenantKeys = "('authlogs_purge_enabled', 'authlogs_purge_days', 'authlogs_purge_interval')";
  const positive = (value, fallback) => {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
  };
  const config = rows => Object.fromEntries(rows.map(row => [row.setting_key, row.setting_value]));
  async function purge(settings, tenantId, multiTenantEnabled = false) {
    if (settings.authlogs_purge_enabled !== 'true' && settings.authlogs_purge_enabled !== '1') return;
    const days = positive(settings.authlogs_purge_days, 30);
    const interval = positive(settings.authlogs_purge_interval, 60);
    const previous = tenantId === null ? lastGlobalRun : lastTenantRun.get(tenantId) || 0;
    if (now() - previous < interval * 60 * 1000) return;
    if (tenantId === null) lastGlobalRun = now();
    else lastTenantRun.set(tenantId, now());
    const [result] = await pool.query(
      tenantId === null
        ? 'DELETE FROM radpostauth WHERE authdate < DATE_SUB(NOW(), INTERVAL ? DAY)' + (multiTenantEnabled ? ' AND tenant_id IS NULL' : '')
        : 'DELETE FROM radpostauth WHERE authdate < DATE_SUB(NOW(), INTERVAL ? DAY) AND tenant_id = ?',
      tenantId === null ? [days] : [days, tenantId]
    );
    if (result.affectedRows > 0) {
      const label = tenantId === null ? '' : ` for tenant ${tenantId}`;
      await auditLog('system', 'system', `Auto-purged ${result.affectedRows} auth log entries older than ${days} days${label}`, 'success', 'Background process auth log purge', '127.0.0.1', tenantId === null ? undefined : {enabled:true, tenantId});
      console.log(`[Background Task] Auto-purged ${result.affectedRows} auth log entries${label}.`);
    }
  }
  async function process() {
    try {
      const [globalRows] = await pool.query(`SELECT setting_key, setting_value FROM settings WHERE setting_key IN ${settingKeys}`);
      const globalConfig = config(globalRows);
      const multiTenantEnabled = globalConfig.multi_tenant_enabled === 'true' || globalConfig.multi_tenant_enabled === '1';
      await purge(globalConfig, null, multiTenantEnabled);
      if (!multiTenantEnabled) return;
      const [tenantRows] = await pool.query(`SELECT tenant_id, setting_key, setting_value FROM tenant_settings WHERE setting_key IN ${tenantKeys}`);
      const perTenant = new Map();
      for (const row of tenantRows) {
        if (!perTenant.has(row.tenant_id)) perTenant.set(row.tenant_id, []);
        perTenant.get(row.tenant_id).push(row);
      }
      for (const [tenantId, rows] of perTenant) await purge(config(rows), tenantId);
    } catch (error) { console.error('[Background Task] Error auto-purging auth logs:', error); }
  }
  return {process};
}

module.exports = {createAuthLogPurgeWorker};
