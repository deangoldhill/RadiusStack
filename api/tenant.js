function isSingleIPv4(value) {
  if (typeof value !== 'string' || value.trim() !== value) return false;
  const parts = value.split('.');
  return parts.length === 4 && parts.every(p => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
}
function resolveTenantScope({ multiTenantEnabled, admin, memberships, requestedTenantId }) {
  const superAdmin = Number(admin.is_super_admin) === 1;
  if (!multiTenantEnabled) return { enabled: false, tenantId: null, superAdmin };
  if (superAdmin && (!requestedTenantId || requestedTenantId === 'global')) return { enabled: false, tenantId: null, superAdmin, globalContext: true };
  const tenantId = Number.parseInt(requestedTenantId, 10);
  if (!Number.isSafeInteger(tenantId) || tenantId < 1) throw new Error('A selected tenant is required when multi-tenancy is enabled');
  if (!superAdmin && !memberships.map(Number).includes(tenantId)) throw new Error('Selected tenant is not assigned to this administrator');
  return { enabled: true, tenantId, superAdmin };
}
async function loadTenantScope(pool, admin, requestedTenantId) {
  const [[setting]] = await pool.query("SELECT setting_value FROM settings WHERE setting_key = 'multi_tenant_enabled'");
  const enabled = setting && ['true', '1'].includes(String(setting.setting_value).toLowerCase());
  const [memberships] = await pool.query('SELECT tenant_id FROM admin_tenants WHERE admin_id = ?', [admin.id]);
  return resolveTenantScope({ multiTenantEnabled: enabled, admin, memberships: memberships.map(r => r.tenant_id), requestedTenantId });
}
function scope(scope, column = 'tenant_id') { return scope.enabled ? { sql: ` AND ${column} = ?`, params: [scope.tenantId] } : { sql: '', params: [] }; }
module.exports = { isSingleIPv4, resolveTenantScope, loadTenantScope, scope };
