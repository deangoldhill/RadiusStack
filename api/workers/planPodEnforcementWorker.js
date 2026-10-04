'use strict';

const { buildDynamicAuthorizationRequest, sendDynamicAuthorization } = require('../dynamic_auth');

function enabled(value) { return value === true || value === 1 || value === '1' || value === 'true'; }
function eligibleReasons(row) {
  const reasons = [];
  if (enabled(row.auto_pod_on_data_depleted) && Number(row.data_limit_mb) > 0 && Number(row.used_bytes) >= Number(row.data_limit_mb) * 1024 * 1024) reasons.push('data');
  if (enabled(row.auto_pod_on_time_depleted) && Number(row.time_limit_seconds) > 0 && Number(row.used_seconds) >= Number(row.time_limit_seconds)) reasons.push('time');
  return reasons;
}
async function loadScopes(pool) {
  const [[setting]] = await pool.query("SELECT setting_value FROM settings WHERE setting_key = 'multi_tenant_enabled'");
  if (!enabled(setting?.setting_value)) return [null];
  const [tenants] = await pool.query('SELECT id FROM tenants ORDER BY id');
  return tenants.map(row => Number(row.id));
}
function scopeSql(tenantId, column) { return tenantId === null ? `${column} IS NULL` : `${column} = ?`; }
function scopeParams(tenantId) { return tenantId === null ? [] : [tenantId]; }
function parsePodAttributes(raw) {
  const config = JSON.parse(raw || '{}');
  if (!Array.isArray(config.pod_attributes)) throw new Error('NAS PoD attributes are not configured');
  return config.pod_attributes;
}
function createPlanPodEnforcementWorker({ pool, sendDynamicAuthorization: send = sendDynamicAuthorization, logger = console }) {
  async function process() {
    let scopes;
    try { scopes = await loadScopes(pool); } catch (error) { logger.error('[Plan PoD enforcement] failed to load scopes:', error.message); return; }
    for (const tenantId of scopes) {
      const predicate = scopeSql(tenantId, 'a.tenant_id');
      const params = scopeParams(tenantId);
      let sessions;
      try {
        [sessions] = await pool.query(`SELECT a.radacctid,a.username,a.acctsessionid,a.nasipaddress,a.nasidentifier,a.callingstationid,a.framedipaddress,a.tenant_id,n.secret,n.dynamic_auth_attributes,p.data_limit_mb,p.time_limit_seconds,p.auto_pod_on_data_depleted,p.auto_pod_on_time_depleted,
          GREATEST(0, COALESCE((SELECT SUM(x.acctinputoctets + x.acctoutputoctets) FROM radacct x WHERE x.username=a.username AND ${scopeSql(tenantId, 'x.tenant_id')}),0)-COALESCE(u.base_input_octets,0)-COALESCE(u.base_output_octets,0)) AS used_bytes,
          GREATEST(0, COALESCE((SELECT SUM(x.acctsessiontime) FROM radacct x WHERE x.username=a.username AND ${scopeSql(tenantId, 'x.tenant_id')}),0)-COALESCE(u.base_session_seconds,0)) AS used_seconds
          FROM radacct a INNER JOIN user_plans up ON up.username=a.username AND ${scopeSql(tenantId, 'up.tenant_id')}
          INNER JOIN plans p ON p.id=up.plan_id AND ${scopeSql(tenantId, 'p.tenant_id')}
          LEFT JOIN user_plan_usage u ON u.username=up.username AND ${scopeSql(tenantId, 'u.tenant_id')}
          INNER JOIN nas n ON n.nasname=a.nasipaddress AND ${scopeSql(tenantId, 'n.tenant_id')}
          WHERE a.acctstoptime IS NULL AND ${predicate}`, [...params, ...params, ...params, ...params, ...params, ...params, ...params]);
      } catch (error) { logger.error(`[Plan PoD enforcement] tenant ${tenantId ?? 'global'} query failed:`, error.message); continue; }
      for (const session of sessions) for (const reason of eligibleReasons(session)) {
        let claim;
        try { [claim] = await pool.query("INSERT IGNORE INTO plan_pod_enforcements (radacctid, tenant_id, reason, status) VALUES (?, ?, ?, 'pending')", [session.radacctid, tenantId, reason]); }
        catch (error) { logger.error(`[Plan PoD enforcement] session ${session.radacctid} ${reason} claim failed:`, error.message); continue; }
        if (!claim.affectedRows) continue;
        try {
          const request = buildDynamicAuthorizationRequest({ kind: 'pod', session, packetAttributes: parsePodAttributes(session.dynamic_auth_attributes) });
          const result = await send({ request, secret: session.secret, host: session.nasipaddress });
          const status = result.acknowledged ? 'acknowledged' : 'nak';
          await pool.query("UPDATE plan_pod_enforcements SET status=?, completed_at=NOW() WHERE radacctid=? AND reason=?", [status, session.radacctid, reason]);
          logger.log(`[Plan PoD enforcement] ${status} for session ${session.radacctid}, reason=${reason}, tenant=${tenantId ?? 'global'}`);
        } catch (error) {
          try { await pool.query("UPDATE plan_pod_enforcements SET status='failed', error_message=?, completed_at=NOW() WHERE radacctid=? AND reason=?", [String(error.message || error).slice(0, 500), session.radacctid, reason]); }
          catch (updateError) { logger.error(`[Plan PoD enforcement] session ${session.radacctid} failure persistence failed:`, updateError.message); }
          logger.error(`[Plan PoD enforcement] failed session ${session.radacctid}, reason=${reason}, tenant=${tenantId ?? 'global'}:`, error.message);
        }
      }
    }
  }
  return { process };
}
module.exports = { eligibleReasons, createPlanPodEnforcementWorker, loadScopes };
