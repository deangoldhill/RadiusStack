'use strict';
module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
  const syslog = dependencies?.syslog || require('../utils/syslog');
  app.post('/api/settings/syslog/test', requireApiAuth('settings', 'read-write'), async (req, res) => {
    if (Number(req.admin?.is_super_admin) !== 1 || !req.tenantScope || req.tenantScope.enabled ||
        req.tenantScope.globalContext === false) return res.status(403).json({ error: 'Global super administrator required' });
    let result;
    try { result = await syslog.test(); }
    catch { result = {ok:false, error:'Send failed'}; }
    try { await auditLog(req.admin.username, req.origin, 'Test syslog', result.ok ? 'success' : 'failed', JSON.stringify({ok:result.ok === true}), req.ip, {enabled:false}); } catch { /* Best-effort audit must not change the test outcome. */ }
    if (result.ok) res.json({ success: true, message: 'Test message sent successfully.' });
    else res.status(500).json({ success: false, error: result.error || 'Send failed' });
  });
};
