'use strict';
module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
  const syslog = require('../utils/syslog');
  app.post('/api/settings/syslog/test', requireApiAuth('settings', 'read-write'), async (req, res) => {
    if (Number(req.admin?.is_super_admin) !== 1 || !req.tenantScope || req.tenantScope.enabled ||
        req.tenantScope.globalContext === false) return res.status(403).json({ error: 'Global super administrator required' });
    const result = await syslog.test();
    if (result.ok) res.json({ success: true, message: 'Test message sent successfully.' });
    else res.status(500).json({ success: false, error: result.error || 'Send failed' });
  });
};
