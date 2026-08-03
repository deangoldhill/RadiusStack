'use strict';
module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
  const syslog = require('../utils/syslog');
  app.post('/api/settings/syslog/test', requireApiAuth('settings', 'read-only'), async (req, res) => {
    const { host, port, protocol } = req.body;
    if (!host) return res.status(400).json({ error: 'host is required' });
    const result = await syslog.test(host, parseInt(port || 514, 10), protocol || 'udp');
    if (result.ok) res.json({ success: true, message: 'Test message sent successfully.' });
    else res.status(500).json({ success: false, error: result.error || 'Send failed' });
  });
};