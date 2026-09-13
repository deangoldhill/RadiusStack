const { scope } = require('../tenant');

module.exports = function(app, pool, requireApiAuth, auditLog) {
  app.get('/api/audit', requireApiAuth('admins', 'read-only'), async (req, res) => {
    const { search, result, start_date, end_date } = req.query;
    const paginated = req.query.page !== undefined;
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = [25, 50, 100].includes(Number(req.query.page_size)) ? Number(req.query.page_size) : 25;
    const scoped = scope(req.tenantScope);
    let where = ' WHERE 1=1' + scoped.sql; const params = [...scoped.params];
    if (search) { const like = `%${String(search).slice(0, 100)}%`; where += ' AND (admin_username LIKE ? OR action LIKE ? OR details LIKE ?)'; params.push(like, like, like); }
    if (result) { where += ' AND result = ?'; params.push(result); }
    if (start_date) { where += ' AND timestamp >= ?'; params.push(start_date); }
    if (end_date) { where += ' AND timestamp <= ?'; params.push(end_date); }
    if (!paginated) { const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 1000); const [rows] = await pool.query('SELECT * FROM admin_audit_log' + where + ' ORDER BY timestamp DESC LIMIT ?', [...params, limit]); return res.json(rows); }
    const [[count]] = await pool.query('SELECT COUNT(*) AS total FROM admin_audit_log' + where, params);
    const total = Number(count.total); const safePage = Math.min(page, Math.max(1, Math.ceil(total / pageSize)));
    const [rows] = await pool.query('SELECT * FROM admin_audit_log' + where + ' ORDER BY timestamp DESC LIMIT ? OFFSET ?', [...params, pageSize, (safePage - 1) * pageSize]);
    res.json({ items: rows, total, page: safePage, pageSize, totalPages: Math.max(1, Math.ceil(total / pageSize)) });
  });

  app.delete('/api/logs/auth', requireApiAuth('reports', 'read-write'), async (req, res) => {
    try {
      const { username, nasip, callingstationid, date_from, date_to, reply } = req.query;
      const scoped = scope(req.tenantScope, 'p.tenant_id'); const conditions = ['1=1' + scoped.sql], params = [...scoped.params];
      if (username) { conditions.push('(p.username = ? OR m.mac_id = ?)'); params.push(username, username); }
      if (nasip) { conditions.push('p.nasipaddress = ?'); params.push(nasip); }
      if (callingstationid) { conditions.push('p.callingstationid LIKE ?'); params.push('%' + callingstationid + '%'); }
      if (date_from) { conditions.push('p.authdate >= ?'); params.push(new Date(date_from).toISOString().slice(0, 19).replace('T', ' ')); }
      if (date_to) { conditions.push('p.authdate <= ?'); params.push(new Date(date_to).toISOString().slice(0, 19).replace('T', ' ')); }
      if (reply) { conditions.push('p.reply = ?'); params.push(reply); }
      const [result] = await pool.query('DELETE p FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address=p.username AND m.tenant_id <=> p.tenant_id WHERE ' + conditions.join(' AND '), params);
      await auditLog(req.admin.username, req.origin, `Deleted ${result.affectedRows} auth log entries`, 'success', JSON.stringify(req.query), req.ip, req.tenantScope);
      res.json({ deleted: result.affectedRows });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });
};
