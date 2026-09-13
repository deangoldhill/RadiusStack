module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { scope } = require('../tenant');
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

// --- AUDIT LOG API ---
app.get('/api/audit', requireApiAuth('admins', 'read-only'), async (req, res) => {
    const { search, result, start_date, end_date } = req.query;
    const paginated = req.query.page !== undefined;
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = [25, 50, 100].includes(parseInt(req.query.page_size, 10)) ? parseInt(req.query.page_size, 10) : 25;
    let where = ' WHERE 1=1'; const params = [];
    const scoped = scope(req.tenantScope, 'l.tenant_id');
    where += scoped.sql; params.push(...scoped.params);
    if (search) { where += ' AND (l.admin_username LIKE ? OR l.action LIKE ? OR l.details LIKE ?)'; params.push(`%${String(search).slice(0,100)}%`, `%${String(search).slice(0,100)}%`, `%${String(search).slice(0,100)}%`); }
    if (result) { where += ' AND l.result = ?'; params.push(result); }
    if (start_date) { where += ' AND l.timestamp >= ?'; params.push(start_date); }
    if (end_date) { where += ' AND l.timestamp <= ?'; params.push(end_date); }
    const from = ' FROM admin_audit_log l LEFT JOIN tenants t ON t.id=l.tenant_id';
    const select = "SELECT l.*,COALESCE(t.name, 'Global') AS tenant_name";
    if (!paginated) { const limit=Math.min(Math.max(parseInt(req.query.limit,10)||100,1),1000); const [rows]=await pool.query(select+from+where+' ORDER BY l.timestamp DESC LIMIT ?', [...params,limit]); return res.json(rows); }
    const [[count]] = await pool.query('SELECT COUNT(*) AS total'+from+where, params);
    const total=Number(count.total); const safePage=Math.min(page,Math.max(1,Math.ceil(total/pageSize)));
    const [rows]=await pool.query(select+from+where+' ORDER BY l.timestamp DESC LIMIT ? OFFSET ?', [...params,pageSize,(safePage-1)*pageSize]);
    res.json({items:rows,total,page:safePage,pageSize,totalPages:Math.max(1,Math.ceil(total/pageSize))});
});

app.delete('/api/logs/auth', requireApiAuth('reports', 'read-write'), async (req, res) => {
    try {
        const { username, nasip, callingstationid, date_from, date_to, reply } = req.query;
        const scoped = scope(req.tenantScope, 'p.tenant_id');
        let query = 'DELETE p FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address = p.username' + (req.tenantScope.enabled ? ' AND m.tenant_id = ?' : '');
        const conditions = req.tenantScope.enabled ? [scoped.sql.slice(5)] : []; const params = [...(req.tenantScope.enabled ? [req.tenantScope.tenantId] : []), ...scoped.params];
        if (username) { conditions.push('(p.username = ? OR m.mac_id = ?)'); params.push(username, username); }
        if (nasip) { conditions.push('p.nasipaddress = ?'); params.push(nasip); }
        if (callingstationid) { conditions.push('p.callingstationid LIKE ?'); params.push('%' + callingstationid + '%'); }
        if (date_from) { conditions.push('p.authdate >= ?'); params.push(new Date(date_from).toISOString().slice(0, 19).replace('T', ' ')); }
        if (date_to) { conditions.push('p.authdate <= ?'); params.push(new Date(date_to).toISOString().slice(0, 19).replace('T', ' ')); }
        if (reply) { conditions.push('p.reply = ?'); params.push(reply); }
        if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
        const [result] = await pool.query(query, params);
        await auditLog(req.admin.username, req.origin, `Deleted ${result.affectedRows} auth log entries`, 'success', JSON.stringify(req.query), req.ip);
        res.json({ deleted: result.affectedRows });
    } catch (err) {
        console.error('DELETE /api/logs/auth error:', err);
        res.status(500).json({ error: err.message });
    }
});



};
