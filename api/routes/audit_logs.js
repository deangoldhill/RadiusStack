module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { scope } = require('../tenant');
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;
    const oldMacAction = /^(Reset limits for user|Updated MAC device|Deleted MAC device): ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})$/i;
    async function withMacDisplayNames(rows) {
        const targets = new Map();
        const keyFor = (tenantId, address) => `${tenantId ?? 'global'}|${address.toLowerCase()}`;
        for (const row of rows) {
            const match = oldMacAction.exec(row.action || '');
            if (match) targets.set(keyFor(row.tenant_id, match[2]), { tenantId: row.tenant_id, address: match[2].toLowerCase() });
        }
        if (!targets.size) return rows;
        const conditions = [], params = [];
        for (const { tenantId, address } of targets.values()) {
            conditions.push(tenantId == null ? '(tenant_id IS NULL AND mac_address = ?)' : '(tenant_id = ? AND mac_address = ?)');
            if (tenantId != null) params.push(tenantId);
            params.push(address);
        }
        const [devices] = await pool.query('SELECT tenant_id, mac_address, mac_id FROM mac_auth_devices WHERE ' + conditions.join(' OR '), params);
        const names = new Map(devices.map(d => [keyFor(d.tenant_id, d.mac_address), d.mac_id]));
        return rows.map(row => {
            const match = oldMacAction.exec(row.action || '');
            const name = match && names.get(keyFor(row.tenant_id, match[2]));
            if (!name) return row; // Deleted legacy devices have no recoverable name.
            const prefix = match[1] === 'Reset limits for user' ? 'Reset limits for MAC device' : match[1];
            return { ...row, display_action: `${prefix}: ${name}` }; // Never rewrite audit history.
        });
    }

app.get('/api/audit', requireApiAuth('admins', 'read-only'), async (req, res) => {
    const { search, result, start_date, end_date } = req.query;
    const paginated = req.query.page !== undefined;
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = [25, 50, 100].includes(parseInt(req.query.page_size, 10)) ? parseInt(req.query.page_size, 10) : 25;
    let where = ' WHERE 1=1'; const params = [];
    const scoped = req.tenantScope.globalContext && req.tenantScope.superAdmin
        ? { sql: '', params: [] }
        : scope(req.tenantScope, 'l.tenant_id');
    where += scoped.sql; params.push(...scoped.params);
    if (search) { where += ' AND (l.admin_username LIKE ? OR l.action LIKE ? OR l.details LIKE ?)'; params.push(`%${String(search).slice(0,100)}%`, `%${String(search).slice(0,100)}%`, `%${String(search).slice(0,100)}%`); }
    if (result) { where += ' AND l.result = ?'; params.push(result); }
    if (start_date) { where += ' AND l.timestamp >= ?'; params.push(start_date); }
    if (end_date) { where += ' AND l.timestamp <= ?'; params.push(end_date); }
    const from = ' FROM admin_audit_log l LEFT JOIN tenants t ON t.id=l.tenant_id';
    const select = "SELECT l.*,CASE WHEN l.tenant_id IS NULL THEN 'Global' ELSE t.name END AS tenant_name";
    if (!paginated) { const limit=Math.min(Math.max(parseInt(req.query.limit,10)||100,1),1000); const [rows]=await pool.query(select+from+where+' ORDER BY l.timestamp DESC LIMIT ?', [...params,limit]); return res.json(await withMacDisplayNames(rows)); }
    const [[count]] = await pool.query('SELECT COUNT(*) AS total'+from+where, params);
    const total=Number(count.total); const safePage=Math.min(page,Math.max(1,Math.ceil(total/pageSize)));
    const [rows]=await pool.query(select+from+where+' ORDER BY l.timestamp DESC LIMIT ? OFFSET ?', [...params,pageSize,(safePage-1)*pageSize]);
    res.json({items:await withMacDisplayNames(rows),total,page:safePage,pageSize,totalPages:Math.max(1,Math.ceil(total/pageSize))});
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
        await auditLog(req.admin.username, req.origin, `Deleted ${result.affectedRows} auth log entries`, 'success', JSON.stringify(req.query), req.ip, req.tenantScope);
        res.json({ deleted: result.affectedRows });
    } catch (err) {
        console.error('DELETE /api/logs/auth error:', err);
        res.status(500).json({ error: err.message });
    }
});



};
