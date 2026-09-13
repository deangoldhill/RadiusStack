module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { isSingleIPv4, scope } = require('../tenant');
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

// --- NAS ---
app.get('/api/nas', requireApiAuth('nas', 'read-only'), async (req, res) => {
    const scoped = scope(req.tenantScope); const [rows] = await pool.query('SELECT * FROM nas WHERE 1=1'+scoped.sql, scoped.params);
    res.json(rows);
});

app.post('/api/nas', requireApiAuth('nas', 'read-write'), async (req, res) => {
    const { nasname, shortname, type, secret, description } = req.body;
    if (!isSingleIPv4(nasname)) return res.status(400).json({ error: 'NAS address must be one canonical IPv4 address (no CIDR or ranges)' });
    const tenantId = req.tenantScope.enabled ? req.tenantScope.tenantId : null;
    await pool.query('INSERT INTO nas (nasname, shortname, type, secret, description, tenant_id) VALUES (?, ?, ?, ?, ?, ?)', [nasname, shortname, type || 'other', secret, description, tenantId]);
    await auditLog(req.admin.username, req.origin, `Created NAS: ${nasname} (${shortname})`, 'success', '', req.ip);
    res.json({ success: true });
});

app.put('/api/nas/:id', requireApiAuth('nas', 'read-write'), async (req, res) => {
    const { id } = req.params;
    const { nasname, shortname, type, secret, description } = req.body;
    if (!isSingleIPv4(nasname)) return res.status(400).json({ error: 'NAS address must be one canonical IPv4 address (no CIDR or ranges)' });
    const scoped = scope(req.tenantScope);
    try {
        const [result] = await pool.query('UPDATE nas SET nasname=?, shortname=?, type=?, secret=?, description=? WHERE id=?'+scoped.sql, [nasname, shortname, type || 'other', secret, description, id, ...scoped.params]);
        if (!result.affectedRows) return res.status(404).json({ error: 'NAS not found in selected tenant' });
        await auditLog(req.admin.username, req.origin, `Updated NAS: ${nasname}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/nas/:id', requireApiAuth('nas', 'read-write'), async (req, res) => {
    const scoped = scope(req.tenantScope);
    const [nas] = await pool.query('SELECT * FROM nas WHERE id = ?'+scoped.sql, [req.params.id, ...scoped.params]);
    if (!nas.length) return res.status(404).json({ error: 'NAS not found in selected tenant' });
    await pool.query('DELETE FROM nas WHERE id = ?'+scoped.sql, [req.params.id, ...scoped.params]);
    await auditLog(req.admin.username, req.origin, `Deleted NAS: ${nas[0]?.nasname}`, 'success', '', req.ip);
    res.json({ success: true });
});


};
