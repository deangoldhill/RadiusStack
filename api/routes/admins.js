module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

// --- ADMINS ---
function normaliseTenantIds(value) {
    if (!Array.isArray(value)) return [];
    return [...new Set(value.map(Number).filter(id => Number.isSafeInteger(id) && id > 0))];
}

async function replaceTenantMemberships(connection, adminId, tenantIds, isSuperAdmin) {
    await connection.query('DELETE FROM admin_tenants WHERE admin_id = ?', [adminId]);
    if (isSuperAdmin) return;
    if (tenantIds.length === 0) return;
    const [tenants] = await connection.query('SELECT id FROM tenants WHERE id IN (?)', [tenantIds]);
    if (tenants.length !== tenantIds.length) throw new Error('One or more selected tenants do not exist');
    for (const tenantId of tenantIds) {
        await connection.query('INSERT INTO admin_tenants (admin_id, tenant_id) VALUES (?, ?)', [adminId, tenantId]);
    }
}

app.get('/api/admins', requireApiAuth('admins', 'read-only'), async (req, res) => {
    const columns = 'a.id, a.username, a.require_password_change, a.two_factor_enabled, a.two_factor_setup_complete, a.permissions, a.is_super_admin';
    let rows;
    if (req.tenantScope.enabled) {
        [rows] = await pool.query(`SELECT ${columns}, GROUP_CONCAT(at.tenant_id ORDER BY at.tenant_id) AS tenant_ids FROM admins a LEFT JOIN admin_tenants at ON at.admin_id = a.id WHERE a.is_super_admin = 1 OR at.tenant_id = ? GROUP BY a.id, a.username, a.require_password_change, a.two_factor_enabled, a.two_factor_setup_complete, a.permissions, a.is_super_admin`, [req.tenantScope.tenantId]);
    } else if (req.tenantScope.superAdmin) {
        [rows] = await pool.query(`SELECT ${columns}, GROUP_CONCAT(at.tenant_id ORDER BY at.tenant_id) AS tenant_ids FROM admins a LEFT JOIN admin_tenants at ON at.admin_id = a.id GROUP BY a.id, a.username, a.require_password_change, a.two_factor_enabled, a.two_factor_setup_complete, a.permissions, a.is_super_admin`);
    } else rows = [];
    res.json(rows.map(row => ({ ...row, tenant_ids: !Number(row.is_super_admin) ? String(row.tenant_ids || '').split(',').filter(Boolean).map(Number) : [] })));
});

app.post('/api/admins', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { username, password, permissions, enable_2fa, is_super_admin } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const apikey = crypto.randomBytes(32).toString('hex');
    const actorIsSuperAdmin = req.tenantScope.superAdmin;
    const isSuperAdmin = actorIsSuperAdmin && !!is_super_admin;
    const tenantIds = actorIsSuperAdmin ? normaliseTenantIds(req.body.tenant_ids) : [];
    let connection;
    try {
        const [settingRows] = await pool.query("SELECT setting_value FROM settings WHERE setting_key = 'enforce_2fa'");
        const enforce2fa = settingRows.length > 0 && settingRows[0].setting_value === 'true';
        const is2faEnabled = enforce2fa || !!enable_2fa;
        connection = await pool.getConnection();
        await connection.beginTransaction();
        const [created] = await connection.query('INSERT INTO admins (username, password_hash, api_key, permissions, two_factor_enabled, two_factor_setup_complete, is_super_admin) VALUES (?, ?, ?, ?, ?, false, ?)', [username, hash, apikey, JSON.stringify(permissions), is2faEnabled, isSuperAdmin ? 1 : 0]);
        if (actorIsSuperAdmin) await replaceTenantMemberships(connection, created.insertId, tenantIds, isSuperAdmin);
        await connection.commit();
        await auditLog(req.admin.username, req.origin, `Created admin: ${username}`, 'success', '', req.ip);
        res.json({ success: true, id: created.insertId });
    } catch (err) {
        if (connection) await connection.rollback();
        res.status(400).json({ error: err.message });
    } finally { if (connection) connection.release(); }
});

app.put('/api/admins/:id', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { id } = req.params;
    const { username, password, permissions, is_super_admin } = req.body;
    const actorIsSuperAdmin = req.tenantScope.superAdmin;
    const isSuperAdmin = actorIsSuperAdmin && !!is_super_admin;
    const tenantIds = actorIsSuperAdmin ? normaliseTenantIds(req.body.tenant_ids) : [];
    let connection;
    try {
        connection = await pool.getConnection();
        await connection.beginTransaction();
        if (password) {
            const hash = await bcrypt.hash(password, 10);
            await connection.query('UPDATE admins SET username = ?, password_hash = ?, permissions = ?, is_super_admin = ? WHERE id = ?', [username, hash, JSON.stringify(permissions), isSuperAdmin ? 1 : 0, id]);
        } else {
            await connection.query('UPDATE admins SET username = ?, permissions = ?, is_super_admin = ? WHERE id = ?', [username, JSON.stringify(permissions), isSuperAdmin ? 1 : 0, id]);
        }
        if (actorIsSuperAdmin) await replaceTenantMemberships(connection, id, tenantIds, isSuperAdmin);
        await connection.commit();
        await auditLog(req.admin.username, req.origin, `Updated admin: ${username}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        if (connection) await connection.rollback();
        res.status(400).json({ error: err.message });
    } finally { if (connection) connection.release(); }
});

app.delete('/api/admins/:id', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { id } = req.params;
    await pool.query('DELETE FROM admins WHERE id = ?', [id]);
    await auditLog(req.admin.username, req.origin, `Deleted admin ID: ${id}`, 'success', '', req.ip);
    res.json({ success: true });
});

app.post('/api/admins/:id/generate-key', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { id } = req.params;
    const newKey = crypto.randomBytes(32).toString('hex');
    try {
        await pool.query('UPDATE admins SET api_key = ? WHERE id = ?', [newKey, id]);
        await auditLog(req.admin.username, req.origin, `Generated new API key for admin ID: ${id}`, 'success', '', req.ip);
        res.json({ success: true, apiKey: newKey });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admins/:id/enable-2fa', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { id } = req.params;
    try {
        const [admins] = await pool.query('SELECT * FROM admins WHERE id = ?', [id]);
        const admin = admins[0];
        if (!admin) return res.status(404).json({ error: 'Admin not found' });

        const secret = authenticator.generateSecret();
        await pool.query('UPDATE admins SET two_factor_enabled = true, two_factor_setup_complete = true, two_factor_secret = ? WHERE id = ?', [secret, id]);

        const qrImage = await qrcode.toDataURL(authenticator.keyuri(admin.username, 'RadiusFullStack', secret));

        await auditLog(req.admin.username, req.origin, `Enabled 2FA for admin: ${admin.username}`, 'success', '', req.ip);
        res.json({ success: true, qrImage, secret });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admins/:id/disable-2fa', requireApiAuth('settings', 'read-write'), async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('UPDATE admins SET two_factor_enabled = false, two_factor_setup_complete = false, two_factor_secret = NULL WHERE id = ?', [id]);
        await auditLog(req.admin.username, req.origin, `Disabled 2FA for admin ID: ${id}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


};
