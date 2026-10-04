module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

    const isGlobalSuperAdmin = req => req.tenantScope.globalContext && Number(req.admin.is_super_admin) === 1;
    async function assertAdminTargetAccess(req, adminId) {
        if (isGlobalSuperAdmin(req)) return true;
        if (!req.tenantScope.enabled) throw new Error('A tenant context is required');
        const [rows] = await pool.query('SELECT a.id FROM admins a JOIN admin_tenants at ON at.admin_id = a.id WHERE a.id = ? AND a.is_super_admin = 0 AND at.tenant_id = ? AND NOT EXISTS (SELECT 1 FROM admin_tenants other WHERE other.admin_id = a.id AND other.tenant_id <> ?) LIMIT 1', [adminId, req.tenantScope.tenantId, req.tenantScope.tenantId]);
        if (!rows.length) throw new Error('Administrator not found in selected tenant');
        return true;
    }
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
        [rows] = await pool.query(`SELECT ${columns}, GROUP_CONCAT(at.tenant_id ORDER BY at.tenant_id) AS tenant_ids FROM admins a LEFT JOIN admin_tenants at ON at.admin_id = a.id WHERE a.is_super_admin = 0 AND at.tenant_id = ? GROUP BY a.id, a.username, a.require_password_change, a.two_factor_enabled, a.two_factor_setup_complete, a.permissions, a.is_super_admin`, [req.tenantScope.tenantId]);
    } else if (req.tenantScope.superAdmin) {
        [rows] = await pool.query(`SELECT ${columns}, GROUP_CONCAT(at.tenant_id ORDER BY at.tenant_id) AS tenant_ids FROM admins a LEFT JOIN admin_tenants at ON at.admin_id = a.id GROUP BY a.id, a.username, a.require_password_change, a.two_factor_enabled, a.two_factor_setup_complete, a.permissions, a.is_super_admin`);
    } else rows = [];
    res.json(rows.map(row => ({ ...row, tenant_ids: !Number(row.is_super_admin) ? String(row.tenant_ids || '').split(',').filter(Boolean).map(Number) : [] })));
});

app.post('/api/admins', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { username, password, permissions, enable_2fa, is_super_admin } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const apikey = crypto.randomBytes(32).toString('hex');
    const actorIsSuperAdmin = isGlobalSuperAdmin(req);
    const isSuperAdmin = actorIsSuperAdmin && !!is_super_admin;
    const tenantIds = actorIsSuperAdmin ? normaliseTenantIds(req.body.tenant_ids) : (req.tenantScope.enabled ? [req.tenantScope.tenantId] : []);
    let connection;
    try {
        const [settingRows] = req.tenantScope.enabled
            ? await pool.query("SELECT setting_value FROM tenant_settings WHERE tenant_id = ? AND setting_key = 'enforce_2fa'", [req.tenantScope.tenantId])
            : await pool.query("SELECT setting_value FROM settings WHERE setting_key = 'enforce_2fa'");
        const enforce2fa = settingRows.length > 0 && settingRows[0].setting_value === 'true';
        const is2faEnabled = enforce2fa || !!enable_2fa;
        connection = await pool.getConnection();
        await connection.beginTransaction();
        const [created] = await connection.query('INSERT INTO admins (username, password_hash, api_key, permissions, two_factor_enabled, two_factor_setup_complete, is_super_admin) VALUES (?, ?, ?, ?, ?, false, ?)', [username, hash, apikey, JSON.stringify(permissions), is2faEnabled, isSuperAdmin ? 1 : 0]);
        await replaceTenantMemberships(connection, created.insertId, tenantIds, isSuperAdmin);
        await connection.commit();
        await auditLog(req.admin.username, req.origin, `Created admin: ${username}`, 'success', JSON.stringify({ admin_id: created.insertId, tenant_ids: tenantIds, super_admin: isSuperAdmin }), req.ip, req.tenantScope);
        res.json({ success: true, id: created.insertId });
    } catch (err) {
        if (connection) await connection.rollback();
        res.status(400).json({ error: err.message });
    } finally { if (connection) connection.release(); }
});

app.put('/api/admins/:id', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { id } = req.params;
    const { username, password, permissions, is_super_admin } = req.body;
    const actorIsSuperAdmin = isGlobalSuperAdmin(req);
    const isSuperAdmin = actorIsSuperAdmin && !!is_super_admin;
    const tenantIds = actorIsSuperAdmin ? normaliseTenantIds(req.body.tenant_ids) : (req.tenantScope.enabled ? [req.tenantScope.tenantId] : []);
    let connection;
    try {
        await assertAdminTargetAccess(req, id);
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
        await auditLog(req.admin.username, req.origin, `Updated admin: ${username}`, 'success', JSON.stringify({ admin_id: Number(id), tenant_ids: tenantIds, super_admin: isSuperAdmin }), req.ip, req.tenantScope);
        res.json({ success: true });
    } catch (err) {
        if (connection) await connection.rollback();
        res.status(400).json({ error: err.message });
    } finally { if (connection) connection.release(); }
});

app.delete('/api/admins/:id', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { id } = req.params;
    try { await assertAdminTargetAccess(req, id); } catch (err) { return res.status(403).json({ error: err.message }); }
    await pool.query('DELETE FROM admins WHERE id = ?', [id]);
    await auditLog(req.admin.username, req.origin, `Deleted admin ID: ${id}`, 'success', JSON.stringify({ admin_id: Number(id) }), req.ip, req.tenantScope);
    res.json({ success: true });
});

app.post('/api/admins/:id/generate-key', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { id } = req.params;
    const newKey = crypto.randomBytes(32).toString('hex');
    try {
        await assertAdminTargetAccess(req, id);
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
        await assertAdminTargetAccess(req, id);
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
        await assertAdminTargetAccess(req, id);
        await pool.query('UPDATE admins SET two_factor_enabled = false, two_factor_setup_complete = false, two_factor_secret = NULL WHERE id = ?', [id]);
        await auditLog(req.admin.username, req.origin, `Disabled 2FA for admin ID: ${id}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});



app.post('/api/tenants/:id/enforce-2fa', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const tenantId = Number(req.params.id);
    if (!Number.isSafeInteger(tenantId) || tenantId < 1) return res.status(400).json({ error: 'Invalid tenant' });
    try {
        const [tenants] = await pool.query('SELECT id FROM tenants WHERE id = ? LIMIT 1', [tenantId]);
        if (!tenants.length) return res.status(404).json({ error: 'Tenant not found' });
        if (req.tenantScope.enabled && Number(req.tenantScope.tenantId) !== tenantId) {
            return res.status(403).json({ error: 'Selected tenant does not match request' });
        }
        await pool.query("INSERT INTO tenant_settings (tenant_id, setting_key, setting_value) VALUES (?, 'enforce_2fa', 'true') ON DUPLICATE KEY UPDATE setting_value = 'true'", [tenantId]);
        await auditLog(req.admin.username, req.origin, `Enabled tenant administrator MFA for tenant ${tenantId}`, 'success', '', req.ip, req.tenantScope);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Unable to enable tenant administrator MFA' });
    }
});


app.post('/api/admins/:id/sync-password', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const adminId = Number(req.params.id);
    const password = String(req.body && req.body.password || '');
    if (!Number.isSafeInteger(adminId) || adminId < 1 || password.length < 4) {
        return res.status(400).json({ error: 'Invalid administrator password synchronization request' });
    }
    try {
        await assertAdminTargetAccess(req, adminId);
        const passwordHash = await bcrypt.hash(password, 10);
        await pool.query('UPDATE admins SET password_hash = ? WHERE id = ?', [passwordHash, adminId]);
        await auditLog(req.admin.username, req.origin, `Synchronized password for admin ID: ${adminId}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Unable to synchronize administrator password' });
    }
});

app.post('/api/admins/:id/provision-2fa', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const adminId = Number(req.params.id);
    const secret = String(req.body && req.body.secret || '').trim().toUpperCase();
    if (!Number.isSafeInteger(adminId) || adminId < 1 || !/^[A-Z2-7]{16,128}$/.test(secret)) {
        return res.status(400).json({ error: 'Invalid administrator MFA provisioning request' });
    }
    try {
        await assertAdminTargetAccess(req, adminId);
        await pool.query('UPDATE admins SET two_factor_enabled = true, two_factor_setup_complete = true, two_factor_secret = ? WHERE id = ?', [secret, adminId]);
        await auditLog(req.admin.username, req.origin, `Provisioned existing TOTP secret for admin ID: ${adminId}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Unable to provision administrator MFA' });
    }
});


};
