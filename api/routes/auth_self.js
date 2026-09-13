module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

// --- CURRENT ADMIN (self) ---
app.get('/api/auth/me', async (req, res) => {
    const apiKey = req.header('X-API-Key');
    if (!apiKey) return res.status(401).json({ error: 'API Key missing' });
    const [admins] = await pool.query(
        'SELECT id, username, permissions, is_super_admin FROM admins WHERE api_key = ?',
        [apiKey]
    );
    if (!admins.length) return res.status(401).json({ error: 'Invalid API Key' });
    res.json(admins[0]);
});

// Bootstrap context intentionally does not depend on X-Tenant-ID. It gives a
// signed-in administrator only the tenant choices they are authorized to use,
// allowing the browser to normalize stale localStorage before scoped requests.
app.get('/api/auth/context', async (req, res) => {
    const apiKey = req.header('X-API-Key');
    if (!apiKey) return res.status(401).json({ error: 'API Key missing' });
    const [[admin]] = await pool.query('SELECT id, is_super_admin FROM admins WHERE api_key = ?', [apiKey]);
    if (!admin) return res.status(401).json({ error: 'Invalid API Key' });
    const [[setting]] = await pool.query("SELECT setting_value FROM settings WHERE setting_key = 'multi_tenant_enabled'");
    const multiTenantEnabled = ['true', '1'].includes(String(setting?.setting_value || '').toLowerCase());
    const tenants = !multiTenantEnabled ? [] : Number(admin.is_super_admin) === 1
        ? (await pool.query('SELECT id, name FROM tenants ORDER BY name'))[0]
        : (await pool.query('SELECT t.id, t.name FROM tenants t JOIN admin_tenants at ON at.tenant_id = t.id WHERE at.admin_id = ? ORDER BY t.name', [admin.id]))[0];
    res.json({ multiTenantEnabled, is_super_admin: Number(admin.is_super_admin) === 1, tenants });
});

app.put('/api/auth/me/password', async (req, res) => {
    const apiKey = req.header('X-API-Key');
    if (!apiKey) return res.status(401).json({ error: 'API Key missing' });

    const [admins] = await pool.query('SELECT * FROM admins WHERE api_key = ?', [apiKey]);
    if (!admins.length) return res.status(401).json({ error: 'Invalid API Key' });

    const admin = admins[0];
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) return res.status(400).json({ error: 'Missing fields' });

    const valid = await bcrypt.compare(oldPassword, admin.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid current password' });

    const hash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE admins SET password_hash = ? WHERE id = ?', [hash, admin.id]);

    await auditLog(admin.username, 'webui', 'Changed their own password', 'success', '', req.ip || '');
    res.json({ success: true });
});


};
