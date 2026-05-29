module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

// --- ADMINS ---
app.get('/api/admins', requireApiAuth('admins', 'read-only'), async (req, res) => {
    const [rows] = await pool.query('SELECT id, username, require_password_change, two_factor_enabled, two_factor_setup_complete, api_key, permissions FROM admins');
    res.json(rows);
});

app.post('/api/admins', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { username, password, permissions, enable_2fa } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const apikey = crypto.randomBytes(32).toString('hex');
    try {
        const [settingRows] = await pool.query("SELECT setting_value FROM settings WHERE setting_key = 'enforce_2fa'");
        const enforce2fa = settingRows.length > 0 && settingRows[0].setting_value === 'true';
        const is2faEnabled = enforce2fa || !!enable_2fa;

        await pool.query('INSERT INTO admins (username, password_hash, api_key, permissions, two_factor_enabled, two_factor_setup_complete) VALUES (?, ?, ?, ?, ?, false)', [username, hash, apikey, JSON.stringify(permissions), is2faEnabled]);
        await auditLog(req.admin.username, req.origin, `Created admin: ${username}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.put('/api/admins/:id', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { id } = req.params;
    const { username, password, permissions } = req.body;
    try {
        if (password) {
            const hash = await bcrypt.hash(password, 10);
            await pool.query('UPDATE admins SET username = ?, password_hash = ?, permissions = ? WHERE id = ?', [username, hash, JSON.stringify(permissions), id]);
        } else {
            await pool.query('UPDATE admins SET username = ?, permissions = ? WHERE id = ?', [username, JSON.stringify(permissions), id]);
        }
        await auditLog(req.admin.username, req.origin, `Updated admin: ${username}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
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
