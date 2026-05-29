module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

// --- CURRENT ADMIN (self) ---
app.get('/api/auth/me', async (req, res) => {
    const apiKey = req.header('X-API-Key');
    if (!apiKey) return res.status(401).json({ error: 'API Key missing' });
    const [admins] = await pool.query(
        'SELECT id, username, permissions FROM admins WHERE api_key = ?',
        [apiKey]
    );
    if (!admins.length) return res.status(401).json({ error: 'Invalid API Key' });
    res.json(admins[0]);
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
