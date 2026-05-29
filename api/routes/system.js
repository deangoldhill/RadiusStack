module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

// --- SYSTEM HEALTH ---
app.get('/api/system/status', requireApiAuth('settings', 'read-only'), (req, res) => {
    exec('docker ps -a --format "{{.Names}}|{{.State}}|{{.Status}}" | grep radius_', (error, stdout) => {
        if (error) return res.json([]);
        const containers = stdout.trim().split('\n').filter(Boolean).map(line => {
            const [name, state, status] = line.split('|');
            return { name, state, status };
        });
        res.json(containers);
    });
});

app.post('/api/system/restart/:container', requireApiAuth('settings', 'read-write'), (req, res) => {
    const { container } = req.params;
    if (!container.startsWith('radius_')) return res.status(403).json({ error: 'Invalid container' });

    exec(`docker restart ${container}`, async (error) => {
        if (error) {
            await auditLog(req.admin.username, req.origin, `Restart container ${container}`, 'failed', error.message, req.ip);
            return res.status(500).json({ error: error.message });
        }
        await auditLog(req.admin.username, req.origin, `Restarted container ${container}`, 'success', '', req.ip);
        res.json({ success: true });
    });
});

app.get('/api/system/logs/:container', requireApiAuth('settings', 'read-only'), (req, res) => {
    const { container } = req.params;
    if (!container.startsWith('radius_')) return res.status(403).json({ error: 'Invalid container' });

    exec(`docker logs --tail 200 ${container}`, (error, stdout, stderr) => {
        res.json({ logs: stdout + stderr });
    });
});


};
