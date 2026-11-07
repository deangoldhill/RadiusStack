const { getContainerHealth } = require('../container_health');

module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily, requireGlobalSuperAdmin } = dependencies;

app.get('/api/system/health', requireApiAuth('settings', 'read-only'), requireGlobalSuperAdmin, async (req, res) => {
    try {
        res.json(await getContainerHealth());
    } catch (err) {
        res.status(503).json({ error: 'Docker container health unavailable' });
    }
});

app.get('/api/system/status', requireApiAuth('settings', 'read-only'), requireGlobalSuperAdmin, (req, res) => {
    exec('docker ps -a --format "{{.Names}}|{{.State}}|{{.Status}}" | grep radius_', (error, stdout) => {
        if (error) return res.json([]);
        const containers = stdout.trim().split('\n').filter(Boolean).map(line => {
            const [name, state, status] = line.split('|');
            return { name, state, status };
        });
        res.json(containers);
    });
});

app.post('/api/system/restart/:container', requireApiAuth('settings', 'read-write'), requireGlobalSuperAdmin, async (req, res) => {
    const { container } = req.params;
    if (!/^radius_[a-z0-9_-]+$/.test(container)) return res.status(403).json({ error: 'Invalid container' });

    // Notify before execution, since restarting the API stops this process.
    await dependencies.notify?.({tenantId:null,event:'container_restart',title:'Manual container restart requested',body:`${req.admin.username} requested a restart of ${container} from ${req.ip}.`});
    exec(`docker restart ${container}`, async (error) => {
        if (error) {
            await auditLog(req.admin.username, req.origin, `Restart container ${container}`, 'failed', error.message, req.ip);
            return res.status(500).json({ error: error.message });
        }
        await auditLog(req.admin.username, req.origin, `Restarted container ${container}`, 'success', '', req.ip);
        res.json({ success: true });
    });
});

app.get('/api/system/logs/:container', requireApiAuth('settings', 'read-only'), requireGlobalSuperAdmin, (req, res) => {
    const { container } = req.params;
    if (!/^radius_[a-z0-9_-]+$/.test(container)) return res.status(403).json({ error: 'Invalid container' });

    exec(`docker logs --tail 200 ${container}`, (error, stdout, stderr) => {
        res.json({ logs: stdout + stderr });
    });
});


};
