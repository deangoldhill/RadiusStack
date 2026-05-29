module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

// --- PLANS ---

app.get('/api/plans/:id/stats', requireApiAuth('plans', 'read-only'), async (req, res) => {
    try {
        const [planRow] = await pool.query("SELECT * FROM plans WHERE id = ?", [req.params.id]);
        if (!planRow[0]) return res.status(404).json({ error: 'Plan not found' });
        const plan = planRow[0];

        const [users] = await pool.query(`
    SELECT 
        COALESCE(m.mac_id, up.username) AS username,
        COALESCE((SELECT SUM(acctinputoctets) + SUM(acctoutputoctets) FROM radacct WHERE username = up.username), 0) - COALESCE(pu.base_input_octets, 0) - COALESCE(pu.base_output_octets, 0) AS total_bytes,
        COALESCE((SELECT SUM(acctsessiontime) FROM radacct WHERE username = up.username), 0) - COALESCE(pu.base_session_seconds, 0) AS total_seconds
    FROM user_plans up
    LEFT JOIN user_plan_usage pu ON pu.username = up.username
    LEFT JOIN mac_auth_devices m ON m.mac_address = up.username
    WHERE up.plan_id = ?
`, [req.params.id]);

        let depletedCount = 0;
        const topUsers = [];
        let total_bytes_all = 0;
        let total_seconds_all = 0;

        users.forEach(u => {
            let total_mb = Math.max(0, u.total_bytes / (1024 * 1024));
            let total_sec = Math.max(0, u.total_seconds);
            total_bytes_all += Math.max(0, u.total_bytes);
            total_seconds_all += total_sec;

            let isDepleted = false;
            let depletionReason = null;
            if (plan.data_limit_mb > 0 && total_mb >= plan.data_limit_mb) {
                isDepleted = true;
                depletionReason = 'Data';
            }
            if (plan.time_limit_seconds > 0 && total_sec >= plan.time_limit_seconds) {
                isDepleted = true;
                depletionReason = 'Time';
            }

            if (isDepleted) depletedCount++;

            topUsers.push({
                username: u.username,
                data_used_mb: parseFloat(total_mb).toFixed(2),
                time_used_sec: parseInt(total_sec),
                status: isDepleted ? 'Depleted' : 'Active',
                depletionReason
            });
        });

        topUsers.sort((a, b) => b.data_used_mb - a.data_used_mb);

        res.json({
            plan,
            total_users: users.length,
            depleted_users: depletedCount,
            active_users: users.length - depletedCount,
            total_data_gb: (total_bytes_all / (1024*1024*1024)).toFixed(2),
            total_hours: (total_seconds_all / 3600).toFixed(1),
            top_users: topUsers.slice(0, 10)
        });

    } catch (e) {
        console.error('Plan stats error', e);
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/plans', requireApiAuth('plans', 'read-only'), async (req, res) => {
    const [rows] = await pool.query('SELECT * FROM plans ORDER BY id DESC');
    res.json(rows);
});

app.post('/api/plans', requireApiAuth('plans', 'read-write'), async (req, res) => {
    const { name, data_limit_mb, time_limit_seconds, reset_period } = req.body;
    try {
        await pool.query('INSERT INTO plans (name, data_limit_mb, time_limit_seconds, reset_period) VALUES (?, ?, ?, ?)',
            [name, data_limit_mb || 0, time_limit_seconds || 0, reset_period || 'never']);
        await auditLog(req.admin.username, req.origin, `Created plan: ${name}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/plans/:id', requireApiAuth('plans', 'read-write'), async (req, res) => {
    const { id } = req.params;
    const { name, data_limit_mb, time_limit_seconds, reset_period } = req.body;
    try {
        await pool.query('UPDATE plans SET name=?, data_limit_mb=?, time_limit_seconds=?, reset_period=? WHERE id=?',
            [name, data_limit_mb || 0, time_limit_seconds || 0, reset_period || 'never', id]);
        await auditLog(req.admin.username, req.origin, `Updated plan ID: ${id}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/plans/:id', requireApiAuth('plans', 'read-write'), async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM plans WHERE id = ?', [id]);
        await auditLog(req.admin.username, req.origin, `Deleted plan ID: ${id}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


};
