module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, puppeteer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

// --- REPORTS ---


// --- STALE SESSIONS ---
app.get('/api/sessions/stale', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const [settings] = await pool.query("SELECT * FROM settings WHERE setting_key IN ('clear_stale_sessions', 'stale_session_threshold', 'stale_session_interim_threshold_minutes')");
    let clearEnabled = false;
    let thresholdDays = 3;
    let interimThresholdMinutes = 180;
    settings.forEach(s => {
        if (s.setting_key === 'clear_stale_sessions') clearEnabled = (s.setting_value === 'true' || s.setting_value === '1');
        if (s.setting_key === 'stale_session_threshold') thresholdDays = parseInt(s.setting_value, 10) || 3;
        if (s.setting_key === 'stale_session_interim_threshold_minutes') interimThresholdMinutes = parseInt(s.setting_value, 10) || 180;
    });

    const query = `
        SELECT
            radacctid,
            username,
            nasipaddress,
            framedipaddress,
            acctstarttime,
            acctupdatetime,
            acctinterval,
            TIMESTAMPDIFF(DAY, acctstarttime, NOW()) AS days_since_start,
            TIMESTAMPDIFF(MINUTE, acctupdatetime, NOW()) AS minutes_since_update,
            TIMESTAMPDIFF(SECOND, acctstarttime, acctupdatetime) AS update_after_start_seconds,
            CASE
                WHEN acctupdatetime IS NULL OR TIMESTAMPDIFF(SECOND, acctstarttime, acctupdatetime) <= 10 THEN 'start-only'
                ELSE 'interim-stale'
            END AS stale_reason
        FROM radacct
        WHERE acctstoptime IS NULL
          AND (
                (
                    acctstarttime <= DATE_SUB(NOW(), INTERVAL ? DAY)
                    AND (
                        acctupdatetime IS NULL
                        OR TIMESTAMPDIFF(SECOND, acctstarttime, acctupdatetime) <= 10
                    )
                )
                OR
                (
                    acctupdatetime IS NOT NULL
                    AND TIMESTAMPDIFF(SECOND, acctstarttime, acctupdatetime) > 10
                    AND acctupdatetime <= DATE_SUB(NOW(), INTERVAL ? MINUTE)
                )
              )
        ORDER BY acctstarttime ASC
    `;
    const [rows] = await pool.query(query, [thresholdDays, interimThresholdMinutes]);
    res.json(rows);
});

app.post('/api/sessions/clear', requireApiAuth('reports', 'read-write'), async (req, res) => {
    const { sessionIds } = req.body;
    if (!sessionIds || !sessionIds.length) return res.status(400).json({ error: 'No sessions provided' });

    // Clear by updating acctstoptime to current time
    const placeholders = sessionIds.map(() => '?').join(',');
    await pool.query(`UPDATE radacct SET acctstoptime = NOW() WHERE radacctid IN (${placeholders})`, sessionIds);
    await auditLog(req.admin.username, req.origin, `Cleared ${sessionIds.length} stale sessions`, 'success', '', req.ip);
    res.json({ success: true });
});
app.get('/api/sessions/active', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const { limit = 200, username, nasip, callingstationid, framedip } = req.query;
    const queryLimit = Math.min(parseInt(limit) || 200, 1000);
    const conditions = ['a.acctstoptime IS NULL'];
    const params = [];
    if (username) { conditions.push('(a.username LIKE ? OR m.mac_id LIKE ?)'); params.push('%' + username + '%', '%' + username + '%'); }
    if (nasip) { conditions.push('a.nasipaddress = ?'); params.push(nasip); }
    if (callingstationid) { conditions.push('a.callingstationid LIKE ?'); params.push('%' + callingstationid + '%'); }
    if (framedip) { conditions.push('a.framedipaddress LIKE ?'); params.push('%' + framedip + '%'); }
    const where = conditions.join(' AND ');
    const [rows] = await pool.query(
        'SELECT a.*, COALESCE(m.mac_id, a.username) AS username FROM radacct a LEFT JOIN mac_auth_devices m ON m.mac_address = a.username WHERE ' + where + ' ORDER BY a.acctstarttime DESC LIMIT ?',
        [...params, queryLimit]
    );
    res.json(rows);
});

app.get('/api/logs/auth', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const { username, nasip, callingstationid, date_from, date_to, reply, limit = 100 } = req.query;
    let query = 'SELECT p.*, COALESCE(m.mac_id, p.username) AS username FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address = p.username';
    const conditions = [], params = [];
    if (username) { conditions.push('(p.username LIKE ? OR m.mac_id LIKE ?)'); params.push('%' + username + '%', '%' + username + '%'); }
    if (nasip) { conditions.push('p.nasipaddress = ?'); params.push(nasip); }
    if (callingstationid) { conditions.push('p.callingstationid LIKE ?'); params.push('%' + callingstationid + '%'); }
    if (date_from) { conditions.push('p.authdate >= ?'); params.push(new Date(date_from).toISOString().slice(0, 19).replace('T', ' ')); }
    if (date_to) { conditions.push('p.authdate <= ?'); params.push(new Date(date_to).toISOString().slice(0, 19).replace('T', ' ')); }
    if (reply) { conditions.push('p.reply = ?'); params.push(reply); }

    if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
    query += ' ORDER BY authdate DESC';
    const queryLimit = Math.min(parseInt(limit) || 100, 10000);
    query += ' LIMIT ?';
    params.push(queryLimit);
    const [rows] = await pool.query(query, params);
    res.json(rows);
});

app.delete('/api/logs/auth', requireApiAuth('reports', 'read-write'), async (req, res) => {
    try {
        const { username, nasip, callingstationid, date_from, date_to, reply } = req.query;
        let query = 'DELETE p FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address = p.username';
        const conditions = [], params = [];
        if (username) { conditions.push('(p.username LIKE ? OR m.mac_id LIKE ?)'); params.push('%' + username + '%', '%' + username + '%'); }
        if (nasip) { conditions.push('p.nasipaddress = ?'); params.push(nasip); }
        if (callingstationid) { conditions.push('p.callingstationid LIKE ?'); params.push('%' + callingstationid + '%'); }
        if (date_from) { conditions.push('p.authdate >= ?'); params.push(new Date(date_from).toISOString().slice(0, 19).replace('T', ' ')); }
        if (date_to) { conditions.push('p.authdate <= ?'); params.push(new Date(date_to).toISOString().slice(0, 19).replace('T', ' ')); }
        if (reply) { conditions.push('p.reply = ?'); params.push(reply); }
        if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
        const [result] = await pool.query(query, params);
        await auditLog(req.admin.username, req.origin, `Deleted ${result.affectedRows} auth log entries`, 'success', JSON.stringify(req.query), req.ip);
        res.json({ deleted: result.affectedRows });
    } catch (err) {
        console.error('DELETE /api/logs/auth error:', err);
        res.status(500).json({ error: err.message });
    }
});


// LIVE STATS DASHBOARD
app.get('/api/reports/live-stats', requireApiAuth('reports', 'read-only'), async (req, res) => {
    try {
        const [[{ active_sessions }]] = await pool.query("SELECT COUNT(*) AS active_sessions FROM radacct WHERE acctstoptime IS NULL");
        const [[{ avg_session_min }]] = await pool.query("SELECT ROUND(AVG(acctsessiontime)/60,1) AS avg_session_min FROM radacct WHERE acctstoptime IS NOT NULL AND acctstarttime >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
        const [nas_breakdown] = await pool.query("SELECT nasipaddress, COUNT(*) AS session_count FROM radacct WHERE acctstoptime IS NULL GROUP BY nasipaddress ORDER BY session_count DESC LIMIT 8");
        const [[{ unique_users_24h }]] = await pool.query("SELECT COUNT(DISTINCT username) AS unique_users_24h FROM radpostauth WHERE authdate >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");

        let accepts_1h = 0;
        let rejects_1h = 0;
        let accepts_24h = 0;
        let rejects_24h = 0;
        let hourly_trend = [];

        try {
            const tzOffset = new Date().getTimezoneOffset() * 60000;
            const nowMsLocal = Date.now() - tzOffset;
            const nowStr = new Date(nowMsLocal).toISOString().slice(0, 19).replace('T', ' ');

            const d1h = new Date(nowMsLocal - 3600000).toISOString().slice(0, 19).replace('T', ' ');
            const stats1h = await calculateRadiusStats(pool, 'auth', d1h, nowStr);

            const d24h = new Date(nowMsLocal - 86400000).toISOString().slice(0, 19).replace('T', ' ');
            const stats24h = await calculateRadiusStats(pool, 'auth', d24h, nowStr);

            hourly_trend = await calculateTrendHourly(pool, 'auth', 24);

            accepts_1h = stats1h ? Number(stats1h.total_accepts || 0) : 0;
            rejects_1h = stats1h ? Number(stats1h.total_rejects || 0) : 0;
            accepts_24h = stats24h ? Number(stats24h.total_accepts || 0) : 0;
            rejects_24h = stats24h ? Number(stats24h.total_rejects || 0) : 0;
        } catch (e) {
            console.error('[live-stats radius_stats fallback]', e);

            const [[a1h]] = await pool.query("SELECT COUNT(*) AS cnt FROM radpostauth WHERE reply = 'Access-Accept' AND authdate >= DATE_SUB(NOW(), INTERVAL 1 HOUR)");
            const [[r1h]] = await pool.query("SELECT COUNT(*) AS cnt FROM radpostauth WHERE reply = 'Access-Reject' AND authdate >= DATE_SUB(NOW(), INTERVAL 1 HOUR)");
            const [[a24h]] = await pool.query("SELECT COUNT(*) AS cnt FROM radpostauth WHERE reply = 'Access-Accept' AND authdate >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
            const [[r24h]] = await pool.query("SELECT COUNT(*) AS cnt FROM radpostauth WHERE reply = 'Access-Reject' AND authdate >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
            const [fallbackTrend] = await pool.query("SELECT DATE_FORMAT(authdate,'%H:00') AS hour_label, SUM(reply='Access-Accept') AS accepts, SUM(reply='Access-Reject') AS rejects FROM radpostauth WHERE authdate >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY DATE_FORMAT(authdate,'%Y-%m-%d %H:00:00') ORDER BY MIN(authdate)");

            accepts_1h = Number(a1h.cnt);
            rejects_1h = Number(r1h.cnt);
            accepts_24h = Number(a24h.cnt);
            rejects_24h = Number(r24h.cnt);
            hourly_trend = fallbackTrend;
        }

        res.json({
            active_sessions: Number(active_sessions),
            accepts_1h,
            rejects_1h,
            accepts_24h,
            rejects_24h,
            unique_users_24h: Number(unique_users_24h),
            avg_session_min: Number(avg_session_min) || 0,
            nas_breakdown,
            hourly_trend
        });
    } catch (err) {
        console.error('[/api/reports/live-stats]', err);
        res.status(500).json({ error: err.message });
    }
});



// PER-USER QUICK STATS
app.get('/api/users/:username/stats', requireApiAuth('users', 'read-only'), async (req, res) => {
    const { username } = req.params;

    const [macMapping] = await pool.query(
        'SELECT mac_address FROM mac_auth_devices WHERE mac_id = ? OR mac_address = ? LIMIT 1',
        [username, username]
    );
    const realUsername = macMapping.length > 0 ? macMapping[0].mac_address : username;

    try {
        const [[auth24]] = await pool.query(
            `SELECT COUNT(*) AS cnt FROM radpostauth WHERE username = ? AND authdate >= DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
            [realUsername]
        );
        const [[auth7d]] = await pool.query(
            `SELECT COUNT(*) AS cnt FROM radpostauth WHERE username = ? AND authdate >= DATE_SUB(NOW(), INTERVAL 7 DAY)`,
            [realUsername]
        );
        const [[rej24]] = await pool.query(
            `SELECT COUNT(*) AS cnt FROM radpostauth WHERE username = ? AND reply = 'Access-Reject' AND authdate >= DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
            [realUsername]
        );
        const [[rej7d]] = await pool.query(
            `SELECT COUNT(*) AS cnt FROM radpostauth WHERE username = ? AND reply = 'Access-Reject' AND authdate >= DATE_SUB(NOW(), INTERVAL 7 DAY)`,
            [realUsername]
        );
        const [[acct24]] = await pool.query(
            `SELECT COUNT(*) AS sessions,
                    COALESCE(SUM(acctinputoctets + acctoutputoctets), 0) AS data_bytes,
                    COALESCE(SUM(acctsessiontime), 0) AS time_sec,
                    COALESCE(AVG(acctsessiontime), 0) AS avg_sec
             FROM radacct WHERE username = ? AND acctstarttime >= DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
            [realUsername]
        );
        const [[acct7d]] = await pool.query(
            `SELECT COUNT(*) AS sessions,
                    COALESCE(SUM(acctinputoctets + acctoutputoctets), 0) AS data_bytes,
                    COALESCE(SUM(acctsessiontime), 0) AS time_sec,
                    COALESCE(AVG(acctsessiontime), 0) AS avg_sec
             FROM radacct WHERE username = ? AND acctstarttime >= DATE_SUB(NOW(), INTERVAL 7 DAY)`,
            [realUsername]
        );

        const [planRows] = await pool.query(
            `SELECT up.plan_id, up.manual_reset_date,
                    upu.cycle_started_at,
                    upu.base_input_octets,
                    upu.base_output_octets,
                    upu.base_session_seconds
             FROM user_plans up
             LEFT JOIN user_plan_usage upu ON upu.username = up.username
             WHERE up.username = ? LIMIT 1`,
            [realUsername]
        );

        let cycleData = {};
        if (planRows.length > 0) {
            const row = planRows[0];
            const cycleStart = row.cycle_started_at || row.manual_reset_date;
            const [[allTime]] = await pool.query(
                `SELECT
                    COALESCE(SUM(acctinputoctets), 0)  AS total_input,
                    COALESCE(SUM(acctoutputoctets), 0) AS total_output,
                    COALESCE(SUM(acctsessiontime), 0)  AS total_time
                 FROM radacct WHERE username = ?`,
                [realUsername]
            );

            const baseInput = Number(row.base_input_octets) || 0;
            const baseOutput = Number(row.base_output_octets) || 0;
            const baseTime = Number(row.base_session_seconds) || 0;
            const cycleDataUsed = Math.max(0, Number(allTime.total_input) + Number(allTime.total_output) - baseInput - baseOutput);
            const cycleTimeUsed = Math.max(0, Number(allTime.total_time) - baseTime);

            cycleData = {
                cycle_started_at: cycleStart,
                cycle_data_used: cycleDataUsed,
                cycle_time_used: cycleTimeUsed
            };
        }

        res.json({
            auths_24h: Number(auth24.cnt),
            auths_7d: Number(auth7d.cnt),
            rejects_24h: Number(rej24.cnt),
            rejects_7d: Number(rej7d.cnt),
            sessions_24h: Number(acct24.sessions),
            sessions_7d: Number(acct7d.sessions),
            data_24h: Number(acct24.data_bytes),
            data_7d: Number(acct7d.data_bytes),
            time_24h: Number(acct24.time_sec),
            time_7d: Number(acct7d.time_sec),
            avg_session_24h: Number(acct24.avg_sec),
            avg_session_7d: Number(acct7d.avg_sec),
            ...cycleData
        });

    } catch (err) {
        console.error('GET /api/users/:username/stats error:', err);
        res.status(500).json({ error: err.message });
    }
});

// USER EXECUTIVE REPORT
app.get('/api/reports/user/:username', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const { username } = req.params;
    const { start_date, end_date } = req.query;

    const [macMapping] = await pool.query('SELECT mac_address FROM mac_auth_devices WHERE mac_id = ? OR mac_address = ? LIMIT 1', [username, username]);
    const realUsername = macMapping.length > 0 ? macMapping[0].mac_address : username;

    const dateCondition = (start_date ? ' AND a.acctstarttime >= ?' : '') + (end_date ? ' AND a.acctstarttime <= ?' : '');
    const dateParams = [...(start_date ? [start_date] : []), ...(end_date ? [end_date] : [])];

    const [acct] = await pool.query(
        'SELECT a.*, COALESCE(m.mac_id, a.username) AS username FROM radacct a LEFT JOIN mac_auth_devices m ON m.mac_address = a.username WHERE a.username = ?' + dateCondition + ' ORDER BY a.acctstarttime DESC',
        [realUsername, ...dateParams]
    );
    const [auth] = await pool.query(
        'SELECT p.*, COALESCE(m.mac_id, p.username) AS username FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address = p.username WHERE p.username = ? ORDER BY p.authdate DESC LIMIT 200',
        [realUsername]
    );
    const [stats] = await pool.query(
        'SELECT COUNT(*) as total_sessions, SUM(acctinputoctets) as total_input, SUM(acctoutputoctets) as total_output, SUM(acctsessiontime) as total_time, MAX(acctstarttime) as last_seen, MIN(acctstarttime) as first_seen, AVG(acctsessiontime) as avg_session_time, MAX(acctsessiontime) as longest_session FROM radacct WHERE username = ?' + dateCondition.replace(/a\./g, ''),
        [realUsername, ...dateParams]
    );
    const [nasStats] = await pool.query(
        'SELECT nasipaddress, COUNT(*) as session_count, SUM(acctinputoctets+acctoutputoctets) as total_bytes, AVG(acctsessiontime) as avg_duration FROM radacct WHERE username = ?' + dateCondition.replace(/a\./g, '') + ' GROUP BY nasipaddress ORDER BY session_count DESC',
        [realUsername, ...dateParams]
    );
    const [daily] = await pool.query(
        'SELECT DATE(acctstarttime) as day, COUNT(*) as sessions, SUM(acctinputoctets) as upload, SUM(acctoutputoctets) as download, SUM(acctsessiontime) as duration FROM radacct WHERE username = ?' + dateCondition.replace(/a\./g, '') + ' GROUP BY DATE(acctstarttime) ORDER BY day ASC',
        [realUsername, ...dateParams]
    );
    const [hourly] = await pool.query(
        'SELECT HOUR(acctstarttime) as hour, COUNT(*) as sessions FROM radacct WHERE username = ?' + dateCondition.replace(/a\./g, '') + ' GROUP BY HOUR(acctstarttime) ORDER BY hour ASC',
        [realUsername, ...dateParams]
    );
    const [authStats] = await pool.query(
        "SELECT reply, COUNT(*) as count FROM radpostauth WHERE username = ? GROUP BY reply",
        [realUsername]
    );

    res.json({ username, accounting: acct, postauth: auth, stats: stats[0], nasStats, daily, hourly, authStats });
});

// FAILED AUTH REPORT
app.get('/api/reports/failed-auth', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const [details] = await pool.query("SELECT p.*, COALESCE(m.mac_id, p.username) AS username FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address = p.username WHERE p.reply = 'Access-Reject' ORDER BY p.authdate DESC LIMIT 500");
    const [summary] = await pool.query("SELECT COALESCE(m.mac_id, p.username) AS username, COUNT(*) as fail_count FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address = p.username WHERE p.reply = 'Access-Reject' GROUP BY COALESCE(m.mac_id, p.username) ORDER BY fail_count DESC");
    res.json({ details, summary });
});

// PDF GENERATION
app.post('/api/reports/pdf/user/:username', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const { username } = req.params;
    const reportRes = await fetch(`http://localhost:3000/api/reports/user/${username}`, {
        headers: { 'X-API-Key': req.admin.api_key }
    });
    const data = await reportRes.json();

    const html = `
        <html><head><style>body{font-family:sans-serif;padding:20px;} table{width:100%;border-collapse:collapse;margin-top:10px;} th,td{border:1px solid #ccc;padding:8px;text-align:left;} th{background:#f4f4f4;} h1,h2{color:#333;}</style></head>
        <body>
            <h1>Executive Report: ${data.username}</h1>
            <h2>Summary</h2>
            <table>
                <tr><th>Total Sessions</th><th>Total Upload (bytes)</th><th>Total Download (bytes)</th><th>Total Time (sec)</th></tr>
                <tr><td>${data.stats.total_sessions}</td><td>${data.stats.total_input || 0}</td><td>${data.stats.total_output || 0}</td><td>${data.stats.total_time || 0}</td></tr>
            </table>
            <h2>Recent Accounting</h2>
            <table>
                <tr><th>Session ID</th><th>NAS IP</th><th>Start</th><th>Stop</th><th>Duration</th></tr>
                ${data.accounting.slice(0, 20).map(a => `<tr><td>${a.acctsessionid}</td><td>${a.nasipaddress}</td><td>${a.acctstarttime || 'N/A'}</td><td>${a.acctstoptime || 'Active'}</td><td>${a.acctsessiontime || 0}s</td></tr>`).join('')}
            </table>
            <h2>Recent Authentications</h2>
            <table>
                <tr><th>Date</th><th>Reply</th><th>Class</th></tr>
                ${data.postauth.slice(0, 20).map(p => `<tr><td>${p.authdate}</td><td>${p.reply}</td><td>${p.class}</td></tr>`).join('')}
            </table>
        </body></html>
    `;

    const browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium-browser', args: ['--no-sandbox'] });
    const page = await browser.newPage();
    await page.setContent(html);
    const pdf = await page.pdf({ format: 'A4' });
    await browser.close();

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=Report_${username}.pdf`);
    res.send(pdf);
});

app.post('/api/reports/pdf/failed-auth', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const reportRes = await fetch(`http://localhost:3000/api/reports/failed-auth`, {
        headers: { 'X-API-Key': req.admin.api_key }
    });
    const data = await reportRes.json();

    const html = `
        <html><head><style>body{font-family:sans-serif;padding:20px;} table{width:100%;border-collapse:collapse;margin-top:10px;} th,td{border:1px solid #ccc;padding:8px;text-align:left;} th{background:#f4f4f4;} h1,h2{color:#333;}</style></head>
        <body>
            <h1>Failed Authentication Report</h1>
            <h2>Most Failures</h2>
            <table>
                <tr><th>Username</th><th>Failed Attempts</th></tr>
                ${data.summary.slice(0, 20).map(s => `<tr><td>${s.username}</td><td>${s.fail_count}</td></tr>`).join('')}
            </table>
            <h2>Recent Failures</h2>
            <table>
                <tr><th>Username</th><th>Date/Time</th><th>Class</th></tr>
                ${data.details.slice(0, 50).map(d => `<tr><td>${d.username}</td><td>${d.authdate}</td><td>${d.class}</td></tr>`).join('')}
            </table>
        </body></html>
    `;

    const browser = await puppeteer.launch({ executablePath: '/usr/bin/chromium-browser', args: ['--no-sandbox'] });
    const page = await browser.newPage();
    await page.setContent(html);
    const pdf = await page.pdf({ format: 'A4' });
    await browser.close();

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=FailedAuthReport.pdf`);
    res.send(pdf);
});

app.get('/api/reports/dashboard-stats', requireApiAuth('reports', 'read-only'), async (req, res) => {
    try {
        const [topSessions] = await pool.query(`
    SELECT COALESCE(m.mac_id, a.username) AS username,
        COUNT(*) AS session_count,
        SUM(a.acctinputoctets + a.acctoutputoctets) / 1.073741824e+09 AS data_gb
    FROM radacct a
    LEFT JOIN mac_auth_devices m ON m.mac_address = a.username
    WHERE a.acctstarttime >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    GROUP BY COALESCE(m.mac_id, a.username)
    ORDER BY session_count DESC
    LIMIT 20
`);
        const [topData] = await pool.query(`
            SELECT COALESCE(m.mac_id, a.username) AS username,
                SUM(a.acctinputoctets + a.acctoutputoctets) / 1048576 as data_mb
            FROM radacct a
            LEFT JOIN mac_auth_devices m ON m.mac_address = a.username
            WHERE a.acctstarttime >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY COALESCE(m.mac_id, a.username) ORDER BY data_mb DESC LIMIT 20
        `);
        res.json({ topSessions, topData });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// === DASHBOARD OVERVIEW ===
app.get('/api/reports/dashboard-overview', requireApiAuth('reports', 'read-only'), async (req, res) => {
    try {
        const [[users]] = await pool.query("SELECT COUNT(*) AS cnt FROM radcheck WHERE username NOT IN (SELECT mac_address FROM mac_auth_devices)");
        const [[macs]] = await pool.query("SELECT COUNT(*) AS cnt FROM mac_auth_devices");
        const [[nas]] = await pool.query("SELECT COUNT(*) AS cnt FROM nas");
        const [[plans]] = await pool.query("SELECT COUNT(*) AS cnt FROM plans");
        const [[activeSess]] = await pool.query("SELECT COUNT(*) AS cnt FROM radacct WHERE acctstoptime IS NULL");
        const [[totalSess]] = await pool.query("SELECT COUNT(*) AS cnt FROM radacct");
        const [[dataToday]] = await pool.query("SELECT COALESCE(SUM(acctinputoctets+acctoutputoctets),0) AS bytes FROM radacct WHERE DATE(acctstarttime)=CURDATE()");
        const [[dataWeek]] = await pool.query("SELECT COALESCE(SUM(acctinputoctets+acctoutputoctets),0) AS bytes FROM radacct WHERE acctstarttime >= DATE_SUB(NOW(),INTERVAL 7 DAY)");
        const [recentAuths] = await pool.query("SELECT p.reply, COALESCE(m.mac_id,p.username) AS username, p.nasipaddress, p.authdate FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address=p.username ORDER BY p.authdate DESC LIMIT 8");
        const [nasLoad] = await pool.query("SELECT nasipaddress, COUNT(*) AS active FROM radacct WHERE acctstoptime IS NULL GROUP BY nasipaddress ORDER BY active DESC LIMIT 6");
        const [profileDist] = await pool.query("SELECT groupname, COUNT(*) AS cnt FROM radusergroup GROUP BY groupname ORDER BY cnt DESC LIMIT 8");
        const [planDist] = await pool.query("SELECT p.name, COUNT(up.plan_id) AS cnt FROM plans p LEFT JOIN user_plans up ON up.plan_id=p.id GROUP BY p.id ORDER BY cnt DESC LIMIT 8");

        let authTodayCnt = 0;
        let rejectTodayCnt = 0;
        let authTrend7d = [];

        try {
            const tzOffset = new Date().getTimezoneOffset() * 60000;
            const nowMsLocal = Date.now() - tzOffset;
            const nowStr = new Date(nowMsLocal).toISOString().slice(0, 19).replace('T', ' ');
            const startOfTodayStr = new Date(nowMsLocal).toISOString().split('T')[0] + ' 00:00:00';

            const todayStats = await calculateRadiusStats(pool, 'auth', startOfTodayStr, nowStr);
            authTodayCnt = todayStats
                ? Number(todayStats.total_accepts || 0) + Number(todayStats.total_rejects || 0)
                : 0;
            rejectTodayCnt = todayStats ? Number(todayStats.total_rejects || 0) : 0;

            authTrend7d = await calculateTrendDaily(pool, 'auth', 7);
        } catch (e) {
            console.error('[dashboard-overview radius_stats fallback]', e);

            const [[authToday]] = await pool.query("SELECT COUNT(*) AS cnt FROM radpostauth WHERE authdate >= CURDATE()");
            const [[rejectToday]] = await pool.query("SELECT COUNT(*) AS cnt FROM radpostauth WHERE reply='Access-Reject' AND authdate >= CURDATE()");
            const [fallbackTrend] = await pool.query("SELECT DATE(authdate) AS day, SUM(reply='Access-Accept') AS accepts, SUM(reply='Access-Reject') AS rejects FROM radpostauth WHERE authdate >= DATE_SUB(NOW(),INTERVAL 7 DAY) GROUP BY DATE(authdate) ORDER BY day ASC");

            authTodayCnt = Number(authToday.cnt);
            rejectTodayCnt = Number(rejectToday.cnt);
            authTrend7d = fallbackTrend;
        }

        res.json({
            counts: {
                users: Number(users.cnt),
                macs: Number(macs.cnt),
                nas: Number(nas.cnt),
                plans: Number(plans.cnt),
                activeSessions: Number(activeSess.cnt),
                totalSessions: Number(totalSess.cnt),
                authToday: authTodayCnt,
                rejectToday: rejectTodayCnt
            },
            data: {
                today: Number(dataToday.bytes),
                week: Number(dataWeek.bytes)
            },
            recentAuths,
            authTrend7d,
            nasLoad,
            profileDist,
            planDist
        });
    } catch (err) {
        console.error('[/api/reports/dashboard-overview]', err);
        res.status(500).json({ error: err.message });
    }
});



// === ACCOUNTING HISTORY API ===
app.get('/api/accounting', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const { username, nasip, start_date, end_date, sort = 'acctstarttime', order = 'desc', limit = 300 } = req.query;

    let query = `
        SELECT a.*, (a.acctinputoctets + a.acctoutputoctets) AS total_data,
            COALESCE(m.mac_id, a.username) AS username
        FROM radacct a
        LEFT JOIN mac_auth_devices m ON m.mac_address = a.username
        WHERE 1=1
    `;
    const params = [];

    if (username) { query += ' AND (a.username LIKE ? OR m.mac_id LIKE ?)'; params.push('%' + username + '%', '%' + username + '%'); }
    if (nasip) { query += ' AND nasipaddress = ?'; params.push(nasip); }
    if (start_date) { query += ' AND acctstarttime >= ?'; params.push(start_date); }
    if (end_date) { query += ' AND acctstarttime <= ?'; params.push(end_date + ' 23:59:59'); }

    const allowedSort = ['acctstarttime', 'acctstoptime', 'username', 'nasipaddress', 'acctsessiontime', 'acctinputoctets', 'acctoutputoctets', 'total_data'];
    const sortField = allowedSort.includes(sort) ? sort : 'acctstarttime';
    const sortOrder = order.toLowerCase() === 'asc' ? 'ASC' : 'DESC';

    query += ` ORDER BY ${sortField} ${sortOrder} LIMIT ?`;
    params.push(parseInt(limit));

    try {
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch accounting data' });
    }
});

app.delete('/api/accounting', requireApiAuth('reports', 'read-write'), async (req, res) => {
    const { username, nasip, start_date, end_date } = req.body;

    if (!username && !nasip && !start_date && !end_date) {
        return res.status(400).json({ error: 'At least one filter is required for safety' });
    }

    let query = 'DELETE FROM radacct WHERE 1=1';
    const params = [];

    if (username) { query += ' AND (username LIKE ? OR username IN (SELECT mac_address FROM mac_auth_devices WHERE mac_id LIKE ?))'; params.push('%' + username + '%', '%' + username + '%'); }
    if (nasip) { query += ' AND nasipaddress = ?'; params.push(nasip); }
    if (start_date) { query += ' AND acctstarttime >= ?'; params.push(start_date); }
    if (end_date) { query += ' AND acctstarttime <= ?'; params.push(end_date + ' 23:59:59'); }

    try {
        const [result] = await pool.query(query, params);
        await auditLog(req.admin.username, req.origin, 'Deleted accounting records', 'success',
            `Filters: ${JSON.stringify({ username, nasip, start_date, end_date })}`, req.ip);
        res.json({ success: true, deleted: result.affectedRows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete records' });
    }
});

app.post('/api/users/:username/totp/reset', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { username } = req.params;
    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();
        await conn.query(
            `INSERT INTO user_totp (username, enabled, secret, pending_secret, enrolled_at)
             VALUES (?, 1, NULL, NULL, NULL)
             ON DUPLICATE KEY UPDATE secret = NULL, pending_secret = NULL, enrolled_at = NULL`,
            [username]
        );
        await syncUserTotpToRadius(conn, username);

        const eData = await generateEnrollmentCode(conn, username);
        const baseUrl = `${req.protocol}://${req.hostname}`;
        const enrollment = {
            code: eData.code,
            expires_at: eData.expires_at,
            url: `${baseUrl}/totp-setup.html?username=${encodeURIComponent(username)}`
        };

        await conn.commit();
        await auditLog(req.admin.username, req.origin, `Reset TOTP for user: ${username}`, 'success', '', req.ip);
        res.json({ success: true, enrollment });
    } catch (err) {
        await conn.rollback();
        res.status(400).json({ error: err.message });
    } finally {
        conn.release();
    }
});

app.post('/auth/radius/totp/start', async (req, res) => {
    const { username, password, enrollmentCode } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    try {
        const radiusPassword = await getRadiusPassword(username);
        if (!radiusPassword || radiusPassword !== password) {
            await auditLog(username, 'webui', 'User TOTP enrollment login', 'failed', 'Invalid RADIUS credentials', ip);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const [rows] = await pool.query(
            `SELECT username, enabled, secret, pending_secret, enrolled_at, enrollment_code_hash, enrollment_expires_at
             FROM user_totp WHERE username = ? LIMIT 1`, [username]
        );
        const totp = rows[0];
        if (!totp || Number(totp.enabled) !== 1) {
            await auditLog(username, 'webui', 'User TOTP enrollment login', 'failed', 'TOTP not enabled for user', ip);
            return res.status(403).json({ error: 'TOTP is not enabled for this user' });
        }
        if (totp.secret) {
            await auditLog(username, 'webui', 'User TOTP enrollment login', 'failed', 'TOTP already enrolled', ip);
            return res.status(403).json({ error: 'TOTP already enrolled. Contact admin to reset.' });
        }
        if (!totp.enrollment_code_hash || !totp.enrollment_expires_at) {
            await auditLog(username, 'webui', 'User TOTP enrollment login', 'failed', 'No pending enrollment code', ip);
            return res.status(403).json({ error: 'No enrollment pending' });
        }
        if (new Date() > new Date(totp.enrollment_expires_at)) {
            await auditLog(username, 'webui', 'User TOTP enrollment login', 'failed', 'Enrollment code expired', ip);
            return res.status(403).json({ error: 'Enrollment code expired. Contact admin to reset.' });
        }
        const codeValid = await bcrypt.compare(enrollmentCode, totp.enrollment_code_hash);
        if (!codeValid) {
            await auditLog(username, 'webui', 'User TOTP enrollment login', 'failed', 'Invalid enrollment code', ip);
            return res.status(401).json({ error: 'Invalid enrollment code' });
        }

        let secret = totp.pending_secret;
        if (!secret) {
            secret = authenticator.generateSecret();
            await pool.query(
                `UPDATE user_totp SET pending_secret = ?, enrolled_at = NULL WHERE username = ?`,
                [secret, username]
            );
        }

        const otpauth = authenticator.keyuri(username, TOTP_ISSUER, secret);
        const qrImage = await qrcode.toDataURL(otpauth);
        const token = signTotpEnrollmentToken(username);

        await auditLog(username, 'webui', 'User TOTP enrollment login', 'success', 'Enrollment session created', ip);
        return res.json({ success: true, token, username, qrImage, manualSecret: secret });
    } catch (err) {
        console.error('TOTP start error:', err);
        return res.status(500).json({ error: 'Failed to start TOTP enrollment' });
    }
});

app.post('/auth/radius/totp/confirm', async (req, res) => {
    const { token, code } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    try {
        const decoded = verifyTotpEnrollmentToken(token);
        const username = decoded.username;
        const [rows] = await pool.query(
            `SELECT username, enabled, secret, pending_secret FROM user_totp WHERE username = ? LIMIT 1`, [username]
        );
        const totp = rows[0];
        if (!totp || Number(totp.enabled) !== 1) {
            await auditLog(username, 'webui', 'User TOTP confirm', 'failed', 'TOTP not enabled for user', ip);
            return res.status(403).json({ error: 'TOTP is not enabled for this user' });
        }
        const secret = totp.pending_secret || totp.secret;
        if (!secret) {
            await auditLog(username, 'webui', 'User TOTP confirm', 'failed', 'No pending secret', ip);
            return res.status(400).json({ error: 'No TOTP enrollment is pending' });
        }
        const ok = authenticator.check(String(code || '').trim(), secret);
        if (!ok) {
            await auditLog(username, 'webui', 'User TOTP confirm', 'failed', 'Invalid TOTP code', ip);
            return res.status(400).json({ error: 'Invalid TOTP code' });
        }
        const conn = await pool.getConnection();
        try {
            await conn.beginTransaction();
            await conn.query(
                `UPDATE user_totp SET secret = ?, pending_secret = NULL, enrollment_code_hash = NULL, enrolled_at = NOW() WHERE username = ?`, [secret, username]
            );
            await syncUserTotpToRadius(conn, username);
            await conn.commit();
        } catch (err) {
            await conn.rollback();
            throw err;
        } finally {
            conn.release();
        }
        await auditLog(username, 'webui', 'User TOTP confirm', 'success', 'TOTP enrolled', ip);
        return res.json({ success: true });
    } catch (err) {
        console.error('TOTP confirm error:', err);
        return res.status(400).json({ error: 'Failed to confirm TOTP' });
    }
});


};
