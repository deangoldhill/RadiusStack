module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

// --- PROFILES ---
app.get('/api/profiles', requireApiAuth('users', 'read-only'), async (req, res) => {
    const [rows] = await pool.query('SELECT DISTINCT groupname FROM (SELECT groupname FROM radgroupreply UNION SELECT groupname FROM radgroupcheck UNION SELECT groupname FROM radusergroup) AS profiles WHERE groupname != ""');
    res.json(rows.map(r => r.groupname));
});

app.post('/api/profiles/attributes', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { profile, attribute, type, value } = req.body;
    const table = type === 'reply' ? 'radgroupreply' : 'radgroupcheck';
    const op = type === 'reply' ? '=' : '==';
    await pool.query(`INSERT INTO ${table} (groupname, attribute, op, value) VALUES (?, ?, ?, ?)`, [profile, attribute, op, value]);
    await auditLog(req.admin.username, req.origin, `Added ${type} attribute to profile ${profile}`, 'success', `${attribute}=${value}`, req.ip);
    res.json({ success: true });
});

app.post('/api/profiles/nas', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { profile, nas_id } = req.body;
    const [nas] = await pool.query('SELECT nasname FROM nas WHERE id = ?', [nas_id]);
    if (!nas.length) return res.status(404).json({ error: 'NAS not found' });

    const ip = nas[0].nasname.split('/')[0];
    await pool.query(`INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES (?, 'NAS-IP-Address', '+=', ?)`, [profile, ip]);
    await auditLog(req.admin.username, req.origin, `Added NAS-IP-Address check to profile ${profile}`, 'success', `NAS: ${ip}`, req.ip);
    res.json({ success: true });
});

app.get('/api/profiles/data', requireApiAuth('users', 'read-only'), async (req, res) => {
    const [checks] = await pool.query('SELECT * FROM radgroupcheck');
    const [replies] = await pool.query('SELECT * FROM radgroupreply');
    res.json({ checks, replies });
});

// === FULL PROFILE CREATE / UPDATE ===
app.post('/api/profiles/:name', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { name } = req.params;
    let { nas_ips = [], vlan_id = '', reply_attributes = [] } = req.body;

    if (!name || typeof name !== 'string' || name.trim() === '') {
        return res.status(400).json({ error: 'Profile name is required' });
    }

    nas_ips = Array.isArray(nas_ips) ? nas_ips.filter(ip => typeof ip === 'string' && ip.trim() !== '') : [];
    vlan_id = typeof vlan_id === 'string' ? vlan_id.trim() : '';
    reply_attributes = Array.isArray(reply_attributes) ? reply_attributes : [];

    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();

        await conn.query('DELETE FROM radgroupcheck WHERE groupname = ?', [name]);
        await conn.query('DELETE FROM radgroupreply WHERE groupname = ?', [name]);

        if (nas_ips.length > 0) {
            for (const ip of nas_ips) {
                await conn.query(
                    `INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES (?, 'NAS-IP-Address', '+=', ?)`,
                    [name, ip]
                );
            }
        }

        if (vlan_id !== '') {
            await conn.query(
                `INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
                 (?, 'Tunnel-Type', '=', 'VLAN'),
                 (?, 'Tunnel-Medium-Type', '=', 'IEEE-802'),
                 (?, 'Tunnel-Private-Group-ID', '=', ?)`,
                [name, name, name, vlan_id]
            );
        }

        for (const attr of reply_attributes) {
            const attrName = (attr.attribute || '').toString().trim();
            const attrValue = (attr.value || '').toString().trim();
            if (attrName && attrValue) {
                await conn.query(
                    `INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES (?, ?, '=', ?)`,
                    [name, attrName, attrValue]
                );
            }
        }

        await conn.commit();
        await auditLog(req.admin.username, req.origin, `Saved profile: ${name}`, 'success',
            `NAS: ${nas_ips.length}, VLAN: ${vlan_id || 'none'}, Attributes: ${reply_attributes.length}`, req.ip);
        res.json({ success: true });

    } catch (err) {
        await conn.rollback();
        console.error('Profile save error:', err);
        res.status(500).json({ error: err.message || 'Failed to save profile' });
    } finally {
        conn.release();
    }
});

app.get('/api/profiles/:name', requireApiAuth('users', 'read-only'), async (req, res) => {
    const { name } = req.params;

    try {
        const [members] = await pool.query(`
            SELECT
                u.username AS real_username,
                COALESCE(m.mac_id, u.username) AS username,
                CASE WHEN m.mac_address IS NOT NULL THEN 'mac' ELSE 'user' END AS object_type,
                u.groupname AS profile,
                up.plan_id,
                p.name AS plan_name,

                COALESCE(acct.sessions_30d, 0) AS sessions_30d,
                COALESCE(acct.data_30d, 0) AS data_30d,
                COALESCE(acct.time_30d, 0) AS time_30d,
                COALESCE(acct.last_seen, NULL) AS last_seen,

                COALESCE(auth.auth_count_30d, 0) AS auth_count_30d,
                COALESCE(auth.accept_count_30d, 0) AS accept_count_30d,
                COALESCE(auth.reject_count_30d, 0) AS reject_count_30d,
                COALESCE(auth.last_auth_at, NULL) AS last_auth_at,
                COALESCE(auth.last_reply, NULL) AS last_reply
            FROM radusergroup u
            LEFT JOIN mac_auth_devices m ON m.mac_address = u.username
            LEFT JOIN user_plans up ON up.username = u.username
            LEFT JOIN plans p ON p.id = up.plan_id
            LEFT JOIN (
                SELECT
                    username,
                    COUNT(*) AS sessions_30d,
                    SUM(acctinputoctets + acctoutputoctets) AS data_30d,
                    SUM(acctsessiontime) AS time_30d,
                    MAX(COALESCE(acctupdatetime, acctstarttime, acctstoptime)) AS last_seen
                FROM radacct
                WHERE acctstarttime >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                GROUP BY username
            ) acct ON acct.username = u.username
            LEFT JOIN (
                SELECT
                    p1.username,
                    COUNT(*) AS auth_count_30d,
                    SUM(CASE WHEN p1.reply = 'Access-Accept' THEN 1 ELSE 0 END) AS accept_count_30d,
                    SUM(CASE WHEN p1.reply = 'Access-Reject' THEN 1 ELSE 0 END) AS reject_count_30d,
                    MAX(p1.authdate) AS last_auth_at,
                    SUBSTRING_INDEX(
                        GROUP_CONCAT(p1.reply ORDER BY p1.authdate DESC SEPARATOR ','),
                        ',', 1
                    ) AS last_reply
                FROM radpostauth p1
                WHERE p1.authdate >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                GROUP BY p1.username
            ) auth ON auth.username = u.username
            WHERE u.groupname = ?
            ORDER BY object_type ASC, username ASC
        `, [name]);

        const summary = members.reduce((acc, row) => {
            acc.total_objects += 1;
            if (row.object_type === 'user') acc.total_users += 1;
            if (row.object_type === 'mac') acc.total_macs += 1;
            acc.total_sessions_30d += Number(row.sessions_30d || 0);
            acc.total_data_30d += Number(row.data_30d || 0);
            acc.total_time_30d += Number(row.time_30d || 0);
            acc.total_auth_count_30d += Number(row.auth_count_30d || 0);
            acc.total_accept_count_30d += Number(row.accept_count_30d || 0);
            acc.total_reject_count_30d += Number(row.reject_count_30d || 0);
            return acc;
        }, {
            total_objects: 0,
            total_users: 0,
            total_macs: 0,
            total_sessions_30d: 0,
            total_data_30d: 0,
            total_time_30d: 0,
            total_auth_count_30d: 0,
            total_accept_count_30d: 0,
            total_reject_count_30d: 0
        });

        res.json({
            profile: name,
            summary,
            members
        });
    } catch (err) {
        console.error('GET /api/profiles/:name error:', err);
        res.status(500).json({ error: err.message });
    }
});

// Support PUT
app.put('/api/profiles/:name', requireApiAuth('users', 'read-write'), (req, res) => {
    req.method = 'POST';
    return app._router.handle(req, res);
});

app.delete('/api/profiles/:name', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { name } = req.params;
    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();
        await conn.query('DELETE FROM radgroupcheck WHERE groupname = ?', [name]);
        await conn.query('DELETE FROM radgroupreply WHERE groupname = ?', [name]);
        await conn.query('DELETE FROM radusergroup WHERE groupname = ?', [name]);
        await conn.commit();
        await auditLog(req.admin.username, req.origin, `Deleted profile: ${name}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        await conn.rollback();
        console.error('Delete Profile Error:', err);
        res.status(500).json({ error: 'Failed to delete profile' });
    } finally {
        conn.release();
    }
});


};
