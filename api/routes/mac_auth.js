module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

// --- MAC AUTH ---
app.get('/api/mac-auth', requireApiAuth('users', 'read-only'), async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT
                m.mac_id,
                m.mac_address,
                g.groupname AS profile,
                up.plan_id,
                p.name AS plan_name,
                COALESCE(a.data_30d, 0) AS data_30d,
                COALESCE(a.time_30d, 0) AS time_30d,
                COALESCE(a.sessions_30d, 0) AS sessions_30d,
                a.last_online
            FROM mac_auth_devices m
            LEFT JOIN radusergroup g ON g.username = m.mac_address
            LEFT JOIN user_plans up ON up.username = m.mac_address
            LEFT JOIN plans p ON p.id = up.plan_id
            LEFT JOIN (
                SELECT 
                    username,
                    SUM(acctinputoctets + acctoutputoctets) AS data_30d,
                    SUM(acctsessiontime) AS time_30d,
                    COUNT(*) AS sessions_30d,
                    MAX(acctstarttime) AS last_online
                FROM radacct
                WHERE acctstarttime >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                GROUP BY username
            ) a ON a.username = m.mac_address
            ORDER BY m.mac_id ASC
        `);
        res.json(rows);
    } catch (err) {
        console.error("GET /api/mac-auth Error:", err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/mac-auth', requireApiAuth('users', 'read-write'), async (req, res) => {
    let { mac_id, mac_address, profile, plan_id } = req.body;
    if (!mac_id || !mac_address) return res.status(400).json({ error: 'MAC ID and Address required' });

    mac_address = mac_address.trim().toLowerCase().replace(/-/g, ':');
    if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac_address)) return res.status(400).json({ error: 'Invalid MAC address format' });

    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();
        await conn.query('INSERT INTO mac_auth_devices (mac_address, mac_id) VALUES (?, ?)', [mac_address, mac_id]);
        await conn.query(`DELETE FROM radcheck WHERE username = ? AND attribute = 'Cleartext-Password'`, [mac_address]);
        await conn.query(`INSERT INTO radcheck (username, attribute, op, value) VALUES (?, 'Cleartext-Password', ':=', ?)`, [mac_address, mac_address]);
        await conn.query('DELETE FROM radusergroup WHERE username = ?', [mac_address]);
        if (profile) await conn.query('INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)', [mac_address, profile]);
        if (plan_id) await conn.query('INSERT INTO user_plans (username, plan_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE plan_id = VALUES(plan_id)', [mac_address, plan_id]);
        else await conn.query('DELETE FROM user_plans WHERE username = ?', [mac_address]);
        await conn.query('DELETE FROM user_totp WHERE username = ?', [mac_address]);
        await conn.commit();
        res.json({ message: 'MAC authenticated device created' });
    } catch (err) {
        await conn.rollback();
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'MAC ID or Address already exists' });
        res.status(500).json({ error: err.message });
    } finally {
        conn.release();
    }
});

app.post('/api/mac-auth/bulk', requireApiAuth('users', 'read-write'), async (req, res) => {
    const devices = req.body;
    if (!Array.isArray(devices)) return res.status(400).json({ error: 'Expected array of devices' });

    const conn = await pool.getConnection();
    let successCount = 0;
    let errors = [];

    try {
        await conn.beginTransaction();
        for (let i = 0; i < devices.length; i++) {
            let { mac_id, mac_address, profile, plan_id } = devices[i];
            if (!mac_id || !mac_address) {
                errors.push(`Row ${i + 1}: Missing MAC ID or Address`);
                continue;
            }

            mac_address = mac_address.trim().toLowerCase().replace(/-/g, ':');
            if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac_address)) {
                errors.push(`Row ${i + 1}: Invalid MAC address format (${mac_address})`);
                continue;
            }

            try {
                await conn.query('INSERT INTO mac_auth_devices (mac_address, mac_id) VALUES (?, ?)', [mac_address, mac_id]);
                await conn.query(`DELETE FROM radcheck WHERE username = ? AND attribute = 'Cleartext-Password'`, [mac_address]);
                await conn.query(`INSERT INTO radcheck (username, attribute, op, value) VALUES (?, 'Cleartext-Password', ':=', ?)`, [mac_address, mac_address]);
                await conn.query('DELETE FROM radusergroup WHERE username = ?', [mac_address]);
                if (profile) await conn.query('INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)', [mac_address, profile]);
                if (plan_id) await conn.query('INSERT INTO user_plans (username, plan_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE plan_id = VALUES(plan_id)', [mac_address, plan_id]);
                else await conn.query('DELETE FROM user_plans WHERE username = ?', [mac_address]);
                await conn.query('DELETE FROM user_totp WHERE username = ?', [mac_address]);
                successCount++;
            } catch (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    errors.push(`Row ${i + 1} (${mac_address}): MAC ID or Address already exists`);
                } else {
                    errors.push(`Row ${i + 1} (${mac_address}): ${err.message}`);
                }
            }
        }
        await conn.commit();
        res.json({ message: `Imported ${successCount} MAC devices.`, errors });
    } catch (err) {
        await conn.rollback();
        res.status(500).json({ error: 'Bulk import failed completely' });
    } finally {
        conn.release();
    }
});

app.put('/api/mac-auth/:macAddress', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { macAddress } = req.params;
    const { mac_id, profile, plan_id } = req.body;
    if (!mac_id) return res.status(400).json({ error: 'MAC ID required' });

    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();
        const [existing] = await conn.query('SELECT * FROM mac_auth_devices WHERE mac_address = ?', [macAddress]);
        if (existing.length === 0) throw new Error('MAC device not found');
        await conn.query('UPDATE mac_auth_devices SET mac_id = ? WHERE mac_address = ?', [mac_id, macAddress]);
        await conn.query('DELETE FROM radusergroup WHERE username = ?', [macAddress]);
        if (profile) await conn.query('INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)', [macAddress, profile]);
        if (plan_id) await conn.query('INSERT INTO user_plans (username, plan_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE plan_id = VALUES(plan_id)', [macAddress, plan_id]);
        else await conn.query('DELETE FROM user_plans WHERE username = ?', [macAddress]);
        await conn.commit();
        res.json({ message: 'MAC authenticated device updated' });
    } catch (err) {
        await conn.rollback();
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'MAC ID already exists' });
        res.status(500).json({ error: err.message });
    } finally {
        conn.release();
    }
});

app.delete('/api/mac-auth/:macAddress', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { macAddress } = req.params;
    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();
        await conn.query('DELETE FROM mac_auth_devices WHERE mac_address = ?', [macAddress]);
        await conn.query('DELETE FROM radcheck WHERE username = ?', [macAddress]);
        await conn.query('DELETE FROM radusergroup WHERE username = ?', [macAddress]);
        await conn.query('DELETE FROM user_plans WHERE username = ?', [macAddress]);
        await conn.commit();
        res.json({ message: 'MAC device deleted' });
    } catch (err) {
        await conn.rollback();
        res.status(500).json({ error: err.message });
    } finally {
        conn.release();
    }
});



};
