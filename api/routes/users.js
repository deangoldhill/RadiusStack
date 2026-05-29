module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

// --- USERS ---
app.get('/api/users', requireApiAuth('users', 'read-only'), async (req, res) => {
    const [rows] = await pool.query(`
    SELECT
      c.username,
      c.value AS password,
      u.groupname AS profile,
      up.plan_id,
      p.name AS plan_name,
      COALESCE(a.data_30d, 0) AS data_30d,
      COALESCE(a.sessions_30d, 0) AS sessions_30d,
      COALESCE(a.time_30d, 0) AS time_30d,
      COALESCE(ut.enabled, 0) AS totp_enabled,
      CASE WHEN ut.secret IS NOT NULL THEN 1 ELSE 0 END AS totp_registered
    FROM radcheck c
    LEFT JOIN mac_auth_devices m ON c.username = m.mac_address
    LEFT JOIN radusergroup u ON c.username = u.username
    LEFT JOIN user_plans up ON c.username = up.username
    LEFT JOIN plans p ON up.plan_id = p.id
    LEFT JOIN user_totp ut ON c.username = ut.username
    LEFT JOIN (
        SELECT username,
               COUNT(*) AS sessions_30d,
               SUM(acctinputoctets + acctoutputoctets) AS data_30d,
               SUM(acctsessiontime) AS time_30d
        FROM radacct
        WHERE acctstarttime >= DATE_SUB(NOW(), INTERVAL 30 DAY)
        GROUP BY username
    ) a ON c.username = a.username
    WHERE c.attribute = 'Cleartext-Password' AND m.mac_address IS NULL
  `);
    res.json(rows);
});

app.post('/api/users', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { username, password, profile, plan_id, totp_enabled } = req.body;
    const conn = await pool.getConnection();

    try {
        await conn.beginTransaction();

        await conn.query(
            'INSERT INTO radcheck (username, attribute, op, value) VALUES (?, "Cleartext-Password", ":=", ?)',
            [username, password]
        );

        if (profile && profile !== '') {
            await conn.query(
                'INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)',
                [username, profile]
            );
        }

        if (plan_id && plan_id !== '') {
            await conn.query(
                'INSERT INTO user_plans (username, plan_id, manual_reset_date) VALUES (?, ?, NOW())',
                [username, parseInt(plan_id, 10)]
            );
            await snapshotUserPlanUsage(conn, username);
        } else {
            await conn.query('DELETE FROM user_plan_usage WHERE username = ?', [username]);
        }

        await conn.query(
            `INSERT INTO user_totp (username, enabled)
       VALUES (?, ?)
       ON DUPLICATE KEY UPDATE enabled = VALUES(enabled)`,
            [username, totp_enabled ? 1 : 0]
        );
        await syncUserTotpToRadius(conn, username);

        let enrollment = null;
        if (totp_enabled) {
            const baseUrl = `${req.protocol}://${req.get('host')}`;
            const eData = await generateEnrollmentCode(conn, username);
            enrollment = {
                code: eData.code,
                expires_at: eData.expires_at,
                url: `${baseUrl}/totp-setup.html?username=${encodeURIComponent(username)}`
            };
        }

        await conn.commit();
        await auditLog(req.admin.username, req.origin, `Created user: ${username}`, 'success', '', req.ip);
        res.json({ success: true, enrollment });
    } catch (err) {
        await conn.rollback();
        console.error("POST User Error:", err);
        res.status(400).json({ error: err.message });
    } finally {
        conn.release();
    }
});

app.post('/api/users/:username/reset-plan', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { username } = req.params;

    try {
        const [plans] = await pool.query('SELECT plan_id FROM user_plans WHERE username = ?', [username]);
        if (!plans.length) {
            return res.status(404).json({ error: 'User has no plan assigned' });
        }

        await snapshotUserPlanUsage(pool, username);
        await pool.query('UPDATE user_plans SET manual_reset_date = NOW() WHERE username = ?', [username]);

        await auditLog(req.admin.username, req.origin, `Reset limits for user: ${username}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/users/bulk', requireApiAuth('users', 'read-write'), async (req, res) => {
    const users = req.body;
    if (!Array.isArray(users)) return res.status(400).json({ error: 'Expected array of users' });

    const conn = await pool.getConnection();
    let successCount = 0;
    let errors = [];

    try {
        await conn.beginTransaction();
        for (let i = 0; i < users.length; i++) {
            const { username, password, profile, plan_id, totp_enabled } = users[i];
            if (!username || !password) {
                errors.push(`Row ${i + 1}: Missing username or password`);
                continue;
            }
            try {
                await conn.query('INSERT INTO radcheck (username, attribute, op, value) VALUES (?, "Cleartext-Password", ":=", ?)', [username, password]);
                if (profile && profile !== '') {
                    await conn.query('INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)', [username, profile]);
                }
                if (plan_id && plan_id !== '') {
                    await conn.query('INSERT INTO user_plans (username, plan_id, manual_reset_date) VALUES (?, ?, NOW())', [username, parseInt(plan_id, 10)]);
                }
                if (totp_enabled) {
                    await conn.query('INSERT INTO user_totp (username, enabled) VALUES (?, 1)', [username]);
                }
                successCount++;
            } catch (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    errors.push(`Row ${i + 1} (${username}): Already exists`);
                } else {
                    errors.push(`Row ${i + 1} (${username}): ${err.message}`);
                }
            }
        }
        await conn.commit();
        res.json({ message: `Imported ${successCount} users.`, errors });
    } catch (err) {
        await conn.rollback();
        res.status(500).json({ error: 'Bulk import failed completely' });
    } finally {
        conn.release();
    }
});

app.put('/api/users/:username', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { username } = req.params;
    const { password, profile, plan_id, totp_enabled } = req.body;
    const conn = await pool.getConnection();

    try {
        await conn.beginTransaction();

        if (password && password.trim() !== '') {
            await conn.query(
                "UPDATE radcheck SET value = ? WHERE username = ? AND attribute = 'Cleartext-Password'",
                [password, username]
            );
        }

        if (profile !== undefined) {
            await conn.query("DELETE FROM radusergroup WHERE username = ?", [username]);
            if (profile) {
                await conn.query(
                    "INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)",
                    [username, profile]
                );
            }
        }

        if (plan_id !== undefined) {
            await conn.query("DELETE FROM user_plans WHERE username = ?", [username]);
            await conn.query("DELETE FROM user_plan_usage WHERE username = ?", [username]);

            if (plan_id && plan_id !== '') {
                await conn.query(
                    "INSERT INTO user_plans (username, plan_id, manual_reset_date) VALUES (?, ?, NOW())",
                    [username, parseInt(plan_id, 10)]
                );
                await snapshotUserPlanUsage(conn, username);
            }
        }

        let enrollment = null;
        if (totp_enabled !== undefined) {
            await conn.query(
                `INSERT INTO user_totp (username, enabled)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE enabled = VALUES(enabled)`,
                [username, totp_enabled ? 1 : 0]
            );
            await syncUserTotpToRadius(conn, username);

            const [rows] = await conn.query("SELECT secret FROM user_totp WHERE username = ?", [username]);

            if (totp_enabled && (!rows[0] || !rows[0].secret)) {
                const eData = await generateEnrollmentCode(conn, username);
                const baseUrl = `${req.protocol}://${req.hostname}`;
                enrollment = {
                    code: eData.code,
                    expires_at: eData.expires_at,
                    url: `${baseUrl}/totp-setup.html?username=${encodeURIComponent(username)}`
                };
            }
        }

        await conn.commit();
        await auditLog(req.admin.username, req.origin, `Updated user: ${username}`, 'success', '', req.ip);
        res.json({ success: true, enrollment });
    } catch (err) {
        await conn.rollback();
        res.status(400).json({ error: err.message });
    } finally {
        conn.release();
    }
});

app.delete('/api/users/:username', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { username } = req.params;
    await pool.query('DELETE FROM radcheck WHERE username = ?', [username]);
    await pool.query('DELETE FROM radusergroup WHERE username = ?', [username]);
    await pool.query('DELETE FROM user_plans WHERE username = ?', [username]);
    await pool.query('DELETE FROM user_plan_usage WHERE username = ?', [username]);
    await auditLog(req.admin.username, req.origin, `Deleted user: ${username}`, 'success', '', req.ip);
    res.json({ success: true });
});


};
