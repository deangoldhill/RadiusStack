const net = require('net');

module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { generateEnrollmentCode, syncUserTotpToRadius, snapshotUserPlanUsage } = dependencies;
    const { scope } = require('../tenant');

    const selectedTenantId = req => req.tenantScope.enabled ? req.tenantScope.tenantId : null;
    const userScope = (req, column = 'tenant_id') => req.tenantScope.enabled ? scope(req.tenantScope, column) : { sql: ` AND ${column} IS NULL`, params: [] };
    const missingUser = (res) => res.status(404).json({ error: 'User not found in selected tenant' });
    function validateStaticIpv4(value) {
        if (value === undefined || value === null || String(value).trim() === '') return null;
        const address = String(value).trim();
        if (net.isIP(address) !== 4) throw new Error('Static IPv4 address must be a valid IPv4 address');
        return address;
    }
    async function replaceStaticIpv4(conn, req, username, staticIp) {
        const scoped = userScope(req, 'tenant_id');
        await conn.query("DELETE FROM radreply WHERE username = ? AND attribute = 'Framed-IP-Address'" + scoped.sql, [username, ...scoped.params]);
        if (staticIp) await conn.query("INSERT INTO radreply (username, attribute, op, value, tenant_id) VALUES (?, 'Framed-IP-Address', ':=', ?, ?)", [username, staticIp, selectedTenantId(req)]);
    }
    async function userExists(db, req, username) {
        const scoped = userScope(req);
        const [rows] = await db.query("SELECT 1 FROM radcheck WHERE username = ? AND attribute = 'Cleartext-Password'" + scoped.sql + ' LIMIT 1', [username, ...scoped.params]);
        return rows.length > 0;
    }
    async function userNotFound(db, username, tenantScope) {
        return !(await userExists(db, { tenantScope }, username));
    }

    app.get('/api/users', requireApiAuth('users', 'read-only'), async (req, res) => {
        const paginated = req.query.page !== undefined;
        const page = Math.max(1, parseInt(req.query.page, 10) || 1);
        const pageSize = [25, 50, 100].includes(parseInt(req.query.page_size, 10)) ? parseInt(req.query.page_size, 10) : 25;
        const sortColumns = { username: 'c.username', value: 'c.value', planName: 'p.name', profileName: 'u.groupname', totp: 'COALESCE(ut.enabled, 0)' };
        const sort = sortColumns[req.query.sort] || 'c.username';
        const order = req.query.order === 'desc' ? 'DESC' : 'ASC';
        const scoped = userScope(req, 'c.tenant_id');
        const tenantJoinParams = req.tenantScope.enabled ? [req.tenantScope.tenantId, req.tenantScope.tenantId, req.tenantScope.tenantId, req.tenantScope.tenantId] : [];
        const where = ["c.attribute = 'Cleartext-Password'", 'm.mac_address IS NULL'];
        const values = [];
        const search = String(req.query.search || '').trim().slice(0, 100);
        if (search) { const like = `%${search}%`; where.push('(c.username LIKE ? OR c.value LIKE ? OR p.name LIKE ? OR u.groupname LIKE ?)'); values.push(like, like, like, like); }
        const plan = String(req.query.plan || '');
        if (plan === '__NO_PLAN__') where.push('up.plan_id IS NULL'); else if (/^\d+$/.test(plan)) { where.push('up.plan_id = ?'); values.push(Number(plan)); }
        const profile = String(req.query.profile || '').slice(0, 64);
        if (profile === '__NO_PROFILE__') where.push('(u.groupname IS NULL OR u.groupname = "")'); else if (profile) { where.push('u.groupname = ?'); values.push(profile); }
        const totp = String(req.query.totp || '');
        if (totp === 'enabled') where.push('COALESCE(ut.enabled, 0) = 1'); else if (totp === 'disabled') where.push('COALESCE(ut.enabled, 0) = 0'); else if (totp === 'registered') where.push('COALESCE(ut.enabled, 0) = 1 AND ut.secret IS NOT NULL'); else if (totp === 'pending') where.push('COALESCE(ut.enabled, 0) = 1 AND ut.secret IS NULL');
        const joins = `FROM radcheck c LEFT JOIN mac_auth_devices m ON c.username = m.mac_address LEFT JOIN radusergroup u ON c.username = u.username${req.tenantScope.enabled ? ' AND u.tenant_id = ?' : ''} LEFT JOIN user_plans up ON c.username = up.username${req.tenantScope.enabled ? ' AND up.tenant_id = ?' : ''} LEFT JOIN plans p ON up.plan_id = p.id LEFT JOIN user_totp ut ON c.username = ut.username${req.tenantScope.enabled ? ' AND ut.tenant_id = ?' : ''} LEFT JOIN radreply sr ON sr.username = c.username AND sr.attribute = 'Framed-IP-Address'${req.tenantScope.enabled ? ' AND sr.tenant_id = ?' : ''}`;
        const clause = `WHERE ${where.join(' AND ')}${scoped.sql}`;
        const params = [...tenantJoinParams, ...values, ...scoped.params];
        const fields = 'c.username, c.value AS password, u.groupname AS profile, up.plan_id, p.name AS plan_name, 0 AS data_30d, 0 AS sessions_30d, 0 AS time_30d, NULL AS last_online, COALESCE(ut.enabled, 0) AS totp_enabled, CASE WHEN ut.secret IS NOT NULL THEN 1 ELSE 0 END AS totp_registered, sr.value AS static_ip';
        if (!paginated) { const [rows] = await pool.query(`SELECT ${fields} ${joins} ${clause}`, params); return res.json(rows); }
        const [[count]] = await pool.query(`SELECT COUNT(*) AS total ${joins} ${clause}`, params);
        const [rows] = await pool.query(`SELECT ${fields} ${joins} ${clause} ORDER BY ${sort} ${order}, c.username ASC LIMIT ? OFFSET ?`, [...params, pageSize, (page - 1) * pageSize]);
        const total = Number(count.total); res.json({ items: rows, total, page: Math.min(page, Math.max(1, Math.ceil(total / pageSize))), pageSize, totalPages: Math.max(1, Math.ceil(total / pageSize)) });
    });

    app.post('/api/users', requireApiAuth('users', 'read-write'), async (req, res) => {
        const { username, password, profile, plan_id, totp_enabled } = req.body; const staticIp = validateStaticIpv4(req.body.static_ip);
        const tenantId = selectedTenantId(req); const conn = await pool.getConnection();
        try {
            await conn.beginTransaction();
            const [existing] = await conn.query('SELECT 1 FROM radcheck WHERE username = ? LIMIT 1', [username]);
            if (existing.length) throw new Error('Username already exists');
            await conn.query('INSERT INTO radcheck (username, attribute, op, value, tenant_id) VALUES (?, "Cleartext-Password", ":=", ?, ?)', [username, password, tenantId]);
            if (profile) await conn.query('INSERT INTO radusergroup (username, groupname, priority, tenant_id) VALUES (?, ?, 1, ?)', [username, profile, tenantId]);
            await replaceStaticIpv4(conn, req, username, staticIp);
            if (plan_id) { await conn.query('INSERT INTO user_plans (username, plan_id, manual_reset_date, tenant_id) VALUES (?, ?, NOW(), ?)', [username, parseInt(plan_id, 10), tenantId]); await snapshotUserPlanUsage(conn, username, tenantId); }
            else await conn.query('DELETE FROM user_plan_usage WHERE username = ?' + userScope(req).sql, [username, ...userScope(req).params]);
            await conn.query('INSERT INTO user_totp (username, enabled, tenant_id) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE enabled = VALUES(enabled)', [username, totp_enabled ? 1 : 0, tenantId]);
            await syncUserTotpToRadius(conn, username, tenantId);
            let enrollment = null;
            if (totp_enabled) { const eData = await generateEnrollmentCode(conn, username, tenantId); enrollment = { code: eData.code, expires_at: eData.expires_at, url: `${req.protocol}://${req.get('host')}/totp-setup.html?username=${encodeURIComponent(username)}` }; }
            await conn.commit(); await auditLog(req.admin.username, req.origin, `Created user: ${username}`, 'success', '', req.ip, req.tenantScope); res.json({ success: true, enrollment });
        } catch (err) { await conn.rollback(); res.status(400).json({ error: err.message }); } finally { conn.release(); }
    });

    app.post('/api/users/:username/reset-plan', requireApiAuth('users', 'read-write'), async (req, res) => {
        const { username } = req.params; const scoped = userScope(req);
        try {
            const [plans] = await pool.query('SELECT plan_id FROM user_plans WHERE username = ?' + scoped.sql, [username, ...scoped.params]);
            if (!plans.length) return res.status(404).json({ error: 'User has no plan assigned' });
            await snapshotUserPlanUsage(pool, username, selectedTenantId(req));
            const [result] = await pool.query('UPDATE user_plans SET manual_reset_date = NOW() WHERE username = ?' + scoped.sql, [username, ...scoped.params]);
            if (!result.affectedRows) return missingUser(res);
            await auditLog(req.admin.username, req.origin, `Reset limits for user: ${username}`, 'success', '', req.ip, req.tenantScope); res.json({ success: true });
        } catch (err) { res.status(500).json({ error: err.message }); }
    });

    app.post('/api/users/bulk', requireApiAuth('users', 'read-write'), async (req, res) => {
        if (!Array.isArray(req.body)) return res.status(400).json({ error: 'Expected array of users' });
        const tenantId = selectedTenantId(req); const conn = await pool.getConnection(); const errors = []; let successCount = 0;
        try { await conn.beginTransaction(); for (let i = 0; i < req.body.length; i++) { const { username, password, profile, plan_id, totp_enabled } = req.body[i]; if (!username || !password) { errors.push(`Row ${i + 1}: Missing username or password`); continue; } const [existing] = await conn.query('SELECT 1 FROM radcheck WHERE username = ? LIMIT 1', [username]); if (existing.length) { errors.push(`Row ${i + 1} (${username}): Already exists`); continue; } await conn.query('INSERT INTO radcheck (username, attribute, op, value, tenant_id) VALUES (?, "Cleartext-Password", ":=", ?, ?)', [username, password, tenantId]); if (profile) await conn.query('INSERT INTO radusergroup (username, groupname, priority, tenant_id) VALUES (?, ?, 1, ?)', [username, profile, tenantId]); if (plan_id) await conn.query('INSERT INTO user_plans (username, plan_id, manual_reset_date, tenant_id) VALUES (?, ?, NOW(), ?)', [username, parseInt(plan_id, 10), tenantId]); await conn.query('INSERT INTO user_totp (username, enabled, tenant_id) VALUES (?, ?, ?)', [username, totp_enabled ? 1 : 0, tenantId]); successCount++; } await conn.commit(); await auditLog(req.admin.username, req.origin, `Imported ${successCount} users`, 'success', JSON.stringify({ errors }), req.ip, req.tenantScope); res.json({ message: `Imported ${successCount} users.`, errors }); } catch (err) { await conn.rollback(); res.status(500).json({ error: 'Bulk import failed completely' }); } finally { conn.release(); }
    });

    app.put('/api/users/:username', requireApiAuth('users', 'read-write'), async (req, res) => {
        const { username } = req.params; const { password, profile, plan_id, totp_enabled } = req.body; const staticIp = req.body.static_ip === undefined ? undefined : validateStaticIpv4(req.body.static_ip); const tenantId = selectedTenantId(req); const scoped = userScope(req); const conn = await pool.getConnection();
        try {
            await conn.beginTransaction(); if (!await userExists(conn, req, username)) { await conn.rollback(); return missingUser(res); }
            if (password && password.trim()) await conn.query("UPDATE radcheck SET value = ? WHERE username = ? AND attribute = 'Cleartext-Password'" + scoped.sql, [password, username, ...scoped.params]);
            if (profile !== undefined) { await conn.query('DELETE FROM radusergroup WHERE username = ?' + scoped.sql, [username, ...scoped.params]); if (profile) await conn.query('INSERT INTO radusergroup (username, groupname, priority, tenant_id) VALUES (?, ?, 1, ?)', [username, profile, tenantId]); }
            if (plan_id !== undefined) { await conn.query('DELETE FROM user_plans WHERE username = ?' + scoped.sql, [username, ...scoped.params]); await conn.query('DELETE FROM user_plan_usage WHERE username = ?' + scoped.sql, [username, ...scoped.params]); if (plan_id) { await conn.query('INSERT INTO user_plans (username, plan_id, manual_reset_date, tenant_id) VALUES (?, ?, NOW(), ?)', [username, parseInt(plan_id, 10), tenantId]); await snapshotUserPlanUsage(conn, username, tenantId); } }
            if (staticIp !== undefined) await replaceStaticIpv4(conn, req, username, staticIp);
            let enrollment = null;
            if (totp_enabled !== undefined) { await conn.query('INSERT INTO user_totp (username, enabled, tenant_id) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE enabled = VALUES(enabled)', [username, totp_enabled ? 1 : 0, tenantId]); await syncUserTotpToRadius(conn, username, tenantId); const [rows] = await conn.query('SELECT secret FROM user_totp WHERE username = ?' + scoped.sql, [username, ...scoped.params]); if (totp_enabled && (!rows[0] || !rows[0].secret)) { const eData = await generateEnrollmentCode(conn, username, tenantId); enrollment = { code: eData.code, expires_at: eData.expires_at, url: `${req.protocol}://${req.hostname}/totp-setup.html?username=${encodeURIComponent(username)}` }; } }
            await conn.commit(); await auditLog(req.admin.username, req.origin, `Updated user: ${username}`, 'success', '', req.ip, req.tenantScope); res.json({ success: true, enrollment });
        } catch (err) { await conn.rollback(); res.status(400).json({ error: err.message }); } finally { conn.release(); }
    });

    app.delete('/api/users/:username', requireApiAuth('users', 'read-write'), async (req, res) => {
        const { username } = req.params; const scoped = userScope(req); const conn = await pool.getConnection();
        try {
            await conn.beginTransaction();
            if (await userNotFound(conn, username, req.tenantScope)) { await conn.rollback(); return missingUser(res); }
            const radreplyScope = userScope(req, 'tenant_id');
            await conn.query('DELETE FROM radreply WHERE username = ?' + radreplyScope.sql, [username, ...radreplyScope.params]);
            for (const table of ['radusergroup', 'user_plans', 'user_plan_usage', 'user_totp', 'radcheck']) await conn.query(`DELETE FROM ${table} WHERE username = ?` + scoped.sql, [username, ...scoped.params]);
            await conn.commit();
            await auditLog(req.admin.username, req.origin, `Deleted user: ${username}`, 'success', '', req.ip, req.tenantScope); res.json({ success: true });
        } catch (err) { await conn.rollback(); res.status(500).json({ error: err.message }); } finally { conn.release(); }
    });
};
