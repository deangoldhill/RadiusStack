const net = require('net');

module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { scope } = require('../tenant');
    const selectedTenantId = req => req.tenantScope.enabled ? req.tenantScope.tenantId : null;
    const tenantScope = (req, column = 'tenant_id') => req.tenantScope.enabled ? scope(req.tenantScope, column) : { sql: ` AND ${column} IS NULL`, params: [] };
    const tenantParams = req => req.tenantScope.enabled ? [req.tenantScope.tenantId] : [];
    const tenantJoin = (req, column) => req.tenantScope.enabled ? ` AND ${column}.tenant_id = ?` : ` AND ${column}.tenant_id IS NULL`;

    function macAddress(value) {
        return String(value || '').trim().toLowerCase().replace(/-/g, ':');
    }
    function validMac(value) {
        return /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(value);
    }
    function validateStaticIpv4(value) {
        if (value === undefined || value === null || String(value).trim() === '') return null;
        const address = String(value).trim();
        if (net.isIP(address) !== 4) throw new Error('Static IPv4 address must be a valid IPv4 address');
        return address;
    }
    async function macExists(db, req, address) {
        const scoped = tenantScope(req);
        const [rows] = await db.query('SELECT 1 FROM mac_auth_devices WHERE mac_address = ?' + scoped.sql + ' LIMIT 1', [address, ...scoped.params]);
        return rows.length > 0;
    }
    async function replaceMacRelations(conn, req, address, profile, planId, staticIp) {
        const tenantId = selectedTenantId(req);
        const scoped = tenantScope(req);
        await conn.query('DELETE FROM radcheck WHERE username = ? AND attribute = \'Cleartext-Password\'' + scoped.sql, [address, ...scoped.params]);
        await conn.query('INSERT INTO radcheck (username, attribute, op, value, tenant_id) VALUES (?, \'Cleartext-Password\', \':=\', ?, ?)', [address, address, tenantId]);
        await conn.query('DELETE FROM radusergroup WHERE username = ?' + scoped.sql, [address, ...scoped.params]);
        if (profile) await conn.query('INSERT INTO radusergroup (username, groupname, priority, tenant_id) VALUES (?, ?, 1, ?)', [address, profile, tenantId]);
        await conn.query('DELETE FROM user_plans WHERE username = ?' + scoped.sql, [address, ...scoped.params]);
        if (planId) await conn.query('INSERT INTO user_plans (username, plan_id, tenant_id) VALUES (?, ?, ?)', [address, planId, tenantId]);
        await conn.query('DELETE FROM user_totp WHERE username = ?' + scoped.sql, [address, ...scoped.params]);
        await conn.query("DELETE FROM radreply WHERE username = ? AND attribute = 'Framed-IP-Address'" + scoped.sql, [address, ...scoped.params]);
        if (staticIp) await conn.query("INSERT INTO radreply (username, attribute, op, value, tenant_id) VALUES (?, 'Framed-IP-Address', ':=', ?, ?)", [address, staticIp, tenantId]);
    }

    app.get('/api/mac-auth', requireApiAuth('users', 'read-only'), async (req, res) => {
        try {
            const paginated = req.query.page !== undefined;
            const page = Math.max(1, parseInt(req.query.page, 10) || 1);
            const pageSize = [25, 50, 100].includes(parseInt(req.query.page_size, 10)) ? parseInt(req.query.page_size, 10) : 25;
            const sortColumns = { username: 'm.mac_id', callingstationid: 'm.mac_address', planName: 'p.name', profileName: 'g.groupname' };
            const sort = sortColumns[req.query.sort] || 'm.mac_id';
            const order = req.query.order === 'desc' ? 'DESC' : 'ASC';
            const where = ['1=1']; const values = [];
            const search = String(req.query.search || '').trim().slice(0, 100);
            if (search) { const like = `%${search}%`; where.push('(m.mac_id LIKE ? OR m.mac_address LIKE ? OR p.name LIKE ? OR g.groupname LIKE ?)'); values.push(like, like, like, like); }
            const plan = String(req.query.plan || '');
            if (plan === '__NO_PLAN__') where.push('up.plan_id IS NULL'); else if (/^\d+$/.test(plan)) { where.push('up.plan_id = ?'); values.push(Number(plan)); }
            const profile = String(req.query.profile || '').slice(0, 64);
            if (profile === '__NO_PROFILE__') where.push('(g.groupname IS NULL OR g.groupname = "")'); else if (profile) { where.push('g.groupname = ?'); values.push(profile); }
            const scoped = tenantScope(req, 'm.tenant_id');
            const joins = `FROM mac_auth_devices m LEFT JOIN radusergroup g ON g.username = m.mac_address${tenantJoin(req, 'g')} LEFT JOIN user_plans up ON up.username = m.mac_address${tenantJoin(req, 'up')} LEFT JOIN plans p ON p.id = up.plan_id${tenantJoin(req, 'p')} LEFT JOIN radreply sr ON sr.username = m.mac_address AND sr.attribute = 'Framed-IP-Address'${tenantJoin(req, 'sr')}`;
            const joinParams = req.tenantScope.enabled ? [req.tenantScope.tenantId, req.tenantScope.tenantId, req.tenantScope.tenantId, req.tenantScope.tenantId] : [];
            const clause = `WHERE ${where.join(' AND ')}${scoped.sql}`;
            const params = [...joinParams, ...values, ...scoped.params];
            const fields = 'm.mac_id, m.mac_address, g.groupname AS profile, up.plan_id, p.name AS plan_name, 0 AS data_30d, 0 AS time_30d, 0 AS sessions_30d, NULL AS last_online, sr.value AS static_ip';
            if (!paginated) { const [rows] = await pool.query(`SELECT ${fields} ${joins} ${clause} ORDER BY m.mac_id ASC`, params); return res.json(rows); }
            const [[count]] = await pool.query(`SELECT COUNT(*) AS total ${joins} ${clause}`, params);
            const [rows] = await pool.query(`SELECT ${fields} ${joins} ${clause} ORDER BY ${sort} ${order}, m.mac_address ASC LIMIT ? OFFSET ?`, [...params, pageSize, (page - 1) * pageSize]);
            const total = Number(count.total);
            res.json({ items: rows, total, page: Math.min(page, Math.max(1, Math.ceil(total / pageSize))), pageSize, totalPages: Math.max(1, Math.ceil(total / pageSize)) });
        } catch (err) { console.error('GET /api/mac-auth Error:', err); res.status(500).json({ error: err.message }); }
    });

    app.post('/api/mac-auth', requireApiAuth('users', 'read-write'), async (req, res) => {
        const { mac_id, profile, plan_id } = req.body; const staticIp = validateStaticIpv4(req.body.static_ip); const address = macAddress(req.body.mac_address);
        if (!mac_id || !address) return res.status(400).json({ error: 'MAC ID and Address required' });
        if (!validMac(address)) return res.status(400).json({ error: 'Invalid MAC address format' });
        const conn = await pool.getConnection();
        try {
            await conn.beginTransaction();
            await conn.query('INSERT INTO mac_auth_devices (mac_address, mac_id, tenant_id) VALUES (?, ?, ?)', [address, mac_id, selectedTenantId(req)]);
            await replaceMacRelations(conn, req, address, profile, plan_id, staticIp);
            await conn.commit(); await auditLog(req.admin.username, req.origin, `Created MAC device: ${mac_id}`, 'success', '', req.ip, req.tenantScope); res.json({ message: 'MAC authenticated device created' });
        } catch (err) { await conn.rollback(); res.status(err.code === 'ER_DUP_ENTRY' ? 400 : 500).json({ error: err.code === 'ER_DUP_ENTRY' ? 'MAC ID or Address already exists' : err.message }); } finally { conn.release(); }
    });

    app.post('/api/mac-auth/bulk', requireApiAuth('users', 'read-write'), async (req, res) => {
        if (!Array.isArray(req.body)) return res.status(400).json({ error: 'Expected array of devices' });
        const conn = await pool.getConnection(); const errors = []; let successCount = 0;
        try {
            await conn.beginTransaction();
            for (let i = 0; i < req.body.length; i++) {
                const { mac_id, profile, plan_id } = req.body[i]; const address = macAddress(req.body[i].mac_address);
                if (!mac_id || !address) { errors.push(`Row ${i + 1}: Missing MAC ID or Address`); continue; }
                if (!validMac(address)) { errors.push(`Row ${i + 1}: Invalid MAC address format (${address})`); continue; }
                try { await conn.query('INSERT INTO mac_auth_devices (mac_address, mac_id, tenant_id) VALUES (?, ?, ?)', [address, mac_id, selectedTenantId(req)]); await replaceMacRelations(conn, req, address, profile, plan_id); successCount++; }
                catch (err) { errors.push(`Row ${i + 1} (${address}): ${err.code === 'ER_DUP_ENTRY' ? 'MAC ID or Address already exists' : err.message}`); }
            }
            await conn.commit(); await auditLog(req.admin.username, req.origin, `Imported ${successCount} MAC devices`, 'success', JSON.stringify({ errors }), req.ip, req.tenantScope); res.json({ message: `Imported ${successCount} MAC devices.`, errors });
        } catch (err) { await conn.rollback(); res.status(500).json({ error: 'Bulk import failed completely' }); } finally { conn.release(); }
    });

    app.put('/api/mac-auth/:macAddress', requireApiAuth('users', 'read-write'), async (req, res) => {
        const { mac_id, profile, plan_id } = req.body; const staticIp = req.body.static_ip === undefined ? undefined : validateStaticIpv4(req.body.static_ip); const address = macAddress(req.params.macAddress);
        if (!mac_id) return res.status(400).json({ error: 'MAC ID required' });
        const conn = await pool.getConnection();
        try {
            await conn.beginTransaction();
            if (!await macExists(conn, req, address)) { await conn.rollback(); return res.status(404).json({ error: 'MAC device not found in selected tenant' }); }
            const scoped = tenantScope(req);
            await conn.query('UPDATE mac_auth_devices SET mac_id = ? WHERE mac_address = ?' + scoped.sql, [mac_id, address, ...scoped.params]);
            if (staticIp === undefined) { const existingIp = await conn.query("SELECT value FROM radreply WHERE username = ? AND attribute = 'Framed-IP-Address'" + tenantScope(req).sql, [address, ...tenantScope(req).params]); await replaceMacRelations(conn, req, address, profile, plan_id, existingIp[0][0]?.value || null); } else await replaceMacRelations(conn, req, address, profile, plan_id, staticIp);
            await conn.commit(); await auditLog(req.admin.username, req.origin, `Updated MAC device: ${address}`, 'success', '', req.ip, req.tenantScope); res.json({ message: 'MAC authenticated device updated' });
        } catch (err) { await conn.rollback(); res.status(err.code === 'ER_DUP_ENTRY' ? 400 : 500).json({ error: err.code === 'ER_DUP_ENTRY' ? 'MAC ID already exists' : err.message }); } finally { conn.release(); }
    });

    app.delete('/api/mac-auth/:macAddress', requireApiAuth('users', 'read-write'), async (req, res) => {
        const address = macAddress(req.params.macAddress); const conn = await pool.getConnection();
        try {
            await conn.beginTransaction();
            if (!await macExists(conn, req, address)) { await conn.rollback(); return res.status(404).json({ error: 'MAC device not found in selected tenant' }); }
            const scoped = tenantScope(req);
            for (const table of ['mac_auth_devices', 'radcheck', 'radusergroup', 'user_plans', 'user_plan_usage', 'user_totp']) await conn.query(`DELETE FROM ${table} WHERE ${table === 'mac_auth_devices' ? 'mac_address' : 'username'} = ?` + scoped.sql, [address, ...scoped.params]);
            await conn.commit(); await auditLog(req.admin.username, req.origin, `Deleted MAC device: ${address}`, 'success', '', req.ip, req.tenantScope); res.json({ message: 'MAC device deleted' });
        } catch (err) { await conn.rollback(); res.status(500).json({ error: err.message }); } finally { conn.release(); }
    });
};
