module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { scope } = require('../tenant');
    const { STANDARD_REPLY_ATTRIBUTES, normalizeCustomReplyAttributes } = require('../custom_attributes');
    const tenant = req => req.tenantScope || { enabled: false, tenantId: null };
    const selectedTenantId = req => tenant(req).enabled ? tenant(req).tenantId : null;
    const profileScope = (req, column = 'tenant_id') => tenant(req).enabled ? scope(tenant(req), column) : { sql: ` AND ${column} IS NULL`, params: [] };
    const profileNotFound = res => res.status(404).json({ error: 'Profile not found in selected tenant' });

    async function profileExists(db, req, name) {
        const scoped = profileScope(req);
        const sql = `SELECT 1 FROM (
            SELECT groupname FROM radgroupcheck WHERE groupname = ?${scoped.sql}
            UNION SELECT groupname FROM radgroupreply WHERE groupname = ?${scoped.sql}
            UNION SELECT groupname FROM radusergroup WHERE groupname = ?${scoped.sql}
        ) profiles LIMIT 1`;
        const params = [name, ...scoped.params, name, ...scoped.params, name, ...scoped.params];
        const [rows] = await db.query(sql, params);
        return rows.length > 0;
    }

    async function installedReplyAttributes(db, req) {
        const installed = new Set(STANDARD_REPLY_ATTRIBUTES.filter(attribute => attribute.dictionary_status !== 'unavailable').map(attribute => attribute.name));
        const table = tenant(req).enabled ? 'tenant_settings' : 'settings';
        const where = tenant(req).enabled ? 'tenant_id = ? AND ' : '';
        const params = tenant(req).enabled ? [req.tenantScope.tenantId] : [];
        const [rows] = await db.query(`SELECT setting_value FROM ${table} WHERE ${where}setting_key = 'custom_reply_attributes' LIMIT 1`, params);
        if (!rows.length) return installed;
        try {
            for (const attribute of normalizeCustomReplyAttributes(rows[0].setting_value)) {
                if (Number.isInteger(attribute.vendor_code) && Number.isInteger(attribute.vendor_attribute_number)) installed.add(attribute.name);
            }
        } catch (_) { /* malformed legacy settings never become profile choices */ }
        return installed;
    }

    app.get('/api/profiles', requireApiAuth('users', 'read-only'), async (req, res) => {
        const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 0, 0), 1000);
        const scoped = profileScope(req);
        const sql = `SELECT DISTINCT groupname FROM (
            SELECT groupname FROM radgroupreply WHERE groupname != ''${scoped.sql}
            UNION SELECT groupname FROM radgroupcheck WHERE groupname != ''${scoped.sql}
            UNION SELECT groupname FROM radusergroup WHERE groupname != ''${scoped.sql}
        ) AS profiles ORDER BY groupname${limit ? ' LIMIT ?' : ''}`;
        const params = [...scoped.params, ...scoped.params, ...scoped.params];
        const [rows] = await pool.query(sql, limit ? [...params, limit] : params);
        res.json(rows.map(r => r.groupname));
    });

    app.post('/api/profiles/attributes', requireApiAuth('users', 'read-write'), async (req, res) => {
        const { profile, attribute, type, value } = req.body;
        const table = type === 'reply' ? 'radgroupreply' : 'radgroupcheck';
        const exists = await profileExists(pool, req, profile);
        if (!exists && tenant(req).enabled) {
            const [global] = await pool.query(`SELECT 1 FROM ${table} WHERE groupname = ? LIMIT 1`, [profile]);
            if (global.length) return profileNotFound(res);
        }
        const installed = await installedReplyAttributes(pool, req);
        if (!installed.has(attribute)) return res.status(400).json({ error: 'Profile reply attribute is not installed in the FreeRADIUS dictionary' });
        const op = type === 'reply' ? '=' : '==';
        await pool.query(`INSERT INTO ${table} (groupname, attribute, op, value, tenant_id) VALUES (?, ?, ?, ?, ?)`, [profile, attribute, op, value, selectedTenantId(req)]);
        await auditLog(req.admin.username, req.origin, `Added ${type} attribute to profile ${profile}`, 'success', `${attribute}=${value}`, req.ip, req.tenantScope);
        res.json({ success: true });
    });

    app.post('/api/profiles/nas', requireApiAuth('users', 'read-write'), async (req, res) => {
        const { profile, nas_id } = req.body;
        const nasScope = profileScope(req);
        const [nas] = await pool.query('SELECT nasname FROM nas WHERE id = ?' + nasScope.sql, [nas_id, ...nasScope.params]);
        if (!nas.length) return res.status(404).json({ error: 'NAS not found' });
        if (!await profileExists(pool, req, profile) && tenant(req).enabled) {
            const [global] = await pool.query('SELECT 1 FROM radgroupcheck WHERE groupname = ? LIMIT 1', [profile]);
            if (global.length) return profileNotFound(res);
        }
        const ip = nas[0].nasname.split('/')[0];
        await pool.query(`INSERT INTO radgroupcheck (groupname, attribute, op, value, tenant_id) VALUES (?, 'NAS-IP-Address', '+=', ?, ?)`, [profile, ip, selectedTenantId(req)]);
        await auditLog(req.admin.username, req.origin, `Added NAS-IP-Address check to profile ${profile}`, 'success', `NAS: ${ip}`, req.ip, req.tenantScope);
        res.json({ success: true });
    });

    app.get('/api/profiles/data', requireApiAuth('users', 'read-only'), async (req, res) => {
        const scoped = profileScope(req);
        const [checks] = await pool.query('SELECT * FROM radgroupcheck WHERE 1=1' + scoped.sql, scoped.params);
        const [replies] = await pool.query('SELECT * FROM radgroupreply WHERE 1=1' + scoped.sql, scoped.params);
        const [userCounts] = await pool.query('SELECT groupname, COUNT(*) AS users FROM radusergroup WHERE 1=1' + scoped.sql + ' GROUP BY groupname', scoped.params);
        res.json({ checks, replies, userCounts });
    });

    app.post('/api/profiles/:name', requireApiAuth('users', 'read-write'), async (req, res) => {
        const { name } = req.params;
        let { nas_ips = [], vlan_id = '', reply_attributes = [] } = req.body;
        if (!name || typeof name !== 'string' || name.trim() === '') return res.status(400).json({ error: 'Profile name is required' });
        nas_ips = Array.isArray(nas_ips) ? nas_ips.filter(ip => typeof ip === 'string' && ip.trim() !== '') : [];
        vlan_id = typeof vlan_id === 'string' ? vlan_id.trim() : '';
        reply_attributes = Array.isArray(reply_attributes) ? reply_attributes : [];
        const conn = await pool.getConnection();
        const scoped = profileScope(req);
        try {
            await conn.beginTransaction();
            if (!await profileExists(conn, req, name) && tenant(req).enabled) {
                const [global] = await conn.query(`SELECT 1 FROM (
                    SELECT groupname FROM radgroupcheck WHERE groupname = ?
                    UNION SELECT groupname FROM radgroupreply WHERE groupname = ?
                    UNION SELECT groupname FROM radusergroup WHERE groupname = ?
                ) profiles LIMIT 1`, [name, name, name]);
                if (global.length) { await conn.rollback(); return profileNotFound(res); }
            }
            await conn.query('DELETE FROM radgroupcheck WHERE groupname = ?' + scoped.sql, [name, ...scoped.params]);
            await conn.query('DELETE FROM radgroupreply WHERE groupname = ?' + scoped.sql, [name, ...scoped.params]);
            const tenantId = selectedTenantId(req);
            for (const ip of nas_ips) await conn.query(`INSERT INTO radgroupcheck (groupname, attribute, op, value, tenant_id) VALUES (?, 'NAS-IP-Address', '+=', ?, ?)`, [name, ip, tenantId]);
            if (vlan_id !== '') await conn.query(`INSERT INTO radgroupreply (groupname, attribute, op, value, tenant_id) VALUES
                (?, 'Tunnel-Type', '=', 'VLAN', ?), (?, 'Tunnel-Medium-Type', '=', 'IEEE-802', ?), (?, 'Tunnel-Private-Group-ID', '=', ?, ?)`, [name, tenantId, name, tenantId, name, vlan_id, tenantId]);
            const validReplyAttributes = reply_attributes.map(attr => ({ attribute: (attr.attribute || '').toString().trim(), value: (attr.value || '').toString().trim() })).filter(attr => attr.attribute && attr.value);
            const installed = await installedReplyAttributes(conn, req);
            if (validReplyAttributes.some(attr => !installed.has(attr.attribute))) throw new Error('Profile reply attribute is not installed in the FreeRADIUS dictionary');
            for (const attr of validReplyAttributes) await conn.query(`INSERT INTO radgroupreply (groupname, attribute, op, value, tenant_id) VALUES (?, ?, '=', ?, ?)`, [name, attr.attribute, attr.value, tenantId]);
            const addedDefaultReply = nas_ips.length === 0 && vlan_id === '' && validReplyAttributes.length === 0;
            if (addedDefaultReply) await conn.query(`INSERT INTO radgroupreply (groupname, attribute, op, value, tenant_id) VALUES (?, 'Reply-Message', '=', ?, ?)`, [name, `Assigned to ${name} profile`, tenantId]);
            await conn.commit();
            await auditLog(req.admin.username, req.origin, `Saved profile: ${name}`, 'success', `NAS: ${nas_ips.length}, VLAN: ${vlan_id || 'none'}, Attributes: ${validReplyAttributes.length + (addedDefaultReply ? 1 : 0)}`, req.ip, req.tenantScope);
            res.json({ success: true });
        } catch (err) {
            await conn.rollback(); console.error('Profile save error:', err); res.status(500).json({ error: err.message || 'Failed to save profile' });
        } finally { conn.release(); }
    });

    app.get('/api/profiles/:name', requireApiAuth('users', 'read-only'), async (req, res) => {
        const { name } = req.params;
        if (!await profileExists(pool, req, name)) return profileNotFound(res);
        const memberScope = profileScope(req, 'u.tenant_id');
        const joins = tenant(req).enabled ? ' AND up.tenant_id = ? AND p.tenant_id = ? AND m.tenant_id = ?' : '';
        const joinParams = tenant(req).enabled ? [req.tenantScope.tenantId, req.tenantScope.tenantId, req.tenantScope.tenantId] : [];
        try {
            const [members] = await pool.query(`SELECT u.username AS real_username, COALESCE(m.mac_id, u.username) AS username,
                CASE WHEN m.mac_address IS NOT NULL THEN 'mac' ELSE 'user' END AS object_type, u.groupname AS profile, up.plan_id, p.name AS plan_name,
                COALESCE(acct.sessions_30d, 0) AS sessions_30d, COALESCE(acct.data_30d, 0) AS data_30d, COALESCE(acct.time_30d, 0) AS time_30d, COALESCE(acct.last_seen, NULL) AS last_seen,
                COALESCE(auth.auth_count_30d, 0) AS auth_count_30d, COALESCE(auth.accept_count_30d, 0) AS accept_count_30d, COALESCE(auth.reject_count_30d, 0) AS reject_count_30d, COALESCE(auth.last_auth_at, NULL) AS last_auth_at, COALESCE(auth.last_reply, NULL) AS last_reply
                FROM radusergroup u LEFT JOIN mac_auth_devices m ON m.mac_address = u.username${tenant(req).enabled ? ' AND m.tenant_id = ?' : ''}
                LEFT JOIN user_plans up ON up.username = u.username${tenant(req).enabled ? ' AND up.tenant_id = ?' : ''}
                LEFT JOIN plans p ON p.id = up.plan_id${tenant(req).enabled ? ' AND p.tenant_id = ?' : ''}
                LEFT JOIN (SELECT username, COUNT(*) AS sessions_30d, SUM(acctinputoctets + acctoutputoctets) AS data_30d, SUM(acctsessiontime) AS time_30d, MAX(COALESCE(acctupdatetime, acctstarttime, acctstoptime)) AS last_seen FROM radacct WHERE acctstarttime >= DATE_SUB(NOW(), INTERVAL 30 DAY) GROUP BY username) acct ON acct.username = u.username
                LEFT JOIN (SELECT p1.username, COUNT(*) AS auth_count_30d, SUM(CASE WHEN p1.reply = 'Access-Accept' THEN 1 ELSE 0 END) AS accept_count_30d, SUM(CASE WHEN p1.reply = 'Access-Reject' THEN 1 ELSE 0 END) AS reject_count_30d, MAX(p1.authdate) AS last_auth_at, SUBSTRING_INDEX(GROUP_CONCAT(p1.reply ORDER BY p1.authdate DESC SEPARATOR ','), ',', 1) AS last_reply FROM radpostauth p1 WHERE p1.authdate >= DATE_SUB(NOW(), INTERVAL 30 DAY) GROUP BY p1.username) auth ON auth.username = u.username
                WHERE u.groupname = ?${memberScope.sql} ORDER BY object_type ASC, username ASC`, [...joinParams, name, ...memberScope.params]);
            const summary = members.reduce((acc, row) => { acc.total_objects++; if (row.object_type === 'user') acc.total_users++; if (row.object_type === 'mac') acc.total_macs++; acc.total_sessions_30d += Number(row.sessions_30d || 0); acc.total_data_30d += Number(row.data_30d || 0); acc.total_time_30d += Number(row.time_30d || 0); acc.total_auth_count_30d += Number(row.auth_count_30d || 0); acc.total_accept_count_30d += Number(row.accept_count_30d || 0); acc.total_reject_count_30d += Number(row.reject_count_30d || 0); return acc; }, { total_objects: 0, total_users: 0, total_macs: 0, total_sessions_30d: 0, total_data_30d: 0, total_time_30d: 0, total_auth_count_30d: 0, total_accept_count_30d: 0, total_reject_count_30d: 0 });
            res.json({ profile: name, summary, members });
        } catch (err) { console.error('GET /api/profiles/:name error:', err); res.status(500).json({ error: err.message }); }
    });

    app.put('/api/profiles/:name', requireApiAuth('users', 'read-write'), (req, res) => { req.method = 'POST'; return app._router.handle(req, res); });
    app.delete('/api/profiles/:name', requireApiAuth('users', 'read-write'), async (req, res) => {
        const { name } = req.params;
        if (!await profileExists(pool, req, name)) return profileNotFound(res);
        const conn = await pool.getConnection(); const scoped = profileScope(req);
        try {
            await conn.beginTransaction();
            await conn.query('DELETE FROM radgroupcheck WHERE groupname = ?' + scoped.sql, [name, ...scoped.params]);
            await conn.query('DELETE FROM radgroupreply WHERE groupname = ?' + scoped.sql, [name, ...scoped.params]);
            await conn.query('DELETE FROM radusergroup WHERE groupname = ?' + scoped.sql, [name, ...scoped.params]);
            await conn.commit(); await auditLog(req.admin.username, req.origin, `Deleted profile: ${name}`, 'success', '', req.ip, req.tenantScope); res.json({ success: true });
        } catch (err) { await conn.rollback(); console.error('Delete Profile Error:', err); res.status(500).json({ error: 'Failed to delete profile' }); } finally { conn.release(); }
    });
};
