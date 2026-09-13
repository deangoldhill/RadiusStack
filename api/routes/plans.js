module.exports = function(app, pool, requireApiAuth, auditLog) {
    const { scope } = require('../tenant');
    const selectedTenantId = req => req.tenantScope.enabled ? req.tenantScope.tenantId : null;
    const planScope = (req, column = 'tenant_id') => req.tenantScope.enabled ? scope(req.tenantScope, column) : { sql: ` AND ${column} IS NULL`, params: [] };
    const planNotFound = res => res.status(404).json({ error: 'Plan not found in selected tenant' });

    async function findPlan(db, req, id) {
        const scoped = planScope(req);
        const [rows] = await db.query('SELECT * FROM plans WHERE id = ?' + scoped.sql, [id, ...scoped.params]);
        return rows[0] || null;
    }

    app.get('/api/plans/:id/stats', requireApiAuth('plans', 'read-only'), async (req, res) => {
        try {
            const plan = await findPlan(pool, req, req.params.id);
            if (!plan) return planNotFound(res);
            const assignmentScope = planScope(req, 'up.tenant_id');
            const usageJoin = req.tenantScope.enabled ? ' AND pu.tenant_id = ?' : '';
            const macJoin = req.tenantScope.enabled ? ' AND m.tenant_id = ?' : '';
            const joinParams = req.tenantScope.enabled ? [req.tenantScope.tenantId, req.tenantScope.tenantId] : [];
            const [users] = await pool.query(`SELECT COALESCE(m.mac_id, up.username) AS username,
                COALESCE((SELECT SUM(acctinputoctets) + SUM(acctoutputoctets) FROM radacct WHERE username = up.username), 0) - COALESCE(pu.base_input_octets, 0) - COALESCE(pu.base_output_octets, 0) AS total_bytes,
                COALESCE((SELECT SUM(acctsessiontime) FROM radacct WHERE username = up.username), 0) - COALESCE(pu.base_session_seconds, 0) AS total_seconds
                FROM user_plans up
                LEFT JOIN user_plan_usage pu ON pu.username = up.username${usageJoin}
                LEFT JOIN mac_auth_devices m ON m.mac_address = up.username${macJoin}
                WHERE up.plan_id = ?${assignmentScope.sql}`, [...joinParams, req.params.id, ...assignmentScope.params]);
            let depletedCount = 0; let total_bytes_all = 0; let total_seconds_all = 0;
            const topUsers = users.map(u => {
                const total_mb = Math.max(0, u.total_bytes / (1024 * 1024)); const total_sec = Math.max(0, u.total_seconds);
                total_bytes_all += Math.max(0, u.total_bytes); total_seconds_all += total_sec;
                let depletionReason = null;
                if (plan.data_limit_mb > 0 && total_mb >= plan.data_limit_mb) depletionReason = 'Data';
                if (plan.time_limit_seconds > 0 && total_sec >= plan.time_limit_seconds) depletionReason = 'Time';
                if (depletionReason) depletedCount++;
                return { username: u.username, data_used_mb: parseFloat(total_mb).toFixed(2), time_used_sec: parseInt(total_sec), status: depletionReason ? 'Depleted' : 'Active', depletionReason };
            });
            topUsers.sort((a, b) => b.data_used_mb - a.data_used_mb);
            res.json({ plan, total_users: users.length, depleted_users: depletedCount, active_users: users.length - depletedCount, total_data_gb: (total_bytes_all / (1024 * 1024 * 1024)).toFixed(2), total_hours: (total_seconds_all / 3600).toFixed(1), top_users: topUsers.slice(0, 10) });
        } catch (e) { console.error('Plan stats error', e); res.status(500).json({ error: e.message }); }
    });

    app.get('/api/plans', requireApiAuth('plans', 'read-only'), async (req, res) => {
        const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 0, 0), 1000);
        const scoped = planScope(req);
        const sql = 'SELECT * FROM plans WHERE 1=1' + scoped.sql + ' ORDER BY id DESC' + (limit ? ' LIMIT ?' : '');
        const [rows] = await pool.query(sql, limit ? [...scoped.params, limit] : scoped.params);
        res.json(rows);
    });

    app.post('/api/plans', requireApiAuth('plans', 'read-write'), async (req, res) => {
        const { name, data_limit_mb, time_limit_seconds, reset_period } = req.body;
        try {
            await pool.query('INSERT INTO plans (name, data_limit_mb, time_limit_seconds, reset_period, tenant_id) VALUES (?, ?, ?, ?, ?)', [name, data_limit_mb || 0, time_limit_seconds || 0, reset_period || 'never', selectedTenantId(req)]);
            await auditLog(req.admin.username, req.origin, `Created plan: ${name}`, 'success', '', req.ip, req.tenantScope); res.json({ success: true });
        } catch (err) { res.status(500).json({ error: err.message }); }
    });

    app.put('/api/plans/:id', requireApiAuth('plans', 'read-write'), async (req, res) => {
        const { id } = req.params; const { name, data_limit_mb, time_limit_seconds, reset_period } = req.body; const scoped = planScope(req);
        try {
            const [result] = await pool.query('UPDATE plans SET name=?, data_limit_mb=?, time_limit_seconds=?, reset_period=? WHERE id=?' + scoped.sql, [name, data_limit_mb || 0, time_limit_seconds || 0, reset_period || 'never', id, ...scoped.params]);
            if (!result.affectedRows) return planNotFound(res);
            await auditLog(req.admin.username, req.origin, `Updated plan ID: ${id}`, 'success', '', req.ip, req.tenantScope); res.json({ success: true });
        } catch (err) { res.status(500).json({ error: err.message }); }
    });

    app.delete('/api/plans/:id', requireApiAuth('plans', 'read-write'), async (req, res) => {
        const { id } = req.params; const conn = await pool.getConnection(); const scopedPlans = planScope(req); const scopedAssignments = planScope(req, 'up.tenant_id');
        try {
            await conn.beginTransaction();
            if (!await findPlan(conn, req, id)) { await conn.rollback(); return planNotFound(res); }
            const usageScope = req.tenantScope.enabled ? ' AND pu.tenant_id = ?' : '';
            const usageParams = req.tenantScope.enabled ? [req.tenantScope.tenantId] : [];
            await conn.query(`DELETE pu FROM user_plan_usage pu INNER JOIN user_plans up ON up.username = pu.username${req.tenantScope.enabled ? ' AND up.tenant_id = ?' : ''} WHERE up.plan_id = ?${scopedAssignments.sql}${usageScope}`, [...(req.tenantScope.enabled ? [req.tenantScope.tenantId] : []), id, ...scopedAssignments.params, ...usageParams]);
            const [result] = await conn.query('DELETE FROM plans WHERE id = ?' + scopedPlans.sql, [id, ...scopedPlans.params]);
            if (!result.affectedRows) { await conn.rollback(); return planNotFound(res); }
            await conn.commit(); await auditLog(req.admin.username, req.origin, `Deleted plan ID: ${id}`, 'success', '', req.ip, req.tenantScope); res.json({ success: true });
        } catch (err) { await conn.rollback(); res.status(500).json({ error: err.message }); } finally { conn.release(); }
    });
};
