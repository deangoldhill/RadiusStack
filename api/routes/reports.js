module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { scope } = require('../tenant');
    // Global reporting is read-only observability across every tenant.
    function reportScope(req, column = 'tenant_id') {
        return req.tenantScope.enabled ? scope(req.tenantScope, column) : { sql: '', params: [] };
    }
    const { buildDynamicAuthorizationRequest, sendDynamicAuthorization } = require('../dynamic_auth');
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, puppeteer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusCredential, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily, signTotpEnrollmentToken, verifyTotpEnrollmentToken } = dependencies;


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

    const scoped = scope(req.tenantScope, 'tenant_id');
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
        WHERE acctstoptime IS NULL${scoped.sql}
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
    const [rows] = await pool.query(query, [...scoped.params, thresholdDays, interimThresholdMinutes]);
    res.json(rows);
});

app.post('/api/sessions/clear', requireApiAuth('reports', 'read-write'), async (req, res) => {
    const { sessionIds } = req.body;
    if (!sessionIds || !sessionIds.length) return res.status(400).json({ error: 'No sessions provided' });

    const placeholders = sessionIds.map(() => '?').join(',');
    const scoped = scope(req.tenantScope, 'tenant_id');
    await pool.query(`UPDATE radacct SET acctstoptime = NOW() WHERE radacctid IN (${placeholders})${scoped.sql}`, [...sessionIds, ...scoped.params]);
    await auditLog(req.admin.username, req.origin, `Cleared ${sessionIds.length} stale sessions`, 'success', '', req.ip, req.tenantScope);
    res.json({ success: true });
});
app.get('/api/sessions/active', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const { username, nasip, callingstationid, framedip } = req.query; const paginated=req.query.page !== undefined;
    const page=Math.max(1,parseInt(req.query.page,10)||1); const pageSize=[25,50,100].includes(parseInt(req.query.page_size,10))?parseInt(req.query.page_size,10):25;
    const scoped = scope(req.tenantScope, 'a.tenant_id');
    const conditions=['a.acctstoptime IS NULL' + scoped.sql], params=[...scoped.params];
    if(username){conditions.push('(a.username LIKE ? OR m.mac_id LIKE ?)');params.push('%'+username+'%','%'+username+'%');} if(nasip){conditions.push('a.nasipaddress = ?');params.push(nasip);} if(callingstationid){conditions.push('a.callingstationid LIKE ?');params.push('%'+callingstationid+'%');} if(framedip){conditions.push('a.framedipaddress LIKE ?');params.push('%'+framedip+'%');}
    const from=' FROM radacct a LEFT JOIN mac_auth_devices m ON m.mac_address=a.username WHERE '+conditions.join(' AND ');
    if(!paginated){const limit=Math.min(parseInt(req.query.limit,10)||200,1000);const [rows]=await pool.query('SELECT a.*,COALESCE(m.mac_id,a.username) AS username'+from+' ORDER BY a.acctstarttime DESC LIMIT ?',[...params,limit]);return res.json(rows);}
    const [[count]]=await pool.query('SELECT COUNT(*) AS total'+from,params);const total=Number(count.total),safePage=Math.min(page,Math.max(1,Math.ceil(total/pageSize)));const [rows]=await pool.query('SELECT a.*,COALESCE(m.mac_id,a.username) AS username'+from+' ORDER BY a.acctstarttime DESC LIMIT ? OFFSET ?',[...params,pageSize,(safePage-1)*pageSize]);res.json({items:rows,total,page:safePage,pageSize,totalPages:Math.max(1,Math.ceil(total/pageSize))});
});

app.post('/api/sessions/:sessionId/dynamic-auth', requireApiAuth('reports', 'read-write'), async (req, res) => {
    const sessionId = Number(req.params.sessionId);
    const kind = req.body && req.body.kind;
    if (!Number.isSafeInteger(sessionId) || sessionId < 1 || !['coa', 'pod'].includes(kind)) return res.status(400).json({ error: 'Invalid dynamic authorization request' });
    const dynamicScope = scope(req.tenantScope, 'a.tenant_id');
    try {
        const [sessions] = await pool.query(`SELECT a.radacctid,a.username,a.acctsessionid,a.nasipaddress,a.nasidentifier,a.callingstationid,a.framedipaddress,a.tenant_id,n.secret,n.dynamic_auth_attributes FROM radacct a INNER JOIN nas n ON n.nasname=a.nasipaddress AND n.tenant_id <=> a.tenant_id WHERE a.radacctid=? AND a.acctstoptime IS NULL${dynamicScope.sql}`, [sessionId, ...dynamicScope.params]);
        const session = sessions[0];
        if (!session) return res.status(404).json({ error: 'Active session not found in the selected tenant' });
        let replyAttributes = [];
        if (kind === 'coa') {
            const [profiles] = await pool.query('SELECT groupname FROM radusergroup WHERE username=? AND tenant_id <=> ? ORDER BY priority ASC LIMIT 1', [session.username, session.tenant_id]);
            if (!profiles[0]) return res.status(409).json({ error: 'The active session has no current profile to reauthorize' });
            const [rows] = await pool.query('SELECT attribute,value FROM radgroupreply WHERE groupname=? AND tenant_id <=> ? ORDER BY id ASC', [profiles[0].groupname, session.tenant_id]);
            replyAttributes = rows;
        }
        let config; try { config=JSON.parse(session.dynamic_auth_attributes || 'null') || {}; } catch { return res.status(500).json({error:'Invalid NAS dynamic authorization configuration'}); }
        const packetAttributes = kind === 'coa' ? config.coa_attributes : config.pod_attributes;
        const request = buildDynamicAuthorizationRequest({ kind, session, replyAttributes, packetAttributes });
        const result = await sendDynamicAuthorization({ request, secret: session.secret, host: session.nasipaddress });
        const action = kind === 'coa' ? 'CoA profile reauthorization' : 'PoD session disconnect';
        const details = `session=${session.radacctid}; attributes=${kind === 'coa' ? replyAttributes.map(row => row.attribute).join(',') : 'none'}`;
        await auditLog(req.admin.username, req.origin, action, result.acknowledged ? 'success' : 'failed', details, req.ip, req.tenantScope);
        if (!result.acknowledged) return res.status(409).json({ error: 'NAS rejected the dynamic authorization request' });
        res.json({ success: true, action: kind, response: kind === 'coa' ? 'CoA-ACK' : 'Disconnect-ACK' });
    } catch (err) {
        console.error('[dynamic authorization]', err.message);
        await auditLog(req.admin.username, req.origin, kind === 'coa' ? 'CoA profile reauthorization' : 'PoD session disconnect', 'failed', `session=${sessionId}; ${err.message}`, req.ip, req.tenantScope);
        res.status(502).json({ error: 'Dynamic authorization request failed' });
    }
});

app.get('/api/logs/auth', requireApiAuth('reports', 'read-only'), async (req, res) => {
 const {username,nasip,callingstationid,date_from,date_to,reply}=req.query,paginated=req.query.page!==undefined;const page=Math.max(1,parseInt(req.query.page,10)||1),pageSize=[25,50,100].includes(parseInt(req.query.page_size,10))?parseInt(req.query.page_size,10):25;const scoped=reportScope(req,'p.tenant_id');let where='';const params=[...scoped.params];
 const c=[scoped.sql.slice(5)].filter(Boolean);if(username){c.push('(p.username LIKE ? OR m.mac_id LIKE ?)');params.push('%'+username+'%','%'+username+'%');}if(nasip){c.push('p.nasipaddress=?');params.push(nasip);}if(callingstationid){c.push('p.callingstationid LIKE ?');params.push('%'+callingstationid+'%');}if(date_from){c.push('p.authdate>=?');params.push(new Date(date_from).toISOString().slice(0,19).replace('T',' '));}if(date_to){c.push('p.authdate<=?');params.push(new Date(date_to).toISOString().slice(0,19).replace('T',' '));}if(reply){c.push('p.reply=?');params.push(reply);}if(c.length)where=' WHERE '+c.join(' AND ');
 const from=' FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address=p.username AND m.tenant_id <=> p.tenant_id LEFT JOIN tenants t ON t.id=p.tenant_id'+where,select="SELECT p.*,COALESCE(m.mac_id,p.username) AS username,COALESCE(t.name, 'Default') AS tenant_name";if(!paginated){const limit=Math.min(Math.max(parseInt(req.query.limit,10)||100,1),10000);const [rows]=await pool.query(select+from+' ORDER BY authdate DESC LIMIT ?',[...params,limit]);return res.json(rows);}const [[count]]=await pool.query('SELECT COUNT(*) AS total'+from,params);const total=Number(count.total),safePage=Math.min(page,Math.max(1,Math.ceil(total/pageSize)));const [rows]=await pool.query(select+from+' ORDER BY authdate DESC LIMIT ? OFFSET ?',[...params,pageSize,(safePage-1)*pageSize]);res.json({items:rows,total,page:safePage,pageSize,totalPages:Math.max(1,Math.ceil(total/pageSize))});
});

app.delete('/api/logs/auth', requireApiAuth('reports', 'read-write'), async (req, res) => {
    try {
        const { username, nasip, callingstationid, date_from, date_to, reply } = req.query;
        const scoped = scope(req.tenantScope, 'p.tenant_id');
        let query = 'DELETE p FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address = p.username' + (req.tenantScope.enabled ? ' AND m.tenant_id = ?' : '');
        const conditions = req.tenantScope.enabled ? [scoped.sql.slice(5)] : []; const params = [...(req.tenantScope.enabled ? [req.tenantScope.tenantId] : []), ...scoped.params];
        if (username) { conditions.push('(p.username LIKE ? OR m.mac_id LIKE ?)'); params.push('%' + username + '%', '%' + username + '%'); }
        if (nasip) { conditions.push('p.nasipaddress = ?'); params.push(nasip); }
        if (callingstationid) { conditions.push('p.callingstationid LIKE ?'); params.push('%' + callingstationid + '%'); }
        if (date_from) { conditions.push('p.authdate >= ?'); params.push(new Date(date_from).toISOString().slice(0, 19).replace('T', ' ')); }
        if (date_to) { conditions.push('p.authdate <= ?'); params.push(new Date(date_to).toISOString().slice(0, 19).replace('T', ' ')); }
        if (reply) { conditions.push('p.reply = ?'); params.push(reply); }
        if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
        const [result] = await pool.query(query, params);
        await auditLog(req.admin.username, req.origin, `Deleted ${result.affectedRows} auth log entries`, 'success', JSON.stringify(req.query), req.ip, req.tenantScope);
        res.json({ deleted: result.affectedRows });
    } catch (err) {
        console.error('DELETE /api/logs/auth error:', err);
        res.status(500).json({ error: err.message });
    }
});


app.get('/api/reports/live-stats', requireApiAuth('reports', 'read-only'), async (req, res) => {
    try {
        const aScope = reportScope(req, 'a.tenant_id');
        const pScope = reportScope(req, 'p.tenant_id');
        const [[{ active_sessions }]] = await pool.query(`SELECT COUNT(*) AS active_sessions FROM radacct a WHERE a.acctstoptime IS NULL${aScope.sql}`, aScope.params);
        const [[{ avg_session_min }]] = await pool.query(`SELECT ROUND(AVG(a.acctsessiontime)/60,1) AS avg_session_min FROM radacct a WHERE a.acctstoptime IS NOT NULL AND a.acctstarttime >= DATE_SUB(NOW(), INTERVAL 24 HOUR)${aScope.sql}`, aScope.params);
        const [nas_breakdown] = await pool.query(`SELECT a.nasipaddress, COUNT(*) AS session_count FROM radacct a WHERE a.acctstoptime IS NULL${aScope.sql} GROUP BY a.nasipaddress ORDER BY session_count DESC LIMIT 8`, aScope.params);
        const [[{ unique_users_24h }]] = await pool.query(`SELECT COUNT(DISTINCT p.username) AS unique_users_24h FROM radpostauth p WHERE p.authdate >= DATE_SUB(NOW(), INTERVAL 24 HOUR)${pScope.sql}`, pScope.params);

        let accepts_1h = 0;
        let rejects_1h = 0;
        let accepts_24h = 0;
        let rejects_24h = 0;
        let hourly_trend = [];

        try { throw new Error('Use tenant-scoped post-auth totals');
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

            const [[a1h]] = await pool.query(`SELECT COUNT(*) AS cnt FROM radpostauth p WHERE p.reply = 'Access-Accept' AND p.authdate >= DATE_SUB(NOW(), INTERVAL 1 HOUR)${pScope.sql}`, pScope.params);
            const [[r1h]] = await pool.query(`SELECT COUNT(*) AS cnt FROM radpostauth p WHERE p.reply = 'Access-Reject' AND p.authdate >= DATE_SUB(NOW(), INTERVAL 1 HOUR)${pScope.sql}`, pScope.params);
            const [[a24h]] = await pool.query(`SELECT COUNT(*) AS cnt FROM radpostauth p WHERE p.reply = 'Access-Accept' AND p.authdate >= DATE_SUB(NOW(), INTERVAL 24 HOUR)${pScope.sql}`, pScope.params);
            const [[r24h]] = await pool.query(`SELECT COUNT(*) AS cnt FROM radpostauth p WHERE p.reply = 'Access-Reject' AND p.authdate >= DATE_SUB(NOW(), INTERVAL 24 HOUR)${pScope.sql}`, pScope.params);
            const [fallbackTrend] = await pool.query(`SELECT DATE_FORMAT(p.authdate,'%H:00') AS hour_label, SUM(p.reply='Access-Accept') AS accepts, SUM(p.reply='Access-Reject') AS rejects FROM radpostauth p WHERE p.authdate >= DATE_SUB(NOW(), INTERVAL 24 HOUR)${pScope.sql} GROUP BY DATE_FORMAT(p.authdate,'%Y-%m-%d %H:00:00') ORDER BY MIN(p.authdate)`, pScope.params);

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

app.get('/api/reports/user/:username', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const { username } = req.params;
    const { start_date, end_date } = req.query;

    const cScope = scope(req.tenantScope, 'c.tenant_id');
    const macScope = scope(req.tenantScope, 'm.tenant_id');
    const [macMapping] = await pool.query(`SELECT m.mac_address FROM mac_auth_devices m WHERE (m.mac_id = ? OR m.mac_address = ?)${macScope.sql} LIMIT 1`, [username, username, ...macScope.params]);
    const realUsername = macMapping.length > 0 ? macMapping[0].mac_address : username;
    const [[ownedUser]] = await pool.query(`SELECT 1 FROM radcheck c WHERE c.username = ?${cScope.sql} LIMIT 1`, [realUsername, ...cScope.params]);
    if (!ownedUser) return res.status(404).json({ error: 'User not found in selected tenant' });

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

app.get('/api/reports/failed-auth', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const pScope = scope(req.tenantScope, 'p.tenant_id');
    const from = ` FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address=p.username AND m.tenant_id <=> p.tenant_id WHERE p.reply='Access-Reject'${pScope.sql}`;
    const [details] = await pool.query(`SELECT p.*, COALESCE(m.mac_id,p.username) AS username${from} ORDER BY p.authdate DESC LIMIT 500`, pScope.params);
    const [summary] = await pool.query(`SELECT COALESCE(m.mac_id,p.username) AS username, COUNT(*) AS fail_count${from} GROUP BY COALESCE(m.mac_id,p.username) ORDER BY fail_count DESC`, pScope.params);
    res.json({ details, summary });
});

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
        const aScope = reportScope(req, 'a.tenant_id');
        const from = ` FROM radacct a LEFT JOIN mac_auth_devices m ON m.mac_address=a.username AND m.tenant_id <=> a.tenant_id WHERE a.acctstarttime >= DATE_SUB(NOW(), INTERVAL 7 DAY)${aScope.sql}`;
        const [topSessions] = await pool.query(`SELECT COALESCE(m.mac_id,a.username) AS username, COUNT(*) AS session_count, SUM(a.acctinputoctets+a.acctoutputoctets)/1.073741824e+09 AS data_gb${from} GROUP BY COALESCE(m.mac_id,a.username) ORDER BY session_count DESC LIMIT 20`, aScope.params);
        const [topData] = await pool.query(`SELECT COALESCE(m.mac_id,a.username) AS username, SUM(a.acctinputoctets+a.acctoutputoctets)/1048576 AS data_mb${from} GROUP BY COALESCE(m.mac_id,a.username) ORDER BY data_mb DESC LIMIT 20`, aScope.params);
        res.json({ topSessions, topData });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/reports/dashboard-overview', requireApiAuth('reports', 'read-only'), async (req, res) => {
    try {
        const c = reportScope(req, 'c.tenant_id');
        const m = reportScope(req, 'm.tenant_id');
        const n = reportScope(req, 'n.tenant_id');
        const plan = reportScope(req, 'p.tenant_id');
        const a = reportScope(req, 'a.tenant_id');
        const post = reportScope(req, 'p.tenant_id');
        const g = reportScope(req, 'g.tenant_id');

        const [[users]] = await pool.query(`SELECT COUNT(DISTINCT c.username) AS cnt FROM radcheck c WHERE 1=1${c.sql} AND NOT EXISTS (SELECT 1 FROM mac_auth_devices m WHERE m.mac_address=c.username AND m.tenant_id <=> c.tenant_id)`, c.params);
        const [[macs]] = await pool.query(`SELECT COUNT(*) AS cnt FROM mac_auth_devices m WHERE 1=1${m.sql}`, m.params);
        const [[nas]] = await pool.query(`SELECT COUNT(*) AS cnt FROM nas n WHERE 1=1${n.sql}`, n.params);
        const [[plans]] = await pool.query(`SELECT COUNT(*) AS cnt FROM plans p WHERE 1=1${plan.sql}`, plan.params);
        const [[activeSess]] = await pool.query(`SELECT COUNT(*) AS cnt FROM radacct a WHERE a.acctstoptime IS NULL${a.sql}`, a.params);
        const [[totalSess]] = await pool.query(`SELECT COUNT(*) AS cnt FROM radacct a WHERE 1=1${a.sql}`, a.params);
        const [[dataToday]] = await pool.query(`SELECT COALESCE(SUM(a.acctinputoctets+a.acctoutputoctets),0) AS bytes FROM radacct a WHERE DATE(a.acctstarttime)=CURDATE()${a.sql}`, a.params);
        const [[dataWeek]] = await pool.query(`SELECT COALESCE(SUM(a.acctinputoctets+a.acctoutputoctets),0) AS bytes FROM radacct a WHERE a.acctstarttime >= DATE_SUB(NOW(),INTERVAL 7 DAY)${a.sql}`, a.params);
        const [recentAuths] = await pool.query(`SELECT p.reply, COALESCE(m.mac_id,p.username) AS username, p.nasipaddress, p.authdate FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address=p.username AND m.tenant_id <=> p.tenant_id WHERE 1=1${post.sql} ORDER BY p.authdate DESC LIMIT 8`, post.params);
        const [nasLoad] = await pool.query(`SELECT a.nasipaddress, COUNT(*) AS active FROM radacct a WHERE a.acctstoptime IS NULL${a.sql} GROUP BY a.nasipaddress ORDER BY active DESC LIMIT 6`, a.params);
        const [profileDist] = await pool.query(`SELECT g.groupname, COUNT(*) AS cnt FROM radusergroup g WHERE 1=1${g.sql} GROUP BY g.groupname ORDER BY cnt DESC LIMIT 8`, g.params);
        const [planDist] = await pool.query(`SELECT p.name, COUNT(up.plan_id) AS cnt FROM plans p LEFT JOIN user_plans up ON up.plan_id=p.id AND up.tenant_id <=> p.tenant_id WHERE 1=1${plan.sql} GROUP BY p.id, p.name ORDER BY cnt DESC LIMIT 8`, plan.params);
        const [[authToday]] = await pool.query(`SELECT COUNT(*) AS cnt, COALESCE(SUM(p.reply='Access-Reject'),0) AS rejects FROM radpostauth p WHERE p.authdate >= CURDATE()${post.sql}`, post.params);
        const [authTrend7d] = await pool.query(`SELECT DATE(p.authdate) AS day, SUM(p.reply='Access-Accept') AS accepts, SUM(p.reply='Access-Reject') AS rejects FROM radpostauth p WHERE p.authdate >= DATE_SUB(NOW(),INTERVAL 7 DAY)${post.sql} GROUP BY DATE(p.authdate) ORDER BY day ASC`, post.params);

        res.json({
            counts: { users:Number(users.cnt), macs:Number(macs.cnt), nas:Number(nas.cnt), plans:Number(plans.cnt), activeSessions:Number(activeSess.cnt), totalSessions:Number(totalSess.cnt), authToday:Number(authToday.cnt), rejectToday:Number(authToday.rejects) },
            data: { today:Number(dataToday.bytes), week:Number(dataWeek.bytes) },
            recentAuths, authTrend7d, nasLoad, profileDist, planDist
        });
    } catch (err) {
        console.error('[/api/reports/dashboard-overview]', err);
        res.status(500).json({ error: err.message });
    }
});



app.get('/api/accounting', requireApiAuth('reports', 'read-only'), async (req, res) => {
 const {username,nasip,start_date,end_date,sort='acctstarttime',order='desc'}=req.query;const paginated=req.query.page!==undefined;const page=Math.max(1,parseInt(req.query.page,10)||1);const pageSize=[25,50,100].includes(parseInt(req.query.page_size,10))?parseInt(req.query.page_size,10):25;
 const allowed=['acctstarttime','acctstoptime','username','nasipaddress','acctsessiontime','acctinputoctets','acctoutputoctets','total_data'];const field=allowed.includes(sort)?sort:'acctstarttime',direction=String(order).toLowerCase()==='asc'?'ASC':'DESC';const tenant=reportScope(req,'a.tenant_id');let where=' WHERE 1=1'+tenant.sql;const params=[...tenant.params];
 if(username){where+=' AND (a.username LIKE ? OR m.mac_id LIKE ?)';params.push('%'+username+'%','%'+username+'%');}if(nasip){where+=' AND a.nasipaddress=?';params.push(nasip);}if(start_date){where+=' AND a.acctstarttime>=?';params.push(start_date);}if(end_date){where+=' AND a.acctstarttime<=?';params.push(end_date+' 23:59:59');}
 const from=' FROM radacct a LEFT JOIN mac_auth_devices m ON m.mac_address=a.username AND m.tenant_id <=> a.tenant_id LEFT JOIN tenants t ON t.id=a.tenant_id'+where;const select="SELECT a.*,(a.acctinputoctets+a.acctoutputoctets) AS total_data,COALESCE(m.mac_id,a.username) AS username,COALESCE(t.name, 'Default') AS tenant_name";
 try {if(!paginated){const limit=Math.min(Math.max(parseInt(req.query.limit,10)||300,1),1000);const [rows]=await pool.query(select+from+` ORDER BY ${field} ${direction} LIMIT ?`,[...params,limit]);return res.json(rows);}const [[count]]=await pool.query('SELECT COUNT(*) AS total'+from,params);const total=Number(count.total),safePage=Math.min(page,Math.max(1,Math.ceil(total/pageSize)));const [rows]=await pool.query(select+from+` ORDER BY ${field} ${direction} LIMIT ? OFFSET ?`,[...params,pageSize,(safePage-1)*pageSize]);res.json({items:rows,total,page:safePage,pageSize,totalPages:Math.max(1,Math.ceil(total/pageSize))});}catch(err){console.error(err);res.status(500).json({error:'Failed to fetch accounting data'});}
});

app.delete('/api/accounting', requireApiAuth('reports', 'read-write'), async (req, res) => {
    const { username, nasip, start_date, end_date } = req.body;

    if (!username && !nasip && !start_date && !end_date) {
        return res.status(400).json({ error: 'At least one filter is required for safety' });
    }

    const tenant = scope(req.tenantScope, 'tenant_id');
    let query = 'DELETE FROM radacct WHERE 1=1' + tenant.sql;
    const params = [...tenant.params];

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
    const tenantId = req.tenantScope.enabled ? req.tenantScope.tenantId : null;
    if (!tenantId) return res.status(403).json({ error: 'Select a tenant for TOTP reset' });
    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();
        const [users] = await conn.query("SELECT tenant_id FROM radcheck WHERE username = ? AND attribute = 'Cleartext-Password' AND tenant_id = ? LIMIT 1", [username, tenantId]);
        if (!users.length) { await conn.rollback(); return res.status(404).json({ error: 'User not found in selected tenant' }); }
        const [existing] = await conn.query('SELECT tenant_id FROM user_totp WHERE username = ? LIMIT 1', [username]);
        if (existing.length && Number(existing[0].tenant_id) !== tenantId) { await conn.rollback(); return res.status(404).json({ error: 'User not found in selected tenant' }); }
        await conn.query(
            `INSERT INTO user_totp (username, enabled, secret, pending_secret, enrolled_at, tenant_id)
             VALUES (?, 1, NULL, NULL, NULL, ?)
             ON DUPLICATE KEY UPDATE enabled = 1, secret = NULL, pending_secret = NULL, enrolled_at = NULL`,
            [username, tenantId]
        );
        await syncUserTotpToRadius(conn, username, tenantId);

        const eData = await generateEnrollmentCode(conn, username, tenantId);
        const baseUrl = `${req.protocol}://${req.get('host')}`;
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
        const credential = await getRadiusCredential(username);
        if (!credential || credential.value !== password) {
            await auditLog(username, 'webui', 'User TOTP enrollment login', 'failed', 'Invalid RADIUS credentials', ip);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const [rows] = await pool.query(
            `SELECT username, enabled, secret, pending_secret, enrolled_at, enrollment_code_hash, enrollment_expires_at
             FROM user_totp WHERE username = ? AND tenant_id = ? LIMIT 1`, [username, credential.tenantId]
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
                `UPDATE user_totp SET pending_secret = ?, enrolled_at = NULL WHERE username = ? AND tenant_id = ?`,
                [secret, username, credential.tenantId]
            );
        }

        const otpauth = authenticator.keyuri(username, TOTP_ISSUER, secret);
        const qrImage = await qrcode.toDataURL(otpauth);
        const token = signTotpEnrollmentToken(username, credential.tenantId);

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
        const tenantId = decoded.tenantId;
        const [rows] = await pool.query(
            `SELECT username, enabled, secret, pending_secret FROM user_totp WHERE username = ? AND tenant_id = ? LIMIT 1`, [username, tenantId]
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
                `UPDATE user_totp SET secret = ?, pending_secret = NULL, enrollment_code_hash = NULL, enrolled_at = NOW() WHERE username = ? AND tenant_id = ?`, [secret, username, tenantId]
            );
            await syncUserTotpToRadius(conn, username, tenantId);
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
