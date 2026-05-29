module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

// --- AUDIT LOG API ---
app.get('/api/audit', requireApiAuth('admins', 'read-only'), async (req, res) => {
    const { search, result, start_date, end_date, limit = 100 } = req.query;
    let query = 'SELECT * FROM admin_audit_log WHERE 1=1';
    const params = [];

    if (search) {
        query += ' AND (admin_username LIKE ? OR action LIKE ? OR details LIKE ?)';
        params.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    if (result) {
        query += ' AND result = ?';
        params.push(result);
    }
    if (start_date) {
        query += ' AND timestamp >= ?';
        params.push(start_date);
    }
    if (end_date) {
        query += ' AND timestamp <= ?';
        params.push(end_date);
    }

    query += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(parseInt(limit));

    const [rows] = await pool.query(query, params);
    res.json(rows);
});

app.delete('/api/logs/auth', requireApiAuth('reports', 'read-write'), async (req, res) => {
    try {
        const { username, nasip, callingstationid, date_from, date_to, reply } = req.query;
        let query = 'DELETE p FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address = p.username';
        const conditions = [], params = [];
        if (username) { conditions.push('(p.username = ? OR m.mac_id = ?)'); params.push(username, username); }
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



};
