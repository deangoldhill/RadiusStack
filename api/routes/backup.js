module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

// --- DATABASE BACKUP & RESTORE ---
app.get('/api/system/backup', requireApiAuth('settings', 'read-write'), async (req, res) => {
    const type = req.query.type || 'full';
    const include_accounting = req.query.acct === 'true' || type === 'full';
    const include_authlogs = req.query.auth === 'true' || type === 'full';
    const include_auditlogs = req.query.audit === 'true' || type === 'full';

    try {
        const safeQuery = async (q) => { try { const [r] = await pool.query(q); return r; } catch { return []; } };

        const admins = await safeQuery('SELECT * FROM admins');
        const nas = await safeQuery('SELECT * FROM nas');
        const plans = await safeQuery('SELECT * FROM plans');
        const radcheck = await safeQuery('SELECT * FROM radcheck');
        const radreply = await safeQuery('SELECT * FROM radreply');
        const radgroupcheck = await safeQuery('SELECT * FROM radgroupcheck');
        const radgroupreply = await safeQuery('SELECT * FROM radgroupreply');
        const radusergroup = await safeQuery('SELECT * FROM radusergroup');
        const mac_auth_devices = await safeQuery('SELECT * FROM mac_auth_devices');
        const user_plans = await safeQuery('SELECT * FROM user_plans');
        const user_plan_usage = await safeQuery('SELECT * FROM user_plan_usage');
        const settings = await safeQuery('SELECT * FROM settings');

        const macSet = new Set(mac_auth_devices.map(d => d.mac_address.toLowerCase()));
        const radcheck_users = radcheck.filter(r => !macSet.has(r.username.toLowerCase()));
        const radcheck_mac = radcheck.filter(r => macSet.has(r.username.toLowerCase()));

        const backup = {
            metadata: { type, timestamp: new Date().toISOString(), version: '1.1' },
            data: {
                admins,
                nas,
                plans,
                mac_auth_devices,
                radcheck_users,
                radcheck_mac,
                radreply,
                radgroupcheck,
                radgroupreply,
                user_plans,
                user_plan_usage,
                radusergroup,
                settings,
            }
        };

        if (include_accounting) {
            backup.data.radacct = await safeQuery('SELECT * FROM radacct');
        }
        if (include_authlogs) {
            backup.data.radpostauth = await safeQuery('SELECT * FROM radpostauth');
        }
        if (include_auditlogs) {
            backup.data.admin_audit_log = await safeQuery('SELECT * FROM admin_audit_log');
        }

        const filename = `radius_${type}_backup_${new Date().toISOString().slice(0, 10)}.json`;
        await auditLog(req.admin.username, req.origin, `Downloaded ${type} backup`, 'success', '', req.ip);
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.setHeader('Content-Type', 'application/json');
        res.send(JSON.stringify(backup, null, 2));

    } catch (err) {
        console.error('Backup error:', err.message, err.code, err.sql || '');
        res.status(500).json({ error: 'Backup failed: ' + err.message });
    }
});

// Helper: insert rows in chunks to avoid max_allowed_packet issues
async function chunkInsert(pool, table, rows, chunkSize = 100) {
    if (!rows || rows.length === 0) return { inserted: 0 };
    let inserted = 0;
    for (let i = 0; i < rows.length; i += chunkSize) {
        const chunk = rows.slice(i, i + chunkSize);
        const keys = Object.keys(chunk[0]);
        const placeholders = chunk.map(() => `(${keys.map(() => '?').join(',')})`).join(',');
        const values = chunk.flatMap(row => keys.map(k => row[k] ?? null));
        await pool.query(
            `INSERT IGNORE INTO \`${table}\` (\`${keys.join('`,`')}\`) VALUES ${placeholders}`,
            values
        );
        inserted += chunk.length;
    }
    return { inserted };
}

// FIX: Use multer memoryStorage to accept uploaded JSON file; parse from buffer
app.post('/api/system/restore', requireApiAuth('settings', 'read-write'), multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } }).single('backup'), async (req, res) => {
    const conn = await pool.getConnection();
    const results = {};
    const errors = [];

    try {
        if (!req.file) return res.status(400).json({ error: 'No backup file uploaded' });

        let backup;
        try {
            backup = JSON.parse(req.file.buffer.toString('utf8'));
        } catch (e) {
            return res.status(400).json({ error: 'Invalid JSON in backup file: ' + e.message });
        }

        const { metadata, data } = backup;
        if (!data) return res.status(400).json({ error: 'Backup file has no data section' });

        const isV11 = metadata?.version === '1.1';

        await conn.beginTransaction();

        // --- NAS ---
        if (data.nas?.length) {
            await conn.query('DELETE FROM nas');
            await chunkInsert(conn, 'nas', data.nas);
            results.nas = data.nas.length;
        }

        // --- Plans ---
        if (data.plans?.length) {
            await conn.query('DELETE FROM plans');
            await chunkInsert(conn, 'plans', data.plans);
            results.plans = data.plans.length;
        }

        // --- MAC auth devices ---
        if (data.mac_auth_devices?.length) {
            await conn.query('DELETE FROM mac_auth_devices');
            await chunkInsert(conn, 'mac_auth_devices', data.mac_auth_devices);
            results.mac_auth_devices = data.mac_auth_devices.length;
        }

        const macSet = new Set((data.mac_auth_devices || []).map(d => d.mac_address.toLowerCase()));

        const MAC_PATTERN = /^([0-9a-f]{2}[:\-]){5}[0-9a-f]{2}$/i;
        let radcheckUsers = [];
        let radcheckMac = [];

        if (isV11) {
            radcheckUsers = data.radcheck_users || [];
            radcheckMac = data.radcheck_mac || [];
        } else if (data.radcheck?.length) {
            radcheckUsers = data.radcheck.filter(r =>
                !macSet.has(r.username.toLowerCase()) && !MAC_PATTERN.test(r.username)
            );
            radcheckMac = data.radcheck.filter(r =>
                macSet.has(r.username.toLowerCase()) || MAC_PATTERN.test(r.username)
            );
        }

        if (radcheckUsers.length || radcheckMac.length) {
            await conn.query(
                `DELETE FROM radcheck WHERE username NOT REGEXP ?`,
                ['^([0-9a-fA-F]{2}[:\\-]){5}[0-9a-fA-F]{2}$']
            );
            if (radcheckUsers.length) {
                await chunkInsert(conn, 'radcheck', radcheckUsers);
                results.radcheck_users = radcheckUsers.length;
            }
            if (radcheckMac.length) {
                await conn.query(
                    `DELETE FROM radcheck WHERE username REGEXP ?`,
                    ['^([0-9a-fA-F]{2}[:\\-]){5}[0-9a-fA-F]{2}$']
                );
                await chunkInsert(conn, 'radcheck', radcheckMac);
                results.radcheck_mac = radcheckMac.length;
            }
        }

        // --- radreply ---
        if (data.radreply?.length) {
            await conn.query('DELETE FROM radreply');
            await chunkInsert(conn, 'radreply', data.radreply);
            results.radreply = data.radreply.length;
        }

        // --- radgroupcheck / radgroupreply ---
        if (data.radgroupcheck?.length) {
            await conn.query('DELETE FROM radgroupcheck');
            await chunkInsert(conn, 'radgroupcheck', data.radgroupcheck);
            results.radgroupcheck = data.radgroupcheck.length;
        }
        if (data.radgroupreply?.length) {
            await conn.query('DELETE FROM radgroupreply');
            await chunkInsert(conn, 'radgroupreply', data.radgroupreply);
            results.radgroupreply = data.radgroupreply.length;
        }

        // --- radusergroup (assigned profiles) ---
        if (data.radusergroup?.length) {
            await conn.query('DELETE FROM radusergroup');
            await chunkInsert(conn, 'radusergroup', data.radusergroup);
            results.radusergroup = data.radusergroup.length;
        }

        // --- Settings ---
        if (data.settings?.length) {
            for (const s of data.settings) {
                await conn.query('INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?', [s.setting_key, s.setting_value, s.setting_value]);
            }
            results.settings = data.settings.length;
        }

        // --- Plan assignments + snapshots ---
        if (data.user_plans?.length) {
            await conn.query('DELETE FROM user_plans');
            await chunkInsert(conn, 'user_plans', data.user_plans);
            results.user_plans = data.user_plans.length;
        }

        if (data.user_plan_usage?.length) {
            await conn.query('DELETE FROM user_plan_usage');
            await chunkInsert(conn, 'user_plan_usage', data.user_plan_usage);
            results.user_plan_usage = data.user_plan_usage.length;
        }

        // --- Accounting (radacct) ---
        if (data.radacct?.length) {
            try {
                await chunkInsert(conn, 'radacct', data.radacct, 50);
                results.radacct = data.radacct.length;
            } catch (e) {
                errors.push(`radacct: ${e.message}`);
                console.error('radacct restore error:', e);
            }
        }

        // --- Auth logs (radpostauth) ---
        if (data.radpostauth?.length) {
            try {
                await chunkInsert(conn, 'radpostauth', data.radpostauth, 100);
                results.radpostauth = data.radpostauth.length;
            } catch (e) {
                errors.push(`radpostauth: ${e.message}`);
                console.error('radpostauth restore error:', e);
            }
        }

        // --- Admin audit log ---
        if (data.admin_audit_log?.length) {
            try {
                await chunkInsert(conn, 'admin_audit_log', data.admin_audit_log, 100);
                results.admin_audit_log = data.admin_audit_log.length;
            } catch (e) {
                errors.push(`admin_audit_log: ${e.message}`);
            }
        }

        // --- Admins (overwrite existing rows so full restore restores admin passwords/keys) ---
        if (data.admins?.length) {
            await conn.query('DELETE FROM admins');
            await chunkInsert(conn, 'admins', data.admins);
            results.admins = data.admins.length;
        }

        await conn.commit();

        const message = errors.length
            ? `Restore completed with warnings: ${errors.join('; ')}`
            : 'Restore completed successfully';

        await auditLog(req.admin.username, req.origin, `Restored ${metadata?.type || 'unknown'} backup (v${metadata?.version || '1.0'})`, 'success', message, req.ip);
        res.json({ success: true, message, results, warnings: errors });

    } catch (err) {
        await conn.rollback();
        console.error('Restore error:', err);
        await auditLog(req.admin.username, req.origin, 'Restore failed', 'error', err.message, req.ip);
        res.status(500).json({ error: 'Restore failed: ' + err.message, results, warnings: errors });
    } finally {
        conn.release();
    }
});


};
