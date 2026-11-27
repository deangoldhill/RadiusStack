const {createLocalBackups, createScheduler, validateJob, nextRun, utcMysql, jobView, backupView, backupFailure} = require('../local_backups');
const {createRestoreUpload, MAX_BACKUP_BYTES} = require('../backup_upload');
const {pipeline} = require('node:stream/promises');
const {readBackup} = require('../backup_reader');
const {backupChunks} = require('../backup_writer');
module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily, requireGlobalSuperAdmin } = dependencies;

async function buildBackup(pool, job) {
    let connection;
    try {
        if (job.strict) {
            connection = await pool.getConnection();
            await connection.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
            await connection.query('START TRANSACTION WITH CONSISTENT SNAPSHOT');
        }
        const source = connection || pool;
    const type = job.type;
    const include_accounting = !job.omitLogs && (job.acct || type === 'full');
    const include_authlogs = !job.omitLogs && (job.auth || type === 'full');
    const include_auditlogs = !job.omitLogs && (job.audit || type === 'full');
    const safeQuery = async (q) => { try { const [r] = await source.query(q); return r; } catch (error) { if (job.strict || job.strictQueries) throw error; return []; } };

        const admins = await safeQuery('SELECT * FROM admins');
        const tenants = await safeQuery('SELECT * FROM tenants');
        const admin_tenants = await safeQuery('SELECT * FROM admin_tenants');
        const tenant_settings = await safeQuery('SELECT * FROM tenant_settings');
        const user_totp = await safeQuery('SELECT * FROM user_totp');
        const nas = await safeQuery('SELECT * FROM nas');
        const downstream_radius_destinations = await safeQuery('SELECT * FROM downstream_radius_destinations');
        const profile_downstream_routes = await safeQuery('SELECT * FROM profile_downstream_routes');
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
            metadata: { type, timestamp: new Date().toISOString(), version: '1.2' },
            data: {
                admins,
                tenants,
                admin_tenants,
                tenant_settings,
                user_totp,
                downstream_radius_destinations,
                nas,
                profile_downstream_routes,
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

    return backup;
    } finally {
        if (connection) {
            try { await connection.rollback(); }
            finally { connection.release(); }
        }
    }
}

app.get('/api/system/backup', requireApiAuth('settings', 'read-write'), requireGlobalSuperAdmin, async (req, res) => {
    const type = req.query.type || 'full';
    const include_accounting = req.query.acct === 'true' || type === 'full';
    const include_authlogs = req.query.auth === 'true' || type === 'full';
    const include_auditlogs = req.query.audit === 'true' || type === 'full';

    try {
        const backup = await buildBackup(pool, {type, acct: include_accounting, auth: include_authlogs, audit: include_auditlogs});
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

function normalizeAdminRows(rows) {
    return (rows || []).map(row => {
        const permissions = row.permissions;
        let normalized;
        if (permissions === null || permissions === undefined || permissions === '') normalized = '{}';
        else if (typeof permissions === 'string') {
            try { normalized = JSON.stringify(JSON.parse(permissions)); }
            catch { throw new Error(`Invalid admins.permissions value for ${row.username || 'unknown admin'}`); }
        } else if (typeof permissions === 'object') normalized = JSON.stringify(permissions);
        else throw new Error(`Invalid admins.permissions value for ${row.username || 'unknown admin'}`);
        return { ...row, permissions: normalized };
    });
}

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

const restoreHandler = async (req, res) => {
    let conn, parsed;
    const results = {};
    const errors = [];

    try {
        if (!req.file) return res.status(400).json({ error: 'No backup file uploaded' });

        try {
            // Fully validate the file before opening a database transaction. Large log
            // arrays are staged on disk and subsequently read in the existing batches.
            parsed = await readBackup(req.file);
        } catch (e) {
            return res.status(400).json({ error: 'Invalid JSON in backup file: ' + e.message });
        }

        const { metadata, data, logs } = parsed;
        if (!data) return res.status(400).json({ error: 'Backup file has no data section' });

        const isV11 = metadata?.version === '1.1' || metadata?.version === '1.2';

        // Old archives contain tenant IDs on objects but not the tenant identities.
        // Guessing their names or attaching them to a different tenant is unsafe.
        const tenantScopedTables = ['nas', 'downstream_radius_destinations', 'profile_downstream_routes', 'plans', 'mac_auth_devices', 'radcheck_users', 'radcheck_mac', 'radcheck', 'radreply', 'radgroupcheck', 'radgroupreply', 'radusergroup', 'user_plans', 'user_plan_usage', 'user_totp', 'radacct', 'radpostauth'];
        const referencedIds = new Set(tenantScopedTables.flatMap(table =>
            (data[table] || []).map(row => row.tenant_id).filter(id => id !== null && id !== undefined)
        ));
        for (const table of ['radacct', 'radpostauth']) {
            if (logs[table]) for await (const batch of logs[table].batches(100)) {
                for (const row of batch) if (row.tenant_id !== null && row.tenant_id !== undefined) referencedIds.add(row.tenant_id);
            }
        }
        for (const table of ['admin_tenants', 'tenant_settings']) {
            for (const row of data[table] || []) referencedIds.add(row.tenant_id);
        }
        if (referencedIds.size && !Array.isArray(data.tenants)) {
            return res.status(400).json({ error: 'This backup contains tenant-scoped objects but no tenants. Re-export from the source with backup format 1.2; tenant names cannot be recovered from IDs alone.' });
        }
        const backupTenants = data.tenants || [];
        if (new Set(backupTenants.map(t => t.id)).size !== backupTenants.length ||
            new Set(backupTenants.map(t => t.name)).size !== backupTenants.length ||
            backupTenants.some(t => !Number.isInteger(t.id) || t.id < 1 || !t.name)) {
            return res.status(400).json({ error: 'Backup contains invalid or duplicate tenants' });
        }
        const archivedIds = new Set(backupTenants.map(t => t.id));
        if ([...referencedIds].some(id => !archivedIds.has(id))) {
            return res.status(400).json({ error: 'Backup references tenant IDs not present in its tenants section' });
        }

        conn = await pool.getConnection();
        await conn.beginTransaction();

        const [currentTenants] = await conn.query('SELECT id, name FROM tenants FOR UPDATE');
        for (const tenant of backupTenants) {
            const byId = currentTenants.find(t => t.id === tenant.id);
            const byName = currentTenants.find(t => t.name === tenant.name);
            if ((byId && byId.name !== tenant.name) || (byName && byName.id !== tenant.id)) {
                throw new Error(`Tenant identity conflict for ID ${tenant.id}; restore to an empty instance or reconcile IDs first`);
            }
            if (!byId) {
                await conn.query('INSERT INTO tenants (id, name, description, created_at) VALUES (?, ?, ?, ?)',
                    [tenant.id, tenant.name, tenant.description || '', tenant.created_at || new Date()]);
            }
        }
        if (Array.isArray(data.tenants)) results.tenants = backupTenants.length;

        if (Array.isArray(data.downstream_radius_destinations)) {
            // Delete dependent routes first; NAS references become NULL via its FK.
            await conn.query('DELETE FROM profile_downstream_routes');
            await conn.query('DELETE FROM downstream_radius_destinations');
            await chunkInsert(conn, 'downstream_radius_destinations', data.downstream_radius_destinations);
            results.downstream_radius_destinations = data.downstream_radius_destinations.length;
        }

        if (data.nas?.length) {
            await conn.query('DELETE FROM nas');
            await chunkInsert(conn, 'nas', data.nas);
            results.nas = data.nas.length;
        }

        if (data.plans?.length) {
            await conn.query('DELETE FROM plans');
            await chunkInsert(conn, 'plans', data.plans);
            results.plans = data.plans.length;
        }

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

        if (data.radreply?.length) {
            await conn.query('DELETE FROM radreply');
            await chunkInsert(conn, 'radreply', data.radreply);
            results.radreply = data.radreply.length;
        }

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

        if (data.radusergroup?.length) {
            await conn.query('DELETE FROM radusergroup');
            await chunkInsert(conn, 'radusergroup', data.radusergroup);
            results.radusergroup = data.radusergroup.length;
        }

        if (Array.isArray(data.profile_downstream_routes)) {
            await conn.query('DELETE FROM profile_downstream_routes');
            await chunkInsert(conn, 'profile_downstream_routes', data.profile_downstream_routes);
            results.profile_downstream_routes = data.profile_downstream_routes.length;
        }

        if (data.settings?.length) {
            for (const s of data.settings) {
                await conn.query('INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?', [s.setting_key, s.setting_value, s.setting_value]);
            }
            results.settings = data.settings.length;
        }

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

        if (logs.radacct?.length) {
            try {
                for await (const batch of logs.radacct.batches(50)) await chunkInsert(conn, 'radacct', batch, 50);
                results.radacct = logs.radacct.length;
            } catch (e) {
                errors.push(`radacct: ${e.message}`);
                console.error('radacct restore error:', e);
            }
        }

        if (logs.radpostauth?.length) {
            try {
                for await (const batch of logs.radpostauth.batches(100)) await chunkInsert(conn, 'radpostauth', batch, 100);
                results.radpostauth = logs.radpostauth.length;
            } catch (e) {
                errors.push(`radpostauth: ${e.message}`);
                console.error('radpostauth restore error:', e);
            }
        }

        if (logs.admin_audit_log?.length) {
            try {
                for await (const batch of logs.admin_audit_log.batches(100)) await chunkInsert(conn, 'admin_audit_log', batch, 100);
                results.admin_audit_log = logs.admin_audit_log.length;
            } catch (e) {
                errors.push(`admin_audit_log: ${e.message}`);
            }
        }

        if (data.admins?.length) {
            const admins = normalizeAdminRows(data.admins);
            await conn.query('DELETE FROM admins');
            await chunkInsert(conn, 'admins', admins);
            results.admins = admins.length;
        }

        if (Array.isArray(data.admin_tenants)) {
            await conn.query('DELETE FROM admin_tenants');
            await chunkInsert(conn, 'admin_tenants', data.admin_tenants);
            results.admin_tenants = data.admin_tenants.length;
        }
        if (Array.isArray(data.tenant_settings)) {
            await conn.query('DELETE FROM tenant_settings');
            await chunkInsert(conn, 'tenant_settings', data.tenant_settings);
            results.tenant_settings = data.tenant_settings.length;
        }
        if (Array.isArray(data.user_totp)) {
            await conn.query('DELETE FROM user_totp');
            await chunkInsert(conn, 'user_totp', data.user_totp);
            results.user_totp = data.user_totp.length;
        }

        await conn.commit();

        const message = errors.length
            ? `Restore completed with warnings: ${errors.join('; ')}`
            : 'Restore completed successfully';

        const auditMessage = errors.length
            ? `Restore completed with warnings (${errors.length})`
            : 'Restore completed successfully';
        await auditLog(req.admin.username, req.origin, `Restored ${metadata?.type || 'unknown'} backup (v${metadata?.version || '1.0'})`, 'success', auditMessage, req.ip);
        res.json({ success: true, message, results, warnings: errors });

    } catch (err) {
        if (conn) await conn.rollback();
        console.error('Restore error:', err);
        await auditLog(req.admin.username, req.origin, 'Restore failed', 'error', 'Restore failed', req.ip);
        res.status(500).json({ error: 'Restore failed: ' + err.message, results, warnings: errors });
    } finally {
        conn?.release();
        await parsed?.cleanup();
    }
};
app.post('/api/system/restore', requireApiAuth('settings', 'read-write'), requireGlobalSuperAdmin, createRestoreUpload(), restoreHandler);


    const primary = dependencies.isPrimary || (() => process.env.HA_ENABLED !== 'true' || global.haRole === 'primary');
    const local = dependencies.localBackups || createLocalBackups({pool,buildBackup:job=>buildBackup(pool,{...job,strict:true}),streamBackup:job=>backupChunks(pool,job,buildBackup),isPrimary:primary});
    const scheduler = dependencies.scheduler || createScheduler({pool,local,isPrimary:primary,auditLog});
    module.exports.startScheduler = () => scheduler.start();
    const guard = [requireApiAuth('settings','read-write'),requireGlobalSuperAdmin];
    const auditAction=(req,action,result='success')=>auditLog(req.admin.username,req.origin,action,result,'',req.ip);
    const fail = (res,e) => {
        const reason=backupFailure(e);
        console.error('[Local Backup] Operation failed:', e.code||'error', e.backupTable||'', reason);
        return res.status(e.code==='BACKUP_TOO_LARGE'?413:500).json({error:reason});
    };
    const idParam = req => {
        const id=Number(req.params.id);
        if(!Number.isSafeInteger(id) || id<1) throw Error('Invalid job ID');
        return id;
    };
    const writeAllowed = res => {if(!primary()) {res.status(503).json({error:'Primary node required'});return false;}return true;};
    app.get('/api/system/backup-jobs',...guard,async(req,res)=>{
        try {const [rows]=await pool.query('SELECT id,name,frequency,interval_hours,type,acct,auth,audit,keep_count,enabled,next_run,last_run,last_error FROM backup_jobs ORDER BY id');res.setHeader('Cache-Control','no-store');res.json(rows.map(jobView));} catch(e){fail(res,e);}
    });
    app.post('/api/system/backup-jobs',...guard,async(req,res)=>{
        if(!writeAllowed(res))return;
        let job;try {job=validateJob(req.body); }catch(e){return res.status(400).json({error:e.message});}
        try {const [result]=await pool.query('INSERT INTO backup_jobs (name,frequency,interval_hours,type,acct,auth,audit,keep_count,enabled,next_run) VALUES (?,?,?,?,?,?,?,?,?,?)',[job.name,job.frequency,job.interval_hours,job.type,+job.acct,+job.auth,+job.audit,job.keep_count,+job.enabled,utcMysql(nextRun(job,new Date()))]);await auditAction(req,`Created backup job ${result.insertId}`);res.status(201).json(jobView({id:result.insertId,...job,next_run:utcMysql(nextRun(job,new Date())),last_run:null}));}catch(e){fail(res,e);}
    });
    app.put?.('/api/system/backup-jobs/:id',...guard,async(req,res)=>{
        if(!writeAllowed(res))return;
        let job,id;try {id=idParam(req);job=validateJob(req.body);}catch(e){return res.status(400).json({error:e.message});}
        try {const [result]=await pool.query('UPDATE backup_jobs SET name=?,frequency=?,interval_hours=?,type=?,acct=?,auth=?,audit=?,keep_count=?,enabled=?,next_run=? WHERE id=? AND (lease_until IS NULL OR lease_until < UTC_TIMESTAMP())',[job.name,job.frequency,job.interval_hours,job.type,+job.acct,+job.auth,+job.audit,job.keep_count,+job.enabled,utcMysql(nextRun(job,new Date())),id]);if(!result.affectedRows)return res.status(404).json({error:'Job not found or running'});await auditAction(req,`Updated backup job ${id}`);res.json(jobView({id,...job,next_run:utcMysql(nextRun(job,new Date())),last_run:null}));}catch(e){fail(res,e);}
    });
    app.delete?.('/api/system/backup-jobs/:id',...guard,async(req,res)=>{
        if(!writeAllowed(res))return;
        let id;try{id=idParam(req);}catch(e){return res.status(400).json({error:e.message});}
        try {const [result]=await pool.query('DELETE FROM backup_jobs WHERE id=? AND (lease_until IS NULL OR lease_until < UTC_TIMESTAMP())',[id]);if(!result.affectedRows)return res.status(404).json({error:'Job not found or running'});await auditAction(req,`Deleted backup job ${id}`);res.json({success:true});}catch(e){fail(res,e);}
    });
    app.post('/api/system/backup-jobs/:id/run',...guard,async(req,res)=>{
        if(!writeAllowed(res))return;
        let id;try{id=idParam(req);}catch(e){return res.status(400).json({error:e.message});}
        try {const [rows]=await pool.query('SELECT * FROM backup_jobs WHERE id=?',[id]);if(!rows.length)return res.status(404).json({error:'Job not found'});const backup=await scheduler.run(rows[0],true);await auditAction(req,`Ran backup job ${id}`);res.json(backupView(backup));}catch(e){fail(res,e);}
    });
    app.get('/api/system/local-backups',...guard,async(req,res)=>{
        try {res.setHeader('Cache-Control','no-store');res.json((await local.list()).map(backupView));}catch(e){fail(res,e);}
    });
    app.get('/api/system/local-backups/:id/download',...guard,async(req,res)=>{
        let verified;
        try {
            verified=local.open ? await local.open(req.params.id) : null;
            const content=verified?null:await local.read(req.params.id);
            await auditAction(req,`Downloaded local backup ${req.params.id}`);
            res.setHeader('Cache-Control','no-store');res.setHeader('Content-Type','application/json');
            res.setHeader('Content-Disposition',`attachment; filename="radius_backup_${req.params.id}.json"`);
            if(verified) await pipeline(verified.createReadStream(),res);else res.send(content);
        } catch(e) {
            if(res.headersSent) res.destroy(e);else res.status(404).json({error:'Local backup unavailable or corrupt'});
        } finally {await verified?.close();}
    });
    app.post('/api/system/local-backups/:id/restore',...guard,async(req,res)=>{
        if(!writeAllowed(res))return;
        if(req.body?.confirm!=='RESTORE_BACKUP')return res.status(400).json({error:'Explicit RESTORE_BACKUP confirmation required'});
        let verified;
        try {
            // The existing restore handler remains the only implementation of restore SQL.
            if(local.open) {
                verified=await local.open(req.params.id);
                return await restoreHandler({...req,file:{stream:verified.createReadStream()}},res);
            }
            const content=await local.read(req.params.id);
            if(content.length>MAX_BACKUP_BYTES)return res.status(413).json({error:'Backup exceeds 700 MB restore limit'});
            return await restoreHandler({...req,file:{buffer:content}},res);
        }catch(e){return res.status(e.code==='BACKUP_TOO_LARGE'?413:404).json({error:e.code==='BACKUP_TOO_LARGE'?backupFailure(e):'Local backup unavailable or corrupt'});}
        finally {await verified?.close();}
    });
    module.exports.buildBackup = buildBackup;
};
