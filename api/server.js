const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const { v4: uuidv4 } = require('uuid');
const { exec } = require('child_process');
const multer = require('multer');
const fs = require('fs').promises;
const puppeteer = require('puppeteer');
const crypto = require('crypto');
require('./workers/radiusStatsWorker');

const app = express();
const cors = require('cors');

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(cors());

const upload = multer({ dest: '/tmp/' });
// Read from environment — with sensible fallbacks for local development
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-container_config.env';
const TOTP_ISSUER = process.env.TOTP_ISSUER || 'RadiusStack';

if (!process.env.JWT_SECRET) {
    console.warn('[WARN] JWT_SECRET not set in environment — using insecure default. Set it in container_config.env.');
}
if (!process.env.DB_PASS) {
    console.warn('[WARN] DB_PASS not set in environment — DB connections may fail.');
}

function signTotpEnrollmentToken(username) {
    return jwt.sign(
        { username, scope: 'totp-enroll' },
        JWT_SECRET,
        { expiresIn: '10m' }
    );
}

function verifyTotpEnrollmentToken(token) {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.scope !== 'totp-enroll') {
        throw new Error('Invalid enrollment scope');
    }
    return decoded;
}

async function getRadiusPassword(username) {
    const [rows] = await pool.query(
        "SELECT value FROM radcheck WHERE username = ? AND attribute = 'Cleartext-Password' LIMIT 1",
        [username]
    );
    return rows[0]?.value || null;
}

async function getUserTotp(username) {
    const [rows] = await pool.query(
        "SELECT username, enabled, secret, pending_secret, enrolled_at FROM user_totp WHERE username = ? LIMIT 1",
        [username]
    );
    return rows[0] || null;
}

async function syncUserTotpToRadius(conn, username) {
    const [rows] = await conn.query(
        "SELECT enabled, secret FROM user_totp WHERE username = ? LIMIT 1",
        [username]
    );
    const totp = rows[0];

    await conn.query(
        "DELETE FROM radcheck WHERE username = ? AND attribute = 'TOTP-Secret'",
        [username]
    );

    if (totp && Number(totp.enabled) === 1 && totp.secret) {
        await conn.query(
            "INSERT INTO radcheck (username, attribute, op, value) VALUES (?, 'TOTP-Secret', ':=', ?)",
            [username, totp.secret]
        );
    }
}

async function generateEnrollmentCode(conn, username) {
    const plainCode = crypto.randomBytes(24).toString('base64url');
    const hash = await bcrypt.hash(plainCode, 10);

    const [settings] = await conn.query("SELECT setting_value FROM settings WHERE setting_key = 'totp_enrollment_hours'");
    const hours = settings.length > 0 ? parseInt(settings[0].setting_value, 10) : 24;
    const expiry = new Date(Date.now() + (hours * 3600000));

    await conn.query(
        "UPDATE user_totp SET enrollment_code_hash = ?, enrollment_expires_at = ?, pending_secret = NULL WHERE username = ?",
        [hash, expiry, username]
    );

    return {
        code: plainCode,
        expires_at: expiry.toISOString()
    };
}

const pool = mysql.createPool({
    host: process.env.DB_HOST || 'mariadb',
    user: process.env.DB_USER || 'radius',
    password: process.env.DB_PASS || '',
    database: process.env.DB_NAME || 'radius',
    dateStrings: true
});

// --- API DEBUG LOGGING ---
let apiDebugEnabled = false;

// Initialize debug state
pool.query("SELECT setting_value FROM settings WHERE setting_key = 'api_debug'").then(([rows]) => {
    if (rows.length && rows[0].setting_value === 'true') {
        apiDebugEnabled = true;
        console.log('[API DEBUG] API Debug logging is ENABLED from database.');
    }
}).catch(err => {
    // Ignore on first boot if table doesn't exist yet
});

function apiDebugLog(msg) {
    if (apiDebugEnabled) {
        console.log(`[API DEBUG] ${new Date().toISOString()} | ${msg}`);
    }
}

app.use((req, res, next) => {
    if (apiDebugEnabled && !req.originalUrl.includes('/api/ha/status')) { // exclude noise
        apiDebugLog(`${req.method} ${req.originalUrl} - IP: ${req.ip} - Body: ${JSON.stringify(req.body || {}).substring(0, 200)}`);
    }
    next();
});

// --- ADVANCED HA SYNC ENGINE ---

// Generate a static 256-bit AES key by hashing the existing HA_API_TOKEN
const HA_PSK = crypto.createHash('sha256').update(process.env.HA_API_TOKEN || 'default').digest();

function encryptHaPayload(payload) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', HA_PSK, iv);
    let encrypted = cipher.update(JSON.stringify(payload), 'utf8', 'base64');
    encrypted += cipher.final('base64');
    return {
        iv: iv.toString('base64'),
        authTag: cipher.getAuthTag().toString('base64'),
        data: encrypted
    };
}

function decryptHaPayload(body) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', HA_PSK, Buffer.from(body.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(body.authTag, 'base64'));
    let decrypted = decipher.update(body.data, 'base64', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
}

global.haRole = process.env.HA_ROLE || 'primary';
global.haStats = { success: 0, failed: 0, lastSync: null };

setTimeout(() => {
    if (process.env.HA_ENABLED === 'true') {
        originalPoolQuery.call(pool, "ALTER TABLE ha_queue ADD COLUMN insert_id BIGINT DEFAULT NULL", [], { isSync: true }).catch(() => {});
        originalPoolQuery.call(pool, "ALTER TABLE ha_sync_state ADD COLUMN last_time VARCHAR(30) DEFAULT '1970-01-01 00:00:00.000000'", [], { isSync: true }).catch(() => {});
        // Add microsecond tracking column to safely sync Interim-Updates without 1-second collisions
        originalPoolQuery.call(pool, "ALTER TABLE radacct ADD COLUMN ha_updated_at TIMESTAMP(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)", [], { isSync: true }).catch(() => {});
    }
}, 5000);

app.use((req, res, next) => {
    if (process.env.HA_ENABLED === 'true' && global.haRole === 'secondary') {
        const isWrite = ['POST', 'PUT', 'DELETE'].includes(req.method);
        const isHaEndpoint = req.path.startsWith('/api/ha') || req.path.startsWith('/api/sync') || req.path.startsWith('/auth');
        const isRestart = req.path.startsWith('/api/system/restart');
        if (isWrite && !isHaEndpoint && !isRestart) {
            return res.status(403).json({ error: 'Secondary node is read-only. Please promote to primary to make changes.' });
        }
    }
    next();
});

async function pushToHaQueue(queryStr, valuesStr, insertId = null) {
    try {
        await originalPoolQuery.call(pool, "INSERT INTO ha_queue (query, values_json, insert_id) VALUES (?, ?, ?)", [queryStr, valuesStr, insertId], { isSync: true });
    } catch (err) {
        console.error('[HA Queue Error]', err);
    }
}

const originalPoolQuery = pool.query;
pool.query = async function() {
    const args = Array.from(arguments);
    const sqlQuery = args[0] ? args[0].toString().trim().toUpperCase() : '';
    const isWrite = sqlQuery.startsWith('INSERT') || sqlQuery.startsWith('UPDATE') || sqlQuery.startsWith('DELETE') || sqlQuery.startsWith('REPLACE');
    const options = args[2] || {};
    const isSync = options.isSync === true;

    const result = await originalPoolQuery.apply(this, args);
    const insertId = (result && result[0] && result[0].insertId) ? result[0].insertId : null;

    if (process.env.HA_ENABLED === 'true' && global.haRole === 'primary' && isWrite && !isSync && !sqlQuery.includes('HA_QUEUE') && !sqlQuery.includes('HA_SYNC_STATE') && !(sqlQuery.includes('INTO RADIUS_STATS') || sqlQuery.includes('UPDATE RADIUS_STATS') || sqlQuery.includes('FROM RADIUS_STATS'))) {
        await pushToHaQueue(args[0], JSON.stringify(args[1] || []), insertId);
    }
    return result;
};

const originalGetConnection = pool.getConnection;
pool.getConnection = async function() {
    const conn = await originalGetConnection.apply(this, arguments);
    const originalConnQuery = conn.query;
    conn.query = async function() {
        const args = Array.from(arguments);
        const sqlQuery = args[0] ? args[0].toString().trim().toUpperCase() : '';
        const isWrite = sqlQuery.startsWith('INSERT') || sqlQuery.startsWith('UPDATE') || sqlQuery.startsWith('DELETE') || sqlQuery.startsWith('REPLACE');
        const options = args[2] || {};
        const isSync = options.isSync === true;

        const result = await originalConnQuery.apply(this, args);
        const insertId = (result && result[0] && result[0].insertId) ? result[0].insertId : null;

        if (process.env.HA_ENABLED === 'true' && global.haRole === 'primary' && isWrite && !isSync && !sqlQuery.includes('HA_QUEUE') && !sqlQuery.includes('HA_SYNC_STATE') && !(sqlQuery.includes('INTO RADIUS_STATS') || sqlQuery.includes('UPDATE RADIUS_STATS') || sqlQuery.includes('FROM RADIUS_STATS'))) {
            await pushToHaQueue(args[0], JSON.stringify(args[1] || []), insertId);
        }
        return result;
    };
    return conn;
};

const originalPoolExecute = pool.execute;
pool.execute = async function() {
    const args = Array.from(arguments);
    const sqlQuery = args[0] ? args[0].toString().trim().toUpperCase() : '';
    const isWrite = sqlQuery.startsWith('INSERT') || sqlQuery.startsWith('UPDATE') || sqlQuery.startsWith('DELETE') || sqlQuery.startsWith('REPLACE');
    const options = args[2] || {};
    const isSync = options.isSync === true;

    const result = await originalPoolExecute.apply(this, args);
    const insertId = (result && result[0] && result[0].insertId) ? result[0].insertId : null;

    if (process.env.HA_ENABLED === 'true' && global.haRole === 'primary' && isWrite && !isSync && !sqlQuery.includes('HA_QUEUE') && !sqlQuery.includes('HA_SYNC_STATE') && !(sqlQuery.includes('INTO RADIUS_STATS') || sqlQuery.includes('UPDATE RADIUS_STATS') || sqlQuery.includes('FROM RADIUS_STATS'))) {
        await pushToHaQueue(args[0], JSON.stringify(args[1] || []), insertId);
    }
    return result;
};

async function processHaQueue() {
    if (process.env.HA_ENABLED !== 'true' || !process.env.HA_PEER_IP) return;

    try {
        const [rows] = await originalPoolQuery.call(pool, "SELECT * FROM ha_queue ORDER BY id ASC LIMIT 50", [], { isSync: true });
        for (let row of rows) {
            try {
                const rawPayload = { 
                    query: row.query, 
                    values: JSON.parse(row.values_json || '[]'),
                    insertId: row.insert_id || null,
                    _ts: Date.now() // Bound timestamp for replay protection
                };

                const securePayload = encryptHaPayload(rawPayload);

                const response = await fetch(`http://${process.env.HA_PEER_IP}:${process.env.API_PORT || 3000}/api/sync/execute`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(securePayload)
                });

                if (response.ok) {
                    await originalPoolQuery.call(pool, "DELETE FROM ha_queue WHERE id = ?", [row.id], { isSync: true });
                    global.haStats.success++;
                    global.haStats.lastSync = new Date().toISOString();
                } else {
                    const errText = await response.text();
                    console.error('[HA Sync Peer Error]', errText);
                    global.haStats.failed++;
                    break;
                }
            } catch (netErr) {
                console.error('[HA Sync Network Error]', netErr.message);
                global.haStats.failed++;
                break;
            }
        }
    } catch (err) {
        console.error('[HA Worker Error]', err);
    }
}

async function syncRadiusTables() {
    if (process.env.HA_ENABLED !== 'true' || !process.env.HA_PEER_IP) return;
    try {
        let hasUpdatedCol = true;
        try { await originalPoolQuery.call(pool, "SELECT ha_updated_at FROM radacct LIMIT 1", [], { isSync: true }); } 
        catch(e) { hasUpdatedCol = false; }

        const tables = [
            { name: 'radacct', idCol: 'radacctid', timeCol: hasUpdatedCol ? 'ha_updated_at' : 'acctupdatetime' },
            { name: 'radpostauth', idCol: 'id', timeCol: 'authdate' }
        ];

        for (let table of tables) {
            const [stateRows] = await originalPoolQuery.call(pool, "SELECT last_time, last_id FROM ha_sync_state WHERE table_name = ?", [table.name], { isSync: true });
            let lastId = stateRows[0] ? stateRows[0].last_id : 0;
            let lastTimeStr = stateRows[0] && stateRows[0].last_time ? stateRows[0].last_time : '1970-01-01 00:00:00.000000';

            if (lastTimeStr instanceof Date) lastTimeStr = lastTimeStr.toISOString().replace('T', ' ').replace('Z', '');

            const [offsetRows] = await originalPoolQuery.call(pool, "SHOW VARIABLES LIKE 'auto_increment_offset'", [], { isSync: true });
            const dbOffset = parseInt(offsetRows[0].Value, 10) || 1;
            const offsetRem = dbOffset % 2;

            let sql = '';
            let params = [];

            if (table.name === 'radpostauth') {
                sql = `SELECT *, authdate AS ha_effective_time FROM ${table.name} WHERE ((authdate > ?) OR (authdate = ? AND ${table.idCol} > ?)) AND (${table.idCol} % 2) = ? ORDER BY authdate ASC, ${table.idCol} ASC LIMIT 200`;
                params = [lastTimeStr, lastTimeStr, lastId, offsetRem];
            } else {
                const effectiveTimeExpr = hasUpdatedCol ? table.timeCol : `COALESCE(${table.timeCol}, acctstarttime, acctstoptime)`;
                sql = `SELECT *, ${effectiveTimeExpr} AS ha_effective_time FROM ${table.name} WHERE ((${effectiveTimeExpr} > ?) OR (${effectiveTimeExpr} = ? AND ${table.idCol} > ?)) AND (${table.idCol} % 2) = ? ORDER BY ${effectiveTimeExpr} ASC, ${table.idCol} ASC LIMIT 200`;
                params = [lastTimeStr, lastTimeStr, lastId, offsetRem];
            }

            const [dataRows] = await originalPoolQuery.call(pool, sql, params, { isSync: true });

            let maxTimeProcessed = lastTimeStr;
            let maxIdProcessed = lastId;

            if (dataRows.length > 0) {
                for (let row of dataRows) {
                    const haEffectiveTime = row.ha_effective_time;
                    delete row.ha_effective_time;
                    delete row.ha_updated_at; // Ensure we don't push the local microsecond tracker to the remote

                    const keys = Object.keys(row).join(', ');
                    const placeholders = Object.keys(row).map(() => '?').join(', ');
                    const updateStmts = Object.keys(row).map(k => `${k}=VALUES(${k})`).join(', ');
                    const values = Object.values(row);
                    const query = `INSERT INTO ${table.name} (${keys}) VALUES (${placeholders}) ON DUPLICATE KEY UPDATE ${updateStmts}`;

                    await originalPoolQuery.call(pool, "INSERT INTO ha_queue (query, values_json) VALUES (?, ?)", [query, JSON.stringify(values)], { isSync: true });

                    if (table.name === 'radacct') {
                        let rowTime = haEffectiveTime || lastTimeStr;
                        if (rowTime instanceof Date) rowTime = rowTime.toISOString().replace('T', ' ').replace('Z', '');
                        else if (typeof rowTime === 'string') rowTime = rowTime.includes('.') ? rowTime.padEnd(26, '0') : rowTime + '.000000';
                        maxTimeProcessed = rowTime;
                        maxIdProcessed = row[table.idCol];
                    } else {
                        maxIdProcessed = Math.max(maxIdProcessed, row[table.idCol]);
                        let rowTime = row[table.timeCol] || lastTimeStr;
                        if (rowTime instanceof Date) rowTime = rowTime.toISOString().replace('T', ' ').replace('Z', '');
                        else if (typeof rowTime === 'string') rowTime = rowTime.includes('.') ? rowTime.padEnd(26, '0') : rowTime + '.000000';
                        maxTimeProcessed = rowTime;
                    }
                }

                await originalPoolQuery.call(pool, "UPDATE ha_sync_state SET last_time = ?, last_id = ? WHERE table_name = ?", [maxTimeProcessed, maxIdProcessed, table.name], { isSync: true });
            }
        }
    } catch (err) {
        console.error('[HA RADIUS Sync Error]', err);
    }
}

if (process.env.HA_ENABLED === 'true') {
    setInterval(processHaQueue, 2000);
    setInterval(syncRadiusTables, 5000);
}

app.get('/api/ha/status', async (req, res) => {
    let queueLength = 0;
    try {
        const [q] = await originalPoolQuery.call(pool, "SELECT COUNT(*) as c FROM ha_queue", [], { isSync: true });
        queueLength = q[0].c;
    } catch(e) {}
    res.json({
        enabled: process.env.HA_ENABLED === 'true',
        role: global.haRole,
        peer: process.env.HA_PEER_IP || 'Not configured',
        queueLength,
        stats: global.haStats
    });
});

app.post('/api/ha/promote', (req, res) => {
    global.haRole = 'primary';
    res.json({ success: true, message: 'Promoted to primary. This node is now fully writable.' });
});

app.post('/api/ha/demote', (req, res) => {
    global.haRole = 'secondary';
    res.json({ success: true, message: 'Demoted to secondary. Node is now read-only.' });
});

app.post('/api/ha/sync-now', async (req, res) => {
    await processHaQueue();
    await syncRadiusTables();
    res.json({ success: true, message: 'Manual sync triggered' });
});

app.post('/api/ha/full-sync', async (req, res) => {
    if (global.haRole !== 'primary') return res.status(403).json({ error: 'Full sync can only be triggered from the primary node.' });

    try {
        const [tables] = await originalPoolQuery.call(pool, "SHOW TABLES", [], { isSync: true });
        const dbName = Object.values(tables[0])[0] ? Object.keys(tables[0])[0] : 'Tables_in_radius';

        for (let t of tables) {
            const tableName = t[dbName];
            if (['ha_queue', 'ha_sync_state', 'radius_stats'].includes(tableName)) continue;

            const [rows] = await originalPoolQuery.call(pool, `SELECT * FROM ${tableName}`, [], { isSync: true });
            for (let row of rows) {
                const keys = Object.keys(row).join(', ');
                const placeholders = Object.keys(row).map(() => '?').join(', ');
                const updateStmts = Object.keys(row).map(k => `${k}=VALUES(${k})`).join(', ');
                const values = Object.values(row);
                const query = `INSERT INTO ${tableName} (${keys}) VALUES (${placeholders}) ON DUPLICATE KEY UPDATE ${updateStmts}`;
                await originalPoolQuery.call(pool, "INSERT INTO ha_queue (query, values_json) VALUES (?, ?)", [query, JSON.stringify(values)], { isSync: true });
            }
        }
        res.json({ success: true, message: 'Full sync queued successfully.' });
    } catch (err) {
        console.error('[HA Full Sync Error]', err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/sync/execute', async (req, res) => {
    let payload;
    try {
        payload = decryptHaPayload(req.body);
    } catch (err) {
        console.error('[HA Sync] Decryption failed - possible token mismatch or tampering');
        return res.status(401).json({ error: 'Decryption failed' });
    }

    // Strict Replay Protection: Reject packets older than 60 seconds
    const age = Date.now() - (payload._ts || 0);
    if (age > 60000 || age < -5000) {
        console.warn('[HA Sync] Rejected expired or replayed payload');
        return res.status(401).json({ error: 'Payload expired' });
    }

    let conn;
    try {
        conn = await originalGetConnection.call(pool);
        const { query, values, insertId } = payload;

        const sanitizedValues = (values || []).map(v => {
            if (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/.test(v)) {
                return v.replace('T', ' ').replace('Z', '');
            }
            return v;
        });

        let success = false;
        let retries = 3;

        while (retries > 0 && !success) {
            try {
                await conn.query("SET FOREIGN_KEY_CHECKS=0", []);
                if (insertId) {
                    await conn.query("SET SESSION auto_increment_increment = 1", []);
                    await conn.query("SET insert_id = ?", [insertId]);
                }

                await conn.query(query, sanitizedValues);

                await conn.query("SET FOREIGN_KEY_CHECKS=1", []);
                success = true;
            } catch (err) {
                if (err.code === 'ER_LOCK_DEADLOCK' && retries > 1) {
                    retries--;
                    console.warn(`[HA Sync] Deadlock detected. Retrying... (${retries} attempts left)`);
                    await new Promise(resolve => setTimeout(resolve, 200));
                    continue;
                }
                throw err;
            }
        }
        res.json({ success: true });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            console.warn('[HA Sync] Ignored duplicate entry:', error.message);
            return res.json({ success: true, ignored: true });
        }
        console.error('[HA Execute Error]', error.message);
        res.status(500).json({ error: error.message });
    } finally {
        if (conn) {
            try {
                await conn.query("SET FOREIGN_KEY_CHECKS=1", []);
            } catch(e) {}
            conn.release();
        }
    }
});
// ------------------------------------------


// Audit Logger
async function auditLog(admin_username, origin, action, result, details = '', ip = '') {
    try {
        await pool.query(
            'INSERT INTO admin_audit_log (admin_username, origin, action, result, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)',
            [admin_username, origin, action, result, details, ip]
        );
        const syslog = require('./utils/syslog');
        syslog.sendAuditLog({ admin_username, origin, action, result, details, ip_address: ip }).catch(e => console.error('[Syslog] auditLog error:', e.message));
    } catch (err) {
        console.error('Audit log failed:', err);
    }
}

async function snapshotUserPlanUsage(db, username) {
    const executor = db && typeof db.query === 'function' ? db : pool;

    const [rows] = await executor.query(`
    SELECT
      COALESCE(SUM(acctinputoctets), 0) AS input_octets,
      COALESCE(SUM(acctoutputoctets), 0) AS output_octets,
      COALESCE(SUM(acctsessiontime), 0) AS session_seconds
    FROM radacct
    WHERE username = ?
  `, [username]);

    const totals = rows[0] || {
        input_octets: 0,
        output_octets: 0,
        session_seconds: 0
    };

    await executor.query(`
    INSERT INTO user_plan_usage
      (username, cycle_started_at, base_input_octets, base_output_octets, base_session_seconds)
    VALUES (?, NOW(), ?, ?, ?)
    ON DUPLICATE KEY UPDATE
      cycle_started_at = VALUES(cycle_started_at),
      base_input_octets = VALUES(base_input_octets),
      base_output_octets = VALUES(base_output_octets),
      base_session_seconds = VALUES(base_session_seconds)
  `, [username, totals.input_octets, totals.output_octets, totals.session_seconds]);
}

async function initDb() {
    await pool.query("INSERT IGNORE INTO settings (setting_key, setting_value) VALUES ('radius_debug', 'false')");
    await pool.query("INSERT IGNORE INTO settings (setting_key, setting_value) VALUES ('mask_user_passwords', 'false')");
  await pool.query("INSERT IGNORE INTO settings (setting_key, setting_value) VALUES ('mac_auth_autocreate', 'false')");
  await pool.query("INSERT IGNORE INTO settings (setting_key, setting_value) VALUES ('mac_auth_autocreate_plan', '')");
  await pool.query("INSERT IGNORE INTO settings (setting_key, setting_value) VALUES ('mac_auth_autocreate_profile', '')");
  await pool.query("INSERT IGNORE INTO settings (setting_key, setting_value) VALUES ('radius_stats_retention_days', '7')");
  await pool.query("INSERT IGNORE INTO settings (setting_key, setting_value) VALUES ('radius_stats_purge_interval', '60')");
  await pool.query("INSERT IGNORE INTO settings (setting_key, setting_value) VALUES ('radius_stats_poll_interval', '60000')");

    
    require('./utils/syslog').init(pool);
    const syslogAuthWorker = require('./workers/syslogAuthWorker');
    await syslogAuthWorker.init(pool);
    setInterval(() => syslogAuthWorker.poll(), 5000);

    const [rows] = await pool.query('SELECT COUNT(*) as count FROM admins');
    if (rows[0].count === 0) {
        const hash = await bcrypt.hash('admin', 10);
        const perms = JSON.stringify({ nas: 'read-write', users: 'read-write', admins: 'read-write', reports: 'read-write', settings: 'read-write', plans: 'read-write' });
        const defaultApiKey = crypto.randomBytes(32).toString('hex');
        await pool.query('INSERT INTO admins (username, password_hash, api_key, permissions) VALUES (?, ?, ?, ?)', ['admin', hash, defaultApiKey, perms]);
        await auditLog('system', 'system', 'Created default admin account', 'success', 'Initial setup');
    }
}
initDb();

// --- Auth Routes with Audit ---
app.post('/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;

    const [admins] = await pool.query('SELECT * FROM admins WHERE username = ?', [username]);
    const admin = admins[0];

    if (!admin) {
        await auditLog(username, 'webui', 'Login attempt', 'failed', 'User not found', ip);
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!(await bcrypt.compare(password, admin.password_hash))) {
        await auditLog(username, 'webui', 'Login attempt', 'failed', 'Invalid password', ip);
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    await auditLog(username, 'webui', 'Login attempt', 'success', 'Password validated', ip);

    const payload = { id: admin.id };

    if (admin.require_password_change)
        return res.json({ status: 'needs_pwd_change', token: jwt.sign({ ...payload, step: 'pwd' }, JWT_SECRET, { expiresIn: '15m' }) });

    if (admin.two_factor_enabled && !admin.two_factor_setup_complete) {
        const secret = authenticator.generateSecret();
        await pool.query('UPDATE admins SET two_factor_secret = ? WHERE id = ?', [secret, admin.id]);
        const qrImage = await qrcode.toDataURL(authenticator.keyuri(admin.username, 'RadiusFullStack', secret));
        return res.json({ status: 'needs_2fa_setup', token: jwt.sign({ ...payload, step: '2fa_setup' }, JWT_SECRET, { expiresIn: '15m' }), qrImage, secret });
    }

    if (admin.two_factor_enabled && admin.two_factor_setup_complete)
        return res.json({ status: 'needs_2fa_verify', token: jwt.sign({ ...payload, step: '2fa_verify' }, JWT_SECRET, { expiresIn: '15m' }) });

    await auditLog(username, 'webui', 'Login completed', 'success', 'Granted API key', ip);
    res.json({ status: 'success', api_key: admin.api_key });
});

app.post('/auth/verify-2fa', async (req, res) => {
    const { token, code } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const [admins] = await pool.query('SELECT * FROM admins WHERE id = ?', [decoded.id]);
        const admin = admins[0];

        if (!authenticator.check(code, admin.two_factor_secret)) {
            await auditLog(admin.username, 'webui', '2FA verification', 'failed', 'Invalid TOTP code', ip);
            return res.status(401).json({ error: 'Invalid Code' });
        }

        await auditLog(admin.username, 'webui', '2FA verification', 'success', 'TOTP validated', ip);

        if (decoded.step === '2fa_setup')
            await pool.query('UPDATE admins SET two_factor_setup_complete = true WHERE id = ?', [admin.id]);

        res.json({ status: 'success', api_key: admin.api_key });
    } catch (err) {
        await auditLog('unknown', 'webui', '2FA verification', 'failed', 'Invalid session token', ip);
        res.status(401).json({ error: 'Invalid session' });
    }
});

app.post('/auth/change-pwd', async (req, res) => {
    const { token, newPassword } = req.body;
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const hash = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE admins SET password_hash = ?, require_password_change = false WHERE id = ?', [hash, decoded.id]);

        const [admins] = await pool.query('SELECT * FROM admins WHERE id = ?', [decoded.id]);
        const admin = admins[0];

        await auditLog(admin.username, 'webui', 'Password changed', 'success', 'Forced password change completed', ip);

        if (admin.two_factor_enabled && !admin.two_factor_setup_complete) {
            const secret = authenticator.generateSecret();
            await pool.query('UPDATE admins SET two_factor_secret = ? WHERE id = ?', [secret, admin.id]);
            const qrImage = await qrcode.toDataURL(authenticator.keyuri(admin.username, 'RadiusFullStack', secret));
            return res.json({ status: 'needs_2fa_setup', token: jwt.sign({ id: admin.id, step: '2fa_setup' }, JWT_SECRET), qrImage });
        }
        if (admin.two_factor_enabled)
            return res.json({ status: 'needs_2fa_verify', token: jwt.sign({ id: admin.id, step: '2fa_verify' }, JWT_SECRET) });

        res.json({ status: 'success', api_key: admin.api_key });
    } catch (err) {
        res.status(401).json({ error: 'Invalid session' });
    }
});

// --- Middleware with Audit ---
const requireApiAuth = (module, requiredLevel) => async (req, res, next) => {
    const apiKey = req.header('X-API-Key');
    const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    const origin = req.header('User-Agent')?.includes('Mozilla') ? 'webui' : 'api';

    if (!apiKey) {
        await auditLog('anonymous', origin, `Access attempt to ${module}`, 'denied', 'Missing API key', ip);
        return res.status(401).json({ error: 'API Key missing' });
    }

    const [admins] = await pool.query('SELECT * FROM admins WHERE api_key = ?', [apiKey]);
    if (!admins.length) {
        await auditLog('unknown', origin, `Access attempt to ${module}`, 'denied', 'Invalid API key', ip);
        return res.status(401).json({ error: 'Invalid API Key' });
    }

    const admin = admins[0];
    const perms = JSON.parse(admin.permissions || '{}');

    if (!perms[module]) {
        await auditLog(admin.username, origin, `Access to ${module}`, 'denied', 'No permission for module', ip);
        return res.status(403).json({ error: `Forbidden: No access to ${module}` });
    }

    if (requiredLevel === 'read-write' && perms[module] !== 'read-write') {
        await auditLog(admin.username, origin, `Write attempt to ${module}`, 'denied', 'Read-only permission', ip);
        return res.status(403).json({ error: `Forbidden: Requires read-write access to ${module}` });
    }

    req.admin = admin;
    req.origin = origin;
    req.ip = ip;
    next();
};


function setApiDebugMode(enabled) {
    apiDebugEnabled = !!enabled;
    apiDebugLog('API Debug mode status changed via Settings');
}

// ==========================================
// --- REGISTER MODULARIZED ROUTES ---
// ==========================================
const routeDependencies = {
    bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, puppeteer, multer,
    JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage,
    calculateRadiusStats, calculateTrendHourly, calculateTrendDaily,
    signTotpEnrollmentToken, verifyTotpEnrollmentToken,
    apiDebugLog, setApiDebugMode
};
require('./routes')(app, pool, requireApiAuth, auditLog, routeDependencies);

// ─── CALCULATE INCREMENTAL RADIUS STATS ───────────────────────────────────────
async function calculateRadiusStats(pool, statType, startDate, endDate) {
    const params = [statType];
    let timeFilter = '';

    if (startDate && endDate) {
        timeFilter = ' AND collected_at >= (SELECT COALESCE((SELECT MAX(collected_at) FROM radius_stats WHERE stat_type = ? AND collected_at < ?), ?)) AND collected_at <= ?';
        params.push(statType, startDate, startDate, endDate);
    } else {
        const hours = 24;
        timeFilter = ' AND collected_at >= (SELECT COALESCE((SELECT MAX(collected_at) FROM radius_stats WHERE stat_type = ? AND collected_at < DATE_SUB(NOW(), INTERVAL ? HOUR)), DATE_SUB(NOW(), INTERVAL ? HOUR)))';
        params.push(statType, hours, hours);
    }

    const [rows] = await pool.query(
        `SELECT * FROM radius_stats WHERE stat_type = ? ${timeFilter} ORDER BY collected_at ASC`,
        params
    );

    if (rows.length === 0) return null;

    const fields = [
        'total_requests', 'total_accepts', 'total_rejects', 'total_challenges',
        'total_responses', 'dup_requests', 'malformed_requests', 'invalid_requests',
        'dropped_requests', 'unknown_types'
    ];

    const result = {};
    for (const f of fields) result[f] = 0;

    let prev = rows[0];
    let startIdx = 1;

    let winStart;
    if (startDate) {
        winStart = new Date(startDate.replace(' ', 'T') + 'Z').getTime();
    } else {
        winStart = Date.now() - (24 * 3600000);
    }

    const firstRowMs = new Date(rows[0].collected_at).getTime();
    if (firstRowMs >= winStart) {
        prev = {};
        for (const f of fields) prev[f] = 0;
        startIdx = 0;
    }

    for (let i = startIdx; i < rows.length; i++) {
        const row = rows[i];
        for (const f of fields) {
            const currVal = Number(row[f] || 0);
            const prevVal = Number(prev[f] || 0);
            if (currVal >= prevVal) {
                result[f] += (currVal - prevVal);
            } else {
                result[f] += currVal;
            }
        }
        prev = row;
    }

    result.server_start_time = rows[rows.length - 1].server_start_time;
    result.collected_at = rows[rows.length - 1].collected_at;

    return result;
}

async function calculateTrendDaily(pool, statType, days) {
    const [rows] = await pool.query(
        `SELECT collected_at, total_accepts, total_rejects 
         FROM radius_stats 
         WHERE stat_type = ? 
         AND collected_at >= (SELECT COALESCE((SELECT MAX(collected_at) FROM radius_stats WHERE stat_type = ? AND collected_at < DATE_SUB(CURDATE(), INTERVAL ? DAY)), DATE_SUB(CURDATE(), INTERVAL ? DAY)))
         ORDER BY collected_at ASC`, [statType, statType, days, days]
    );

    const map = {};
    for(let i=days-1; i>=0; i--) {
        const d = new Date(); d.setDate(d.getDate() - i);
        map[d.toISOString().split('T')[0]] = { accepts: 0, rejects: 0 };
    }

    if (rows.length === 0) return Object.keys(map).sort().map(day => ({ day, accepts: 0, rejects: 0 }));

    let prev = rows[0];
    let startIdx = 1;

    const winStartObj = new Date();
    winStartObj.setDate(winStartObj.getDate() - days);
    winStartObj.setHours(0,0,0,0);
    const winStartMs = winStartObj.getTime();

    if (new Date(rows[0].collected_at).getTime() >= winStartMs) {
        prev = { total_accepts: 0, total_rejects: 0 };
        startIdx = 0;
    }

    for (let i = startIdx; i < rows.length; i++) {
        const r = rows[i];
        const dayStr = new Date(r.collected_at).toISOString().split('T')[0];
        if (!map[dayStr]) map[dayStr] = { accepts: 0, rejects: 0 };

        const cA = Number(r.total_accepts || 0), pA = Number(prev.total_accepts || 0);
        const cR = Number(r.total_rejects || 0), pR = Number(prev.total_rejects || 0);

        map[dayStr].accepts += (cA >= pA) ? (cA - pA) : cA;
        map[dayStr].rejects += (cR >= pR) ? (cR - pR) : cR;
        prev = r;
    }
    return Object.keys(map).sort().map(day => ({ day, accepts: map[day].accepts, rejects: map[day].rejects }));
}

async function calculateTrendHourly(pool, statType, hours) {
    const [rows] = await pool.query(
        `SELECT collected_at, total_accepts, total_rejects 
         FROM radius_stats 
         WHERE stat_type = ? 
         AND collected_at >= (SELECT COALESCE((SELECT MAX(collected_at) FROM radius_stats WHERE stat_type = ? AND collected_at < DATE_SUB(NOW(), INTERVAL ? HOUR)), DATE_SUB(NOW(), INTERVAL ? HOUR)))
         ORDER BY collected_at ASC`, [statType, statType, hours, hours]
    );

    const arr = [];
    for(let i=hours-1; i>=0; i--) {
        const d = new Date(); d.setHours(d.getHours() - i);
        arr.push({ dateObj: d, hour_label: d.getHours().toString().padStart(2, '0') + ':00', accepts: 0, rejects: 0 });
    }

    if (rows.length === 0) return arr.map(({hour_label, accepts, rejects}) => ({hour_label, accepts, rejects}));

    let prev = rows[0];
    let startIdx = 1;

    const winStartMs = Date.now() - (hours * 3600000);
    if (new Date(rows[0].collected_at).getTime() >= winStartMs) {
        prev = { total_accepts: 0, total_rejects: 0 };
        startIdx = 0;
    }

    for (let i = startIdx; i < rows.length; i++) {
        const r = rows[i];
        const rd = new Date(r.collected_at);

        const bin = arr.find(b => b.dateObj.getHours() === rd.getHours() && b.dateObj.getDate() === rd.getDate());

        const cA = Number(r.total_accepts || 0), pA = Number(prev.total_accepts || 0);
        const cR = Number(r.total_rejects || 0), pR = Number(prev.total_rejects || 0);

        if (bin) {
            bin.accepts += (cA >= pA) ? (cA - pA) : cA;
            bin.rejects += (cR >= pR) ? (cR - pR) : cR;
        }
        prev = r;
    }
    return arr.map(({hour_label, accepts, rejects}) => ({hour_label, accepts, rejects}));
}

// ─── RADIUS SERVER STATS ──────────────────────────────────────────────────────
app.get('/api/radius/stats', requireApiAuth('reports', 'read-only'), async (req, res) => {
    try {
        const { start_date, end_date } = req.query;

        const auth = await calculateRadiusStats(pool, 'auth', start_date, end_date);
        const acct = await calculateRadiusStats(pool, 'acct', start_date, end_date);

        let uptimeSeconds = null;
        if (auth && auth.server_start_time > 0) {
            uptimeSeconds = Math.floor(Date.now() / 1000) - auth.server_start_time;
        }

        const totalReq = Number(auth?.total_requests || 0);
        const totalAcc = Number(auth?.total_accepts || 0);
        const acceptRate = totalReq > 0 ? parseFloat(((totalAcc / totalReq) * 100).toFixed(1)) : null;

        res.json({ auth, acct, uptimeSeconds, acceptRate });
    } catch (err) {
        console.error('[/api/radius/stats]', err);
        res.status(500).json({ error: err.message });
    }
});

app.listen(3000, '0.0.0.0', () => {
    console.log('Radius UI Server listening on port 3000');
});


// --- MAC AUTH AUTO-CREATE WORKER ---
    apiDebugLog('MAC Auth Auto-Create worker initialized');
async function processAutoCreateMacs() {
    try {
        const [settingsRows] = await pool.query("SELECT setting_key, setting_value FROM settings WHERE setting_key IN ('mac_auth_autocreate', 'mac_auth_autocreate_plan', 'mac_auth_autocreate_profile', 'mac_auth_autocreate_interval')");
        const config = settingsRows.reduce((acc, row) => ({ ...acc, [row.setting_key]: row.setting_value }), {});

        if (config.mac_auth_autocreate !== 'true') return;

        const intervalSeconds = parseInt(config.mac_auth_autocreate_interval) || 5;
        const now = Date.now();
        if (now - lastAutoCreateMacRun < intervalSeconds * 1000) return;
        lastAutoCreateMacRun = now;


        const plan_id = config.mac_auth_autocreate_plan || '';
        const profile = config.mac_auth_autocreate_profile || '';

        // Find MACs rejected in the last 60 seconds
        const [rejectedRows] = await pool.query(`
            SELECT DISTINCT p.username 
            FROM radpostauth p
            LEFT JOIN radcheck r ON r.username = p.username
            WHERE p.reply = 'Access-Reject' 
              AND p.username REGEXP '^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$'
              AND r.username IS NULL
              AND p.authdate > DATE_SUB(NOW(), INTERVAL 1 MINUTE)
        `);

        for (let row of rejectedRows) {
            let mac_address = row.username.trim().toLowerCase().replace(/-/g, ':');
            let mac_id = mac_address;

            // Double check existence
            const [existing] = await pool.query('SELECT username FROM radcheck WHERE username = ?', [mac_address]);
            if (existing.length > 0) continue;

            const conn = await pool.getConnection();
            try {
                await conn.beginTransaction();
                await conn.query('INSERT IGNORE INTO mac_auth_devices (mac_address, mac_id) VALUES (?, ?)', [mac_address, mac_id]);
                await conn.query(`DELETE FROM radcheck WHERE username = ? AND attribute = 'Cleartext-Password'`, [mac_address]);
                await conn.query(`INSERT INTO radcheck (username, attribute, op, value) VALUES (?, 'Cleartext-Password', ':=', ?)`, [mac_address, mac_address]);
                await conn.query('DELETE FROM radusergroup WHERE username = ?', [mac_address]);
                if (profile) {
                    await conn.query('INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)', [mac_address, profile]);
                }
                await conn.query('DELETE FROM user_plans WHERE username = ?', [mac_address]);
                if (plan_id) {
                    await conn.query('INSERT INTO user_plans (username, plan_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE plan_id = VALUES(plan_id)', [mac_address, plan_id]);
                }
                await conn.commit();
                console.log(`[MAC Auto-Create Worker] Registered new MAC: ${mac_address} (Plan: ${plan_id || 'None'}, Profile: ${profile || 'None'})`);
            } catch (err) {
                await conn.rollback();
                console.error(`[MAC Auto-Create Worker] Error registering MAC ${mac_address}:`, err);
            } finally {
                conn.release();
            }
        }
    } catch (err) {
        console.error('[MAC Auto-Create Worker] Error:', err);
    }
}
setInterval(processAutoCreateMacs, 1000);



// --- STALE SESSIONS AUTO-CLEAR WORKER ---
    apiDebugLog('Stale session worker initialized');
let lastStaleSessionRun = 0;

let lastAuthLogPurgeRun = 0;
let lastAutoCreateMacRun = 0;

async function processAuthLogPurge() {
    try {
        const [settings] = await pool.query(
            "SELECT setting_key, setting_value FROM settings WHERE setting_key IN ('authlogs_purge_enabled', 'authlogs_purge_days', 'authlogs_purge_interval')"
        );
        let purgeEnabled = false;
        let purgeDays = 30;
        let intervalMinutes = 60;
        settings.forEach(s => {
            if (s.setting_key === 'authlogs_purge_enabled') purgeEnabled = (s.setting_value === 'true' || s.setting_value === '1');
            if (s.setting_key === 'authlogs_purge_days') purgeDays = parseInt(s.setting_value) || 30;
            if (s.setting_key === 'authlogs_purge_interval') intervalMinutes = parseInt(s.setting_value) || 60;
        });
        if (!purgeEnabled) return;
        const now = Date.now();
        if (now - lastAuthLogPurgeRun < intervalMinutes * 60 * 1000) return;
        lastAuthLogPurgeRun = now;
        const [result] = await pool.query(
            'DELETE FROM radpostauth WHERE authdate < DATE_SUB(NOW(), INTERVAL ? DAY)',
            [purgeDays]
        );
        if (result.affectedRows > 0) {
            await auditLog('system', 'system', `Auto-purged ${result.affectedRows} auth log entries older than ${purgeDays} days`, 'success', 'Background process auth log purge', '127.0.0.1');
            console.log(`[Background Task] Auto-purged ${result.affectedRows} auth log entries.`);
        }
    } catch (error) {
        console.error('[Background Task] Error auto-purging auth logs:', error);
    }
}

async function processStaleSessions() {
    try {
        const [settings] = await pool.query("SELECT setting_key, setting_value FROM settings WHERE setting_key IN ('clear_stale_sessions', 'stale_session_threshold', 'stale_session_interval')");
        let clearEnabled = false;
        let thresholdDays = 3;
        let intervalMinutes = 10;
        settings.forEach(s => {
            if(s.setting_key === 'clear_stale_sessions') clearEnabled = (s.setting_value === 'true' || s.setting_value === '1');
            if(s.setting_key === 'stale_session_threshold') thresholdDays = parseInt(s.setting_value) || 3;
            if(s.setting_key === 'stale_session_interval') intervalMinutes = parseInt(s.setting_value) || 10;
        });

        if (!clearEnabled) { apiDebugLog('Stale session worker skipped: Disabled in settings'); return; }

        // Throttle by interval setting
        const now = Date.now();
        if (now - lastStaleSessionRun < intervalMinutes * 60 * 1000) { apiDebugLog('Stale session worker skipped: Throttled by interval'); return; }
        lastStaleSessionRun = now;

        const query = `
            SELECT radacctid, username, nasipaddress, framedipaddress, acctstarttime, acctupdatetime,
            TIMESTAMPDIFF(HOUR, acctstarttime, NOW()) as hours_old,
            TIMESTAMPDIFF(DAY, acctstarttime, NOW()) as days_old,
            TIMESTAMPDIFF(MINUTE, acctstarttime, acctupdatetime) as up_to_start_diff,
            TIMESTAMPDIFF(HOUR, acctupdatetime, NOW()) as up_to_now_diff_hr,
            TIMESTAMPDIFF(SECOND, acctstarttime, acctupdatetime) as up_to_start_sec_diff
            FROM radacct
            WHERE acctstoptime IS NULL
            HAVING 
              (hours_old >= 3 AND up_to_start_diff > 10 AND up_to_now_diff_hr >= 1)
              OR
              (days_old >= ? AND (acctupdatetime IS NULL OR up_to_start_sec_diff <= 30))
        `;
        const [staleSessions] = await pool.query(query, [thresholdDays]);

        if (staleSessions.length > 0) {
            const sessionIds = staleSessions.map(s => s.radacctid);
            const placeholders = sessionIds.map(() => '?').join(',');
            await pool.query(`UPDATE radacct SET acctstoptime = NOW() WHERE radacctid IN (${placeholders})`, sessionIds);

            // Log as 'system' origin
            await auditLog('system', 'system', `Cleared ${sessionIds.length} stale sessions`, 'success', 'Background process auto-clear', '127.0.0.1');
            console.log(`[Background Task] Auto-cleared ${sessionIds.length} stale sessions.`);
        }
    } catch (error) {
        console.error('[Background Task] Error auto-clearing stale sessions:', error);
    }
}
setInterval(processStaleSessions, 60 * 1000);
setInterval(processAuthLogPurge, 60 * 1000); // Poll every minute, internal logic handles the defined interval
