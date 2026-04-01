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

const app = express();
const cors = require('cors');

app.use(cors());
app.use(express.json());
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
    database: process.env.DB_NAME || 'radius'
});

// Audit Logger
async function auditLog(admin_username, origin, action, result, details = '', ip = '') {
    try {
        await pool.query(
            'INSERT INTO admin_audit_log (admin_username, origin, action, result, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)',
            [admin_username, origin, action, result, details, ip]
        );
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

// --- CURRENT ADMIN (self) ---
app.get('/api/auth/me', async (req, res) => {
    const apiKey = req.header('X-API-Key');
    if (!apiKey) return res.status(401).json({ error: 'API Key missing' });
    const [admins] = await pool.query(
        'SELECT id, username, permissions FROM admins WHERE api_key = ?',
        [apiKey]
    );
    if (!admins.length) return res.status(401).json({ error: 'Invalid API Key' });
    res.json(admins[0]);
});

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

// --- SETTINGS ---
app.get('/api/settings', requireApiAuth('settings', 'read-only'), async (req, res) => {
    const [rows] = await pool.query('SELECT * FROM settings');
    res.json(rows.reduce((acc, row) => ({ ...acc, [row.setting_key]: row.setting_value }), {}));
});

app.post('/api/settings', requireApiAuth('settings', 'read-write'), async (req, res) => {
    const { enforce_2fa, radius_debug, custom_reply_attributes, ui_theme, totp_enrollment_hours, mask_user_passwords } = req.body;

    if (enforce_2fa !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('enforce_2fa', ?) ON DUPLICATE KEY UPDATE setting_value=?", [enforce_2fa, enforce_2fa]);
    if (radius_debug !== undefined) {
        await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('radius_debug', ?) ON DUPLICATE KEY UPDATE setting_value=?", [radius_debug, radius_debug]);
        exec('docker restart radius_server');
    }
    if (custom_reply_attributes !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('custom_reply_attributes', ?) ON DUPLICATE KEY UPDATE setting_value=?", [custom_reply_attributes, custom_reply_attributes]);
    if (ui_theme !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('ui_theme', ?) ON DUPLICATE KEY UPDATE setting_value=?", [ui_theme, ui_theme]);
    if (totp_enrollment_hours !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('totp_enrollment_hours', ?) ON DUPLICATE KEY UPDATE setting_value=?", [totp_enrollment_hours, totp_enrollment_hours]);
    if (mask_user_passwords !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('mask_user_passwords', ?) ON DUPLICATE KEY UPDATE setting_value=?", [mask_user_passwords, mask_user_passwords]);

    await auditLog(req.admin.username, req.origin, `Updated settings (2FA:${enforce_2fa}, Debug:${radius_debug})`, 'success', '', req.ip);
    res.json({ success: true });
});

// --- SYSTEM HEALTH ---
app.get('/api/system/status', requireApiAuth('settings', 'read-only'), (req, res) => {
    exec('docker ps -a --format "{{.Names}}|{{.State}}|{{.Status}}" | grep radius_', (error, stdout) => {
        if (error) return res.json([]);
        const containers = stdout.trim().split('\n').filter(Boolean).map(line => {
            const [name, state, status] = line.split('|');
            return { name, state, status };
        });
        res.json(containers);
    });
});

app.post('/api/system/restart/:container', requireApiAuth('settings', 'read-write'), (req, res) => {
    const { container } = req.params;
    if (!container.startsWith('radius_')) return res.status(403).json({ error: 'Invalid container' });

    exec(`docker restart ${container}`, async (error) => {
        if (error) {
            await auditLog(req.admin.username, req.origin, `Restart container ${container}`, 'failed', error.message, req.ip);
            return res.status(500).json({ error: error.message });
        }
        await auditLog(req.admin.username, req.origin, `Restarted container ${container}`, 'success', '', req.ip);
        res.json({ success: true });
    });
});

app.get('/api/system/logs/:container', requireApiAuth('settings', 'read-only'), (req, res) => {
    const { container } = req.params;
    if (!container.startsWith('radius_')) return res.status(403).json({ error: 'Invalid container' });

    exec(`docker logs --tail 200 ${container}`, (error, stdout, stderr) => {
        res.json({ logs: stdout + stderr });
    });
});

// --- CERTS ---
app.post('/api/certs/generate', requireApiAuth('settings', 'read-write'), (req, res) => {
    const { c = 'US', st = 'State', l = 'City', o = 'Radius', cn = 'RadiusServer' } = req.body;
    const subj = `/C=${c}/ST=${st}/L=${l}/O=${o}/CN=${cn}`;
    const cmd = `openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -keyout /certs_shared/server.key -out /certs_shared/server.pem -subj "${subj}"`;

    exec(cmd, async (error) => {
        if (error) {
            await auditLog(req.admin.username, req.origin, 'Generate EAP certificate', 'failed', error.message, req.ip);
            return res.status(500).json({ error: error.message });
        }
        exec('docker restart radius_server');
        await auditLog(req.admin.username, req.origin, 'Generated new 10-year EAP certificate', 'success', `Subject: ${subj}`, req.ip);
        res.json({ success: true });
    });
});

app.post('/api/certs/upload', requireApiAuth('settings', 'read-write'), upload.fields([{ name: 'cert' }, { name: 'key' }]), async (req, res) => {
    try {
        const certPath = req.files['cert'][0].path;
        const keyPath = req.files['key'][0].path;
        const pwd = req.body.password;

        await fs.copyFile(certPath, '/certs_shared/server.pem');

        if (pwd) {
            await new Promise((resolve, reject) => {
                exec(`openssl rsa -in ${keyPath} -passin env:PK_PASS -out /certs_shared/server.key`,
                    { env: { ...process.env, PK_PASS: pwd } },
                    (err) => err ? reject(err) : resolve()
                );
            });
        } else {
            await fs.copyFile(keyPath, '/certs_shared/server.key');
        }

        exec('docker restart radius_server');
        await auditLog(req.admin.username, req.origin, 'Uploaded custom EAP certificate', 'success', 'Radius restarted', req.ip);
        res.json({ success: true });
    } catch (err) {
        await auditLog(req.admin.username, req.origin, 'Upload EAP certificate', 'failed', err.message, req.ip);
        res.status(500).json({ error: err.message });
    }
});

// === CERT DETAILS & DOWNLOAD (fixes "Loading..." and Download button) ===
app.get('/api/certs/details', requireApiAuth('settings', 'read-only'), (req, res) => {
    exec('openssl x509 -in /certs_shared/server.pem -text -noout', (error, stdout, stderr) => {
        if (error) {
            return res.json({
                details: 'Certificate file not found or invalid.\n\n' +
                    'Click "Generate New 10-Year Certificate" above to create one.'
            });
        }
        res.json({ details: stdout.trim() || 'Certificate exists but has no readable details.' });
    });
});

app.get('/api/certs/download', requireApiAuth('settings', 'read-only'), (req, res) => {
    const filePath = '/certs_shared/server.pem';
    res.download(filePath, 'radius-server.pem', (err) => {
        if (err) res.status(404).json({ error: 'Certificate not found' });
    });
});

// --- ADMINS ---
app.get('/api/admins', requireApiAuth('admins', 'read-only'), async (req, res) => {
    const [rows] = await pool.query('SELECT id, username, require_password_change, two_factor_enabled, two_factor_setup_complete, api_key, permissions FROM admins');
    res.json(rows);
});

const crypto = require('crypto');

app.post('/api/admins', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { username, password, permissions, enable_2fa } = req.body;
    const hash = await bcrypt.hash(password, 10);
    const apikey = crypto.randomBytes(32).toString('hex');
    try {
        const [settingRows] = await pool.query("SELECT setting_value FROM settings WHERE setting_key = 'enforce_2fa'");
        const enforce2fa = settingRows.length > 0 && settingRows[0].setting_value === 'true';
        const is2faEnabled = enforce2fa || !!enable_2fa;

        await pool.query('INSERT INTO admins (username, password_hash, api_key, permissions, two_factor_enabled, two_factor_setup_complete) VALUES (?, ?, ?, ?, ?, false)', [username, hash, apikey, JSON.stringify(permissions), is2faEnabled]);
        await auditLog(req.admin.username, req.origin, `Created admin: ${username}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.put('/api/admins/:id', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { id } = req.params;
    const { username, password, permissions } = req.body;
    try {
        if (password) {
            const hash = await bcrypt.hash(password, 10);
            await pool.query('UPDATE admins SET username = ?, password_hash = ?, permissions = ? WHERE id = ?', [username, hash, JSON.stringify(permissions), id]);
        } else {
            await pool.query('UPDATE admins SET username = ?, permissions = ? WHERE id = ?', [username, JSON.stringify(permissions), id]);
        }
        await auditLog(req.admin.username, req.origin, `Updated admin: ${username}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(400).json({ error: err.message });
    }
});

app.delete('/api/admins/:id', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { id } = req.params;
    await pool.query('DELETE FROM administrators WHERE id = ?', [id]);
    await auditLog(req.admin.username, req.origin, `Deleted admin ID: ${id}`, 'success', '', req.ip);
    res.json({ success: true });
});

app.post('/api/admins/:id/generate-key', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { id } = req.params;
    const newKey = crypto.randomBytes(32).toString('hex');
    try {
        await pool.query('UPDATE admins SET api_key = ? WHERE id = ?', [newKey, id]);
        await auditLog(req.admin.username, req.origin, `Generated new API key for admin ID: ${id}`, 'success', '', req.ip);
        res.json({ success: true, apiKey: newKey });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admins/:id/enable-2fa', requireApiAuth('admins', 'read-write'), async (req, res) => {
    const { id } = req.params;
    try {
        const [admins] = await pool.query('SELECT * FROM admins WHERE id = ?', [id]);
        const admin = admins[0];
        if (!admin) return res.status(404).json({ error: 'Admin not found' });

        const secret = authenticator.generateSecret();
        await pool.query('UPDATE admins SET two_factor_enabled = true, two_factor_setup_complete = true, two_factor_secret = ? WHERE id = ?', [secret, id]);

        const qrImage = await qrcode.toDataURL(authenticator.keyuri(admin.username, 'RadiusFullStack', secret));

        await auditLog(req.admin.username, req.origin, `Enabled 2FA for admin: ${admin.username}`, 'success', '', req.ip);
        res.json({ success: true, qrImage, secret });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/admins/:id/disable-2fa', requireApiAuth('settings', 'read-write'), async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('UPDATE admins SET two_factor_enabled = false, two_factor_setup_complete = false, two_factor_secret = NULL WHERE id = ?', [id]);
        await auditLog(req.admin.username, req.origin, `Disabled 2FA for admin ID: ${id}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- PLANS ---
app.get('/api/plans', requireApiAuth('plans', 'read-only'), async (req, res) => {
    const [rows] = await pool.query('SELECT * FROM plans ORDER BY id DESC');
    res.json(rows);
});

app.post('/api/plans', requireApiAuth('plans', 'read-write'), async (req, res) => {
    const { name, data_limit_mb, time_limit_seconds, reset_period } = req.body;
    try {
        await pool.query('INSERT INTO plans (name, data_limit_mb, time_limit_seconds, reset_period) VALUES (?, ?, ?, ?)',
            [name, data_limit_mb || 0, time_limit_seconds || 0, reset_period || 'never']);
        await auditLog(req.admin.username, req.origin, `Created plan: ${name}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/plans/:id', requireApiAuth('plans', 'read-write'), async (req, res) => {
    const { id } = req.params;
    const { name, data_limit_mb, time_limit_seconds, reset_period } = req.body;
    try {
        await pool.query('UPDATE plans SET name=?, data_limit_mb=?, time_limit_seconds=?, reset_period=? WHERE id=?',
            [name, data_limit_mb || 0, time_limit_seconds || 0, reset_period || 'never', id]);
        await auditLog(req.admin.username, req.origin, `Updated plan ID: ${id}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/plans/:id', requireApiAuth('plans', 'read-write'), async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM plans WHERE id = ?', [id]);
        await auditLog(req.admin.username, req.origin, `Deleted plan ID: ${id}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- NAS ---
app.get('/api/nas', requireApiAuth('nas', 'read-only'), async (req, res) => {
    const [rows] = await pool.query('SELECT * FROM nas');
    res.json(rows);
});

app.post('/api/nas', requireApiAuth('nas', 'read-write'), async (req, res) => {
    const { nasname, shortname, type, secret, description } = req.body;
    await pool.query('INSERT INTO nas (nasname, shortname, type, secret, description) VALUES (?, ?, ?, ?, ?)', [nasname, shortname, type || 'other', secret, description]);
    await auditLog(req.admin.username, req.origin, `Created NAS: ${nasname} (${shortname})`, 'success', '', req.ip);
    res.json({ success: true });
});

app.put('/api/nas/:id', requireApiAuth('nas', 'read-write'), async (req, res) => {
    const { id } = req.params;
    const { nasname, shortname, type, secret, description } = req.body;
    try {
        await pool.query('UPDATE nas SET nasname=?, shortname=?, type=?, secret=?, description=? WHERE id=?', [nasname, shortname, type || 'other', secret, description, id]);
        await auditLog(req.admin.username, req.origin, `Updated NAS: ${nasname}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/nas/:id', requireApiAuth('nas', 'read-write'), async (req, res) => {
    const [nas] = await pool.query('SELECT * FROM nas WHERE id = ?', [req.params.id]);
    await pool.query('DELETE FROM nas WHERE id = ?', [req.params.id]);
    await auditLog(req.admin.username, req.origin, `Deleted NAS: ${nas[0]?.nasname}`, 'success', '', req.ip);
    res.json({ success: true });
});

// --- PROFILES ---
app.get('/api/profiles', requireApiAuth('users', 'read-only'), async (req, res) => {
    const [rows] = await pool.query('SELECT DISTINCT groupname FROM (SELECT groupname FROM radgroupreply UNION SELECT groupname FROM radgroupcheck UNION SELECT groupname FROM radusergroup) AS profiles WHERE groupname != ""');
    res.json(rows.map(r => r.groupname));
});

app.post('/api/profiles/attributes', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { profile, attribute, type, value } = req.body;
    const table = type === 'reply' ? 'radgroupreply' : 'radgroupcheck';
    const op = type === 'reply' ? '=' : '==';
    await pool.query(`INSERT INTO ${table} (groupname, attribute, op, value) VALUES (?, ?, ?, ?)`, [profile, attribute, op, value]);
    await auditLog(req.admin.username, req.origin, `Added ${type} attribute to profile ${profile}`, 'success', `${attribute}=${value}`, req.ip);
    res.json({ success: true });
});

app.post('/api/profiles/nas', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { profile, nas_id } = req.body;
    const [nas] = await pool.query('SELECT nasname FROM nas WHERE id = ?', [nas_id]);
    if (!nas.length) return res.status(404).json({ error: 'NAS not found' });

    const ip = nas[0].nasname.split('/')[0];
    await pool.query(`INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES (?, 'NAS-IP-Address', '+=', ?)`, [profile, ip]);
    await auditLog(req.admin.username, req.origin, `Added NAS-IP-Address check to profile ${profile}`, 'success', `NAS: ${ip}`, req.ip);
    res.json({ success: true });
});

app.get('/api/profiles/data', requireApiAuth('users', 'read-only'), async (req, res) => {
    const [checks] = await pool.query('SELECT * FROM radgroupcheck');
    const [replies] = await pool.query('SELECT * FROM radgroupreply');
    res.json({ checks, replies });
});

// === FULL PROFILE CREATE / UPDATE - FIXED FOR EMPTY NAS/VLAN ===
app.post('/api/profiles/:name', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { name } = req.params;
    let { nas_ips = [], vlan_id = '', reply_attributes = [] } = req.body;

    if (!name || typeof name !== 'string' || name.trim() === '') {
        return res.status(400).json({ error: 'Profile name is required' });
    }

    nas_ips = Array.isArray(nas_ips) ? nas_ips.filter(ip => typeof ip === 'string' && ip.trim() !== '') : [];
    vlan_id = typeof vlan_id === 'string' ? vlan_id.trim() : '';
    reply_attributes = Array.isArray(reply_attributes) ? reply_attributes : [];

    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();

        // Clear existing data
        await conn.query('DELETE FROM radgroupcheck WHERE groupname = ?', [name]);
        await conn.query('DELETE FROM radgroupreply WHERE groupname = ?', [name]);

        // NAS-IP-Address (works with empty array)
        if (nas_ips.length > 0) {
            for (const ip of nas_ips) {
                await conn.query(
                    `INSERT INTO radgroupcheck (groupname, attribute, op, value) 
                     VALUES (?, 'NAS-IP-Address', '+=', ?)`,
                    [name, ip]
                );
            }
        }

        // VLAN (only if provided)
        if (vlan_id !== '') {
            await conn.query(
                `INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES 
                 (?, 'Tunnel-Type', '=', 'VLAN'),
                 (?, 'Tunnel-Medium-Type', '=', 'IEEE-802'),
                 (?, 'Tunnel-Private-Group-ID', '=', ?)`,
                [name, name, name, vlan_id]
            );
        }

        // Reply Attributes
        for (const attr of reply_attributes) {
            const attrName = (attr.attribute || '').toString().trim();
            const attrValue = (attr.value || '').toString().trim();

            if (attrName && attrValue) {
                await conn.query(
                    `INSERT INTO radgroupreply (groupname, attribute, op, value) 
                     VALUES (?, ?, '=', ?)`,
                    [name, attrName, attrValue]
                );
            }
        }

        await conn.commit();

        await auditLog(req.admin.username, req.origin, `Saved profile: ${name}`, 'success',
            `NAS: ${nas_ips.length}, VLAN: ${vlan_id || 'none'}, Attributes: ${reply_attributes.length}`, req.ip);

        res.json({ success: true });

    } catch (err) {
        await conn.rollback();
        console.error('Profile save error:', err);
        res.status(500).json({ error: err.message || 'Failed to save profile' });
    } finally {
        conn.release();
    }
});

// Support PUT
app.put('/api/profiles/:name', requireApiAuth('users', 'read-write'), (req, res) => {
    req.method = 'POST';
    return app._router.handle(req, res);
});

app.delete('/api/profiles/:name', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { name } = req.params;
    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();

        await conn.query('DELETE FROM radgroupcheck WHERE groupname = ?', [name]);
        await conn.query('DELETE FROM radgroupreply WHERE groupname = ?', [name]);
        // Remove users from this profile
        await conn.query('DELETE FROM radusergroup WHERE groupname = ?', [name]);

        await conn.commit();
        await auditLog(req.admin.username, req.origin, `Deleted profile: ${name}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        await conn.rollback();
        console.error('Delete Profile Error:', err);
        res.status(500).json({ error: 'Failed to delete profile' });
    } finally {
        conn.release();
    }
});

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
            const port = process.env.WEB_UI_PORT === '80' ? '' : `:${process.env.WEB_UI_PORT || '80'}`;
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
                const baseUrl = `${req.protocol}://${req.hostname}`; // Behind proxy
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

// --- REPORTS ---
app.get('/api/sessions/active', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const { limit = 200, username, nasip, callingstationid, framedip } = req.query;
    const queryLimit = Math.min(parseInt(limit) || 200, 1000);
    const conditions = ['a.acctstoptime IS NULL'];
    const params = [];
    if (username) { conditions.push('(a.username = ? OR m.mac_id = ?)'); params.push(username, username); }
    if (nasip) { conditions.push('a.nasipaddress = ?'); params.push(nasip); }
    if (callingstationid) { conditions.push('a.callingstationid LIKE ?'); params.push('%' + callingstationid + '%'); }
    if (framedip) { conditions.push('a.framedipaddress LIKE ?'); params.push('%' + framedip + '%'); }
    const where = conditions.join(' AND ');
    const [rows] = await pool.query(
        'SELECT a.*, COALESCE(m.mac_id, a.username) AS username FROM radacct a LEFT JOIN mac_auth_devices m ON m.mac_address = a.username WHERE ' + where + ' ORDER BY a.acctstarttime DESC LIMIT ?',
        [...params, queryLimit]
    );
    res.json(rows);
});

app.get('/api/logs/auth', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const { username, nasip, callingstationid, date_from, date_to, limit = 100 } = req.query;
    let query = 'SELECT p.*, COALESCE(m.mac_id, p.username) AS username FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address = p.username';
    const conditions = [], params = [];
    if (username) { conditions.push('(p.username = ? OR m.mac_id = ?)'); params.push(username, username); }
    if (nasip) { conditions.push('p.nasipaddress = ?'); params.push(nasip); }
    if (callingstationid) { conditions.push('p.callingstationid LIKE ?'); params.push('%' + callingstationid + '%'); }
    if (date_from) { conditions.push('p.authdate >= ?'); params.push(new Date(date_from).toISOString().slice(0, 19).replace('T', ' ')); }
    if (date_to) { conditions.push('p.authdate <= ?'); params.push(new Date(date_to).toISOString().slice(0, 19).replace('T', ' ')); }
    if (conditions.length > 0) query += ' WHERE ' + conditions.join(' AND ');
    query += ' ORDER BY authdate DESC';
    const queryLimit = Math.min(parseInt(limit) || 100, 10000);
    query += ' LIMIT ?';
    params.push(queryLimit);
    const [rows] = await pool.query(query, params);
    res.json(rows);
});

// LIVE STATS DASHBOARD
app.get('/api/reports/live-stats', requireApiAuth('reports', 'read-only'), async (req, res) => {
    try {
        const [[{ active_sessions }]] = await pool.query("SELECT COUNT(*) AS active_sessions FROM radacct WHERE acctstoptime IS NULL");
        const [[{ accepts_1h }]] = await pool.query("SELECT COUNT(*) AS accepts_1h FROM radpostauth WHERE reply = 'Access-Accept' AND authdate >= DATE_SUB(NOW(), INTERVAL 1 HOUR)");
        const [[{ rejects_1h }]] = await pool.query("SELECT COUNT(*) AS rejects_1h FROM radpostauth WHERE reply = 'Access-Reject' AND authdate >= DATE_SUB(NOW(), INTERVAL 1 HOUR)");
        const [[{ accepts_24h }]] = await pool.query("SELECT COUNT(*) AS accepts_24h FROM radpostauth WHERE reply = 'Access-Accept' AND authdate >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
        const [[{ rejects_24h }]] = await pool.query("SELECT COUNT(*) AS rejects_24h FROM radpostauth WHERE reply = 'Access-Reject' AND authdate >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
        const [[{ unique_users_24h }]] = await pool.query("SELECT COUNT(DISTINCT username) AS unique_users_24h FROM radpostauth WHERE authdate >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
        const [nas_breakdown] = await pool.query("SELECT nasipaddress, COUNT(*) AS session_count FROM radacct WHERE acctstoptime IS NULL GROUP BY nasipaddress ORDER BY session_count DESC LIMIT 8");
        const [hourly_trend] = await pool.query("SELECT DATE_FORMAT(authdate,'%H:00') AS hour_label, SUM(reply='Access-Accept') AS accepts, SUM(reply='Access-Reject') AS rejects FROM radpostauth WHERE authdate >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY DATE_FORMAT(authdate,'%Y-%m-%d %H:00:00') ORDER BY MIN(authdate)");
        const [[{ avg_session_min }]] = await pool.query("SELECT ROUND(AVG(acctsessiontime)/60,1) AS avg_session_min FROM radacct WHERE acctstoptime IS NOT NULL AND acctstarttime >= DATE_SUB(NOW(), INTERVAL 24 HOUR)");
        res.json({ active_sessions: Number(active_sessions), accepts_1h: Number(accepts_1h), rejects_1h: Number(rejects_1h), accepts_24h: Number(accepts_24h), rejects_24h: Number(rejects_24h), unique_users_24h: Number(unique_users_24h), avg_session_min: Number(avg_session_min) || 0, nas_breakdown, hourly_trend });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// USER EXECUTIVE REPORT
app.get('/api/reports/user/:username', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const { username } = req.params;
    const { start_date, end_date } = req.query;

    const [macMapping] = await pool.query('SELECT mac_address FROM mac_auth_devices WHERE mac_id = ? OR mac_address = ? LIMIT 1', [username, username]);
    const realUsername = macMapping.length > 0 ? macMapping[0].mac_address : username;

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

// FAILED AUTH REPORT
app.get('/api/reports/failed-auth', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const [details] = await pool.query("SELECT p.*, COALESCE(m.mac_id, p.username) AS username FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address = p.username WHERE p.reply = 'Access-Reject' ORDER BY p.authdate DESC LIMIT 500");
    const [summary] = await pool.query("SELECT COALESCE(m.mac_id, p.username) AS username, COUNT(*) as fail_count FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address = p.username WHERE p.reply = 'Access-Reject' GROUP BY COALESCE(m.mac_id, p.username) ORDER BY fail_count DESC");
    res.json({ details, summary });
});

// PDF GENERATION
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

// Add this under the --- REPORTS --- section in server.js
app.get('/api/reports/dashboard-stats', requireApiAuth('reports', 'read-only'), async (req, res) => {
    try {
        // 1. Top 20 Users by Session Count (Last 7 Days)
        const [topSessions] = await pool.query(`
            SELECT 
                username, 
                COUNT(*) as session_count,
                SUM(acctinputoctets + acctoutputoctets) / 1073741824 as data_gb
            FROM radacct 
            WHERE acctstarttime >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY username 
            ORDER BY session_count DESC 
            LIMIT 20
        `);

        // 2. Top 20 Users by Data Usage (Last 7 Days)
        const [topData] = await pool.query(`
            SELECT 
                COALESCE(m.mac_id, a.username) AS username, 
                SUM(a.acctinputoctets + a.acctoutputoctets) / 1048576 as data_mb
            FROM radacct a
            LEFT JOIN mac_auth_devices m ON m.mac_address = a.username
            WHERE a.acctstarttime >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY COALESCE(m.mac_id, a.username) 
            ORDER BY data_mb DESC 
            LIMIT 20
        `);

        res.json({ topSessions, topData });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// === DASHBOARD OVERVIEW ===
app.get('/api/reports/dashboard-overview', requireApiAuth('reports', 'read-only'), async (req, res) => {
    try {
        const [[users]] = await pool.query("SELECT COUNT(*) AS cnt FROM radcheck WHERE username NOT IN (SELECT mac_address FROM mac_auth_devices)");
        const [[macs]] = await pool.query("SELECT COUNT(*) AS cnt FROM mac_auth_devices");
        const [[nas]] = await pool.query("SELECT COUNT(*) AS cnt FROM nas");
        const [[plans]] = await pool.query("SELECT COUNT(*) AS cnt FROM plans");
        const [[activeSess]] = await pool.query("SELECT COUNT(*) AS cnt FROM radacct WHERE acctstoptime IS NULL");
        const [[totalSess]] = await pool.query("SELECT COUNT(*) AS cnt FROM radacct");
        const [[authToday]] = await pool.query("SELECT COUNT(*) AS cnt FROM radpostauth WHERE authdate >= CURDATE()");
        const [[rejectToday]] = await pool.query("SELECT COUNT(*) AS cnt FROM radpostauth WHERE reply='Access-Reject' AND authdate >= CURDATE()");
        const [[dataToday]] = await pool.query("SELECT COALESCE(SUM(acctinputoctets+acctoutputoctets),0) AS bytes FROM radacct WHERE DATE(acctstarttime)=CURDATE()");
        const [[dataWeek]] = await pool.query("SELECT COALESCE(SUM(acctinputoctets+acctoutputoctets),0) AS bytes FROM radacct WHERE acctstarttime >= DATE_SUB(NOW(),INTERVAL 7 DAY)");
        const [recentAuths] = await pool.query("SELECT p.reply, COALESCE(m.mac_id,p.username) AS username, p.nasipaddress, p.authdate FROM radpostauth p LEFT JOIN mac_auth_devices m ON m.mac_address=p.username ORDER BY p.authdate DESC LIMIT 8");
        const [authTrend7d] = await pool.query("SELECT DATE(authdate) AS day, SUM(reply='Access-Accept') AS accepts, SUM(reply='Access-Reject') AS rejects FROM radpostauth WHERE authdate >= DATE_SUB(NOW(),INTERVAL 7 DAY) GROUP BY DATE(authdate) ORDER BY day ASC");
        const [nasLoad] = await pool.query("SELECT nasipaddress, COUNT(*) AS active FROM radacct WHERE acctstoptime IS NULL GROUP BY nasipaddress ORDER BY active DESC LIMIT 6");
        const [profileDist] = await pool.query("SELECT groupname, COUNT(*) AS cnt FROM radusergroup GROUP BY groupname ORDER BY cnt DESC LIMIT 8");
        const [planDist] = await pool.query("SELECT p.name, COUNT(up.plan_id) AS cnt FROM plans p LEFT JOIN user_plans up ON up.plan_id=p.id GROUP BY p.id ORDER BY cnt DESC LIMIT 8");
        res.json({
            counts: { users: Number(users.cnt), macs: Number(macs.cnt), nas: Number(nas.cnt), plans: Number(plans.cnt), activeSessions: Number(activeSess.cnt), totalSessions: Number(totalSess.cnt), authToday: Number(authToday.cnt), rejectToday: Number(rejectToday.cnt) },
            data: { today: Number(dataToday.bytes), week: Number(dataWeek.bytes) },
            recentAuths, authTrend7d, nasLoad, profileDist, planDist
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// === ACCOUNTING HISTORY API ===
app.get('/api/accounting', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const { username, nasip, start_date, end_date, sort = 'acctstarttime', order = 'desc', limit = 300 } = req.query;

    let query = `
        SELECT 
            a.*,
            (a.acctinputoctets + a.acctoutputoctets) AS total_data,
            COALESCE(m.mac_id, a.username) AS username
        FROM radacct a
        LEFT JOIN mac_auth_devices m ON m.mac_address = a.username
        WHERE 1=1
    `;
    const params = [];

    if (username) {
        query += ' AND (a.username = ? OR m.mac_id = ?)';
        params.push(username, username);
    }
    if (nasip) {
        query += ' AND nasipaddress = ?';
        params.push(nasip);
    }
    if (start_date) {
        query += ' AND acctstarttime >= ?';
        params.push(start_date);
    }
    if (end_date) {
        query += ' AND acctstarttime <= ?';
        params.push(end_date + ' 23:59:59'); // include whole day
    }

    // Basic sorting protection
    const allowedSort = ['acctstarttime', 'acctstoptime', 'username', 'nasipaddress', 'acctsessiontime', 'acctinputoctets', 'acctoutputoctets', 'total_data'];
    const sortField = allowedSort.includes(sort) ? sort : 'acctstarttime';
    const sortOrder = order.toLowerCase() === 'asc' ? 'ASC' : 'DESC';

    query += ` ORDER BY ${sortField} ${sortOrder} LIMIT ?`;
    params.push(parseInt(limit));

    try {
        const [rows] = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch accounting data' });
    }
});

app.delete('/api/accounting', requireApiAuth('reports', 'read-write'), async (req, res) => {
    const { username, nasip, start_date, end_date } = req.body;

    if (!username && !nasip && !start_date && !end_date) {
        return res.status(400).json({ error: 'At least one filter is required for safety' });
    }

    let query = 'DELETE FROM radacct WHERE 1=1';
    const params = [];

    if (username) { query += ' AND username = ?'; params.push(username); }
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

// Start Server

app.post('/api/users/:username/totp/reset', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { username } = req.params;
    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();
        await conn.query(
            `INSERT INTO user_totp (username, enabled, secret, pending_secret, enrolled_at)
             VALUES (?, 1, NULL, NULL, NULL)
             ON DUPLICATE KEY UPDATE secret = NULL, pending_secret = NULL, enrolled_at = NULL`,
            [username]
        );
        await syncUserTotpToRadius(conn, username);

        const eData = await generateEnrollmentCode(conn, username);
        const baseUrl = `${req.protocol}://${req.hostname}`;
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
        const radiusPassword = await getRadiusPassword(username);
        if (!radiusPassword || radiusPassword !== password) {
            await auditLog(username, 'webui', 'User TOTP enrollment login', 'failed', 'Invalid RADIUS credentials', ip);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const [rows] = await pool.query(
            `SELECT username, enabled, secret, pending_secret, enrolled_at, enrollment_code_hash, enrollment_expires_at
             FROM user_totp WHERE username = ? LIMIT 1`, [username]
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
                `UPDATE user_totp SET pending_secret = ?, enrolled_at = NULL WHERE username = ?`,
                [secret, username]
            );
        }

        const otpauth = authenticator.keyuri(username, TOTP_ISSUER, secret);
        const qrImage = await qrcode.toDataURL(otpauth);
        const token = signTotpEnrollmentToken(username);

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
        const [rows] = await pool.query(
            `SELECT username, enabled, secret, pending_secret FROM user_totp WHERE username = ? LIMIT 1`, [username]
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
                `UPDATE user_totp SET secret = ?, pending_secret = NULL, enrollment_code_hash = NULL, enrolled_at = NOW() WHERE username = ?`, [secret, username]
            );
            await syncUserTotpToRadius(conn, username);
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


// --- DATABASE BACKUP & RESTORE ---

app.get('/api/system/backup', requireApiAuth('admins', 'read-only'), async (req, res) => {
    const { type, acct, auth, audit } = req.query;

    try {
        const backup = {
            metadata: {
                type: type === 'full' ? 'full' : 'partial',
                timestamp: new Date().toISOString(),
                version: '1.0'
            },
            data: {}
        };

        let tablesToBackup = [];

        if (type === 'full') {
            const [tables] = await pool.query("SHOW TABLES");
            tablesToBackup = tables.map(t => Object.values(t)[0]);
        } else {
            tablesToBackup = [
                'admins', 'nas', 'plans', 'user_plans', 'user_plan_usage', 'user_totp',
                'radcheck', 'radreply', 'radusergroup', 'radgroupcheck', 'radgroupreply', 'settings'
            ];
            if (acct === 'true') tablesToBackup.push('radacct');
            if (auth === 'true') tablesToBackup.push('radpostauth');
            if (audit === 'true') tablesToBackup.push('admin_audit_log');
        }

        for (const table of tablesToBackup) {
            try {
                const [rows] = await pool.query(`SELECT * FROM ??`, [table]);
                backup.data[table] = rows;
            } catch (e) {
                console.warn(`Skipping missing table for backup: ${table}`);
            }
        }

        await auditLog(req.admin.username, req.origin, `Generated ${type} database backup`, 'success', '', req.ip);

        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="radius_${type}_backup.json"`);
        res.send(JSON.stringify(backup));
    } catch (err) {
        console.error("Backup generation error:", err);
        res.status(500).json({ error: 'Failed to generate backup' });
    }
});

app.post('/api/system/restore', requireApiAuth('admins', 'read-write'), upload.single('backup'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No backup file provided' });

    const fs = require('fs');
    let backup;
    try {
        const fileContent = fs.readFileSync(req.file.path, 'utf8');
        backup = JSON.parse(fileContent);
        fs.unlinkSync(req.file.path);
    } catch (e) {
        return res.status(400).json({ error: 'Invalid JSON backup file' });
    }

    if (!backup.metadata || !backup.data) {
        return res.status(400).json({ error: 'Unrecognized backup format' });
    }

    const type = backup.metadata.type;
    const tables = Object.keys(backup.data);
    const conn = await pool.getConnection();

    try {
        await conn.beginTransaction();

        const [existingTablesRaw] = await conn.query("SHOW TABLES");
        const existingTables = existingTablesRaw.map(t => Object.values(t)[0]);

        let restoredCounts = {};
        await conn.query('SET FOREIGN_KEY_CHECKS = 0');

        for (const table of tables) {
            if (!existingTables.includes(table)) {
                console.warn(`Restore skipping table ${table}: doesn't exist in current DB`);
                continue;
            }

            const rows = backup.data[table];
            if (!rows || rows.length === 0) continue;

            if (type === 'full') {
                await conn.query(`TRUNCATE TABLE ??`, [table]);
            }

            // Use REPLACE to cleanly overwrite duplicates with the backup's data
            const queryCmd = type === 'full' ? 'INSERT' : 'REPLACE';

            const [columnsRaw] = await conn.query(`SHOW COLUMNS FROM ??`, [table]);
            const validColumns = columnsRaw.map(c => c.Field);

            for (const row of rows) {
                // Filter out columns that were in the backup but no longer exist in the new schema version
                const rowCols = Object.keys(row).filter(c => validColumns.includes(c));
                const rowVals = rowCols.map(c => {
                    let val = row[c];
                    if (typeof val === 'string' && val.length >= 19 && val[10] === 'T') {
                        val = val.slice(0, 19).replace('T', ' ');
                    }
                    return val;
                });

                if (rowCols.length > 0) {
                    const placeholders = new Array(rowCols.length).fill('?').join(',');
                    await conn.query(
                        `${queryCmd} INTO ?? (??) VALUES (${placeholders})`,
                        [table, rowCols, ...rowVals]
                    );
                }
            }
            restoredCounts[table] = rows.length;
        }

        await conn.query('SET FOREIGN_KEY_CHECKS = 1');

        // Reset admin password to default if admins table was truncated and restored empty?
        // Let's assume the backup has the admin.

        // Let's do a quick sync for totp secrets after restore
        if (tables.includes('user_totp')) {
            // Because radcheck and user_totp might have gotten out of sync
            // Actually, REPLACE INTO radcheck would have restored the TOTP-Secret properly if it was in the backup.
        }

        await conn.commit();
        await auditLog(req.admin.username, req.origin, `Restored ${type} database backup`, 'success', `Restored tables: ${Object.keys(restoredCounts).join(', ')}`, req.ip);

        res.json({
            success: true,
            message: `Tables processed: ${Object.keys(restoredCounts).length}`
        });

    } catch (err) {
        await conn.query('SET FOREIGN_KEY_CHECKS = 1');
        await conn.rollback();
        console.error("Restore Error:", err);
        res.status(500).json({ error: 'Failed to restore backup: ' + err.message });
    } finally {
        conn.release();
    }
});



// --- MAC AUTH ---
app.get('/api/mac-auth', requireApiAuth('users', 'read-only'), async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT
                m.mac_id,
                m.mac_address,
                g.groupname AS profile,
                up.plan_id,
                p.name AS plan_name,
                COALESCE(a.data_30d, 0) AS data_30d,
                COALESCE(a.time_30d, 0) AS time_30d
            FROM mac_auth_devices m
            LEFT JOIN radusergroup g ON g.username = m.mac_address
            LEFT JOIN user_plans up ON up.username = m.mac_address
            LEFT JOIN plans p ON p.id = up.plan_id
            LEFT JOIN (
                SELECT username,
                       SUM(acctinputoctets + acctoutputoctets) AS data_30d,
                       SUM(acctsessiontime) AS time_30d
                FROM radacct
                WHERE acctstarttime >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                GROUP BY username
            ) a ON a.username = m.mac_address
            ORDER BY m.mac_id ASC
        `);
        res.json(rows);
    } catch (err) {
        console.error("GET /api/mac-auth Error:", err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/mac-auth', requireApiAuth('users', 'read-write'), async (req, res) => {
    let { mac_id, mac_address, profile, plan_id } = req.body;
    if (!mac_id || !mac_address) return res.status(400).json({ error: 'MAC ID and Address required' });

    mac_address = mac_address.trim().toLowerCase().replace(/-/g, ':');
    if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac_address)) return res.status(400).json({ error: 'Invalid MAC address format' });

    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();
        await conn.query('INSERT INTO mac_auth_devices (mac_address, mac_id) VALUES (?, ?)', [mac_address, mac_id]);
        await conn.query(`DELETE FROM radcheck WHERE username = ? AND attribute = 'Cleartext-Password'`, [mac_address]);
        await conn.query(`INSERT INTO radcheck (username, attribute, op, value) VALUES (?, 'Cleartext-Password', ':=', ?)`, [mac_address, mac_address]);
        await conn.query('DELETE FROM radusergroup WHERE username = ?', [mac_address]);
        if (profile) await conn.query('INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)', [mac_address, profile]);
        if (plan_id) await conn.query('INSERT INTO user_plans (username, plan_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE plan_id = VALUES(plan_id)', [mac_address, plan_id]);
        else await conn.query('DELETE FROM user_plans WHERE username = ?', [mac_address]);
        await conn.query('DELETE FROM user_totp WHERE username = ?', [mac_address]);
        await conn.commit();
        res.json({ message: 'MAC authenticated device created' });
    } catch (err) {
        await conn.rollback();
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'MAC ID or Address already exists' });
        res.status(500).json({ error: err.message });
    } finally {
        conn.release();
    }
});


app.post('/api/mac-auth/bulk', requireApiAuth('users', 'read-write'), async (req, res) => {
    const devices = req.body;
    if (!Array.isArray(devices)) return res.status(400).json({ error: 'Expected array of devices' });

    const conn = await pool.getConnection();
    let successCount = 0;
    let errors = [];

    try {
        await conn.beginTransaction();
        for (let i = 0; i < devices.length; i++) {
            let { mac_id, mac_address, profile, plan_id } = devices[i];
            if (!mac_id || !mac_address) {
                errors.push(`Row ${i + 1}: Missing MAC ID or Address`);
                continue;
            }

            mac_address = mac_address.trim().toLowerCase().replace(/-/g, ':');
            if (!/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/.test(mac_address)) {
                errors.push(`Row ${i + 1}: Invalid MAC address format (${mac_address})`);
                continue;
            }

            try {
                await conn.query('INSERT INTO mac_auth_devices (mac_address, mac_id) VALUES (?, ?)', [mac_address, mac_id]);
                await conn.query(`DELETE FROM radcheck WHERE username = ? AND attribute = 'Cleartext-Password'`, [mac_address]);
                await conn.query(`INSERT INTO radcheck (username, attribute, op, value) VALUES (?, 'Cleartext-Password', ':=', ?)`, [mac_address, mac_address]);
                await conn.query('DELETE FROM radusergroup WHERE username = ?', [mac_address]);
                if (profile) await conn.query('INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)', [mac_address, profile]);

                if (plan_id) await conn.query('INSERT INTO user_plans (username, plan_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE plan_id = VALUES(plan_id)', [mac_address, plan_id]);
                else await conn.query('DELETE FROM user_plans WHERE username = ?', [mac_address]);

                await conn.query('DELETE FROM user_totp WHERE username = ?', [mac_address]);
                successCount++;
            } catch (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    errors.push(`Row ${i + 1} (${mac_address}): MAC ID or Address already exists`);
                } else {
                    errors.push(`Row ${i + 1} (${mac_address}): ${err.message}`);
                }
            }
        }
        await conn.commit();
        res.json({ message: `Imported ${successCount} MAC devices.`, errors });
    } catch (err) {
        await conn.rollback();
        res.status(500).json({ error: 'Bulk import failed completely' });
    } finally {
        conn.release();
    }
});

app.put('/api/mac-auth/:macAddress', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { macAddress } = req.params;
    const { mac_id, profile, plan_id } = req.body;
    if (!mac_id) return res.status(400).json({ error: 'MAC ID required' });

    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();
        const [existing] = await conn.query('SELECT * FROM mac_auth_devices WHERE mac_address = ?', [macAddress]);
        if (existing.length === 0) throw new Error('MAC device not found');
        await conn.query('UPDATE mac_auth_devices SET mac_id = ? WHERE mac_address = ?', [mac_id, macAddress]);
        await conn.query('DELETE FROM radusergroup WHERE username = ?', [macAddress]);
        if (profile) await conn.query('INSERT INTO radusergroup (username, groupname, priority) VALUES (?, ?, 1)', [macAddress, profile]);
        if (plan_id) await conn.query('INSERT INTO user_plans (username, plan_id) VALUES (?, ?) ON DUPLICATE KEY UPDATE plan_id = VALUES(plan_id)', [macAddress, plan_id]);
        else await conn.query('DELETE FROM user_plans WHERE username = ?', [macAddress]);
        await conn.commit();
        res.json({ message: 'MAC authenticated device updated' });
    } catch (err) {
        await conn.rollback();
        if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'MAC ID already exists' });
        res.status(500).json({ error: err.message });
    } finally {
        conn.release();
    }
});

app.delete('/api/mac-auth/:macAddress', requireApiAuth('users', 'read-write'), async (req, res) => {
    const { macAddress } = req.params;
    const conn = await pool.getConnection();
    try {
        await conn.beginTransaction();
        await conn.query('DELETE FROM mac_auth_devices WHERE mac_address = ?', [macAddress]);
        await conn.query('DELETE FROM radcheck WHERE username = ?', [macAddress]);
        await conn.query('DELETE FROM radusergroup WHERE username = ?', [macAddress]);
        await conn.query('DELETE FROM user_plans WHERE username = ?', [macAddress]);
        await conn.commit();
        res.json({ message: 'MAC device deleted' });
    } catch (err) {
        await conn.rollback();
        res.status(500).json({ error: err.message });
    } finally {
        conn.release();
    }
});

app.listen(3000, '0.0.0.0', () => {
    console.log('Radius UI Server listening on port 3000');
});
