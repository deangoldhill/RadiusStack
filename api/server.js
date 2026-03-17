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
const JWT_SECRET = 'super-secret-jwt-key-change-me';

const pool = mysql.createPool({
    host: 'mariadb',
    user: 'radius',
    password: 'radiusdbpass',
    database: 'radius'
});

// Audit Logger
async function auditLog(admin_username, origin, action, result, details = '', ip = '') {
    try {
        await pool.query(
            'INSERT INTO admin_audit_log (admin_username, origin, action, result, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)',
            [admin_username, origin, action, result, details, ip]
        );
    } catch(err) {
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
    res.json(rows.reduce((acc, row) => ({...acc, [row.setting_key]: row.setting_value}), {}));
});

app.post('/api/settings', requireApiAuth('settings', 'read-write'), async (req, res) => {
    const { enforce_2fa, radius_debug, custom_reply_attributes, ui_theme } = req.body;

    if (enforce_2fa !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('enforce_2fa', ?) ON DUPLICATE KEY UPDATE setting_value=?", [enforce_2fa, enforce_2fa]);
    if (radius_debug !== undefined) {
        await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('radius_debug', ?) ON DUPLICATE KEY UPDATE setting_value=?", [radius_debug, radius_debug]);
        exec('docker restart radius_server');
    }
    if (custom_reply_attributes !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('custom_reply_attributes', ?) ON DUPLICATE KEY UPDATE setting_value=?", [custom_reply_attributes, custom_reply_attributes]);
    if (ui_theme !== undefined) await pool.query("INSERT INTO settings (setting_key, setting_value) VALUES ('ui_theme', ?) ON DUPLICATE KEY UPDATE setting_value=?", [ui_theme, ui_theme]);

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
    if (!container.startsWith('radius_')) return res.status(403).json({error: 'Invalid container'});
    
    exec(`docker restart ${container}`, async (error) => {
        if (error) {
            await auditLog(req.admin.username, req.origin, `Restart container ${container}`, 'failed', error.message, req.ip);
            return res.status(500).json({error: error.message});
        }
        await auditLog(req.admin.username, req.origin, `Restarted container ${container}`, 'success', '', req.ip);
        res.json({success: true});
    });
});

app.get('/api/system/logs/:container', requireApiAuth('settings', 'read-only'), (req, res) => {
    const { container } = req.params;
    if (!container.startsWith('radius_')) return res.status(403).json({error: 'Invalid container'});

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
            return res.status(500).json({error: error.message});
        }
        exec('docker restart radius_server');
        await auditLog(req.admin.username, req.origin, 'Generated new 10-year EAP certificate', 'success', `Subject: ${subj}`, req.ip);
        res.json({success: true});
    });
});

app.post('/api/certs/upload', requireApiAuth('settings', 'read-write'), upload.fields([{name:'cert'}, {name:'key'}]), async (req, res) => {
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
        res.json({success: true});
    } catch(err) {
        await auditLog(req.admin.username, req.origin, 'Upload EAP certificate', 'failed', err.message, req.ip);
        res.status(500).json({error: err.message});
    }
});

// --- ADMINS ---
app.get('/api/admins', requireApiAuth('admins', 'read-only'), async (req, res) => {
    const [rows] = await pool.query('SELECT id, username, require_password_change, two_factor_enabled, two_factor_setup_complete, api_key, permissions FROM admins');
    res.json(rows);
});

const crypto = require('crypto');

app.post('/api/admins', requireApiAuth('settings', 'read-write'), async (req, res) => {
  const { username, password, permissions, enable_2fa } = req.body;
  const hash = await bcrypt.hash(password, 10);
  const apikey = crypto.randomBytes(32).toString('hex');
  try {
    const [settingRows] = await pool.query("SELECT setting_value FROM settings WHERE setting_key = 'enforce_2fa'");
    const enforce2fa = settingRows.length > 0 && settingRows[0].setting_value === 'true';
    const is2faEnabled = enforce2fa || !!enable_2fa;

    await pool.query('INSERT INTO admins (username, password_hash, api_key, permissions, two_factor_enabled, two_factor_setup_complete) VALUES (?, ?, ?, ?, ?, false)', [username, hash, apikey, JSON.stringify(permissions), is2faEnabled]);
    await auditLog(req.admin.username, req.origin, `Created admin: ${username}`, 'success', '', req.ip);
    res.json({success: true});
  } catch (err) {
    res.status(400).json({error: err.message});
  }
});

app.put('/api/admins/:id', requireApiAuth('settings', 'read-write'), async (req, res) => {
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
        res.json({success: true});
    } catch (err) {
        res.status(400).json({error: err.message});
    }
});

app.delete('/api/admins/:id', requireApiAuth('settings', 'read-write'), async (req, res) => {
    const { id } = req.params;
    await pool.query('DELETE FROM administrators WHERE id = ?', [id]);
    await auditLog(req.admin.username, req.origin, `Deleted admin ID: ${id}`, 'success', '', req.ip);
    res.json({success: true});
});

app.post('/api/admins/:id/generate-key', requireApiAuth('settings', 'read-write'), async (req, res) => {
    const { id } = req.params;
    const newKey = crypto.randomBytes(32).toString('hex');
    try {
        await pool.query('UPDATE admins SET api_key = ? WHERE id = ?', [newKey, id]);
        await auditLog(req.admin.username, req.origin, `Generated new API key for admin ID: ${id}`, 'success', '', req.ip);
        res.json({ success: true, apiKey: newKey });
    } catch (err) {
        res.status(500).json({error: err.message});
    }
});

app.post('/api/admins/:id/enable-2fa', requireApiAuth('settings', 'read-write'), async (req, res) => {
    const { id } = req.params;
    try {
        const [admins] = await pool.query('SELECT * FROM admins WHERE id = ?', [id]);
        const admin = admins[0];
        if (!admin) return res.status(404).json({error: 'Admin not found'});

        const secret = authenticator.generateSecret();
        await pool.query('UPDATE admins SET two_factor_enabled = true, two_factor_setup_complete = true, two_factor_secret = ? WHERE id = ?', [secret, id]);
        
        const qrImage = await qrcode.toDataURL(authenticator.keyuri(admin.username, 'RadiusFullStack', secret));
        
        await auditLog(req.admin.username, req.origin, `Enabled 2FA for admin: ${admin.username}`, 'success', '', req.ip);
        res.json({ success: true, qrImage, secret });
    } catch (err) {
        res.status(500).json({error: err.message});
    }
});

app.post('/api/admins/:id/disable-2fa', requireApiAuth('settings', 'read-write'), async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('UPDATE admins SET two_factor_enabled = false, two_factor_setup_complete = false, two_factor_secret = NULL WHERE id = ?', [id]);
        await auditLog(req.admin.username, req.origin, `Disabled 2FA for admin ID: ${id}`, 'success', '', req.ip);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({error: err.message});
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
        res.json({success: true});
    } catch (err) {
        res.status(500).json({error: err.message});
    }
});

app.put('/api/plans/:id', requireApiAuth('plans', 'read-write'), async (req, res) => {
    const { id } = req.params;
    const { name, data_limit_mb, time_limit_seconds, reset_period } = req.body;
    try {
        await pool.query('UPDATE plans SET name=?, data_limit_mb=?, time_limit_seconds=?, reset_period=? WHERE id=?', 
            [name, data_limit_mb || 0, time_limit_seconds || 0, reset_period || 'never', id]);
        await auditLog(req.admin.username, req.origin, `Updated plan ID: ${id}`, 'success', '', req.ip);
        res.json({success: true});
    } catch (err) {
        res.status(500).json({error: err.message});
    }
});

app.delete('/api/plans/:id', requireApiAuth('plans', 'read-write'), async (req, res) => {
    const { id } = req.params;
    try {
        await pool.query('DELETE FROM plans WHERE id = ?', [id]);
        await auditLog(req.admin.username, req.origin, `Deleted plan ID: ${id}`, 'success', '', req.ip);
        res.json({success: true});
    } catch (err) {
        res.status(500).json({error: err.message});
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
        res.status(500).json({error: err.message});
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
    if (!nas.length) return res.status(404).json({error: 'NAS not found'});
    
    const ip = nas[0].nasname.split('/')[0];
    await pool.query(`INSERT INTO radgroupcheck (groupname, attribute, op, value) VALUES (?, 'NAS-IP-Address', '==', ?)`, [profile, ip]);
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
                     VALUES (?, 'NAS-IP-Address', '==', ?)`,
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
// --- USERS ---
app.get('/api/users', requireApiAuth('users', 'read-only'), async (req, res) => {
  const [rows] = await pool.query(`SELECT 
    c.username, 
    c.value as password, 
    u.groupname as profile,
    up.plan_id,
    p.name as plan_name,
    COALESCE(a.data_30d, 0) as data_30d,
    COALESCE(a.time_30d, 0) as time_30d
FROM radcheck c
LEFT JOIN radusergroup u ON c.username = u.username
LEFT JOIN user_plans up ON c.username = up.username
LEFT JOIN plans p ON up.plan_id = p.id
LEFT JOIN (
    SELECT username,
           SUM(acctinputoctets + acctoutputoctets) as data_30d,
           SUM(acctsessiontime) as time_30d
    FROM radacct
    WHERE acctstarttime >= DATE_SUB(NOW(), INTERVAL 30 DAY)
    GROUP BY username
) a ON c.username = a.username
WHERE c.attribute='Cleartext-Password'`);
  res.json(rows);
});

app.post('/api/users', requireApiAuth('users', 'read-write'), async (req, res) => {
  const { username, password, profile, plan_id } = req.body;
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

    await conn.commit();
    await auditLog(req.admin.username, req.origin, `Created user: ${username}`, 'success', '', req.ip);
    res.json({ success: true });
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

app.put('/api/users/:username', requireApiAuth('users', 'read-write'), async (req, res) => {
  const { username } = req.params;
  const { password, profile, plan_id } = req.body;
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

    await conn.commit();
    await auditLog(req.admin.username, req.origin, `Updated user: ${username}`, 'success', '', req.ip);
    res.json({ success: true });
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
    const { limit = 100 } = req.query;
    
    // Cap the limit for performance and security (max 500)
    const queryLimit = Math.min(parseInt(limit) || 100, 500);

    const [rows] = await pool.query(
        'SELECT * FROM radacct WHERE acctstoptime IS NULL ORDER BY acctstarttime DESC LIMIT ?',
        [queryLimit]
    );
    
    res.json(rows);
});

app.get('/api/logs/auth', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const { username, limit = 100 } = req.query;
    
    let query = 'SELECT * FROM radpostauth';
    const params = [];

    if (username) {
        query += ' WHERE username = ?';
        params.push(username);
    }

    // Always order by newest first
    query += ' ORDER BY authdate DESC';

    // Cap the limit (max 500)
    const queryLimit = Math.min(parseInt(limit) || 100, 500);
    query += ' LIMIT ?';
    params.push(queryLimit);

    const [rows] = await pool.query(query, params);
    res.json(rows);
});
// USER EXECUTIVE REPORT
app.get('/api/reports/user/:username', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const { username } = req.params;
    const [acct] = await pool.query('SELECT * FROM radacct WHERE username = ? ORDER BY acctstarttime DESC', [username]);
    const [auth] = await pool.query('SELECT * FROM radpostauth WHERE username = ? ORDER BY authdate DESC LIMIT 100', [username]);
    const [stats] = await pool.query(
        'SELECT COUNT(*) as total_sessions, SUM(acctinputoctets) as total_input, SUM(acctoutputoctets) as total_output, SUM(acctsessiontime) as total_time FROM radacct WHERE username = ?',
        [username]
    );
    res.json({ username, accounting: acct, postauth: auth, stats: stats[0] });
});

// FAILED AUTH REPORT
app.get('/api/reports/failed-auth', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const [details] = await pool.query("SELECT * FROM radpostauth WHERE reply = 'Access-Reject' ORDER BY authdate DESC LIMIT 500");
    const [summary] = await pool.query("SELECT username, COUNT(*) as fail_count FROM radpostauth WHERE reply = 'Access-Reject' GROUP BY username ORDER BY fail_count DESC");
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
                <tr><td>${data.stats.total_sessions}</td><td>${data.stats.total_input||0}</td><td>${data.stats.total_output||0}</td><td>${data.stats.total_time||0}</td></tr>
            </table>
            <h2>Recent Accounting</h2>
            <table>
                <tr><th>Session ID</th><th>NAS IP</th><th>Start</th><th>Stop</th><th>Duration</th></tr>
                ${data.accounting.slice(0,20).map(a => `<tr><td>${a.acctsessionid}</td><td>${a.nasipaddress}</td><td>${a.acctstarttime||'N/A'}</td><td>${a.acctstoptime||'Active'}</td><td>${a.acctsessiontime||0}s</td></tr>`).join('')}
            </table>
            <h2>Recent Authentications</h2>
            <table>
                <tr><th>Date</th><th>Reply</th><th>Class</th></tr>
                ${data.postauth.slice(0,20).map(p => `<tr><td>${p.authdate}</td><td>${p.reply}</td><td>${p.class}</td></tr>`).join('')}
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
                ${data.summary.slice(0,20).map(s => `<tr><td>${s.username}</td><td>${s.fail_count}</td></tr>`).join('')}
            </table>
            <h2>Recent Failures</h2>
            <table>
                <tr><th>Username</th><th>Date/Time</th><th>Class</th></tr>
                ${data.details.slice(0,50).map(d => `<tr><td>${d.username}</td><td>${d.authdate}</td><td>${d.class}</td></tr>`).join('')}
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

// === ACCOUNTING HISTORY API ===
app.get('/api/accounting', requireApiAuth('reports', 'read-only'), async (req, res) => {
    const { username, nasip, start_date, end_date, sort = 'acctstarttime', order = 'desc', limit = 300 } = req.query;

    let query = `
        SELECT 
            radacct.*,
            (acctinputoctets + acctoutputoctets) AS total_data
        FROM radacct
        WHERE 1=1
    `;
    const params = [];

    if (username) {
        query += ' AND username = ?';
        params.push(username);
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
            `Filters: ${JSON.stringify({username, nasip, start_date, end_date})}`, req.ip);
        
        res.json({ success: true, deleted: result.affectedRows });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to delete records' });
    }
});

// Start Server
app.listen(3000, '0.0.0.0', () => {
    console.log('Radius UI Server listening on port 3000');
});
