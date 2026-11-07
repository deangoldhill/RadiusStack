const crypto = require('node:crypto');

const TENANT_EVENTS = new Set(['admin_new_public_ip', 'admin_failed_login', 'mac_auto_created', 'admin_password_changed']);
const GLOBAL_EVENTS = new Set([...TENANT_EVENTS, 'container_restart', 'ha_disconnected', 'ha_reconnected']);
const KEYS = ['pushbullet_enabled', 'pushbullet_api_key', 'pushbullet_events', 'pushbullet_recipient_email'];

function encryptionKey(deps = {}) {
  const encoded = deps.encryptionKey || process.env.PUSHBULLET_ENCRYPTION_KEY || process.env.RADSEC_PASSPHRASE_ENCRYPTION_KEY;
  // A dedicated Pushbullet key is preferred; the existing RadSec key is a deployment fallback.
  if (typeof encoded !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(encoded)) {
    throw Object.assign(new Error('Pushbullet encryption is not configured'), {status: 503});
  }
  const key = Buffer.from(encoded, 'base64');
  if (key.length !== 32 || key.toString('base64') !== encoded) {
    throw Object.assign(new Error('Pushbullet encryption is not configured'), {status: 503});
  }
  return key;
}
function encrypt(secret, deps) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', encryptionKey(deps), iv);
  const ciphertext = Buffer.concat([cipher.update(secret, 'utf8'), cipher.final()]);
  return `v1:${iv.toString('base64')}:${cipher.getAuthTag().toString('base64')}:${ciphertext.toString('base64')}`;
}
function decrypt(value, deps) {
  const key = encryptionKey(deps);
  try {
    const [version, ivText, tagText, cipherText, extra] = value.split(':');
    if (version !== 'v1' || extra !== undefined) throw Error('invalid');
    const iv = Buffer.from(ivText, 'base64'), tag = Buffer.from(tagText, 'base64');
    if (iv.length !== 12 || tag.length !== 16) throw Error('invalid');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(Buffer.from(cipherText, 'base64')), decipher.final()]).toString('utf8');
  } catch { throw Object.assign(new Error('Pushbullet configuration is unavailable'), {status: 503}); }
}
function scopeInfo(scope) {
  if (scope?.enabled && Number.isSafeInteger(Number(scope.tenantId)) && Number(scope.tenantId) > 0) return {tenantId: Number(scope.tenantId)};
  if (scope && scope.enabled === false) return {tenantId: null};
  throw Object.assign(new Error('A valid notification scope is required'), {status: 403});
}
async function readRaw(pool, scope) {
  const {tenantId} = scopeInfo(scope);
  const [rows] = tenantId === null
    ? await pool.query('SELECT setting_key, setting_value FROM settings WHERE setting_key IN (?,?,?,?)', KEYS)
    : await pool.query('SELECT setting_key, setting_value FROM tenant_settings WHERE tenant_id = ? AND setting_key IN (?,?,?,?)', [tenantId, ...KEYS]);
  const values = Object.fromEntries(rows.filter(row => KEYS.includes(row.setting_key)).map(row => [row.setting_key, row.setting_value]));
  let events = [];
  try { const parsed = JSON.parse(values.pushbullet_events || '[]'); if (Array.isArray(parsed)) events = parsed; } catch { /* Invalid stored events fail closed. */ }
  const allowed = tenantId === null ? GLOBAL_EVENTS : TENANT_EVENTS;
  events = events.filter(e => allowed.has(e));
  return {enabled:values.pushbullet_enabled === 'true', configured:!!values.pushbullet_api_key, events, recipientEmail:values.pushbullet_recipient_email || '', encryptedKey:values.pushbullet_api_key};
}
function publicConfig(config) { return {enabled:config.enabled, configured:config.configured, events:config.events, recipientEmail:config.recipientEmail}; }

// Service-only loader: the plaintext API key must never be serialized to HTTP or audit logs.
async function loadConfig(pool, scope, deps = {}) {
  const config = await readRaw(pool, scope);
  const apiKey = config.encryptedKey ? decrypt(config.encryptedKey, deps) : null;
  return {...publicConfig(config), apiKey};
}
function validRecipientEmail(value) {
  if (typeof value !== 'string') return false;
  const email = value.trim();
  return email === '' || (email.length <= 254 && /^[^\s@<>]{1,64}@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i.test(email));
}
function validate(body, scope) {
  if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).some(k => !['enabled','apiKey','events','recipientEmail'].includes(k)) || typeof body.enabled !== 'boolean' || !Array.isArray(body.events) || (body.apiKey !== undefined && typeof body.apiKey !== 'string') || (body.recipientEmail !== undefined && !validRecipientEmail(body.recipientEmail))) return false;
  const allowed = scope.enabled ? TENANT_EVENTS : GLOBAL_EVENTS;
  return body.events.every(e => typeof e === 'string' && allowed.has(e)) && new Set(body.events).size === body.events.length;
}
module.exports = function registerNotifications(app, pool, requireApiAuth, auditLog, deps = {}) {
  async function handleError(res, err) {
    return res.status(err.status === 403 ? 403 : 503).json({error: err.status === 403 ? 'Notification scope is not permitted' : 'Notification configuration is unavailable'});
  }
  function authorized(req, res) {
    try {
      const scope = scopeInfo(req.tenantScope);
      if (scope.tenantId === null && Number(req.admin?.is_super_admin) !== 1) {res.status(403).json({error:'Global notification settings require a super administrator'}); return false;}
      return true;
    } catch {res.status(403).json({error:'Notification scope is not permitted'}); return false;}
  }
  app.get('/api/notifications/config', requireApiAuth('settings', 'read-only'), async (req, res) => {
    if (!authorized(req, res)) return;
    try {return res.json(publicConfig(await readRaw(pool, req.tenantScope)));}
    catch (err) {return handleError(res, err);}
  });
  app.put('/api/notifications/config', requireApiAuth('settings', 'read-write'), async (req, res) => {
    if (!authorized(req, res)) return;
    if (!validate(req.body, req.tenantScope)) return res.status(400).json({error:'Invalid notification configuration'});
    try {
      const current = await readRaw(pool, req.tenantScope);
      const {enabled, events, apiKey, recipientEmail} = req.body;
      const normalizedEmail = recipientEmail === undefined ? current.recipientEmail : recipientEmail.trim().toLowerCase();
      const replace = typeof apiKey === 'string' && apiKey.trim().length > 0;
      if (enabled && (!replace && !current.configured || !events.length)) return res.status(400).json({error:'Enabling notifications requires a configured API key and at least one event'});
      // Verify encryption is available before persisting enabled state, including retained keys.
      if (enabled || replace) encryptionKey(deps);
      const encryptedKey = replace ? encrypt(apiKey, deps) : current.encryptedKey;
      const {tenantId} = scopeInfo(req.tenantScope);
      const values = [['pushbullet_events',JSON.stringify(events)]];
      if (recipientEmail !== undefined) values.push(['pushbullet_recipient_email',normalizedEmail]);
      if (replace) values.push(['pushbullet_api_key',encryptedKey]);
      values.push(['pushbullet_enabled',String(enabled)]);
      for (const [settingKey, value] of values) {
        if (tenantId === null) await pool.query('INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)', [settingKey, value]);
        else await pool.query('INSERT INTO tenant_settings (tenant_id, setting_key, setting_value) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)', [tenantId, settingKey, value]);
      }
      await auditLog(req.admin.username, req.origin, 'Updated notification configuration', 'success', '', req.ip, req.tenantScope);
      return res.json({enabled, configured:!!encryptedKey, events, recipientEmail:normalizedEmail});
    } catch (err) {return handleError(res, err);}
  });
  app.post('/api/notifications/test', requireApiAuth('settings', 'read-write'), async (req, res) => {
    if (!authorized(req, res)) return;
    if (req.body && (typeof req.body !== 'object' || Array.isArray(req.body) || Object.keys(req.body).length))
      return res.status(400).json({error:'The test message has no editable fields'});
    if (typeof deps.diagnose !== 'function') return res.status(503).json({error:'Pushbullet test is unavailable'});
    try {
      const {tenantId} = scopeInfo(req.tenantScope);
      const result = await deps.diagnose({tenantId});
      console.info('[Pushbullet test]',JSON.stringify({scope:tenantId===null?'global':`tenant:${tenantId}`,ok:result.ok,checks:result.checks}));
      return res.json(result);
    } catch { return res.status(503).json({error:'Pushbullet test is unavailable'}); }
  });
};
module.exports.loadConfig = loadConfig;
module.exports.TENANT_EVENTS = TENANT_EVENTS;
module.exports.GLOBAL_EVENTS = GLOBAL_EVENTS;
