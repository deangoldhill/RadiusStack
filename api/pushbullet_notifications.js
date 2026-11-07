'use strict';

// Standalone delivery service. Persistence and authenticated configuration routes are owned by the caller.
const EVENTS = Object.freeze([
  'admin_new_public_ip',
  'admin_failed_login',
  'container_restart',
  'ha_disconnected',
  'ha_reconnected',
  'mac_auto_created',
  'admin_password_changed',
]);
const EVENT_SET = new Set(EVENTS);
const ENDPOINT = 'https://api.pushbullet.com/v2/pushes';
const KEYS = ['pushbullet_enabled', 'pushbullet_access_token', 'pushbullet_events', 'pushbullet_recipient_email'];

function scopeId(tenantId) {
  if (tenantId == null) return null;
  if (!Number.isSafeInteger(tenantId) || tenantId <= 0) throw new TypeError('Invalid tenantId');
  return tenantId;
}

function decode(rows) {
  const values = Object.create(null);
  for (const row of rows) {
    if (KEYS.includes(row.setting_key)) values[row.setting_key] = row.setting_value;
  }
  let selected = [];
  try {
    const parsed = JSON.parse(values.pushbullet_events || '[]');
    if (Array.isArray(parsed)) selected = EVENTS.filter(event => parsed.includes(event));
  } catch { /* Malformed selection fails closed. */ }
  return {
    enabled: values.pushbullet_enabled === 'true',
    events: selected,
    configured: typeof values.pushbullet_access_token === 'string' && values.pushbullet_access_token.trim().length > 0,
    token: values.pushbullet_access_token,
    recipientEmail: values.pushbullet_recipient_email || '',
  };
}

function createPushbulletService({ pool, configLoader, fetchImpl = globalThis.fetch, now = Date.now, timeoutMs = 5000, cooldownMs = 0 } = {}) {
  if (!pool || typeof pool.query !== 'function') throw new TypeError('pool.query is required');
  if (typeof fetchImpl !== 'function') throw new TypeError('fetchImpl is required');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 30000) throw new TypeError('Invalid timeoutMs');
  if (!Number.isSafeInteger(cooldownMs) || cooldownMs < 0) throw new TypeError('Invalid cooldownMs');
  const lastSent = new Map();
  const lastDiagnostic = new Map();

  async function load(tenantId) {
    const id = scopeId(tenantId);
    if (configLoader) return configLoader(id);
    const [rows] = id === null
      ? await pool.query("SELECT setting_key, setting_value FROM settings WHERE setting_key IN ('pushbullet_enabled', 'pushbullet_access_token', 'pushbullet_events', 'pushbullet_recipient_email')")
      : await pool.query("SELECT setting_key, setting_value FROM tenant_settings WHERE tenant_id = ? AND setting_key IN ('pushbullet_enabled', 'pushbullet_access_token', 'pushbullet_events', 'pushbullet_recipient_email')", [id]);
    return decode(rows);
  }

  async function getConfig({ tenantId = null } = {}) {
    const { enabled, events, configured } = await load(tenantId);
    return { enabled, events, configured };
  }

  async function send({ tenantId = null, event, title, body } = {}) {
    const id = scopeId(tenantId);
    if (!EVENT_SET.has(event)) throw new TypeError('Unsupported notification event');
    const config = await load(id);
    if (!config.enabled || !config.configured || !config.events.includes(event)) return { sent: false, reason: 'disabled' };
    const key = `${id === null ? 'global' : `tenant:${id}`}:${event}`;
    if (cooldownMs && lastSent.has(key) && now() - lastSent.get(key) < cooldownMs) return { sent: false, reason: 'cooldown' };
    if (typeof title !== 'string' || typeof body !== 'string') throw new TypeError('Notification title and body must be strings');
    const payload = { type: 'note', title: title.slice(0, 160), body: body.slice(0, 1000) };
    if (config.recipientEmail) payload.email = config.recipientEmail;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    timer.unref?.();
    let httpStatus;
    try {
      const response = await fetchImpl(ENDPOINT, {
        method: 'POST',
        headers: { 'Access-Token': config.apiKey || config.token, 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      if (!response.ok) {
        httpStatus = response.status;
        throw new Error('upstream failure');
      }
      if (cooldownMs) lastSent.set(key, now());
      return { sent: true };
    } catch (error) {
      // Surface only numeric HTTP status or a standard transport code; never provider text, URLs or tokens.
      const safe = new Error('Pushbullet delivery failed');
      if (Number.isInteger(httpStatus) && httpStatus >= 100 && httpStatus <= 599) safe.httpStatus = httpStatus;
      const code = error.cause?.code;
      if (typeof code === 'string' && /^[A-Z_]{2,40}$/.test(code)) safe.transportCode = code;
      throw safe;
    } finally {
      clearTimeout(timer);
    }
  }

  async function diagnose({ tenantId = null } = {}) {
    const id = scopeId(tenantId);
    const checks = [];
    let config;
    try { config = await load(id); }
    catch { return {ok:false,checks:[{stage:'configuration',outcome:'failed',reason:'Stored settings could not be read or decrypted'}]}; }
    const target = config.recipientEmail ? 'recipient_email' : 'account_devices';
    if (!config.configured || !(config.apiKey || config.token))
      return {ok:false,target,checks:[{stage:'configuration',outcome:'failed',reason:'No Pushbullet API key configured'}]};
    checks.push({stage:'configuration',outcome:'ok',enabled:!!config.enabled,configured:true,target});
    const scopeKey = id === null ? 'global' : `tenant:${id}`;
    const last = lastDiagnostic.get(scopeKey);
    if (last && now() - last < 30000)
      return {ok:false,target,checks:[...checks,{stage:'rate_limit',outcome:'skipped',reason:'A test push was sent within the last 30 seconds'}]};
    const token = config.apiKey || config.token;
    async function request(stage, url, options) {
      const started = Date.now();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      timer.unref?.();
      try {
        const response = await fetchImpl(url,{...options,headers:{'Access-Token':token,...options.headers},signal:controller.signal});
        let providerCode;
        if (!response.ok && typeof response.json === 'function') {
          const data = await response.json().catch(()=>null);
          const code = data?.error?.type;
          if (typeof code === 'string' && /^[a-z_]{1,60}$/.test(code)) providerCode = code;
        }
        const check = {stage,outcome:response.ok?'ok':'failed',httpStatus:response.status,durationMs:Date.now()-started};
        if (providerCode) check.providerCode = providerCode;
        checks.push(check);
        return response.ok;
      } catch (error) {
        const check = {stage,outcome:'failed',durationMs:Date.now()-started};
        const code = error.cause?.code;
        if (typeof code === 'string' && /^[A-Z_]{2,40}$/.test(code)) check.transportCode = code;
        if (controller.signal.aborted) check.timeout = true;
        checks.push(check);
        return false;
      } finally { clearTimeout(timer); }
    }
    if (!await request('authentication','https://api.pushbullet.com/v2/users/me',{})) return {ok:false,target,checks};
    const payload = {type:'note',title:'RadiusStack test notification',body:'This is a test notification from RadiusStack.'};
    if (config.recipientEmail) payload.email = config.recipientEmail;
    const sent = await request('push',ENDPOINT,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    if (sent) lastDiagnostic.set(scopeKey,now());
    return {ok:sent,target,checks};
  }

  return { getConfig, send, diagnose };
}

module.exports = { EVENTS, createPushbulletService };
