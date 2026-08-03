'use strict';
const dgram = require('dgram');
const net   = require('net');
const os    = require('os');

let _pool   = null;
let _config = { enabled: false, host: '', port: 514, protocol: 'udp', send_audit: false, send_authlogs: false };
let _lastLoad = 0;

async function loadConfig() {
  if (!_pool) return;
  const now = Date.now();
  if (now - _lastLoad < 30000) return;
  _lastLoad = now;
  try {
    const [rows] = await _pool.query(
      "SELECT setting_key, setting_value FROM settings WHERE setting_key IN " +
      "('syslog_enabled','syslog_host','syslog_port','syslog_protocol','syslog_send_audit','syslog_send_authlogs')",
      [], { isSync: true }
    );
    const m = rows.reduce((a, r) => { a[r.setting_key] = r.setting_value; return a; }, {});
    _config = {
      enabled:       m.syslog_enabled       === 'true',
      host:          m.syslog_host          || '',
      port:          parseInt(m.syslog_port  || '514', 10),
      protocol:      m.syslog_protocol      || 'udp',
      send_audit:    m.syslog_send_audit    === 'true',
      send_authlogs: m.syslog_send_authlogs === 'true'
    };
  } catch (e) {}
}

function buildMessage(severity, appName, msgId, fields) {
  const sevMap = { emerg:0, alert:1, crit:2, err:3, warning:4, notice:5, info:6, debug:7 };
  const sev = sevMap[severity] !== undefined ? sevMap[severity] : 6;
  const pri = (1 * 8) + sev;
  const ts  = new Date().toISOString();
  const host = os.hostname();
  const fieldStr = Object.entries(fields)
    .map(([k, v]) => `${k}="${String(v == null ? '' : v).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`)
    .join(' ');
  return `<${pri}>1 ${ts} ${host} ${appName} - ${msgId} - ${fieldStr}`;
}

function sendUdp(host, port, message) {
  return new Promise((resolve) => {
    const client = dgram.createSocket('udp4');
    const buf = Buffer.from(message);
    client.send(buf, 0, buf.length, port, host, (err) => {
      client.close();
      if (err) console.error('[Syslog UDP] Send error:', err.message);
      resolve();
    });
  });
}

function sendTcp(host, port, message) {
  return new Promise((resolve) => {
    const client = net.createConnection(port, host, () => {
      client.write(message + '\n', () => { client.destroy(); resolve(); });
    });
    client.on('error', (err) => { console.error('[Syslog TCP] Send error:', err.message); resolve(); });
    client.setTimeout(5000, () => { console.error('[Syslog TCP] Timeout:', host, port); client.destroy(); resolve(); });
  });
}

async function send(severity, appName, msgId, fields) {
  await loadConfig();
  if (!_config.enabled || !_config.host) return;
  const message = buildMessage(severity, appName, msgId, fields);
  try {
    _config.protocol === 'tcp' ? await sendTcp(_config.host, _config.port, message) : await sendUdp(_config.host, _config.port, message);
  } catch (e) {
    console.error('[Syslog] Unexpected error:', e.message);
  }
}

module.exports = {
  init(pool) { _pool = pool; },
  invalidateCache() { _lastLoad = 0; },
  async sendAuditLog(entry) {
    await loadConfig();
    if (!_config.enabled || !_config.send_audit) return;
    await send('info', 'radiusstack-audit', 'AUDIT', {
      admin: entry.admin_username || '', origin: entry.origin || '', action: entry.action || '',
      result: entry.result || '', details: entry.details || '', ip: entry.ip_address || ''
    });
  },
  async sendAuthLog(entry) {
    await loadConfig();
    if (!_config.enabled || !_config.send_authlogs) return;
    const sev = (entry.reply || '').toLowerCase().includes('reject') ? 'warning' : 'info';
    await send(sev, 'radiusstack-authlog', 'AUTHLOG', {
      username: entry.username || '', reply: entry.reply || '', nasipaddress: entry.nasipaddress || '',
      callingstationid: entry.callingstationid || '', authdate: entry.authdate || ''
    });
  },
  async test(host, port, protocol) {
    const message = buildMessage('notice', 'radiusstack-audit', 'TEST', { msg: 'RadiusStack syslog test' });
    try {
      protocol === 'tcp' ? await sendTcp(host, port, message) : await sendUdp(host, port, message);
      return { ok: true };
    } catch (e) { return { ok: false, error: e.message }; }
  }
};