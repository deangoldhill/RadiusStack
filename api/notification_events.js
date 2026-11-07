'use strict';
const net = require('node:net');

function publicClientIp(req, trustedProxies = []) {
  let ip = req.socket?.remoteAddress || req.connection?.remoteAddress || '';
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  // Never use X-Forwarded-For without an explicitly configured trusted proxy.
  if (trustedProxies.includes(ip)) {
    ip = String(req.headers?.['x-forwarded-for'] || '').split(',')[0].trim();
  }
  const family = net.isIP(ip);
  if (family === 4) {
    const [a,b,c] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224 ||
        (a === 100 && b >= 64 && b <= 127) ||
        (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && (b === 168 || (b === 0 && c === 0))) ||
        (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
        (a === 203 && b === 0 && c === 113)) return null;
    return ip;
  }
  if (family === 6) {
    const lower = ip.toLowerCase();
    if (!/^2[0-9a-f]{3}:|^3[0-9a-f]{3}:/.test(lower) || lower.startsWith('2001:db8:')) return null;
    return ip;
  }
  return null;
}

async function newPublicAdminIp(pool, username, ip) {
  if (!ip) return false;
  const [[row]] = await pool.query(
    "SELECT EXISTS(SELECT 1 FROM admin_audit_log WHERE admin_username = ? AND action = 'Login completed' AND result = 'success' AND ip_address = ? LIMIT 1) AS known",
    [username, ip]
  );
  return !Number(row?.known);
}

module.exports = { publicClientIp, newPublicAdminIp };
