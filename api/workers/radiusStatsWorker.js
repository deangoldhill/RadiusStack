'use strict';
const dgram  = require('dgram');
const crypto = require('crypto');
const mysql  = require('mysql2/promise');

const STATUS_HOST      = 'radius_server';
const STATUS_PORT      = '18121';
const STATUS_SECRET    = 'RADIUS_STATUS_SECRET_GENERIC';
const POLL_MS          = parseInt(process.env.STATUS_POLL_INTERVAL || '60000', 10);

const FR_VENDOR = 11344;
// FreeRADIUS-Statistics-Type ID is 127.
// 1 = Auth, 2 = Acct, 3 = Both

// Maps based on dictionary.freeradius
const AUTH_MAP = {
  128: 'total_requests', 129: 'total_accepts', 130: 'total_rejects', 
  131: 'total_challenges', 132: 'total_responses', 133: 'dup_requests', 
  134: 'malformed_requests', 135: 'invalid_requests', 136: 'dropped_requests', 
  137: 'unknown_types', 176: 'server_start_time', 177: 'server_hup_time'
};

const ACCT_MAP = {
  148: 'total_requests', 149: 'total_responses', 150: 'dup_requests', 
  151: 'malformed_requests', 152: 'invalid_requests', 153: 'dropped_requests', 
  154: 'unknown_types', 176: 'server_start_time', 177: 'server_hup_time'
};

const db = mysql.createPool({
  host:     process.env.DB_HOST || 'mariadb',
  user:     process.env.DB_USER || 'radius',
  password: process.env.DB_PASS || '',
  database: process.env.DB_NAME || 'radius',
});

function buildPacket(secret, statTypeInt) {
  const id = Math.floor(Math.random() * 256);
  const reqAuth = crypto.randomBytes(16);

  // Header(20) + VSA for Statistics-Type(12) + Message-Authenticator(18) = 50 bytes
  const buf = Buffer.alloc(50);
  buf[0] = 12; // Status-Server
  buf[1] = id; 
  buf.writeUInt16BE(50, 2);
  reqAuth.copy(buf, 4);

  // FreeRADIUS-Statistics-Type VSA (Type 26, Len 12)
  buf[20] = 26; // VSA
  buf[21] = 12; // Length
  buf.writeUInt32BE(FR_VENDOR, 22); // Vendor ID 11344
  buf[26] = 127; // FreeRADIUS-Statistics-Type
  buf[27] = 6;   // Sub-Length
  buf.writeUInt32BE(statTypeInt, 28); // 1=Auth, 2=Acct

  // Message-Authenticator (Type 80, Len 18)
  buf[32] = 80; 
  buf[33] = 18;

  // Calculate HMAC-MD5 over the whole packet with zeroed MA field
  const mac = crypto.createHmac('md5', Buffer.from(secret, 'utf8')).update(buf).digest();
  mac.copy(buf, 34);
  return { buf, id };
}

function parseVSAs(msg) {
  const vsas = {};
  let pos = 20;
  while (pos + 2 <= msg.length) {
    const type = msg[pos], len = msg[pos + 1];
    if (len < 2 || pos + len > msg.length) break;
    if (type === 26 && len >= 8) {
      const vendorId = msg.readUInt32BE(pos + 2);
      if (vendorId === FR_VENDOR) {
        let vp = pos + 6;
        while (vp + 2 <= pos + len) {
          const vType = msg[vp], vLen = msg[vp + 1];
          if (vLen < 2) break;
          if (vLen >= 6) vsas[vType] = msg.readUInt32BE(vp + 2);
          vp += vLen;
        }
      }
    }
    pos += len;
  }
  return vsas;
}

function query(host, port, secret, statTypeInt) {
  return new Promise((resolve, reject) => {
    const { buf, id } = buildPacket(secret, statTypeInt);
    const sock = dgram.createSocket('udp4');
    const timer = setTimeout(() => { sock.close(); reject(new Error('Timeout')); }, 5000);
    sock.once('message', (msg) => {
      clearTimeout(timer); sock.close();
      if (msg[1] !== id) return reject(new Error('ID mismatch'));
      resolve(parseVSAs(msg));
    });
    sock.once('error', (err) => { clearTimeout(timer); reject(err); });
    sock.send(buf, port, host, (err) => { if (err) { clearTimeout(timer); sock.close(); reject(err); } });
  });
}

function toRow(vsas, attrMap) {
  const row = { total_requests: 0, total_accepts: 0, total_rejects: 0, total_challenges: 0, total_responses: 0, dup_requests: 0, malformed_requests: 0, invalid_requests: 0, dropped_requests: 0, unknown_types: 0, server_start_time: 0, server_hup_time: 0 };
  for (const [vt, col] of Object.entries(attrMap)) if (vsas[vt] !== undefined) row[col] = vsas[vt];
  return row;
}

async function poll() {
  const rows = {};

  // 1 = Auth stats, 2 = Acct stats. Both can be queried from the same status port (18121)
  const targets = [
    ['auth', 1, AUTH_MAP], 
    ['acct', 2, ACCT_MAP]
  ];

  for (const [statType, statTypeInt, attrMap] of targets) {
    try {
      const vsas = await query(STATUS_HOST, STATUS_PORT, STATUS_SECRET, statTypeInt);
      rows[statType] = { ...toRow(vsas, attrMap), raw_vsas: JSON.stringify(vsas) };
    } catch (e) { console.error(`[RadiusStats] ${statType} poll failed: ${e.message}`); }
  }

  for (const [statType, row] of Object.entries(rows)) {
    try {
      await db.query(
        `INSERT INTO radius_stats (stat_type, total_requests, total_accepts, total_rejects, total_challenges, total_responses, dup_requests, malformed_requests, invalid_requests, dropped_requests, unknown_types, server_start_time, server_hup_time, raw_vsas) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [statType, row.total_requests, row.total_accepts, row.total_rejects, row.total_challenges, row.total_responses, row.dup_requests, row.malformed_requests, row.invalid_requests, row.dropped_requests, row.unknown_types, row.server_start_time, row.server_hup_time, row.raw_vsas]
      );
    } catch (e) { console.error(`[RadiusStats] DB write failed: ${e.message}`); }
  }
  try { await db.query(`DELETE FROM radius_stats WHERE collected_at < DATE_SUB(NOW(), INTERVAL 7 DAY)`); } catch (e) {}
}

setTimeout(() => {
  console.log(`[RadiusStats] Worker started — polling every ${POLL_MS / 1000}s`);
  poll(); setInterval(poll, POLL_MS);
}, 30000);
