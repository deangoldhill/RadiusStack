'use strict';
const dgram  = require('dgram');
const crypto = require('crypto');
const mysql  = require('mysql2/promise');

const STATUS_HOST   = 'radius_server';
const STATUS_PORT   = '18121';
const STATUS_SECRET = 'RADIUS_STATUS_SECRET_GENERIC';
const FR_VENDOR     = 11344;

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

// Runtime config — reloaded from the settings table on every poll cycle
let POLL_MS              = 60000;   // fallback default
let PURGE_DAYS           = 7;
let PURGE_INTERVAL_MS    = 60 * 60 * 1000;  // 60 minutes
let lastPurgeRun         = 0;
let pollTimer            = null;

async function loadConfig() {
  try {
    const [rows] = await db.query(
      `SELECT setting_key, setting_value FROM settings
       WHERE setting_key IN (
         'radius_stats_poll_interval',
         'radius_stats_retention_days',
         'radius_stats_purge_interval'
       )`
    );
    rows.forEach(r => {
      if (r.setting_key === 'radius_stats_poll_interval') {
        const ms = parseInt(r.setting_value, 10);
        if (ms >= 5000) POLL_MS = ms;
      }
      if (r.setting_key === 'radius_stats_retention_days') {
        const d = parseInt(r.setting_value, 10);
        if (d >= 1) PURGE_DAYS = d;
      }
      if (r.setting_key === 'radius_stats_purge_interval') {
        const m = parseInt(r.setting_value, 10);
        if (m >= 1) PURGE_INTERVAL_MS = m * 60 * 1000;
      }
    });
  } catch (e) {
    // Settings table may not exist on first boot — use defaults
  }
}

function buildPacket(secret, statTypeInt) {
  const id = Math.floor(Math.random() * 256);
  const reqAuth = crypto.randomBytes(16);
  const buf = Buffer.alloc(50);
  buf[0] = 12; buf[1] = id;
  buf.writeUInt16BE(50, 2);
  reqAuth.copy(buf, 4);
  buf[20] = 26; buf[21] = 12;
  buf.writeUInt32BE(FR_VENDOR, 22);
  buf[26] = 127; buf[27] = 6;
  buf.writeUInt32BE(statTypeInt, 28);
  buf[32] = 80; buf[33] = 18;
  crypto.createHmac('md5', Buffer.from(secret, 'utf8')).update(buf).digest().copy(buf, 34);
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

function queryRadius(host, port, secret, statTypeInt) {
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
  const row = {
    total_requests: 0, total_accepts: 0, total_rejects: 0, total_challenges: 0,
    total_responses: 0, dup_requests: 0, malformed_requests: 0, invalid_requests: 0,
    dropped_requests: 0, unknown_types: 0, server_start_time: 0, server_hup_time: 0
  };
  for (const [vt, col] of Object.entries(attrMap)) {
    if (vsas[vt] !== undefined) row[col] = vsas[vt];
  }
  return row;
}

async function poll() {
  // Always reload config — picks up any changes saved via the Settings page
  await loadConfig();

  const rows = {};
  for (const [statType, statTypeInt, attrMap] of [['auth', 1, AUTH_MAP], ['acct', 2, ACCT_MAP]]) {
    try {
      const vsas = await queryRadius(STATUS_HOST, STATUS_PORT, STATUS_SECRET, statTypeInt);
      rows[statType] = { ...toRow(vsas, attrMap), raw_vsas: JSON.stringify(vsas) };
    } catch (e) {
      console.error(`[RadiusStats] ${statType} poll failed: ${e.message}`);
    }
  }

  for (const [statType, row] of Object.entries(rows)) {
    try {
      await db.query(
        `INSERT INTO radius_stats
           (stat_type, total_requests, total_accepts, total_rejects, total_challenges,
            total_responses, dup_requests, malformed_requests, invalid_requests,
            dropped_requests, unknown_types, server_start_time, server_hup_time, raw_vsas)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [statType, row.total_requests, row.total_accepts, row.total_rejects,
         row.total_challenges, row.total_responses, row.dup_requests,
         row.malformed_requests, row.invalid_requests, row.dropped_requests,
         row.unknown_types, row.server_start_time, row.server_hup_time, row.raw_vsas]
      );
    } catch (e) {
      console.error(`[RadiusStats] DB write failed: ${e.message}`);
    }
  }

  // Purge expired rows only at the configured interval — not every poll
  const now = Date.now();
  if (now - lastPurgeRun >= PURGE_INTERVAL_MS) {
    lastPurgeRun = now;
    try {
      const [result] = await db.query(
        'DELETE FROM radius_stats WHERE collected_at < DATE_SUB(NOW(), INTERVAL ? DAY)',
        [PURGE_DAYS]
      );
      if (result.affectedRows > 0) {
        console.log(`[RadiusStats] Purged ${result.affectedRows} rows older than ${PURGE_DAYS} days.`);
      }
    } catch (e) {
      console.error(`[RadiusStats] Purge failed: ${e.message}`);
    }
  }

  // Schedule next poll using the (possibly updated) POLL_MS value
  pollTimer = setTimeout(poll, POLL_MS);
}

setTimeout(() => {
  console.log('[RadiusStats] Worker started — config will be loaded from the settings table.');
  poll();
}, 30000);
