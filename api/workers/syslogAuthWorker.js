'use strict';
const syslog = require('../utils/syslog');
let _pool = null, _lastId = 0, _ready = false;

async function init(pool) {
  _pool = pool;
  try {
    const [rows] = await pool.query('SELECT MAX(id) AS maxid FROM radpostauth', [], { isSync: true });
    _lastId = rows[0]?.maxid || 0;
    console.log(`[SyslogAuthWorker] Initialised. Seeded from id=${_lastId}`);
  } catch (e) {
    console.warn('[SyslogAuthWorker] Could not seed last id:', e.message);
  }
  _ready = true;
}

async function poll() {
  if (!_pool || !_ready) return;
  try {
    const [rows] = await _pool.query(
      'SELECT id, username, reply, nasipaddress, callingstationid, authdate FROM radpostauth WHERE id > ? ORDER BY id ASC LIMIT 200',
      [_lastId]
    );
    for (const row of rows) {
      await syslog.sendAuthLog(row);
      _lastId = row.id;
    }
  } catch (e) {}
}

module.exports = { init, poll };