'use strict';
const syslog=require('../utils/syslog');
let _pool=null, _busy=false;
async function init(pool) {
  _pool=pool;
  // First deployment starts at the current high-water mark; subsequent starts never reset it.
  await pool.query('INSERT IGNORE INTO syslog_auth_checkpoint (id, last_id) SELECT 1, COALESCE(MAX(id),0) FROM radpostauth');
}
async function poll() {
  if(!_pool||_busy)return;
  _busy=true;
  try {
    if(!await syslog.authEnabled())return;
    const [[state]]=await _pool.query('SELECT last_id FROM syslog_auth_checkpoint WHERE id=1');
    if(!state)throw Error('Syslog auth checkpoint missing');
    const [rows]=await _pool.query('SELECT id, username, reply, nasipaddress, callingstationid, calledstationid, replymessage, authdate, tenant_id FROM radpostauth WHERE id > ? ORDER BY id ASC LIMIT 200',[state.last_id]);
    for(const row of rows) {
      if(!await syslog.sendAuthLog(row))return; // disabled mid-batch: preserve unsent row
      await _pool.query('UPDATE syslog_auth_checkpoint SET last_id=? WHERE id=1 AND last_id < ?',[row.id,row.id]);
    }
  }catch(e){console.error('[SyslogAuthWorker] Delivery/checkpoint failed:',e.message);}
  finally{_busy=false;}
}
module.exports={init,poll};
