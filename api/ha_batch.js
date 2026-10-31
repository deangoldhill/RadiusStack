'use strict';
const MAX_BATCH_ITEMS=200;
const MAX_BATCH_BYTES=1024*1024;
const EXCLUDED_FULL_SYNC_TABLES=new Set(['ha_queue','ha_sync_state','ha_replay_state','ha_control_state','ha_log_reconcile_state','radius_stats','schema_migrations','syslog_auth_checkpoint']);
function shouldFullSyncTable(name){return !EXCLUDED_FULL_SYNC_TABLES.has(name) && !name.startsWith('ha_backup_') && !name.startsWith('ha_stage_')}
function canProduceHaSync(enabled,role){return enabled===true && role==='primary'}
function buildHaBatch(rows) {
  const entries=[];
  for (const row of rows) {
    if (entries.length>=MAX_BATCH_ITEMS) break;
    const entry={id:Number(row.id),query:row.query,values:JSON.parse(row.values_json||'[]'),insertId:row.insert_id||null};
    if (!Number.isSafeInteger(entry.id)||entry.id<=0||typeof entry.query!=='string'||!Array.isArray(entry.values)) throw new Error('Invalid HA queue entry');
    const candidate={entries:[...entries,entry]};
    if (Buffer.byteLength(JSON.stringify(candidate))>MAX_BATCH_BYTES) {
      if (!entries.length) throw new Error('HA queue entry too large for batch');
      break;
    }
    entries.push(entry);
  }
  return {entries};
}
async function applyHaBatch({entries,sourcePeer,getConnection,restart,ready,beforeEntry}) {
  if (!Array.isArray(entries)||!entries.length||entries.length>MAX_BATCH_ITEMS||
      Buffer.byteLength(JSON.stringify({entries}))>MAX_BATCH_BYTES||!sourcePeer) throw new Error('Invalid HA batch bounds');
  let previous=0;
  for (const entry of entries) {
    if (!Number.isSafeInteger(entry?.id)||entry.id<=previous||typeof entry.query!=='string'||!Array.isArray(entry.values)) throw new Error('Invalid HA batch order or contents');
    previous=entry.id;
  }
  const conn=await getConnection();
  let committed=false,applied=0,ignored=0,restartPending=0;
  const ackId=entries.at(-1).id;
  try {
    await conn.query('SET FOREIGN_KEY_CHECKS=0');
    await conn.beginTransaction();
    await conn.query('INSERT IGNORE INTO ha_replay_state (source_peer) VALUES (?)',[sourcePeer]);
    const [stateRows]=await conn.query('SELECT last_queue_id,radsec_restart_pending FROM ha_replay_state WHERE source_peer=? FOR UPDATE',[sourcePeer]);
    const cursor=Number(stateRows[0].last_queue_id);
    // Legacy column name: the durable bit now covers both RadSec and downstream destination restarts.
    restartPending=Number(stateRows[0].radsec_restart_pending);
    const {normalizeHaSqlValues}=require('./ha_admin_json');
    const {needsRadiusRestart}=require('./ha_radsec_sync');
    for(const entry of entries){
      if(entry.id<=cursor)continue;
      const values=normalizeHaSqlValues(entry.query,entry.values.map(value=>
        typeof value==='string'&&/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$/.test(value)?value.replace('T',' ').replace('Z',''):value));
      await conn.query('SAVEPOINT ha_row');
      try {
        if(beforeEntry)await beforeEntry(conn,entry,values);
        if(entry.insertId){await conn.query('SET SESSION auto_increment_increment = 1');await conn.query('SET insert_id = ?',[entry.insertId]);}
        await conn.query(entry.query,values);
        applied++;
      } catch(error){
        if(error.code!=='ER_DUP_ENTRY')throw error;
        await conn.query('ROLLBACK TO SAVEPOINT ha_row');
        ignored++;
      }
      if(needsRadiusRestart(entry.query,values))restartPending=1;
    }
    await conn.query('UPDATE ha_replay_state SET last_queue_id=?,radsec_restart_pending=? WHERE source_peer=?',[Math.max(cursor,ackId),restartPending,sourcePeer]);
    await conn.commit();committed=true;
    if(restartPending){
      await restart();
      if(ready){let healthy=false;for(let n=0;n<10;n++){if(await ready()){healthy=true;break;}if(n<9)await new Promise(resolve=>setTimeout(resolve,500));}if(!healthy)throw new Error('Secondary Radius not ready after HA batch');}
      await conn.query('UPDATE ha_replay_state SET radsec_restart_pending=0 WHERE source_peer=? AND last_queue_id=?',[sourcePeer,Math.max(cursor,ackId)]);
    }
    return {ackId,applied,ignored};
  }catch(error){if(!committed)await conn.rollback();throw error;}
  finally {try{await conn.query('SET FOREIGN_KEY_CHECKS=1')}finally{conn.release()}}
}
async function deliverHaBatch({rows,post,deleteRows}) {
  const batch=buildHaBatch(rows);
  if (!batch.entries.length) return null;
  const ack=await post(batch);
  const ackId=batch.entries.at(-1).id;
  if (!ack || ack.ackId!==ackId) throw new Error('HA batch acknowledgement mismatch');
  await deleteRows(batch.entries.map(entry=>entry.id));
  return {ackId,count:batch.entries.length};
}
module.exports={MAX_BATCH_ITEMS,MAX_BATCH_BYTES,buildHaBatch,applyHaBatch,deliverHaBatch,shouldFullSyncTable,canProduceHaSync};
