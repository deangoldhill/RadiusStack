'use strict';

// Reverse HA traffic is deliberately narrower than primary-to-secondary SQL replay.
// Only the scanner's exact, parameterized radacct/radpostauth upsert format is accepted.
function validateReverseLogBatch(entries, peerOffset) {
  if (peerOffset !== 1 && peerOffset !== 2) throw new Error('Invalid HA peer database offset');
  if (!Array.isArray(entries) || !entries.length || entries.length > 200) throw new Error('Invalid reverse log batch');
  for (const entry of entries) {
    if (!entry || typeof entry.query !== 'string' || !Array.isArray(entry.values) || entry.insertId != null)
      throw new Error('Invalid reverse log entry');
    const match=/^INSERT INTO (radacct|radpostauth) \(([a-z0-9_, ]+)\) VALUES \(/.exec(entry.query);
    if (!match) throw new Error('Reverse HA permits only accounting and auth logs');
    const [, table, fieldList]=match;
    const fields=fieldList.split(', ');
    if (!fields.length || fields.length > 64 || new Set(fields).size !== fields.length ||
        fields.some(name=>!/^[a-z][a-z0-9_]*$/.test(name)) || entry.values.length !== fields.length)
      throw new Error('Invalid reverse log columns');
    const expected=`INSERT INTO ${table} (${fields.join(', ')}) VALUES (${fields.map(()=>'?').join(', ')}) ON DUPLICATE KEY UPDATE ${fields.map(name=>`${name}=VALUES(${name})`).join(', ')}`;
    if (entry.query !== expected) throw new Error('Invalid reverse log SQL format');
    const idIndex=fields.indexOf(table==='radacct'?'radacctid':'id');
    if (idIndex<0) throw new Error('Reverse log primary key required');
    const value=entry.values[idIndex];
    if (!/^[1-9][0-9]*$/.test(String(value)) || BigInt(String(value))%2n !== BigInt(peerOffset%2))
      throw new Error('Reverse log row does not belong to HA peer');
  }
  return true;
}
async function checkReverseLogOwnership(conn,entry,values) {
  if (!entry.query.startsWith('INSERT INTO radacct (')) return;
  const fields=entry.query.match(/^INSERT INTO radacct \(([^)]+)\) VALUES/)[1].split(', ');
  const id=values[fields.indexOf('radacctid')];
  const uniqueIndex=fields.indexOf('acctuniqueid');
  if (uniqueIndex<0)throw new Error('Reverse accounting session key required');
  const uniqueId=values[uniqueIndex];
  const [bySession]=await conn.query('SELECT radacctid FROM radacct WHERE acctuniqueid=? FOR UPDATE',[uniqueId]);
  if(bySession.length && String(bySession[0].radacctid)!==String(id))
    throw new Error('Reverse accounting unique session conflicts with another row; reconcile before retry');
  const [byId]=await conn.query('SELECT acctuniqueid FROM radacct WHERE radacctid=? FOR UPDATE',[id]);
  if(byId.length && byId[0].acctuniqueid!==uniqueId)
    throw new Error('Reverse accounting row ID conflicts with another session; reconcile before retry');
}
module.exports={validateReverseLogBatch,checkReverseLogOwnership};
