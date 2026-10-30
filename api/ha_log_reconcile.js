'use strict';

// Database contract: ha_log_reconcile_state singleton id=1, run_id CHAR(32),
// status ('new','staging','ready','finalized'), and nullable BIGINT
// expected_radacct, expected_radpostauth, expected_admin_audit_log.
// Caller authenticates the peer. Secondary Radius writers remain online.
const TABLES = Object.freeze({radacct: 'radacctid', radpostauth: 'id', admin_audit_log: 'id'});
const MAX_ROWS = 200;
const MAX_BYTES = 1024 * 1024;
function tableNames(table, runId) {
  if (!Object.hasOwn(TABLES, table) || !/^[0-9a-f]{32}$/.test(runId)) throw new Error('Invalid reconciliation table or run ID');
  return {stage: `ha_stage_${table}_${runId}`, backup: `ha_backup_${table}_${runId}`};
}
const quote = s => `\`${s}\``;
function countValue(rows) {
  const n = Number(rows[0]?.n);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('Invalid reconciliation count');
  return n;
}
async function count(conn, table) {
  const [rows] = await conn.query(`SELECT COUNT(*) AS n FROM ${quote(table)}`);
  return countValue(rows);
}
function createHaLogReconciler({getConnection, role}) {
  if (![getConnection, role].every(f => typeof f === 'function')) throw new TypeError('Reconciliation requires getConnection and role');
  async function guard() {
    if (await role() !== 'secondary') throw new Error('Reconciliation is secondary-only');
  }
  async function state(conn, runId, lock = false) {
    const [rows] = await conn.query(`SELECT run_id, status, detail, expected_radacct, expected_radpostauth, expected_admin_audit_log FROM ha_log_reconcile_state WHERE id=1${lock ? ' FOR UPDATE' : ''}`);
    if (rows.length !== 1 || rows[0].run_id !== runId) throw new Error('Missing or mismatched reconciliation singleton');
    return rows[0];
  }
  async function columns(conn, table) {
    const [rows] = await conn.query(`SHOW COLUMNS FROM ${quote(table)}`);
    const names = rows.map(r => r.Field);
    if (!names.length || !names.every(n => /^[a-z][a-z0-9_]*$/.test(n)) || !names.includes(TABLES[table])) throw new Error('Unsupported reconciliation schema');
    return names;
  }
  async function transaction(conn, fn) {
    await conn.beginTransaction();
    try { const result = await fn(); await guard(); await conn.commit(); return result; }
    catch (e) { await conn.rollback(); throw e; }
  }
  // DDL commits implicitly. Create tables before beginning the nonlocking RC copy.
  // Each INSERT SELECT is one statement snapshot; a retry after partial DDL requires operator review.
  async function prepare({runId}) {
    tableNames('radacct', runId); await guard();
    const conn = await getConnection();
    try {
      const s = await state(conn, runId);
      if (s.status !== 'new') throw new Error('Reconciliation run is not new');
      for (const table of Object.keys(TABLES)) {
        await guard();
        const {stage, backup} = tableNames(table, runId), pk = TABLES[table];
        await conn.query(`CREATE TABLE ${quote(backup)} LIKE ${quote(table)}`);
        await conn.query(`CREATE TABLE ${quote(stage)} LIKE ${quote(table)}`);
      }
      await conn.query('SET TRANSACTION ISOLATION LEVEL READ COMMITTED');
      await conn.beginTransaction();
      try {
        for (const table of Object.keys(TABLES)) {
          await guard();
          const {backup} = tableNames(table, runId);
          const [copied] = await conn.query(`INSERT INTO ${quote(backup)} SELECT * FROM ${quote(table)}`);
          if (await count(conn, backup) !== copied.affectedRows) throw new Error('Incomplete local backup copy');
        }
        await conn.commit();
      } catch (e) { await conn.rollback(); throw e; }
      await guard();
      const [r] = await conn.query("UPDATE ha_log_reconcile_state SET status='staging' WHERE id=1 AND run_id=? AND status='new'", [runId]);
      if (r.affectedRows !== 1) throw new Error('Reconciliation state changed during backup');
      return {runId, status: 'staging'};
    } finally { conn.release(); }
  }
  async function stageChunk({runId, table, rows}) {
    const {stage} = tableNames(table, runId);
    if (!Array.isArray(rows) || !rows.length || rows.length > MAX_ROWS || Buffer.byteLength(JSON.stringify(rows)) > MAX_BYTES) throw new Error('Invalid reconciliation chunk bounds');
    await guard();
    const conn = await getConnection();
    try {
      return await transaction(conn, async () => {
        if ((await state(conn, runId, true)).status !== 'staging') throw new Error('Reconciliation staging is closed');
        const names = await columns(conn, table);
        const provided = Object.keys(rows[0]);
        if (provided.length !== names.length || !names.every(n => provided.includes(n)) || rows.some(row => !row || Object.keys(row).length !== names.length || !names.every(n => Object.hasOwn(row, n)))) throw new Error('Invalid reconciliation column set');
        const sql = `INSERT INTO ${quote(stage)} (${names.map(quote).join(',')}) VALUES ${rows.map(() => `(${names.map(() => '?').join(',')})`).join(',')}`;
        const [r] = await conn.query(sql, rows.flatMap(row => names.map(n => row[n])));
        if (r.affectedRows !== rows.length) throw new Error('Incomplete reconciliation chunk');
        return {accepted: rows.length};
      });
    } finally { conn.release(); }
  }
  async function sealTable({runId, table, expectedCount}) {
    const {stage} = tableNames(table, runId);
    if (!Number.isSafeInteger(expectedCount) || expectedCount < 0) throw new Error('Invalid expected count');
    await guard(); const conn = await getConnection();
    try {
      return await transaction(conn, async () => {
        const s = await state(conn, runId, true);
        if (s.status !== 'staging' || s[`expected_${table}`] !== null) throw new Error('Reconciliation table already sealed or staging closed');
        if (await count(conn, stage) !== expectedCount) throw new Error('Incomplete staged transfer count');
        const [r] = await conn.query(`UPDATE ha_log_reconcile_state SET expected_${table}=?, status=? WHERE id=1 AND run_id=? AND status='staging'`, [expectedCount, Object.keys(TABLES).filter(t => t !== table).every(t => s[`expected_${t}`] !== null) ? 'ready' : 'staging', runId]);
        if (r.affectedRows !== 1) throw new Error('Reconciliation state changed');
        return {table, expectedCount};
      });
    } finally { conn.release(); }
  }
  const order = Object.keys(TABLES);
  const initial = () => ({table: order[0], phase: 'backup', pk: null});
  function progress(s) {
    if (!s.detail) return initial();
    let value;
    try { value = JSON.parse(s.detail); } catch { throw new Error('Invalid durable reconciliation progress'); }
    if (!value || !['backup', 'stage', 'done'].includes(value.phase) ||
        (value.table !== null && !order.includes(value.table)) ||
        (value.pk !== null && !/^-?[0-9]+$/.test(String(value.pk)))) throw new Error('Invalid durable reconciliation progress');
    return value;
  }
  function requestedCursor(cursor) {
    if (cursor === null) return {phase: 'backup', pk: null};
    if (!cursor || !['backup', 'stage'].includes(cursor.phase) ||
        (cursor.pk !== null && !/^-?[0-9]+$/.test(String(cursor.pk)))) throw new Error('Invalid reconciliation cursor');
    return {phase: cursor.phase, pk: cursor.pk === null ? null : String(cursor.pk)};
  }
  async function validateStages(conn, s, runId) {
    for (const table of order) {
      const expected = Number(s[`expected_${table}`]);
      if (s[`expected_${table}`] === null || !Number.isSafeInteger(expected) || expected < 0 ||
          await count(conn, tableNames(table, runId).stage) !== expected) throw new Error('Staged transfer count mismatch');
    }
  }
  // A page locks the singleton only for <=200 PKs, never locks a live table.
  // The checkpoint and its CAS writes commit together; retry after a lost reply is safe.
  async function finalizeStep({runId, table, cursor}) {
    const {stage, backup} = tableNames(table, runId);
    const wanted = requestedCursor(cursor);
    await guard(); const conn = await getConnection();
    try {
      await conn.query('SET TRANSACTION ISOLATION LEVEL READ COMMITTED');
      return await transaction(conn, async () => {
        const s = await state(conn, runId, true);
        if (s.status !== 'ready') throw new Error('Reconciliation transfer not ready');
        const p = progress(s);
        if (p.last && p.last.table === table && p.last.phase === wanted.phase && p.last.pk === wanted.pk)
          return {nextCursor: p.table === table ? {phase: p.phase, pk: p.pk} : null, done: p.table !== table};
        if (p.table !== table || p.phase !== wanted.phase || p.pk !== wanted.pk) throw new Error('Stale or out-of-order reconciliation cursor');
        if (!s.detail) await validateStages(conn, s, runId);
        const pk = TABLES[table], source = p.phase === 'backup' ? backup : stage;
        const names = await columns(conn, table);
        const [rows] = await conn.query(`SELECT * FROM ${quote(source)} ${p.pk === null ? '' : `WHERE ${quote(pk)} > ? `}ORDER BY ${quote(pk)} LIMIT ${MAX_ROWS}`, p.pk === null ? [] : [p.pk]);
        if (rows.length > MAX_ROWS) throw new Error('Reconciliation page exceeded bound');
        if (rows.length) {
          const ids = rows.map(row => row[pk]);
          const other = p.phase === 'backup' ? stage : backup;
          const [otherRows] = await conn.query(`SELECT ${p.phase === 'backup' ? quote(pk) : '*'} FROM ${quote(other)} WHERE ${quote(pk)} IN (${ids.map(() => '?').join(',')})`, ids);
          const lookup = new Map(otherRows.map(row => [String(row[pk]), row]));
          for (const row of rows) {
            const id = row[pk], counterpart = lookup.get(String(id));
            if (p.phase === 'backup') {
              if (counterpart || (table === 'radacct' && row.acctstoptime === null)) continue;
              const [r] = await conn.query(`DELETE FROM ${quote(table)} WHERE ${quote(pk)}=? AND ${names.map(n => `${quote(n)} <=> ?`).join(' AND ')}`, [id, ...names.map(n => row[n])]);
              if (r.affectedRows > 1) throw new Error('Unbounded reconciliation delete');
            } else {
              if (counterpart) {
                const writable = names.filter(n => n !== pk);
                try {
                  const [r] = await conn.query(`UPDATE ${quote(table)} SET ${writable.map(n => `${quote(n)}=?`).join(',')} WHERE ${quote(pk)}=? AND ${names.map(n => `${quote(n)} <=> ?`).join(' AND ')}${table === 'radacct' ? ' AND `acctuniqueid` <=> ?' : ''}`, [...writable.map(n => row[n]), id, ...names.map(n => counterpart[n]), ...(table === 'radacct' ? [row.acctuniqueid] : [])]);
                  if (r.affectedRows > 1) throw new Error('Unbounded reconciliation update');
                } catch (e) { if (e.code !== 'ER_DUP_ENTRY') throw e; }
              }
              // Insert only absent PKs; a concurrent PK/unique-ID winner is preserved.
              // An existing changed secondary row is never replaced.
              const [live] = await conn.query(`SELECT ${quote(pk)} FROM ${quote(table)} WHERE ${quote(pk)}=? LIMIT 1`, [id]);
              if (live.length) continue;
              try {
                await conn.query(`INSERT INTO ${quote(table)} (${names.map(quote).join(',')}) VALUES (${names.map(() => '?').join(',')})`, names.map(n => row[n]));
              } catch (e) { if (e.code !== 'ER_DUP_ENTRY') throw e; }
            }
          }
        }
        const exhausted = rows.length < MAX_ROWS;
        let next;
        if (!exhausted) next = {table, phase: p.phase, pk: String(rows[rows.length - 1][pk])};
        else if (p.phase === 'backup') next = {table, phase: 'stage', pk: null};
        else next = {table: order[order.indexOf(table) + 1] || null, phase: order.indexOf(table) === order.length - 1 ? 'done' : 'backup', pk: null};
        next.last = {table, phase: p.phase, pk: p.pk};
        const [r] = await conn.query("UPDATE ha_log_reconcile_state SET detail=? WHERE id=1 AND run_id=? AND status='ready'", [JSON.stringify(next), runId]);
        if (r.affectedRows !== 1) throw new Error('Reconciliation state changed');
        return {nextCursor: next.table === table ? {phase: next.phase, pk: next.pk} : null, done: next.table !== table};
      });
    } finally { conn.release(); }
  }
  async function finalize({runId}) {
    tableNames('radacct', runId); await guard(); const conn = await getConnection();
    try {
      const s = await state(conn, runId);
      if (s.status !== 'ready') throw new Error('Reconciliation transfer not ready');
      if (progress(s).phase !== 'done') throw new Error('Reconciliation steps incomplete');
      await validateStages(conn, s, runId);
      // No live mutations or long transaction here. A failure remains unverified.
      const outcome = await inspect(conn, runId);
      const [r] = await conn.query("UPDATE ha_log_reconcile_state SET status='finalized' WHERE id=1 AND run_id=? AND status='ready' AND detail=?", [runId, s.detail]);
      if (r.affectedRows !== 1) throw new Error('Reconciliation state changed');
      return {runId, status: 'finalized', ...outcome};
    } finally { conn.release(); }
  }
  async function inspect(conn, runId) {
    const result = {reconciliation: 'applied', conflicts: {}, preserved: {}};
    for (const table of Object.keys(TABLES)) {
      const {stage, backup} = tableNames(table, runId), pk = TABLES[table];
      const names = await columns(conn, table);
      const matching = names.map(n => `live.${quote(n)}<=>stage.${quote(n)}`).join(' AND ');
      const unchanged = names.map(n => `live.${quote(n)}<=>backup.${quote(n)}`).join(' AND ');
      result[table] = await count(conn, table);
      const [stageDiff] = await conn.query(`SELECT COUNT(*) AS conflict_count FROM ${quote(stage)} stage LEFT JOIN ${quote(table)} live ON live.${quote(pk)}=stage.${quote(pk)} WHERE live.${quote(pk)} IS NULL OR NOT (${matching})`);
      const [backupDiff] = await conn.query(`SELECT COUNT(*) AS conflict_count FROM ${quote(backup)} backup JOIN ${quote(table)} live ON live.${quote(pk)}=backup.${quote(pk)} LEFT JOIN ${quote(stage)} stage ON stage.${quote(pk)}=backup.${quote(pk)} WHERE stage.${quote(pk)} IS NULL AND ${table === 'radacct' ? 'backup.`acctstoptime` IS NOT NULL AND ' : ''}NOT (${unchanged})`);
      const a = countValue(stageDiff.map(r => ({n: r.conflict_count})));
      const b = countValue(backupDiff.map(r => ({n: r.conflict_count})));
      result.conflicts[table] = a + b;
      // Preserved rows include secondary-only active/new rows and local changes.
      const [preserved] = await conn.query(`SELECT COUNT(*) AS n FROM ${quote(table)} live LEFT JOIN ${quote(stage)} stage ON live.${quote(pk)}=stage.${quote(pk)} WHERE stage.${quote(pk)} IS NULL`);
      result.preserved[table] = countValue(preserved);
      if (result.conflicts[table]) result.reconciliation = 'conflict';
      else if (result.preserved[table] && result.reconciliation === 'applied') result.reconciliation = 'preserved';
    }
    return result;
  }
  async function verify({runId}) {
    tableNames('radacct', runId); await guard(); const conn = await getConnection();
    try {
      const s = await state(conn, runId);
      if (s.status !== 'finalized') throw new Error('Reconciliation not finalized');
      // A live read can race writers: this is a point-in-time observation, not
      // a guarantee that the replica still equals the source after return.
      for (const table of Object.keys(TABLES)) {
        const {stage} = tableNames(table, runId);
        const expected = Number(s[`expected_${table}`]);
        if (s[`expected_${table}`] === null || !Number.isSafeInteger(expected) || expected < 0 || await count(conn, stage) !== expected) throw new Error('Staged transfer count mismatch');
      }
      return {runId, status: 'finalized', ...await inspect(conn, runId)};
    } finally { conn.release(); }
  }
  return {prepare, stageChunk, sealTable, finalizeStep, finalize, verify};
}
module.exports = {createHaLogReconciler, tableNames, MAX_ROWS, MAX_BYTES};
