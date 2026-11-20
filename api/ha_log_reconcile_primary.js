'use strict';
const crypto = require('node:crypto');
const {MAX_ROWS, MAX_BYTES} = require('./ha_log_reconcile');

const TABLES = Object.freeze({radacct: 'radacctid', radpostauth: 'id', admin_audit_log: 'id', plan_pod_enforcements: 'radacctid'});
const PREFIX = '/api/sync/log-reconcile';
function countFrom(rows) {
  const value = rows?.[0]?.n;
  if (!/^(0|[1-9][0-9]*)$/.test(String(value)) || !Number.isSafeInteger(Number(value))) throw new Error('Invalid primary snapshot count');
  return Number(value);
}
function encodeValue(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  // Dates silently lose MySQL wall-clock timezone and fractional precision when JSON encoded.
  // Buffers become JSON objects that the secondary SQL insert cannot decode.
  throw new Error('Unsupported snapshot value; use dateStrings and non-binary columns');
}
function encodeRow(row) {
  if (!row || typeof row !== 'object' || Array.isArray(row)) throw new Error('Invalid snapshot row');
  return Object.fromEntries(Object.entries(row).map(([key, value]) => [key, encodeValue(value)]));
}
function cursorValue(value) {
  if (!/^[0-9]+$/.test(String(value)) || BigInt(value) < 0n) throw new Error('Invalid snapshot primary key');
  return BigInt(value);
}
// Caller owns peer authentication/encryption, primary role authorization and durable
// job state. post(path, payload) must return the decoded secondary acknowledgement.
// getConnection must yield a dedicated MySQL connection with dateStrings enabled:
// Date objects and Buffers are rejected, not silently converted. pauseStatus must
// report {paused:true, queueDepth:<integer>}; queueDrainable must prove the existing
// ha_queue can be delivered after replacement. drainQueue(fence) must deliver
// through a fixed queue ID while normal delivery is paused. This does not repair
// the separate nontransactional source-write/outbox gap.
function createPrimaryHaLogReconciler({post, getConnection, pauseStatus, queueDrainable, queueFence, drainQueue, onProgress = () => {}}) {
  if ([post, getConnection, pauseStatus, queueDrainable, queueFence, drainQueue, onProgress].some(fn => typeof fn !== 'function'))
    throw new TypeError('Reconciliation requires peer post, snapshot connection, pause status, queue drainability, queue fence, drain and progress callbacks');
  let active = false;
  async function guard() {
    const status = await pauseStatus();
    if (status?.paused !== true || !Number.isSafeInteger(status.queueDepth) || status.queueDepth < 0)
      throw new Error('Primary HA delivery must remain paused with a valid queue depth');
    if (await queueDrainable() !== true) throw new Error('HA queue is not drainable; cannot reconcile');
    return status;
  }
  async function request(method, payload, check) {
    const response = await post(PREFIX, {action: method, ...payload});
    if (!response || !check(response)) throw new Error(`Invalid reconciliation ${method} acknowledgement`);
    return response;
  }
  async function progress(value) { await onProgress(value); }
  async function fence() {
    const id=await queueFence();
    if (!Number.isSafeInteger(id) || id<0) throw new Error('Invalid HA queue fence');
    return id;
  }
  async function run() {
    if (active) throw new Error('Reconciliation already running');
    active = true;
    const runId = crypto.randomBytes(16).toString('hex');
    let conn, transactionOpen = false, peerPreparationAttempted = false;
    const counts = {};
    try {
      await guard();
      const before=await fence();
      if (before) {
        await progress({runId,status:'pre-draining',queueFence:before});
        const drained=await drainQueue(before);
        if (drained?.drained!==true) throw new Error('HA queue pre-drain incomplete');
      }
      await guard();
      await progress({runId, status: 'preparing'});
      peerPreparationAttempted = true;
      await request('prepare', {runId}, r => r.runId === runId && r.status === 'staging');
      conn = await getConnection();
      // All three tables must be read on the same connection, in one RR snapshot.
      await conn.query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
      await conn.query('START TRANSACTION WITH CONSISTENT SNAPSHOT');
      transactionOpen = true;
      for (const [table, pk] of Object.entries(TABLES)) {
        await guard();
        const [countRows] = await conn.query(`SELECT COUNT(*) AS n FROM \`${table}\``);
        const expected = countFrom(countRows);
        let cursor = 0n, reasonCursor = '', sent = 0, pending = [], bytes = 2;
        const composite = table === 'plan_pod_enforcements';
        const send = async () => {
          if (!pending.length) return;
          await guard();
          const rows = pending;
          await request('stage', {runId, table, rows}, r => r.accepted === rows.length);
          sent += rows.length;
          await progress({runId, status: 'staging', table, sent, expected});
          pending = []; bytes = 2;
        };
        for (;;) {
          await guard();
          const [page] = composite
            ? await conn.query(`SELECT * FROM \`plan_pod_enforcements\` WHERE (\`radacctid\` > ? OR (\`radacctid\` = ? AND \`reason\` > ?)) ORDER BY \`radacctid\`, \`reason\` LIMIT ${MAX_ROWS}`, [cursor.toString(), cursor.toString(), reasonCursor])
            : await conn.query(`SELECT * FROM \`${table}\` WHERE \`${pk}\` > ? ORDER BY \`${pk}\` LIMIT ${MAX_ROWS}`, [cursor.toString()]);
          if (!Array.isArray(page) || page.length > MAX_ROWS) throw new Error('Invalid snapshot page');
          if (!page.length) break;
          for (const raw of page) {
            const row = encodeRow(raw), id = cursorValue(row[pk]);
            if (id < cursor || (id === cursor && (!composite || typeof row.reason !== 'string' || row.reason <= reasonCursor))) throw new Error('Snapshot primary keys are not strictly increasing');
            cursor = id;
            if (composite) {
              if (!['data','time'].includes(row.reason)) throw new Error('Invalid enforcement reason');
              reasonCursor = row.reason;
            }
            const text = JSON.stringify(row), size = Buffer.byteLength(text);
            if (size + 2 > MAX_BYTES) throw new Error('Snapshot row exceeds reconciliation chunk limit');
            if (pending.length === MAX_ROWS || bytes + size + (pending.length ? 1 : 0) > MAX_BYTES) await send();
            pending.push(row); bytes += size + (pending.length > 1 ? 1 : 0);
          }
          if (page.length < MAX_ROWS) break;
        }
        await send();
        if (sent !== expected) throw new Error(`Primary snapshot count mismatch for ${table}`);
        await guard();
        await request('seal', {runId, table, expectedCount: expected}, r => r.table === table && r.expectedCount === expected);
        counts[table] = expected;
        await progress({runId, status: 'sealed', table, expected});
      }
      await conn.commit(); transactionOpen = false;
      conn.release(); conn = null;
      await guard();
      await progress({runId, status: 'finalizing'});
      const replaced=await request('replace', {runId}, r => r.runId === runId && r.status === 'finalized' &&
        r.verification?.reconciliation === 'applied' &&
        Object.keys(TABLES).every(t=>r.verification.conflicts?.[t]===0 && r.verification.preserved?.[t]===0 && r.verification[t]===counts[t]));
      const verified=replaced.verification;
      await guard();
      const target=await fence();
      await progress({runId, status: 'catching-up',queueFence:target});
      const drained = await drainQueue(target);
      if (drained?.drained !== true) throw new Error('HA queue catchup incomplete');
      await guard();
      // Catch-up replays legitimate post-snapshot writes. Do not compare their
      // resulting live rows against the earlier snapshot a second time.
      const result = {runId, status: 'completed', counts, secondary: verified};
      // Cleanup is idempotent on the secondary. A lost acknowledgement may mean
      // the tables were already dropped, so retry once with the same run ID.
      try { await request('cleanup', {runId}, r => r.runId === runId && r.status === 'cleaned'); }
      catch (_) { await request('cleanup', {runId}, r => r.runId === runId && r.status === 'cleaned'); }
      await progress(result);
      return result;
    } catch (error) {
      if (transactionOpen) {
        try { await conn.rollback(); } catch (rollbackError) { error.rollbackError = rollbackError; }
      }
      // No success is ever emitted on failure, including after remote finalization.
      // Before prepare, the secondary has not been touched and retry is safe.
      // A timed-out prepare may have succeeded remotely, so every later failure
      // stays blocked pending explicit review.
      try { await progress({runId, status: peerPreparationAttempted ? 'failed' : 'failed-pre-drain', error: error.message}); } catch (_) { /* preserve cause */ }
      throw error;
    } finally {
      if (conn) conn.release();
      active = false;
    }
  }
  return {run};
}
module.exports = {createPrimaryHaLogReconciler};
