'use strict';
const crypto = require('node:crypto');
const {MAX_ROWS, MAX_BYTES} = require('./ha_log_reconcile');

const TABLES = Object.freeze({radacct: 'radacctid', radpostauth: 'id', admin_audit_log: 'id'});
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
// ha_queue can be delivered after replacement. drainQueue must actually deliver it
// despite normal HA delivery being paused, then return {drained:true}. Neither the
// pause flag nor queueDepth alone is an atomic primary-writer quiescence barrier.
function createPrimaryHaLogReconciler({post, getConnection, pauseStatus, queueDrainable, drainQueue, onProgress = () => {}}) {
  if ([post, getConnection, pauseStatus, queueDrainable, drainQueue, onProgress].some(fn => typeof fn !== 'function'))
    throw new TypeError('Reconciliation requires peer post, snapshot connection, pause status, queue drainability, drain and progress callbacks');
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
  async function run() {
    if (active) throw new Error('Reconciliation already running');
    active = true;
    const runId = crypto.randomBytes(16).toString('hex');
    let conn, transactionOpen = false;
    const counts = {};
    try {
      if ((await guard()).queueDepth !== 0) throw new Error('Cannot reconcile with a pre-existing HA queue');
      await progress({runId, status: 'preparing'});
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
        let cursor = 0n, sent = 0, pending = [], bytes = 2;
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
          const [page] = await conn.query(`SELECT * FROM \`${table}\` WHERE \`${pk}\` > ? ORDER BY \`${pk}\` LIMIT ${MAX_ROWS}`, [cursor.toString()]);
          if (!Array.isArray(page) || page.length > MAX_ROWS) throw new Error('Invalid snapshot page');
          if (!page.length) break;
          for (const raw of page) {
            const row = encodeRow(raw), id = cursorValue(row[pk]);
            if (id <= cursor) throw new Error('Snapshot primary keys are not strictly increasing');
            cursor = id;
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
      for (const table of Object.keys(TABLES)) {
        let cursor = null;
        for (;;) {
          await guard();
          const step = await request('finalizeStep', {runId, table, cursor}, r =>
            typeof r.done === 'boolean' && (r.done || (r.nextCursor &&
              ['backup','stage'].includes(r.nextCursor.phase) &&
              (r.nextCursor.pk === null || /^[0-9]+$/.test(String(r.nextCursor.pk))))));
          if (step.done) break;
          if (JSON.stringify(step.nextCursor) === JSON.stringify(cursor)) throw new Error('Reconciliation cursor did not advance');
          cursor = step.nextCursor;
        }
      }
      await request('finalize', {runId}, r => r.runId === runId && r.status === 'finalized');
      const verify = () => request('verify', {runId}, r => r.runId === runId && r.status === 'finalized' &&
        ['applied','preserved','conflict'].includes(r.reconciliation) &&
        ['radacct','radpostauth','admin_audit_log'].every(t => Number.isSafeInteger(r.conflicts?.[t]) && r.conflicts[t] >= 0 && Number.isSafeInteger(r.preserved?.[t]) && r.preserved[t] >= 0) &&
        (r.reconciliation !== 'applied' || (r.radacct === counts.radacct && r.radpostauth === counts.radpostauth && r.admin_audit_log === counts.admin_audit_log)));
      await verify();
      await guard();
      await progress({runId, status: 'catching-up'});
      const drained = await drainQueue();
      if (drained?.drained !== true || (await guard()).queueDepth !== 0) throw new Error('HA queue catchup incomplete');
      const verified = await verify();
      const status = verified.reconciliation === 'applied' ? 'completed' : 'partial';
      const result = {runId, status, counts, secondary: verified};
      await progress(result);
      return result;
    } catch (error) {
      if (transactionOpen) {
        try { await conn.rollback(); } catch (rollbackError) { error.rollbackError = rollbackError; }
      }
      // No success is ever emitted on failure, including after remote finalization.
      try { await progress({runId, status: 'failed', error: error.message}); } catch (_) { /* preserve cause */ }
      throw error;
    } finally {
      if (conn) conn.release();
      active = false;
    }
  }
  return {run};
}
module.exports = {createPrimaryHaLogReconciler};
