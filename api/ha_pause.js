'use strict';

// Pass the original (unwrapped) primary DB query so control writes never enter ha_queue.
function createHaPauseControl({ query, role, queueWarningThreshold = 1000 }) {
  if (typeof query !== 'function' || typeof role !== 'function') throw new TypeError('HA control requires query and role functions');
  if (!Number.isSafeInteger(queueWarningThreshold) || queueWarningThreshold < 1) throw new TypeError('Invalid HA queue warning threshold');
  let blocked = false;
  let active = null;
  let transition = null;
  function serial(work) {
    const result = transition ? transition.then(work) : work();
    transition = result.then(() => {}, () => {});
    return result;
  }
  const db = (sql, params = []) => query(sql, params, { isSync: true });
  function requirePrimary() {
    if (role() !== 'primary') throw new Error('HA pause control is primary-only');
  }
  async function readState() {
    const [rows] = await db('SELECT paused, updated_at, reason FROM ha_control_state WHERE id = 1');
    if (rows.length !== 1) throw new Error('Missing ha_control_state singleton; apply database migrations');
    return rows[0];
  }
  async function pause(reason) {
    requirePrimary();
    blocked = true;
    return serial(async () => {
      const [result] = await db('UPDATE ha_control_state SET paused = ?, reason = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1', [1, reason]);
      if (result.affectedRows !== 1) throw new Error('Missing ha_control_state singleton; apply database migrations');
      // An active network callback cannot be cancelled. Acknowledge pause only
      // once it settles; no new callback starts once blocked is set.
      if (active) await active.catch(() => {});
      return readState();
    });
  }
  async function resume() {
    requirePrimary();
    return serial(async () => {
      const [result] = await db('UPDATE ha_control_state SET paused = ?, reason = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1', [0, null]);
      if (result.affectedRows !== 1) throw new Error('Missing ha_control_state singleton; apply database migrations');
      blocked = false;
      return readState();
    });
  }
  async function status() {
    requirePrimary();
    const state = await readState();
    const [rows] = await db('SELECT COUNT(*) AS count, MIN(created_at) AS oldest FROM ha_queue');
    const queueDepth = Number(rows[0].count);
    if (!Number.isSafeInteger(queueDepth) || queueDepth < 0) throw new Error('Invalid HA queue depth');
    return {
      paused: Boolean(state.paused), since: state.paused ? state.updated_at : null,
      reason: state.paused ? state.reason : null, queueDepth,
      oldestQueuedAt: rows[0].oldest || null,
      queueWarning: queueDepth >= queueWarningThreshold
        ? `HA queue has ${queueDepth} pending changes (threshold: ${queueWarningThreshold})` : null
    };
  }
  async function runDelivery(deliver) {
    requirePrimary();
    if (typeof deliver !== 'function') throw new TypeError('HA delivery callback required');
    if (blocked || active) return false;
    const work = (async () => {
      if (Boolean((await readState()).paused) || blocked) return false;
      await deliver();
      return true;
    })();
    active = work;
    try { return await work; }
    finally { if (active === work) active = null; }
  }
  return { pause, resume, status, runDelivery };
}

module.exports = { createHaPauseControl };
