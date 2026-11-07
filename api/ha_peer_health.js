'use strict';
const {randomBytes: secureRandomBytes} = require('node:crypto');

// The receiver must decrypt the request, check _ts freshness and nonce shape,
// then encrypt {success:true, nonce:request.nonce} without changing HA data.
function createHaPeerHealth({peerURL, encrypt, decrypt, fetch: fetchPeer = globalThis.fetch,
  now = Date.now, randomBytes = secureRandomBytes, onTransition = () => {},
  timeoutMs = 3000, failureThreshold = 3, successThreshold = 2} = {}) {
  if ([peerURL, encrypt, decrypt, fetchPeer, now, randomBytes, onTransition].some(fn => typeof fn !== 'function'))
    throw new TypeError('HA peer health requires transport, crypto, fetch and clock functions');
  if (![timeoutMs, failureThreshold, successThreshold].every(n => Number.isSafeInteger(n) && n > 0))
    throw new TypeError('invalid HA peer health thresholds or timeout');

  let state = 'unknown', lastAttemptAt = null, lastSuccessAt = null,
    lastFailureAt = null, changedAt = null, consecutiveSuccesses = 0,
    consecutiveFailures = 0, active = null, generation = 0;
  const status = () => ({state, connected: state === 'connected', lastAttemptAt,
    lastSuccessAt, lastFailureAt, changedAt, consecutiveSuccesses, consecutiveFailures});
  function change(next, time) {
    if (next === state) return;
    const from = state;
    state = next;
    changedAt = time;
    // Notifications are for peer reachability, not administrative modes.
    if ((next === 'connected' || next === 'disconnected') &&
        (from === 'connected' || from === 'disconnected' || from === 'unknown')) {
      try { onTransition({from, to:next, at:time}); } catch { /* notification is best-effort */ }
    }
  }
  async function request() {
    const nonce = randomBytes(16).toString('hex');
    const controller = new AbortController();
    let timer;
    try {
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => {
          controller.abort();
          reject(new Error('HA peer heartbeat timeout'));
        }, timeoutMs);
      });
      const exchange = (async () => {
        const response = await fetchPeer(peerURL('/api/sync/heartbeat'), {
          method:'POST', headers:{'Content-Type':'application/json'}, signal:controller.signal,
          body:JSON.stringify(encrypt({_ts:now(), nonce}))
        });
        if (!response.ok) throw new Error(`HA peer heartbeat HTTP ${response.status}`);
        const reply = decrypt(await response.json());
        if (!reply || reply.success !== true || reply.nonce !== nonce)
          throw new Error('HA peer heartbeat authentication failed');
      })();
      await Promise.race([exchange, timeout]);
    } finally { clearTimeout(timer); }
  }
  function probe({enabled = true, paused = false} = {}) {
    if (!enabled || paused) {
      generation++;
      active = null; // stale requests cannot block a fresh probe after resume
      consecutiveFailures = consecutiveSuccesses = 0;
      change(enabled ? 'paused' : 'disabled', new Date(now()).toISOString());
      return Promise.resolve(status());
    }
    if (state === 'disabled' || state === 'paused') {
      consecutiveFailures = consecutiveSuccesses = 0;
      change('unknown', new Date(now()).toISOString());
    }
    if (active) return active;
    const runGeneration = generation;
    const run = (async () => {
      lastAttemptAt = new Date(now()).toISOString();
      let success = false;
      try { await request(); success = true; } catch { /* reachability failure; no secrets in status */ }
      if (runGeneration !== generation) return status();
      const at = new Date(now()).toISOString();
      if (success) {
        lastSuccessAt = at;
        consecutiveFailures = 0;
        consecutiveSuccesses++;
        if (consecutiveSuccesses >= successThreshold) change('connected', at);
      } else {
        lastFailureAt = at;
        consecutiveSuccesses = 0;
        consecutiveFailures++;
        if (consecutiveFailures >= failureThreshold) change('disconnected', at);
      }
      return status();
    })();
    active = run;
    run.finally(() => { if (active === run) active = null; });
    return run;
  }
  return Object.freeze({probe, status});
}
module.exports = {createHaPeerHealth};
