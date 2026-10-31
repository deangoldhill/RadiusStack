'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const {includeHaCertificate} = require('./ha_certificate_bundle');

function isRadsecSettingWrite(query, values=[]) {
  return /\btenant_settings\b/i.test(query) && (/\bradsec_enabled\b/i.test(query) || values.some(value => value === 'radsec_enabled'));
}
function isDownstreamDestinationWrite(query) {
  return /^\s*(?:INSERT(?:\s+IGNORE)?\s+INTO|REPLACE\s+INTO|UPDATE|DELETE\s+FROM)\s+`?downstream_radius_destinations`?(?:\s|\(|$)/i.test(query);
}
function needsRadiusRestart(query, values=[]) {
  return isRadsecSettingWrite(query, values) || isDownstreamDestinationWrite(query);
}
function needsRadsecCertificateSync(query, values=[]) {
  return isRadsecSettingWrite(query, values) || /\b(radsec_clients|radsec_credential_sets|radsec_credential_set_nas|radsec_nas_passphrases|radsec_proxy_enrollments)\b/i.test(query);
}
function createCertificateReconciler({readBundle, enabledTenants, send, now=Date.now, resyncIntervalMs=300000}) {
  let lastDigest = null;
  let lastSentAt = 0;
  let inFlight = null;
  const status = {pending:false,lastSuccess:null,lastError:null};
  async function attempt(force) {
    const [bundle, ids] = await Promise.all([readBundle(), enabledTenants()]);
    const files = bundle.files || [];
    for (const id of ids) {
      if (!files.some(file => file.root === '/certs_radsec' && file.path === `tenant-${id}/ca.pem`)) {
        throw new Error(`RadSec enabled tenant ${id} lacks its client CA certificate on primary`);
      }
    }
    if (!files.length) return;
    const contents = files.map(file => [file.root,file.path,file.data]).sort((a,b)=>a[0].localeCompare(b[0])||a[1].localeCompare(b[1]));
    const digest = crypto.createHash('sha256').update(JSON.stringify(contents)).digest('hex');
    if (!force && digest === lastDigest && now() - lastSentAt < resyncIntervalMs) return;
    status.pending = true;
    await send(bundle);
    lastDigest = digest;
    lastSentAt = now();
    status.pending = false;
    status.lastError = null;
    status.lastSuccess = new Date().toISOString();
  }
  function reconcile(force=false) {
    if (inFlight) return force ? inFlight.then(()=>reconcile(true)) : inFlight;
    inFlight = attempt(force).catch(error=>{
      status.pending = true;
      status.lastError = error.message;
      throw error;
    }).finally(() => { inFlight = null; });
    return inFlight;
  }
  reconcile.status = status;
  return reconcile;
}
async function waitForRadiusReady(ready,sleep) {
  for (let attempt=0;attempt<10;attempt++) {
    if (await ready()) return;
    if (attempt<9) await sleep(500);
  }
  throw new Error('Secondary Radius not ready after HA update');
}
async function applySyncedWrite({query, values=[], execute, restart, ready=async()=>true, sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms))}) {
  await execute();
  if (needsRadiusRestart(query,values)) {
    await restart();
    await waitForRadiusReady(ready,sleep);
  }
}
function createCertificateInstaller({roots,enabledTenants,restart,isRadiusRunning=async()=>true,sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms))}) {
  let pendingRestart = false;
  return async function install(bundle) {
    if (!Array.isArray(bundle?.files)) throw new Error('Invalid certificate bundle');
    let changed = false;
    for (const file of bundle.files) {
      const root = roots[file.root];
      if (!root || !includeHaCertificate(file.root,file.path)) throw new Error('Invalid certificate path');
      if (typeof file.data !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(file.data)) throw new Error('Invalid certificate data');
      const data = Buffer.from(file.data,'base64');
      if (!data.length || data.length > 1048576 || data.toString('base64') !== file.data) throw new Error('Invalid certificate size or encoding');
      const target = path.join(root,file.path);
      await fs.mkdir(path.dirname(target),{recursive:true,mode:0o700});
      const realDir = await fs.realpath(path.dirname(target));
      const realRoot = await fs.realpath(root);
      if (realDir !== realRoot && !realDir.startsWith(realRoot+path.sep)) throw new Error('Invalid certificate path');
      try { if ((await fs.lstat(target)).isSymbolicLink()) throw new Error('Invalid certificate target'); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
      const existing=await fs.readFile(target).catch(error=>{if(error.code==='ENOENT')return null;throw error;});
      if (existing && existing.equals(data)) continue;
      const temporary = `${target}.${crypto.randomBytes(8).toString('hex')}.incoming`;
      try { await fs.writeFile(temporary,data,{flag:'wx',mode:file.path.endsWith('.key')?0o600:0o644});await fs.rename(temporary,target);changed=true; }
      finally { await fs.rm(temporary,{force:true}); }
    }
    const enabled = await enabledTenants();
    const radsecRoot = roots['/certs_radsec'];
    for (const id of enabled) {
      const pem=path.join(radsecRoot,`tenant-${id}`,'ca.pem');
      if (!await fs.stat(pem).then(s=>s.size>0).catch(()=>false)) throw new Error(`RadSec enabled tenant ${id} lacks its client CA certificate on secondary`);
    }
    if (changed || (enabled.length && !await isRadiusRunning())) pendingRestart = true;
    if (pendingRestart) {
      await restart();
      if (enabled.length) await waitForRadiusReady(isRadiusRunning,sleep);
      pendingRestart = false;
    }
  };
}
async function secondaryRadiusReady({running,identity}) {
  return Boolean(await running() && await identity());
}
module.exports = { createCertificateReconciler, needsRadsecCertificateSync, isRadsecSettingWrite, isDownstreamDestinationWrite, needsRadiusRestart, applySyncedWrite, createCertificateInstaller, secondaryRadiusReady };
