'use strict';
const dgram = require('dgram');
const net = require('net');
const os = require('os');
let _pool = null, _lastLoad = 0;
let _config = {enabled:false,host:'',port:514,protocol:'udp',send_audit:false,send_authlogs:false};

function validateDestination(host, port, protocol) {
  if (typeof host !== 'string' || !host || host.length > 253 || !/^[a-z0-9.:-]+$/i.test(host) ||
      host.startsWith('-') || host.endsWith('-') || host.includes('..') ||
      (!net.isIP(host) && !host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))))
    throw new Error('Invalid syslog host');
  if (!/^[0-9]+$/.test(String(port)) || !Number.isInteger(Number(port)) || Number(port)<1 || Number(port)>65535)
    throw new Error('Invalid syslog port');
  if (!['udp','tcp'].includes(protocol)) throw new Error('Invalid syslog protocol');
  return {host,port:Number(port),protocol};
}
async function loadConfig() {
  if (!_pool || Date.now()-_lastLoad<30000) return _config;
  const [rows] = await _pool.query("SELECT setting_key, setting_value FROM settings WHERE setting_key IN ('syslog_enabled','syslog_host','syslog_port','syslog_protocol','syslog_send_audit','syslog_send_authlogs')",[],{isSync:true});
  const m=Object.fromEntries(rows.map(r=>[r.setting_key,r.setting_value]));
  _config={enabled:m.syslog_enabled==='true',host:m.syslog_host||'',port:m.syslog_port||'514',protocol:m.syslog_protocol||'udp',send_audit:m.syslog_send_audit==='true',send_authlogs:m.syslog_send_authlogs==='true'};
  _lastLoad=Date.now();
  return _config;
}
function buildMessage(severity,appName,msgId,fields) {
  const sev={emerg:0,alert:1,crit:2,err:3,warning:4,notice:5,info:6,debug:7}[severity] ?? 6;
  const fieldStr=Object.entries(fields).map(([k,v])=>`${k}="${String(v == null?'':v).replace(/\\/g,'\\\\').replace(/"/g,'\\"').replace(/\r/g,'\\r').replace(/\n/g,'\\n')}"`).join(' ');
  return `<${8+sev}>1 ${new Date().toISOString()} ${os.hostname()} ${appName} - ${msgId} - ${fieldStr}`;
}
function sendUdp(host,port,message) {
  return new Promise((resolve,reject)=>{
    const client=dgram.createSocket('udp4');
    client.once('error',err=>{client.close();reject(err);});
    client.send(Buffer.from(message),port,host,err=>{client.close();err?reject(err):resolve();});
  });
}
function sendTcp(host,port,message) {
  return new Promise((resolve,reject)=>{
    const client=net.createConnection({host,port}); let done=false;
    const finish=err=>{if(done)return;done=true;client.destroy();err?reject(err):resolve();};
    client.once('error',finish);
    client.setTimeout(5000,()=>finish(new Error('Syslog TCP timeout')));
    client.once('connect',()=>client.end(message+'\n'));
    client.once('finish',()=>finish());
  });
}
async function transmit(destination,message) {
  const {host,port,protocol}=validateDestination(destination.host,destination.port,destination.protocol);
  return protocol==='tcp'?sendTcp(host,port,message):sendUdp(host,port,message);
}
async function configuredSend(severity,appName,msgId,fields) {
  const config=await loadConfig();
  if(!config.enabled || !config.host) return false;
  await transmit(config,buildMessage(severity,appName,msgId,fields));
  return true;
}
module.exports={
  init(pool){_pool=pool;_lastLoad=0;}, invalidateCache(){_lastLoad=0;},
  validateDestination,buildMessage,
  async authEnabled(){const c=await loadConfig();return c.enabled&&c.send_authlogs;},
  async sendAuditLog(entry){const c=await loadConfig();if(!c.enabled||!c.send_audit)return false;
    return configuredSend('info','radiusstack-audit','AUDIT',{tenant_id:entry.tenant_id??'',admin:entry.admin_username||'',origin:entry.origin||'',action:entry.action||'',result:entry.result||'',details:entry.details||'',ip:entry.ip_address||''});},
  async sendAuthLog(entry){const c=await loadConfig();if(!c.enabled||!c.send_authlogs)return false;
    const sev=String(entry.reply||'').toLowerCase().includes('reject')?'warning':'info';
    return configuredSend(sev,'radiusstack-authlog','AUTHLOG',{tenant_id:entry.tenant_id??'',username:entry.username||'',reply:entry.reply||'',nasipaddress:entry.nasipaddress||'',callingstationid:entry.callingstationid||'',calledstationid:entry.calledstationid||'',replymessage:entry.replymessage||'',authdate:entry.authdate||''});},
  async test(){try{const c=await loadConfig();await transmit(c,buildMessage('notice','radiusstack-audit','TEST',{msg:'RadiusStack syslog test'}));return {ok:true};}catch(e){return {ok:false,error:e.message};}}
};
