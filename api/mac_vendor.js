'use strict';
// Wireshark's weekly manuf registry, bundled for offline operation. No lookup leaves this server.
const fs = require('node:fs');
const zlib = require('node:zlib');
const https = require('node:https');
const path = require('node:path');
const UNKNOWN = 'Unknown Device Vendor';
const REGISTRY_URL = 'https://www.wireshark.org/download/automated/data/manuf.gz';

function parseManuf(text) {
  const index = new Map();
  for (const line of text.split(/\r?\n/)) {
    const match = /^((?:[\da-f]{2}:){2,4}[\da-f]{2})(?:\/(24|28|36))?\s+\S+\s+(.+)$/i.exec(line);
    if (!match) continue;
    const prefix = match[1].replaceAll(':','').toUpperCase();
    const bits = Number(match[2] || 24);
    const length = bits / 4;
    if (prefix.length < length) continue;
    const name = match[3].trim().slice(0,255);
    if (name) index.set(prefix.slice(0,length), name);
  }
  return index;
}
function lookup(value, index) {
  const mac = String(value || '').replace(/[:-]/g,'').toUpperCase();
  if (!/^[\dA-F]{12}$/.test(mac) || (parseInt(mac.slice(0,2),16) & 3)) return UNKNOWN;
  for (const length of [9,7,6]) {
    const name = index.get(mac.slice(0,length));
    if (name) return name;
  }
  return UNKNOWN;
}
function fromGzip(data) {
  if (data.length > 4 * 1024 * 1024) throw Error('Manufacturer registry exceeds compressed limit');
  const text = zlib.gunzipSync(data, {maxOutputLength: 20 * 1024 * 1024}).toString('utf8');
  const index = parseManuf(text);
  if (index.size < 10000) throw Error('Manufacturer registry is incomplete');
  return index;
}
let registry = fromGzip(fs.readFileSync(path.join(__dirname,'data/manuf.gz')));
function vendorForMac(mac) { return lookup(mac,registry); }
function refreshRegistry() {
  return new Promise((resolve,reject) => {
    const request = https.get(REGISTRY_URL, {timeout:10000}, response => {
      if (response.statusCode !== 200) { response.resume(); return reject(Error('Manufacturer registry HTTP '+response.statusCode)); }
      const chunks=[]; let bytes=0;
      response.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 4*1024*1024) { request.destroy(Error('Manufacturer registry too large')); return; }
        chunks.push(chunk);
      });
      response.on('end', () => {
        try { registry = fromGzip(Buffer.concat(chunks)); resolve(registry.size); }
        catch (error) { reject(error); }
      });
      response.on('error',reject);
    });
    request.on('timeout',()=>request.destroy(Error('Manufacturer registry timeout')));
    request.on('error',reject);
  });
}
module.exports = {UNKNOWN, parseManuf, lookup, vendorForMac, refreshRegistry};
