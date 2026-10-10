'use strict';
const net = require('node:net');

function isPrivateIPv4(ip) {
  if (net.isIP(ip) !== 4) return false;
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function createHaTransport(env = process.env) {
  if (env.HA_ENABLED !== 'true') {
    return Object.freeze({ enabled: false, mode: 'disabled',
      peerURL() { throw new Error('HA disabled'); }, allowIncoming() { return false; } });
  }
  if (!env.HA_API_TOKEN || env.HA_API_TOKEN.length < 32 || env.HA_API_TOKEN === 'ha_sync_token_123') {
    throw new Error('HA_API_TOKEN must be a unique 32+ character secret');
  }
  const peer = env.HA_PEER_IP || '';
  if (!isPrivateIPv4(peer)) throw new Error('HA_PEER_IP must be a private IPv4 address');
  const port = Number(env.API_PORT || 3000);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('API_PORT invalid');
  return Object.freeze({
    enabled: true, mode: 'http', peer,
    peerURL(path) {
      if (!['/api/sync/execute', '/api/sync/certificates'].includes(path)) throw new Error('unsupported HA endpoint');
      return `http://${peer}:${port}${path}`;
    },
    allowIncoming(req) {
      const remote = req.socket && req.socket.remoteAddress;
      return remote === peer || remote === `::ffff:${peer}`;
    }
  });
}
module.exports = { createHaTransport };
