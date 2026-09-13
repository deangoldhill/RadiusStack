'use strict';

const crypto = require('crypto');
const net = require('net');

const COA_REPLY_ATTRIBUTES = new Set([
  'Service-Type', 'Framed-Protocol', 'Framed-IP-Address', 'Filter-Id',
  'Framed-Route', 'Session-Timeout', 'Idle-Timeout', 'Termination-Action',
  'Called-Station-Id', 'Calling-Station-Id', 'NAS-Port-Type',
  'Tunnel-Type', 'Tunnel-Medium-Type', 'Tunnel-Private-Group-ID'
]);
const STRING_TYPES = { 'User-Name': 1, 'Filter-Id': 11, 'Framed-Route': 22, 'Called-Station-Id': 30, 'Calling-Station-Id': 31, 'NAS-Identifier': 32, 'Acct-Session-Id': 44 };
const IP_TYPES = { 'NAS-IP-Address': 4, 'Framed-IP-Address': 8 };
const INTEGER_TYPES = { 'Service-Type': 6, 'Framed-Protocol': 7, 'Session-Timeout': 27, 'Idle-Timeout': 28, 'Termination-Action': 29, 'NAS-Port-Type': 61 };
const INTEGER_VALUES = { 'Service-Type': { 'Authorize-Only': 17 }, 'Framed-Protocol': { PPP: 1 }, 'Termination-Action': { 'RADIUS-Request': 1 }, 'NAS-Port-Type': { Ethernet: 15, Wireless: 19 } };
const TUNNEL_VALUES = { 'Tunnel-Type': { VLAN: 13 }, 'Tunnel-Medium-Type': { 'IEEE-802': 6 } };
const DEFAULT_DYNAMIC_AUTH_ATTRIBUTES = ['User-Name','Acct-Session-Id','NAS-IP-Address','NAS-Identifier','Calling-Station-Id','Framed-IP-Address','Profile-Reply-Attributes'];
const DYNAMIC_AUTH_ATTRIBUTES = new Set(DEFAULT_DYNAMIC_AUTH_ATTRIBUTES);

function requiredText(value, label) {
  if (typeof value !== 'string' || !value || value.length > 253 || /[\r\n\0]/.test(value)) throw new Error('Invalid ' + label);
  return value;
}
function sessionIdentifiers(session, packetAttributes) {
  if (!session || net.isIP(session.nasipaddress) !== 4) throw new Error('Invalid active-session NAS IP');
  const values = {'User-Name':requiredText(session.username,'session username'),'Acct-Session-Id':requiredText(session.acctsessionid,'accounting session ID'),'NAS-IP-Address':session.nasipaddress,'NAS-Identifier':requiredText(session.nasidentifier,'accounting NAS-Identifier'),'Calling-Station-Id':requiredText(session.callingstationid,'calling station ID'),'Framed-IP-Address':requiredText(session.framedipaddress,'framed IP')};
  return packetAttributes.filter(name => name !== 'Profile-Reply-Attributes').map(name => [name, values[name]]);
}
function buildDynamicAuthorizationRequest({ kind, session, replyAttributes = [], packetAttributes = DEFAULT_DYNAMIC_AUTH_ATTRIBUTES }) {
  if (kind !== 'coa' && kind !== 'pod') throw new Error('Invalid dynamic authorization request type');
  if (!Array.isArray(packetAttributes) || packetAttributes.some(name => !DYNAMIC_AUTH_ATTRIBUTES.has(name))) throw new Error('Invalid dynamic authorization attribute selection');
  const attributes = sessionIdentifiers(session, packetAttributes);
  if (kind === 'coa') {
    const selectedAttributes = packetAttributes.includes('Profile-Reply-Attributes') ? replyAttributes : [];
    for (const reply of selectedAttributes) {
      if (!reply || !COA_REPLY_ATTRIBUTES.has(reply.attribute)) throw new Error('Unsupported CoA profile attribute: ' + (reply && reply.attribute || 'unknown'));
      attributes.push([reply.attribute, requiredText(String(reply.value), reply.attribute)]);
    }
  }
  return { code: kind === 'coa' ? 43 : 40, attributes };
}
function radiusAttribute(type, value) {
  let attributeType, body;
  if (Object.hasOwn(STRING_TYPES, type)) { attributeType = STRING_TYPES[type]; body = Buffer.from(requiredText(value, type), 'utf8'); }
  else if (Object.hasOwn(IP_TYPES, type)) { attributeType = IP_TYPES[type]; if (net.isIP(value) !== 4) throw new Error('Invalid IPv4 value for ' + type); body = Buffer.from(value.split('.').map(Number)); }
  else if (Object.hasOwn(INTEGER_TYPES, type)) { attributeType = INTEGER_TYPES[type]; const mapped = INTEGER_VALUES[type]?.[value]; const number = mapped ?? Number(value); if (!Number.isInteger(number) || number < 0 || number > 0xffffffff) throw new Error('Invalid integer value for ' + type); body = Buffer.alloc(4); body.writeUInt32BE(number); }
  else if (type === 'Tunnel-Private-Group-ID') { attributeType = 81; body = Buffer.concat([Buffer.from([0]), Buffer.from(requiredText(value, type), 'utf8')]); }
  else if (Object.hasOwn(TUNNEL_VALUES, type)) { attributeType = type === 'Tunnel-Type' ? 64 : 65; const number = TUNNEL_VALUES[type][value] ?? Number(value); if (!Number.isInteger(number) || number < 0 || number > 0xffffff) throw new Error('Invalid tunnel value for ' + type); body = Buffer.alloc(4); body.writeUInt32BE(number); }
  else throw new Error('Unsupported dynamic authorization attribute: ' + type);
  if (body.length > 253) throw new Error('RADIUS attribute too long: ' + type);
  return Buffer.concat([Buffer.from([attributeType, body.length + 2]), body]);
}
function encodeDynamicAuthorizationRequest(request, secret, identifier = crypto.randomInt(0, 256)) {
  requiredText(secret, 'NAS shared secret');
  if (!request || ![40, 43].includes(request.code) || !Array.isArray(request.attributes) || !Number.isInteger(identifier) || identifier < 0 || identifier > 255) throw new Error('Invalid dynamic authorization packet');
  const attributes = Buffer.concat(request.attributes.map(([type, value]) => radiusAttribute(type, value)));
  const header = Buffer.alloc(20); header[0] = request.code; header[1] = identifier; header.writeUInt16BE(20 + attributes.length, 2);
  const authenticator = crypto.createHash('md5').update(Buffer.concat([header, attributes, Buffer.from(secret)])).digest();
  authenticator.copy(header, 4);
  return Buffer.concat([header, attributes]);
}
function validateDynamicAuthorizationResponse({ request, response, secret, expectedCode }) {
  if (!Buffer.isBuffer(request) || !Buffer.isBuffer(response) || response.length < 20 || response.readUInt16BE(2) !== response.length || response[0] !== expectedCode || response[1] !== request[1]) return false;
  const expected = crypto.createHash('md5').update(Buffer.concat([response.subarray(0, 4), request.subarray(4, 20), response.subarray(20), Buffer.from(secret)])).digest();
  return crypto.timingSafeEqual(expected, response.subarray(4, 20));
}

function sendDynamicAuthorization({ request, secret, host, port = 3799, timeoutMs = 3000 }) {
  const dgram = require('dgram');
  if (net.isIP(host) !== 4 || !Number.isInteger(port) || port < 1 || port > 65535) return Promise.reject(new Error('Invalid NAS dynamic authorization endpoint'));
  const packet = encodeDynamicAuthorizationRequest(request, secret);
  const ackCode = request.code === 43 ? 44 : 41;
  const nakCode = ackCode + 1;
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    const timer = setTimeout(() => finish(new Error('NAS did not respond to dynamic authorization request')), timeoutMs);
    function finish(error, value) { clearTimeout(timer); socket.close(); error ? reject(error) : resolve(value); }
    socket.once('error', error => finish(error));
    socket.on('message', (response, rinfo) => {
      if (rinfo.address !== host || rinfo.port !== port || response[1] !== packet[1]) return;
      if (validateDynamicAuthorizationResponse({ request: packet, response, secret, expectedCode: ackCode })) return finish(null, { acknowledged: true, code: ackCode });
      if (validateDynamicAuthorizationResponse({ request: packet, response, secret, expectedCode: nakCode })) return finish(null, { acknowledged: false, code: nakCode });
    });
    socket.send(packet, port, host, error => { if (error) finish(error); });
  });
}
module.exports = { DEFAULT_DYNAMIC_AUTH_ATTRIBUTES, DYNAMIC_AUTH_ATTRIBUTES, COA_REPLY_ATTRIBUTES, buildDynamicAuthorizationRequest, encodeDynamicAuthorizationRequest, validateDynamicAuthorizationResponse, sendDynamicAuthorization };