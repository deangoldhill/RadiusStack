'use strict';

const VALUE_TYPES = new Set(['string', 'integer', 'ipv4', 'octets']);
const STANDARD_REPLY_ATTRIBUTES = [
  ['Reply-Message', 'string'], ['Filter-Id', 'string'], ['Session-Timeout', 'integer'],
  ['Idle-Timeout', 'integer'], ['Acct-Interim-Interval', 'integer'], ['Framed-IP-Address', 'ipv4'],
  ['Framed-IP-Netmask', 'ipv4'], ['Framed-Route', 'string'], ['Framed-Pool', 'string'],
  ['Framed-Protocol', 'integer'], ['Framed-Routing', 'integer'], ['Framed-MTU', 'integer'],
  ['Framed-Compression', 'integer'], ['Service-Type', 'integer'], ['Login-Service', 'integer'],
  ['Callback-Id', 'string'], ['Port-Limit', 'integer'], ['Termination-Action', 'integer'],
  ['Cisco-AVPair', 'string', 'Cisco', 9, 1], ['Cisco-NAS-Port', 'integer', 'Cisco', 9, 2],
  ['Cisco-Idle-Limit', 'integer', 'Cisco', 9, 3], ['Cisco-Session-Timeout', 'integer', 'Cisco', 9, 4],
  ['Cisco-Account-Info', 'string', 'Cisco', 9, 250], ['Cisco-Command-Code', 'string', 'Cisco', 9, 252],
  ['Juniper-Local-User-Name', 'string', 'Juniper', 2636, 1], ['Juniper-Allow-Commands', 'string', 'Juniper', 2636, 2],
  ['Juniper-Deny-Commands', 'string', 'Juniper', 2636, 3], ['Juniper-User-Permissions', 'string', 'Juniper', 2636, 4],
  ['Ubiquiti-Rate-Limit', 'string', 'Ubiquiti / UniFi', 41112, 1], ['Ubiquiti-Rate-Limit-DL', 'string', 'Ubiquiti / UniFi', 41112, 2],
  ['Ubiquiti-Rate-Limit-UL', 'string', 'Ubiquiti / UniFi', 41112, 3],
  ['Mikrotik-Recv-Limit', 'integer', 'MikroTik', 14988, 1], ['Mikrotik-Xmit-Limit', 'integer', 'MikroTik', 14988, 2],
  ['Mikrotik-Group', 'string', 'MikroTik', 14988, 3], ['Mikrotik-Rate-Limit', 'string', 'MikroTik', 14988, 8],
  ['Mikrotik-Address-List', 'string', 'MikroTik', 14988, 19],
  ['D-Link-AVPair', 'string', 'D-Link', 171, 1], ['D-Link-User-Privilege', 'string', 'D-Link', 171, 2],
  ['PaloAlto-User-Group', 'string', 'Palo Alto Networks', 25461, 1, 'Guide shape: confirm Palo Alto vendor attribute number and dictionary support before production use.'],
  ['PaloAlto-Admin-Role', 'string', 'Palo Alto Networks', 25461, 2, 'Guide shape: confirm Palo Alto vendor attribute number and dictionary support before production use.']
].map(([name, value_type, vendor, vendor_code, vendor_attribute_number, guide]) => ({
  name, value_type, source: 'standard', dictionary_status: guide ? 'unavailable' : 'installed', ...(vendor ? { vendor, vendor_code, vendor_attribute_number } : {}), ...(guide ? { guide } : {})
}));

function text(value, label, max = 128) {
  if (typeof value !== 'string' || !(value = value.trim()) || value.length > max || /[\0\r\n]/.test(value)) throw new Error(`Invalid ${label}`);
  return value;
}
function positiveInteger(value, label, maximum) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 1 || number > maximum) throw new Error(`Invalid ${label}`);
  return number;
}
function isFreeRadiusAttributeName(value) { return typeof value === 'string' && /^[A-Za-z][A-Za-z0-9_.-]*$/.test(value); }
function normalizeEntry(entry, source = 'custom') {
  if (typeof entry === 'string') return { name: text(entry, 'attribute name'), source: 'legacy', value_type: 'string' };
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new Error('Invalid custom reply attribute');
  const name = text(entry.name || entry.attribute, 'attribute name');
  if (!isFreeRadiusAttributeName(name)) throw new Error('Invalid FreeRADIUS attribute name');
  const value_type = text(entry.value_type || 'string', 'value type', 16).toLowerCase();
  if (!VALUE_TYPES.has(value_type)) throw new Error('Invalid value type');
  const result = { name, value_type, source };
  if (entry.vendor_label !== undefined && String(entry.vendor_label).trim()) result.vendor_label = text(String(entry.vendor_label), 'vendor label');
  if (entry.vendor_code !== undefined || entry.vendor_attribute_number !== undefined) {
    result.vendor_code = positiveInteger(entry.vendor_code, 'vendor code', 0xffffffff);
    result.vendor_attribute_number = positiveInteger(entry.vendor_attribute_number, 'vendor attribute number', 255);
  }
  return result;
}
function normalizeCustomReplyAttributes(value) {
  if (value === undefined || value === null || value === '') return [];
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { value = value.split(',').map(name => name.trim()).filter(Boolean); }
  }
  if (!Array.isArray(value) || value.length > 100) throw new Error('Custom reply attributes must be a list of at most 100 attributes');
  const seen = new Set();
  return value.map(entry => normalizeEntry(entry)).filter(entry => {
    const key = `${entry.vendor_code || 0}:${entry.vendor_attribute_number || 0}:${entry.name.toLowerCase()}`;
    if (seen.has(key)) return false;
    seen.add(key); return true;
  });
}
function renderVsaDictionary(entries) {
  if (!Array.isArray(entries)) throw new Error('Dictionary entries must be a list');
  const normalized = entries.map(entry => {
    const result = normalizeEntry(entry, 'dictionary');
    if (!Number.isInteger(result.vendor_code) || !Number.isInteger(result.vendor_attribute_number)) throw new Error('A vendor code and vendor attribute number are required for a VSA dictionary entry');
    return result;
  }).sort((a, b) => a.vendor_code - b.vendor_code || a.vendor_attribute_number - b.vendor_attribute_number || a.name.localeCompare(b.name));
  const seenNames = new Set(), seenNumbers = new Set(), vendors = new Map();
  for (const entry of normalized) {
    const numberKey = `${entry.vendor_code}:${entry.vendor_attribute_number}`;
    if (seenNames.has(entry.name) || seenNumbers.has(numberKey)) throw new Error('Duplicate VSA name or vendor attribute number');
    seenNames.add(entry.name); seenNumbers.add(numberKey);
    if (!vendors.has(entry.vendor_code)) vendors.set(entry.vendor_code, []);
    vendors.get(entry.vendor_code).push(entry);
  }
  const radiusType = { ipv4: 'ipaddr', string: 'string', integer: 'integer', octets: 'octets' };
  const lines = ['# Generated by RadiusStack from validated structured VSA data. Do not edit.'];
  for (const [vendorCode, attributes] of vendors) {
    const vendorName = `RadiusStack-${vendorCode}`;
    lines.push(`VENDOR ${vendorName} ${vendorCode}`, `BEGIN-VENDOR ${vendorName}`);
    for (const attribute of attributes) lines.push(`ATTRIBUTE ${attribute.name} ${attribute.vendor_attribute_number} ${radiusType[attribute.value_type]}`);
    lines.push(`END-VENDOR ${vendorName}`, '');
  }
  return `${lines.join('\n')}\n`;
}
function displayName(attribute) { return attribute.vendor_label ? `${attribute.vendor_label}: ${attribute.name}` : attribute.name; }
module.exports = { VALUE_TYPES, STANDARD_REPLY_ATTRIBUTES, normalizeCustomReplyAttributes, renderVsaDictionary, displayName, isFreeRadiusAttributeName };
