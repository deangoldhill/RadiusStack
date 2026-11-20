'use strict';

function includeHaCertificate(root, relative) {
  if (typeof relative !== 'string' || !/^[A-Za-z0-9_./-]+\.(pem|key)$/.test(relative) || relative.split('/').some(part => part === '..' || part === '.')) return false;
  if (root === '/certs_radsec') {
    // The secondary must generate its own listener leaf with its own DNS SAN.
    if (['listener/server.pem', 'listener/server.key', 'listener/server-fullchain.pem', 'enabled-ca-bundle.pem'].includes(relative)) return false;
  }
  // EAP identity is node-local: a secondary must be able to replace its own
  // certificate without a later primary bundle overwriting it.
  return root === '/certs_radsec';
}
module.exports = { includeHaCertificate };
