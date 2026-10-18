'use strict';

// mysql2 converts plain objects bound to a query placeholder into '[object Object]'.
// MariaDB returns admins.permissions (JSON) as an object during HA full sync.
// Narrowly repair this one JSON column, including rows already queued by older primaries.
function normalizeHaSqlValues(query, values) {
  if (!Array.isArray(values)) return values;
  const insert = /^\s*INSERT\s+INTO\s+`?admins`?\s*\(([^)]+)\)/i.exec(query);
  if (!insert) return values;
  const columns = insert[1].split(',').map(name => name.trim().replace(/^`|`$/g, '').toLowerCase());
  const index = columns.indexOf('permissions');
  if (index < 0 || index >= values.length) return values;
  const value = values[index];
  if (value === null || typeof value !== 'object' || Buffer.isBuffer(value) || value instanceof Date) return values;
  const normalized = values.slice();
  normalized[index] = JSON.stringify(value);
  return normalized;
}

module.exports = { normalizeHaSqlValues };
