'use strict';

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const readline = require('node:readline');
const {Readable} = require('node:stream');
const {pipeline} = require('node:stream/promises');
const {parser} = require('stream-json');

const LOG_TABLES = new Set(['radacct', 'radpostauth', 'admin_audit_log']);
// Conservative token budget includes key/string bytes and container/value overhead.
// Reject a pathological single row rather than growing memory with the upload size.
const MAX_LOG_ROW_BYTES = 16 * 1024 * 1024;
const VALUE_STARTS = new Set(['startObject', 'startArray', 'startString', 'startNumber',
  'nullValue', 'trueValue', 'falseValue']);

// Only the current log row is assembled. Non-log configuration remains in memory.
async function readBackup(input) {
  const directory = await fsp.mkdtemp(path.join(os.tmpdir(), 'radius-backup-'));
  const handles = new Set();
  let cleaned = false;
  async function cleanup() {
    if (cleaned) return;
    for (const handle of handles) await handle.close();
    handles.clear();
    await fsp.rm(directory, {recursive: true, force: true});
    cleaned = true;
  }

  const logs = {};
  const stack = [];
  let root;
  let scalar = '';
  let rowBytes = null;
  let source;
  let tokens;
  let pumping;

  async function accept(value) {
    const parent = stack[stack.length - 1];
    if (!parent) root = value;
    else if (parent.log) {
      await parent.handle.writeFile(JSON.stringify(value) + '\n');
      logs[parent.log].length++;
      rowBytes = null;
    } else if (parent.array) parent.value.push(value);
    else { parent.value[parent.key] = value; parent.key = undefined; }
  }

  try {
    source = input?.stream || (input && typeof input.path === 'string'
      ? fs.createReadStream(input.path)
      : Readable.from([input.buffer]));
    tokens = parser({packValues: false, streamValues: true});
    pumping = pipeline(source, tokens);
    // Observe immediately; errors also propagate through the async token iterator.
    pumping.catch(() => {});
    for await (const token of tokens) {
      const parent = stack[stack.length - 1];
      const startsValue = VALUE_STARTS.has(token.name);
      if (parent?.log && token.name === 'startObject') rowBytes = 0;
      if (rowBytes !== null) {
        rowBytes += token.value === undefined ? 32 : Buffer.byteLength(String(token.value)) + 32;
        if (rowBytes > MAX_LOG_ROW_BYTES) throw new Error('Log row exceeds memory safety limit (16 MiB)');
      }
      const logKey = stack.length === 2 && stack[0].key === 'data' && LOG_TABLES.has(parent.key)
        ? parent.key : null;
      if (startsValue && logKey && token.name !== 'startArray') {
        throw new Error(`${logKey} must be an array`);
      }
      if (startsValue && parent?.log && token.name !== 'startObject') {
        throw new Error(`${parent.log} row must be an object`);
      }
      switch (token.name) {
        case 'startObject':
        case 'startArray': {
          const array = token.name === 'startArray';
          const log = stack.length === 2 && stack[0].key === 'data' && LOG_TABLES.has(parent.key)
            ? parent.key : null;
          if (log && array) {
            const filename = path.join(directory, log + '.ndjson');
            const handle = await fsp.open(filename, 'wx', 0o600);
            handles.add(handle);
            logs[log] = {
              length: 0,
              async *batches(batchSize) {
                if (!Number.isSafeInteger(batchSize) || batchSize < 1) {
                  throw new Error('Batch size must be a positive safe integer');
                }
                const stream = fs.createReadStream(filename, {encoding: 'utf8'});
                const lines = readline.createInterface({input: stream, crlfDelay: Infinity});
                try {
                  let batch = [];
                  for await (const line of lines) {
                    batch.push(JSON.parse(line));
                    if (batch.length === batchSize) { yield batch; batch = []; }
                  }
                  if (batch.length) yield batch;
                } finally { lines.close(); stream.destroy(); }
              }
            };
            stack.push({log, handle, array: true});
          } else stack.push({value: array ? [] : {}, array, keys: array ? null : new Set()});
          break;
        }
        case 'endObject':
        case 'endArray': {
          const frame = stack.pop();
          if (frame.log) {
            await frame.handle.close();
            handles.delete(frame.handle);
            stack[stack.length - 1].key = undefined;
          } else await accept(frame.value);
          break;
        }
        case 'startKey':
        case 'startString':
        case 'startNumber': scalar = ''; break;
        case 'stringChunk':
        case 'numberChunk': scalar += token.value; break;
        case 'endKey':
          if (scalar === '__proto__' || scalar === 'constructor') {
            throw new Error(`Unsafe prototype key: ${scalar}`);
          }
          if (parent.keys.has(scalar)) throw new Error(`Duplicate backup key: ${scalar}`);
          parent.keys.add(scalar);
          parent.key = scalar;
          scalar = '';
          break;
        case 'endString': await accept(scalar); scalar = ''; break;
        case 'endNumber': await accept(Number(scalar)); scalar = ''; break;
        case 'nullValue': await accept(null); break;
        case 'trueValue': await accept(true); break;
        case 'falseValue': await accept(false); break;
      }
    }
    await pumping;
    const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
    if (!object(root) || !object(root.data)) throw new Error('Backup data must be an object');
    if (Object.hasOwn(root, 'metadata') && !object(root.metadata)) {
      throw new Error('Backup metadata must be an object');
    }
    return {metadata: root.metadata, data: root.data, logs, cleanup};
  } catch (error) {
    if (source) source.destroy();
    if (tokens) tokens.destroy();
    if (pumping) await pumping.catch(() => {});
    await cleanup();
    throw error;
  }
}

module.exports = {readBackup};
