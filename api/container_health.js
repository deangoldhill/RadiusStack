'use strict';
const http = require('node:http');

function dockerGet(socketPath, path) {
    return new Promise((resolve, reject) => {
        const req = http.get({ socketPath, path, timeout: 3000 }, res => {
            let body = '';
            res.setEncoding('utf8');
            res.on('data', chunk => { body += chunk; if (body.length > 1048576) req.destroy(new Error('Docker response too large')); });
            res.on('end', () => {
                if (res.statusCode !== 200) return reject(new Error(`Docker returned ${res.statusCode}`));
                try { resolve(JSON.parse(body)); } catch (err) { reject(err); }
            });
        });
        req.on('timeout', () => req.destroy(new Error('Docker request timed out')));
        req.on('error', reject);
    });
}

async function getContainerHealth({ socketPath = '/var/run/docker.sock', now = Date.now } = {}) {
    const name = 'radius_server';
    const inspect = await dockerGet(socketPath, `/containers/${name}/json`);
    const running = inspect.State?.Running === true;
    const startedAt = Date.parse(inspect.State?.StartedAt);
    const result = {
        source: 'docker-container', container: name, state: running ? 'running' : 'stopped',
        health: inspect.State?.Health?.Status || 'unknown',
        uptimeSeconds: running && Number.isFinite(startedAt) ? Math.max(0, Math.floor((now() - startedAt) / 1000)) : null,
        cpuPercent: null, memoryBytes: null, memoryLimitBytes: null
    };
    if (!running) return result;
    try {
        const stats = await dockerGet(socketPath, `/containers/${name}/stats?stream=false`);
        const cpuDelta = stats.cpu_stats?.cpu_usage?.total_usage - stats.precpu_stats?.cpu_usage?.total_usage;
        const systemDelta = stats.cpu_stats?.system_cpu_usage - stats.precpu_stats?.system_cpu_usage;
        const cpus = stats.cpu_stats?.online_cpus || stats.cpu_stats?.cpu_usage?.percpu_usage?.length;
        if (Number.isFinite(cpuDelta) && Number.isFinite(systemDelta) && systemDelta > 0 && cpus > 0 && cpuDelta >= 0)
            result.cpuPercent = Math.round(cpuDelta / systemDelta * cpus * 1000) / 10;
        const usage = stats.memory_stats?.usage;
        const inactive = stats.memory_stats?.stats?.inactive_file ?? stats.memory_stats?.stats?.total_inactive_file ?? 0;
        if (Number.isFinite(usage)) result.memoryBytes = Math.max(0, usage - inactive);
        if (Number.isFinite(stats.memory_stats?.limit)) result.memoryLimitBytes = stats.memory_stats.limit;
    } catch (_) { /* Docker stats may be unavailable; keep known inspect fields only. */ }
    return result;
}

module.exports = { getContainerHealth };
