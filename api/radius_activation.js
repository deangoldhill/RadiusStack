const { execFile } = require('node:child_process');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const exec = (command, args) => new Promise((resolve, reject) => {
    execFile(command, args, { timeout: 45000, maxBuffer: 1024 * 1024 }, (error, stdout) => error ? reject(error) : resolve(stdout));
});

function makeActivate(run = exec) {
    return async function activateRadius() {
        // Preflight candidate SQL destinations in the current container; never
        // restart a healthy listener when generation or validation has failed.
        try {
            await run('docker', ['exec', 'radius_server', '/usr/local/sbin/generate-downstream', '--check']);
            await run('docker', ['restart', 'radius_server']);
            let ready = false;
            for (let attempt = 0; attempt < 15; attempt++) {
                try {
                    await run('docker', ['exec', 'radius_server', 'pidof', 'radiusd']);
                    ready = true;
                    break;
                } catch (_) {
                    await pause(1000);
                }
            }
            if (!ready) throw new Error('Radius daemon did not start');
            await run('docker', ['exec', 'radius_server', '/opt/sbin/radiusd', '-XC']);
        } catch (_) {
            // Docker and FreeRADIUS stderr can contain rendered secrets.
            throw new Error('Radius activation failed; no active configuration was confirmed');
        }
    };
}

module.exports = makeActivate();
module.exports.makeActivate = makeActivate;
