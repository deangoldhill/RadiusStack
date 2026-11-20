module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, execFile, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily, requireGlobalSuperAdmin } = dependencies;
    const run = (file, args, options = {}) => new Promise((resolve, reject) =>
        execFile(file, args, {timeout: 60000, ...options}, error => error ? reject(error) : resolve()));


app.get('/api/certs/download/:type', requireApiAuth('settings', 'read-only'), requireGlobalSuperAdmin, async (req, res) => {
    try {
        const type = req.params.type;
        let filePath = '';
        let fileName = '';
        if (type === 'server-pem' || type === 'server-cert') {
            filePath = '/certs_shared/server.pem';
            fileName = 'radius-server.pem';
        } else if (type === 'server-key') {
            filePath = '/certs_shared/server.key';
            fileName = 'radius-server.key';
        } else if (type === 'ca-pem' || type === 'ca-cert') {
            filePath = '/certs_shared/ca.pem';
            fileName = 'radius-ca.pem';
        } else if (type === 'ca-key') {
            filePath = '/certs_shared/ca.key';
            fileName = 'radius-ca.key';
        } else {
            return res.status(400).json({ error: 'Invalid cert type' });
        }

        try {
            await fs.access(filePath);
        } catch {
            return res.status(404).json({ error: 'File not found on server' });
        }

        res.download(filePath, fileName);
    } catch (err) {
        console.error('Download error', err);
        res.status(500).json({ error: 'Failed to download certificate' });
    }
});

app.post('/api/certs/generate', requireApiAuth('settings', 'read-write'), requireGlobalSuperAdmin, async (req, res) => {
    const { c = 'US', st = 'State', l = 'City', o = 'Radius', cn = 'RadiusServer' } = req.body || {};
    const fields = [c, st, l, o, cn];
    if (typeof c !== 'string' || !/^[A-Za-z]{2}$/.test(c) ||
        fields.some(value => typeof value !== 'string' || value.length < 1 || value.length > 128 || !/^[A-Za-z0-9 .,_-]+$/.test(value))) {
        return res.status(400).json({ error: 'Invalid certificate subject' });
    }
    const subjCA = `/C=${c}/ST=${st}/L=${l}/O=${o}CA/CN=${cn}CA`;
    const subjServer = `/C=${c}/ST=${st}/L=${l}/O=${o}/CN=${cn}`;
    try {
        await run('openssl', ['req','-new','-newkey','rsa:2048','-days','3650','-nodes','-x509',
            '-keyout','/certs_shared/ca.key','-out','/certs_shared/ca.pem','-subj',subjCA]);
        await run('openssl', ['req','-new','-newkey','rsa:2048','-nodes',
            '-keyout','/certs_shared/server.key','-out','/certs_shared/server.csr','-subj',subjServer]);
        await run('openssl', ['x509','-req','-days','3650','-in','/certs_shared/server.csr',
            '-CA','/certs_shared/ca.pem','-CAkey','/certs_shared/ca.key','-CAcreateserial',
            '-out','/certs_shared/server.pem']);
        await run('docker', ['restart','radius_server']);
        await auditLog(req.admin.username, req.origin, 'Generated new 10-year EAP certificate', 'success', `Subject: ${subjServer}`, req.ip);
        return res.json({ success: true });
    } catch (error) {
        await auditLog(req.admin.username, req.origin, 'Generate EAP certificate', 'failed', error.message, req.ip);
        return res.status(500).json({ error: 'EAP certificate generation or RADIUS restart failed' });
    } finally {
        await fs.rm('/certs_shared/server.csr', {force:true}).catch(()=>{});
        await fs.rm('/certs_shared/ca.srl', {force:true}).catch(()=>{});
    }
});

app.post('/api/certs/upload', requireApiAuth('settings', 'read-write'), requireGlobalSuperAdmin, upload.fields([{ name: 'cert' }, { name: 'key' }]), async (req, res) => {
    const certPath = req.files?.cert?.[0]?.path;
    const keyPath = req.files?.key?.[0]?.path;
    try {
        if (!certPath || !keyPath) return res.status(400).json({ error: 'Certificate and private key are required' });
        const pwd = req.body?.password;
        await fs.copyFile(certPath, '/certs_shared/server.pem');
        if (pwd) {
            await run('openssl', ['rsa','-in',keyPath,'-passin','env:PK_PASS','-out','/certs_shared/server.key'],
                {env: {...process.env, PK_PASS:pwd}});
        } else {
            await fs.copyFile(keyPath, '/certs_shared/server.key');
        }
        await run('docker', ['restart','radius_server']);
        await auditLog(req.admin.username, req.origin, 'Uploaded custom EAP certificate', 'success', 'Radius restarted', req.ip);
        return res.json({ success: true });
    } catch (error) {
        await auditLog(req.admin.username, req.origin, 'Upload EAP certificate', 'failed', error.message, req.ip);
        return res.status(500).json({ error: 'EAP certificate upload or RADIUS restart failed' });
    } finally {
        for (const file of [certPath,keyPath]) if (file) await fs.rm(file,{force:true}).catch(()=>{});
    }
});

app.get('/api/certs/details', requireApiAuth('settings', 'read-only'), (req, res) => {
    exec('openssl x509 -in /certs_shared/server.pem -text -noout', (error, stdout, stderr) => {
        if (error) {
            return res.json({
                details: 'Certificate file not found or invalid.\n\n' +
                    'Click "Generate New 10-Year Certificate" above to create one.'
            });
        }
        res.json({ details: stdout.trim() || 'Certificate exists but has no readable details.' });
    });
});


};
