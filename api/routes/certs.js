module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;

// --- CERTS ---

app.get('/api/certs/download/:type', requireApiAuth('settings', 'read-only'), async (req, res) => {
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

app.post('/api/certs/generate', requireApiAuth('settings', 'read-write'), (req, res) => {
    const { c = 'US', st = 'State', l = 'City', o = 'Radius', cn = 'RadiusServer' } = req.body;
    const subjCA = `/C=${c}/ST=${st}/L=${l}/O=${o}CA/CN=${cn}CA`;
    const subjServer = `/C=${c}/ST=${st}/L=${l}/O=${o}/CN=${cn}`;

    const cmd = `
        openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 -keyout /certs_shared/ca.key -out /certs_shared/ca.pem -subj "${subjCA}" && \
        openssl req -new -newkey rsa:2048 -nodes -keyout /certs_shared/server.key -out /certs_shared/server.csr -subj "${subjServer}" && \
        openssl x509 -req -days 3650 -in /certs_shared/server.csr -CA /certs_shared/ca.pem -CAkey /certs_shared/ca.key -CAcreateserial -out /certs_shared/server.pem && \
        rm -f /certs_shared/server.csr /certs_shared/ca.srl
    `;

    exec(cmd, async (error) => {
        if (error) {
            await auditLog(req.admin.username, req.origin, 'Generate EAP certificate', 'failed', error.message, req.ip);
            return res.status(500).json({ error: error.message });
        }
        exec('docker restart radius_server');
        await auditLog(req.admin.username, req.origin, 'Generated new 10-year EAP certificate', 'success', `Subject: ${subj}`, req.ip);
        res.json({ success: true });
    });
});

app.post('/api/certs/upload', requireApiAuth('settings', 'read-write'), upload.fields([{ name: 'cert' }, { name: 'key' }]), async (req, res) => {
    try {
        const certPath = req.files['cert'][0].path;
        const keyPath = req.files['key'][0].path;
        const pwd = req.body.password;

        await fs.copyFile(certPath, '/certs_shared/server.pem');

        if (pwd) {
            await new Promise((resolve, reject) => {
                exec(`openssl rsa -in ${keyPath} -passin env:PK_PASS -out /certs_shared/server.key`,
                    { env: { ...process.env, PK_PASS: pwd } },
                    (err) => err ? reject(err) : resolve()
                );
            });
        } else {
            await fs.copyFile(keyPath, '/certs_shared/server.key');
        }

        exec('docker restart radius_server');
        await auditLog(req.admin.username, req.origin, 'Uploaded custom EAP certificate', 'success', 'Radius restarted', req.ip);
        res.json({ success: true });
    } catch (err) {
        await auditLog(req.admin.username, req.origin, 'Upload EAP certificate', 'failed', err.message, req.ip);
        res.status(500).json({ error: err.message });
    }
});

// === CERT DETAILS & DOWNLOAD ===
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
