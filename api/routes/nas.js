module.exports = function(app, pool, requireApiAuth, auditLog, dependencies) {
    const { isSingleIPv4, scope } = require('../tenant');
    const { DEFAULT_DYNAMIC_AUTH_ATTRIBUTES, DYNAMIC_AUTH_ATTRIBUTES } = require('../dynamic_auth');
    const { normalizeCustomReplyAttributes } = require('../custom_attributes');
    const { bcrypt, jwt, crypto, exec, fs, qrcode, authenticator, upload, multer, JWT_SECRET, TOTP_ISSUER, generateEnrollmentCode, syncUserTotpToRadius, getRadiusPassword, snapshotUserPlanUsage, calculateRadiusStats, calculateTrendHourly, calculateTrendDaily } = dependencies;
    const reloadRadiusClients = () => new Promise((resolve, reject) => exec('docker restart radius_server', error => error ? reject(error) : resolve()));
    const nasScope = (req, column = 'tenant_id') => req.tenantScope.enabled ? scope(req.tenantScope, column) : { sql: ` AND ${column} IS NULL`, params: [] };

function normalizeDynamicAuthAttributes(value, customAttributeNames = []) {
    const allowedAttributes = new Set([...DYNAMIC_AUTH_ATTRIBUTES, ...customAttributeNames]);
    const defaults = { coa_attributes: DEFAULT_DYNAMIC_AUTH_ATTRIBUTES, pod_attributes: DEFAULT_DYNAMIC_AUTH_ATTRIBUTES.filter(name => name !== 'Profile-Reply-Attributes') };
    if (value === undefined || value === null) return defaults;
    if (Array.isArray(value)) value = { coa_attributes: value, pod_attributes: value.filter(name => name !== 'Profile-Reply-Attributes') };
    const normalize = (list, label) => { if (!Array.isArray(list) || list.some(name => typeof name !== 'string' || !allowedAttributes.has(name))) throw new Error(`Invalid ${label}`); const selected=[...new Set(list)]; if (!selected.some(name=>['User-Name','Acct-Session-Id','Calling-Station-Id','Framed-IP-Address'].includes(name)) || !selected.some(name=>['NAS-IP-Address','NAS-Identifier'].includes(name))) throw new Error(`${label} needs one session and one NAS identifier`); return selected; };
    return { coa_attributes: normalize(value.coa_attributes, 'CoA attributes'), pod_attributes: normalize(value.pod_attributes, 'PoD attributes').filter(name => name !== 'Profile-Reply-Attributes') };
}
async function savedCustomAttributeNames(pool) {
    const [rows] = await pool.query("SELECT setting_value FROM settings WHERE setting_key = 'custom_reply_attributes' LIMIT 1");
    return rows.length ? normalizeCustomReplyAttributes(rows[0].setting_value).map(attribute => attribute.name) : [];
}
app.get('/api/nas', requireApiAuth('nas', 'read-only'), async (req, res) => {
    const scoped = nasScope(req, 'n.tenant_id'); const [rows] = await pool.query('SELECT n.*, t.name AS tenant_name FROM nas n LEFT JOIN tenants t ON t.id=n.tenant_id WHERE 1=1'+scoped.sql, scoped.params);
    res.json(rows);
});

app.post('/api/nas/:id/clone', requireApiAuth('nas', 'read-write'), async (req,res)=>{ const scoped=nasScope(req); const nasname=String(req.body?.nasname||''),shortname=String(req.body?.shortname||''); if(!isSingleIPv4(nasname)||!shortname)return res.status(400).json({error:'New NAS requires one IPv4 address and shortname'}); const conn=await pool.getConnection(); try{await conn.beginTransaction(); const [[src]]=await conn.query('SELECT * FROM nas WHERE id=?'+scoped.sql,[req.params.id,...scoped.params]); if(!src)throw Object.assign(new Error('NAS not found in selected tenant'),{status:404}); const [created]=await conn.query('INSERT INTO nas (nasname,shortname,type,secret,description,dynamic_auth_attributes,tenant_id,radsec_enabled) VALUES (?,?,?,?,?,?,?,?)',[nasname,shortname,src.type,src.secret,req.body?.description ?? src.description,src.dynamic_auth_attributes,src.tenant_id,src.radsec_enabled]); const [[set]]=await conn.query('SELECT credential_set_id FROM radsec_credential_set_nas WHERE nas_id=? LIMIT 1',[src.id]); if(set)await conn.query('INSERT INTO radsec_credential_set_nas (credential_set_id,nas_id,assigned_by) VALUES (?,?,?)',[set.credential_set_id,created.insertId,req.admin.username]); await conn.commit(); await auditLog(req.admin.username,req.origin,`Cloned NAS ${src.id} to ${nasname}`, 'success','',req.ip,req.tenantScope); await reloadRadiusClients(); res.json({success:true,id:created.insertId,reused_credential_set:!!set});}catch(e){await conn.rollback();res.status(e.status||500).json({error:e.message});}finally{conn.release();} });

app.post('/api/nas', requireApiAuth('nas', 'read-write'), async (req, res) => {
    const { nasname, shortname, type, secret, description, dynamic_auth_attributes, radsec_enabled } = req.body;
    if (!isSingleIPv4(nasname)) return res.status(400).json({ error: 'NAS address must be one canonical IPv4 address (no CIDR or ranges)' });
    const tenantId = req.tenantScope.enabled ? req.tenantScope.tenantId : null;
    let attributes; try { attributes=normalizeDynamicAuthAttributes(dynamic_auth_attributes, await savedCustomAttributeNames(pool)); } catch (err) { return res.status(400).json({error:err.message}); }
    await pool.query('INSERT INTO nas (nasname, shortname, type, secret, description, dynamic_auth_attributes, tenant_id, radsec_enabled) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [nasname, shortname, type || 'other', secret, description, JSON.stringify(attributes), tenantId, radsec_enabled ? 1 : 0]);
    await auditLog(req.admin.username, req.origin, `Created NAS: ${nasname} (${shortname})`, 'success', '', req.ip, req.tenantScope);
    await reloadRadiusClients();
    res.json({ success: true, radius_reloaded: true });
});

app.put('/api/nas/:id', requireApiAuth('nas', 'read-write'), async (req, res) => {
    const { id } = req.params;
    const { nasname, shortname, type, secret, description, dynamic_auth_attributes, radsec_enabled } = req.body;
    if (!isSingleIPv4(nasname)) return res.status(400).json({ error: 'NAS address must be one canonical IPv4 address (no CIDR or ranges)' });
    const scoped = nasScope(req);
    try {
        const attributes=normalizeDynamicAuthAttributes(dynamic_auth_attributes, await savedCustomAttributeNames(pool));
        const [result] = await pool.query('UPDATE nas SET nasname=?, shortname=?, type=?, secret=?, description=?, dynamic_auth_attributes=?, radsec_enabled=? WHERE id=?'+scoped.sql, [nasname, shortname, type || 'other', secret, description, JSON.stringify(attributes), radsec_enabled ? 1 : 0, id, ...scoped.params]);
        if (!result.affectedRows) return res.status(404).json({ error: 'NAS not found in selected tenant' });
        await auditLog(req.admin.username, req.origin, `Updated NAS: ${nasname}`, 'success', '', req.ip, req.tenantScope);
        await reloadRadiusClients();
        res.json({ success: true, radius_reloaded: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/nas/:id', requireApiAuth('nas', 'read-write'), async (req, res) => {
    const scoped = nasScope(req);
    const [nas] = await pool.query('SELECT * FROM nas WHERE id = ?'+scoped.sql, [req.params.id, ...scoped.params]);
    if (!nas.length) return res.status(404).json({ error: 'NAS not found in selected tenant' });
    await pool.query('DELETE FROM nas WHERE id = ?'+scoped.sql, [req.params.id, ...scoped.params]);
    await auditLog(req.admin.username, req.origin, `Deleted NAS: ${nas[0]?.nasname}`, 'success', '', req.ip, req.tenantScope);
    await reloadRadiusClients();
    res.json({ success: true, radius_reloaded: true });
});


};
