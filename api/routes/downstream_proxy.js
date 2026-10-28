const { isSingleIPv4, scope } = require('../tenant');

// A null tenant is Global's separate ownership domain, never a wildcard.
const selected = req => req.tenantScope.enabled ? req.tenantScope.tenantId : null;
const scoped = (req, column = 'tenant_id') => scope(req.tenantScope, column);
const validId = value => Number.isSafeInteger(Number(value)) && Number(value) > 0 && String(value).trim() !== '';
const validPort = value => Number.isInteger(Number(value)) && Number(value) >= 1 && Number(value) <= 65535;
const safeEndpointIPv4 = value => {
    if (!isSingleIPv4(value)) return false;
    const [first, second] = value.split('.').map(Number);
    return first > 0 && first < 224 && first !== 127 && !(first === 169 && second === 254);
};
function routing(body) {
    const id = body.downstream_destination_id;
    if (id === undefined || id === null || id === '') {
        if (body.downstream_mode || body.downstream_validate_response) throw new Error('Destination is required for downstream routing');
        return { id: null, mode: null, validate: false };
    }
    if (!validId(id) || !['duplicate', 'proxy-only'].includes(body.downstream_mode)) throw new Error('Valid destination and duplicate or proxy-only mode are required');
    if (body.downstream_validate_response !== undefined && typeof body.downstream_validate_response !== 'boolean') throw new Error('validate_response must be boolean');
    if (body.downstream_mode === 'proxy-only' && body.downstream_validate_response) throw new Error('Response validation is only available in duplicate mode');
    return { id: Number(id), mode: body.downstream_mode, validate: body.downstream_mode === 'duplicate' && body.downstream_validate_response === true };
}
async function verifyDestination(db, req, id) {
    if (id === null) return;
    const restriction = scoped(req);
    const [rows] = await db.query('SELECT id FROM downstream_radius_destinations WHERE id=?' + restriction.sql, [id, ...restriction.params]);
    if (!rows.length) throw Object.assign(new Error('Downstream destination not found in selected tenant'), { status: 404 });
}
module.exports = function(app, pool, requireApiAuth, auditLog, activateRadius = require('../radius_activation')) {
    const endpoint = '/api/downstream-destinations';
    const fields = 'SELECT id, tenant_id, name, ipv4, auth_port, accounting_port FROM downstream_radius_destinations WHERE 1=1';
    const validate = (body, create) => {
        if (typeof body.name !== 'string' || !body.name.trim() || body.name.length > 100 || !safeEndpointIPv4(body.ipv4) || !validPort(body.auth_port) || !validPort(body.accounting_port)) throw new Error('Name, canonical IPv4 and ports 1–65535 are required');
        if (create && (typeof body.shared_secret !== 'string' || !body.shared_secret.length)) throw new Error('Shared secret is required');
        if (body.shared_secret !== undefined && (typeof body.shared_secret !== 'string' || !body.shared_secret.length || body.shared_secret.length > 253)) throw new Error('Invalid shared secret');
    };
    const activate = async () => {
        try { await activateRadius(); }
        catch (cause) {
            const err = new Error('Destination saved, but Radius activation failed; inspect the Radius service before retrying');
            err.status = 503;
            err.saved = true;
            throw err;
        }
    };
    const handle = fn => async (req, res) => { try { await fn(req, res); } catch (err) { res.status(err.status || 500).json({ error: err.status ? err.message : 'Downstream destination operation failed', ...(err.saved ? {saved:true,radius_reloaded:false} : {}) }); } };
    app.get(endpoint, requireApiAuth('nas','read-only'), handle(async (req,res) => { const s=scoped(req); const [rows]=await pool.query(fields+s.sql+' ORDER BY name',s.params); res.json(rows); }));
    app.get(endpoint+'/:id', requireApiAuth('nas','read-only'), handle(async (req,res) => { const s=scoped(req); const [rows]=await pool.query(fields+' AND id=?'+s.sql,[req.params.id,...s.params]); if (!rows.length) return res.status(404).json({error:'Destination not found'}); res.json(rows[0]); }));
    app.post(endpoint, requireApiAuth('nas','read-write'), handle(async (req,res) => {
        try { validate(req.body,true); } catch (err) { return res.status(400).json({error:err.message}); }
        const {name,ipv4,auth_port,accounting_port,shared_secret}=req.body;
        const [result]=await pool.query('INSERT INTO downstream_radius_destinations (tenant_id,name,ipv4,auth_port,accounting_port,shared_secret) VALUES (?,?,?,?,?,?)',[selected(req),name.trim(),ipv4,Number(auth_port),Number(accounting_port),shared_secret]);
        await activate();
        await auditLog(req.admin.username,req.origin,'Created downstream destination','success',name.trim(),req.ip,req.tenantScope);
        res.status(201).json({id:result.insertId,tenant_id:selected(req),name:name.trim(),ipv4,auth_port:Number(auth_port),accounting_port:Number(accounting_port),radius_reloaded:true});
    }));
    app.put(endpoint+'/:id', requireApiAuth('nas','read-write'), handle(async (req,res) => {
        try { validate(req.body,false); } catch (err) { return res.status(400).json({error:err.message}); }
        const {name,ipv4,auth_port,accounting_port,shared_secret}=req.body;
        const s=scoped(req);
        const hasSecret=shared_secret !== undefined;
        const sql='UPDATE downstream_radius_destinations SET name=?,ipv4=?,auth_port=?,accounting_port=?'+(hasSecret?',shared_secret=?':'')+' WHERE id=?'+s.sql;
        const [result]=await pool.query(sql,[name.trim(),ipv4,Number(auth_port),Number(accounting_port),...(hasSecret?[shared_secret]:[]),req.params.id,...s.params]);
        if (!result.affectedRows) return res.status(404).json({error:'Destination not found'});
        await activate();
        await auditLog(req.admin.username,req.origin,'Updated downstream destination','success',name.trim(),req.ip,req.tenantScope);
        res.json({success:true,radius_reloaded:true});
    }));
    app.delete(endpoint+'/:id', requireApiAuth('nas','read-write'), handle(async (req,res) => {
        const s=scoped(req);
        const conn=await pool.getConnection();
        try {
            await conn.beginTransaction();
            const [existing]=await conn.query('SELECT id FROM downstream_radius_destinations WHERE id=?'+s.sql+' FOR UPDATE',[req.params.id,...s.params]);
            if (!existing.length) { await conn.rollback(); return res.status(404).json({error:'Destination not found'}); }
            const nasScope=scoped(req);
            await conn.query('UPDATE nas SET downstream_mode=NULL,downstream_validate_response=0,downstream_destination_id=NULL WHERE downstream_destination_id=?'+nasScope.sql,[req.params.id,...nasScope.params]);
            await conn.query('DELETE FROM downstream_radius_destinations WHERE id=?'+s.sql,[req.params.id,...s.params]);
            await conn.commit();
        } catch (err) { await conn.rollback(); throw err; } finally { conn.release(); }
        await activate();
        await auditLog(req.admin.username,req.origin,'Deleted downstream destination','success','',req.ip,req.tenantScope);
        res.json({success:true,radius_reloaded:true});
    }));
};
module.exports.routing = routing;
module.exports.verifyDestination = verifyDestination;
