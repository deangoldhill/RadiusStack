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
    const fields = 'SELECT id, tenant_id, name, ipv4, auth_port, accounting_port, proxy_traffic FROM downstream_radius_destinations WHERE 1=1';
    const validate = (body, create) => {
        if (typeof body.name !== 'string' || !body.name.trim() || body.name.length > 100 || !safeEndpointIPv4(body.ipv4) || !validPort(body.auth_port) || !validPort(body.accounting_port)) throw new Error('Name, canonical IPv4 and ports 1–65535 are required');
        if (create && (typeof body.shared_secret !== 'string' || !body.shared_secret.length)) throw new Error('Shared secret is required');
        if (body.shared_secret !== undefined && (typeof body.shared_secret !== 'string' || !body.shared_secret.length || body.shared_secret.length > 253)) throw new Error('Invalid shared secret');
        if (body.proxy_traffic !== undefined && !['auth','accounting','both'].includes(body.proxy_traffic)) throw new Error('Select Auth, Accounting or Both traffic');
    };
    const activate = async (req, method, id) => {
        try { await activateRadius(); }
        catch (cause) {
            // Mutation already persisted. Never expose activation errors or request secrets in audit/syslog.
            const details = {method, ...(validId(id) ? {id:Number(id)} : {}), saved:true, radius_reloaded:false};
            try { await auditLog(req.admin.username, req.origin, 'Downstream destination activation failed', 'failed', JSON.stringify(details), req.ip, req.tenantScope); } catch { /* Keep the partial-save response even if audit fails. */ }
            const err = new Error('Destination saved, but Radius activation failed; inspect the Radius service before retrying');
            err.status = 503;
            err.saved = true;
            throw err;
        }
    };
    const handle = fn => async (req, res) => { try { await fn(req, res); } catch (err) { res.status(err.status || 500).json({ error: err.status ? err.message : 'Downstream destination operation failed', ...(err.saved ? {saved:true,radius_reloaded:false} : {}) }); } };
    app.get(endpoint, requireApiAuth('nas','read-only'), handle(async (req,res) => { const s=scoped(req); const [rows]=await pool.query(fields+s.sql+' ORDER BY name',s.params); res.json(rows); }));
    app.get(endpoint+'/:id', requireApiAuth('nas','read-only'), handle(async (req,res) => { const s=scoped(req); const [rows]=await pool.query(fields+' AND id=?'+s.sql,[req.params.id,...s.params]); if (!rows.length) return res.status(404).json({error:'Destination not found'}); res.json(rows[0]); }));
    // Minute counters begin when telemetry is enabled; prior RADIUS history has no destination identifier.
    app.get(endpoint+'/:id/stats', requireApiAuth('nas','read-only'), handle(async (req,res) => {
        const windows = {
            hour: {interval:'1 HOUR', seconds:3600, bucket:"DATE_FORMAT(bucket_start, '%Y-%m-%d %H:%i:00')"},
            day: {interval:'1 DAY', seconds:86400, bucket:"DATE_FORMAT(bucket_start, '%Y-%m-%d %H:00:00')"},
            week: {interval:'7 DAY', seconds:604800, bucket:"DATE_FORMAT(bucket_start, '%Y-%m-%d')"},
            month: {interval:'30 DAY', seconds:2592000, bucket:"DATE_FORMAT(bucket_start, '%Y-%m-%d')"},
            year: {interval:'365 DAY', seconds:31536000, bucket:"DATE_FORMAT(bucket_start, '%Y-%m-01')"}
        };
        const windowName = req.query?.window || 'hour';
        if (!Object.hasOwn(windows,windowName) || !validId(req.params.id) || String(Number(req.params.id)) !== String(req.params.id)) return res.status(400).json({error:'Invalid destination or time window'});
        const id=Number(req.params.id), s=scoped(req), chosen=windows[windowName];
        const [destinations]=await pool.query(fields+' AND id=?'+s.sql,[id,...s.params]);
        if (!destinations.length) return res.status(404).json({error:'Destination not found'});
        const restriction=' WHERE destination_id=?'+s.sql+' AND bucket_start >= UTC_TIMESTAMP() - INTERVAL '+chosen.interval;
        const args=[id,...s.params];
        const [modes]=await pool.query('SELECT route_mode, COALESCE(SUM(auth_requests),0) AS auth_requests, COALESCE(SUM(accounting_requests),0) AS accounting_requests FROM downstream_proxy_stats_minutes'+restriction+' GROUP BY route_mode',args);
        const [series]=await pool.query('SELECT '+chosen.bucket+' AS series_bucket, SUM(auth_requests) AS auth_requests, SUM(accounting_requests) AS accounting_requests FROM downstream_proxy_stats_minutes'+restriction+' GROUP BY series_bucket ORDER BY series_bucket',args);
        const [peaks]=await pool.query('SELECT COALESCE(MAX(requests_in_minute/60),0) AS peak_minute_rps FROM (SELECT SUM(auth_requests+accounting_requests) AS requests_in_minute FROM downstream_proxy_stats_minutes'+restriction+' GROUP BY bucket_start) AS minute_totals',args);
        const totals={auth:0,accounting:0}, breakdown=Object.fromEntries(['proxy-only','duplicate','validated'].map(mode=>[mode,{auth:0,accounting:0}]));
        for (const row of modes) {
            if (!Object.hasOwn(breakdown,row.route_mode)) continue;
            const auth=Number(row.auth_requests)||0, accounting=Number(row.accounting_requests)||0;
            breakdown[row.route_mode]={auth,accounting}; totals.auth+=auth;totals.accounting+=accounting;
        }
        res.json({destination:destinations[0], window:windowName, duration_seconds:chosen.seconds, as_of:new Date().toISOString(),
            since:'telemetry activation', source:'this RadiusStack node', metric:'routed attempts (not confirmed downstream replies)', totals, modes:breakdown,
            average_rps:Number(((totals.auth+totals.accounting)/chosen.seconds).toFixed(4)), peak_minute_rps:Number(peaks[0]?.peak_minute_rps)||0,
            series:series.map(row=>({bucket:String(row.series_bucket),auth:Number(row.auth_requests)||0,accounting:Number(row.accounting_requests)||0}))});
    }));
    app.post(endpoint, requireApiAuth('nas','read-write'), handle(async (req,res) => {
        try { validate(req.body,true); } catch (err) { return res.status(400).json({error:err.message}); }
        const {name,ipv4,auth_port,accounting_port,shared_secret}=req.body;
        const proxy_traffic=req.body.proxy_traffic ?? 'both';
        const [result]=await pool.query('INSERT INTO downstream_radius_destinations (tenant_id,name,ipv4,auth_port,accounting_port,shared_secret,proxy_traffic) VALUES (?,?,?,?,?,?,?)',[selected(req),name.trim(),ipv4,Number(auth_port),Number(accounting_port),shared_secret,proxy_traffic]);
        await activate(req, 'POST', result.insertId);
        await auditLog(req.admin.username,req.origin,'Created downstream destination','success',name.trim(),req.ip,req.tenantScope);
        res.status(201).json({id:result.insertId,tenant_id:selected(req),name:name.trim(),ipv4,auth_port:Number(auth_port),accounting_port:Number(accounting_port),proxy_traffic,radius_reloaded:true});
    }));
    app.put(endpoint+'/:id', requireApiAuth('nas','read-write'), handle(async (req,res) => {
        try { validate(req.body,false); } catch (err) { return res.status(400).json({error:err.message}); }
        const {name,ipv4,auth_port,accounting_port,shared_secret}=req.body;
        const s=scoped(req);
        const hasSecret=shared_secret !== undefined;
        const hasTraffic=req.body.proxy_traffic !== undefined;
        const sql='UPDATE downstream_radius_destinations SET name=?,ipv4=?,auth_port=?,accounting_port=?'+(hasSecret?',shared_secret=?':'')+(hasTraffic?',proxy_traffic=?':'')+' WHERE id=?'+s.sql;
        const [result]=await pool.query(sql,[name.trim(),ipv4,Number(auth_port),Number(accounting_port),...(hasSecret?[shared_secret]:[]),...(hasTraffic?[req.body.proxy_traffic]:[]),req.params.id,...s.params]);
        if (!result.affectedRows) return res.status(404).json({error:'Destination not found'});
        await activate(req, 'PUT', req.params.id);
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
        await activate(req, 'DELETE', req.params.id);
        await auditLog(req.admin.username,req.origin,'Deleted downstream destination','success','',req.ip,req.tenantScope);
        res.json({success:true,radius_reloaded:true});
    }));
};
module.exports.routing = routing;
module.exports.verifyDestination = verifyDestination;
