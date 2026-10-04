const { scope } = require('../tenant');
module.exports = function(app, pool, requireApiAuth, auditLog) {
  const superOnly = (req, res) => { if (!req.tenantScope.superAdmin) { res.status(403).json({error:'Only super admins can manage tenants'}); return false; } return true; };
  app.get('/api/tenants', requireApiAuth('admins','read-only'), async (req,res) => {
    const [[setting]] = await pool.query("SELECT setting_value FROM settings WHERE setting_key='multi_tenant_enabled'");
    if (!setting || String(setting.setting_value) !== 'true') return res.json([]);
    const [rows] = req.tenantScope.superAdmin
      ? await pool.query('SELECT id,name,description,created_at FROM tenants ORDER BY name')
      : await pool.query('SELECT t.id,t.name,t.description,t.created_at FROM tenants t JOIN admin_tenants at ON at.tenant_id=t.id WHERE at.admin_id=? ORDER BY t.name',[req.admin.id]);
    res.json(rows);
  });
  app.post('/api/tenants', requireApiAuth('admins','read-write'), async (req,res) => {
    if (!superOnly(req,res)) return; const name=String(req.body.name||'').trim(); if(!name) return res.status(400).json({error:'Tenant name required'});
    try { const [r]=await pool.query('INSERT INTO tenants (name,description) VALUES (?,?)',[name,String(req.body.description||'').trim()]); await auditLog(req.admin.username,req.origin,'Created tenant','success',JSON.stringify({ tenant_id:r.insertId, name }),req.ip,null); res.status(201).json({id:r.insertId,name}); } catch(err) { res.status(400).json({error:err.message}); }
  });
  app.put('/api/tenants/:id', requireApiAuth('admins','read-write'), async (req,res) => {
    if (!superOnly(req,res)) return; const name=String(req.body.name||'').trim(); if(!name) return res.status(400).json({error:'Tenant name required'});
    const [r]=await pool.query('UPDATE tenants SET name=?,description=? WHERE id=?',[name,String(req.body.description||'').trim(),req.params.id]); if(!r.affectedRows)return res.status(404).json({error:'Tenant not found'}); await auditLog(req.admin.username,req.origin,'Updated tenant','success',JSON.stringify({ tenant_id:Number(req.params.id), name }),req.ip,null); res.json({success:true});
  });
  app.delete('/api/tenants/:id', requireApiAuth('admins','read-write'), async (req,res) => {
    if (!superOnly(req,res)) return;
    const tenantId = Number(req.params.id);
    if (!Number.isInteger(tenantId) || tenantId < 1) return res.status(400).json({error:'Invalid tenant ID'});
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [[tenant]] = await conn.query('SELECT id FROM tenants WHERE id=? FOR UPDATE', [tenantId]);
      if (!tenant) { await conn.rollback(); return res.status(404).json({error:'Tenant not found'}); }
      // Delete dependent rows explicitly: tenant deletion is an intentional destructive operation.
      await conn.query('DELETE FROM plan_pod_enforcements WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM radsec_proxy_enrollments WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM radsec_clients WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE rsn FROM radsec_credential_set_nas rsn INNER JOIN radsec_credential_sets rcs ON rcs.id=rsn.credential_set_id WHERE rcs.tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM radsec_credential_sets WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM user_plan_usage WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM user_plans WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM user_totp WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM radreply WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM radusergroup WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM radcheck WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM radgroupcheck WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM radgroupreply WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM mac_auth_devices WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM plans WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM radacct WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM radpostauth WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM radius_stats WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM tenant_settings WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM admin_tenants WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM admin_audit_log WHERE tenant_id=?', [tenantId]);
      await conn.query('DELETE FROM nas WHERE tenant_id=?', [tenantId]);
      const [result] = await conn.query('DELETE FROM tenants WHERE id=?', [tenantId]);
      if (!result.affectedRows) throw new Error('Tenant disappeared during deletion');
      await conn.commit();
      await auditLog(req.admin.username,req.origin,'Deleted tenant','success','',req.ip,null);
      res.json({success:true});
    } catch (err) {
      await conn.rollback();
      console.error('Tenant deletion failed:', err);
      res.status(409).json({error:'Tenant deletion failed', detail:err.message});
    } finally { conn.release(); }
  });
  app.get('/api/tenants/:id/admins', requireApiAuth('admins','read-only'), async (req,res) => {
    if (!superOnly(req,res)) return; const [rows]=await pool.query('SELECT a.id,a.username,a.is_super_admin FROM admins a JOIN admin_tenants at ON at.admin_id=a.id WHERE at.tenant_id=? ORDER BY a.username',[req.params.id]);res.json(rows);
  });
  app.post('/api/tenants/:id/admins/:adminId', requireApiAuth('admins','read-write'), async(req,res)=>{if(!superOnly(req,res))return; const [[tenant]]=await pool.query('SELECT id FROM tenants WHERE id=?',[req.params.id]); if(!tenant)return res.status(404).json({error:'Tenant not found'}); const [[admin]]=await pool.query('SELECT id FROM admins WHERE id=?',[req.params.adminId]);if(!admin)return res.status(404).json({error:'Administrator not found'});const [result]=await pool.query('INSERT IGNORE INTO admin_tenants (admin_id,tenant_id) VALUES (?,?)',[admin.id,tenant.id]);if (result.affectedRows) await auditLog(req.admin.username,req.origin,'Added tenant administrator membership','success','',req.ip,null);res.json({success:true});});
  app.delete('/api/tenants/:id/admins/:adminId', requireApiAuth('admins','read-write'), async(req,res)=>{if(!superOnly(req,res))return;const [result]=await pool.query('DELETE FROM admin_tenants WHERE admin_id=? AND tenant_id=?',[req.params.adminId,req.params.id]);if (result.affectedRows) await auditLog(req.admin.username,req.origin,'Removed tenant administrator membership','success','',req.ip,null);res.json({success:true});});
};
