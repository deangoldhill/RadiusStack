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
    try { const [r]=await pool.query('INSERT INTO tenants (name,description) VALUES (?,?)',[name,String(req.body.description||'').trim()]); await auditLog(req.admin.username,req.origin,`Created tenant: ${name}`,'success','',req.ip); res.status(201).json({id:r.insertId,name}); } catch(err) { res.status(400).json({error:err.message}); }
  });
  app.put('/api/tenants/:id', requireApiAuth('admins','read-write'), async (req,res) => {
    if (!superOnly(req,res)) return; const name=String(req.body.name||'').trim(); if(!name) return res.status(400).json({error:'Tenant name required'});
    const [r]=await pool.query('UPDATE tenants SET name=?,description=? WHERE id=?',[name,String(req.body.description||'').trim(),req.params.id]); if(!r.affectedRows)return res.status(404).json({error:'Tenant not found'}); res.json({success:true});
  });
  app.delete('/api/tenants/:id', requireApiAuth('admins','read-write'), async (req,res) => {
    if (!superOnly(req,res)) return; const [r]=await pool.query('DELETE FROM tenants WHERE id=?',[req.params.id]); if(!r.affectedRows)return res.status(404).json({error:'Tenant not found'}); res.json({success:true});
  });
  app.get('/api/tenants/:id/admins', requireApiAuth('admins','read-only'), async (req,res) => {
    if (!superOnly(req,res)) return; const [rows]=await pool.query('SELECT a.id,a.username,a.is_super_admin FROM admins a JOIN admin_tenants at ON at.admin_id=a.id WHERE at.tenant_id=? ORDER BY a.username',[req.params.id]);res.json(rows);
  });
  app.post('/api/tenants/:id/admins/:adminId', requireApiAuth('admins','read-write'), async(req,res)=>{if(!superOnly(req,res))return; const [[tenant]]=await pool.query('SELECT id FROM tenants WHERE id=?',[req.params.id]); if(!tenant)return res.status(404).json({error:'Tenant not found'}); const [[admin]]=await pool.query('SELECT id FROM admins WHERE id=?',[req.params.adminId]);if(!admin)return res.status(404).json({error:'Administrator not found'});await pool.query('INSERT IGNORE INTO admin_tenants (admin_id,tenant_id) VALUES (?,?)',[admin.id,tenant.id]);res.json({success:true});});
  app.delete('/api/tenants/:id/admins/:adminId', requireApiAuth('admins','read-write'), async(req,res)=>{if(!superOnly(req,res))return;await pool.query('DELETE FROM admin_tenants WHERE admin_id=? AND tenant_id=?',[req.params.adminId,req.params.id]);res.json({success:true});});
};
