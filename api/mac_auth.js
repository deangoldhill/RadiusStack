const { scope } = require('../tenant');

module.exports = function(app, pool, requireApiAuth, auditLog) {
  const macPattern = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/;
  const tenantId = req => req.tenantScope.enabled ? req.tenantScope.tenantId : null;
  const selected = req => scope(req.tenantScope);
  const normalize = value => String(value || '').trim().toLowerCase().replace(/-/g, ':');

  async function ensurePlan(conn, planId, req) {
    if (!planId) return;
    const s = selected(req);
    const [plans] = await conn.query('SELECT id FROM plans WHERE id = ?' + s.sql, [planId, ...s.params]);
    if (!plans.length) throw Object.assign(new Error('Plan not found in selected tenant'), { status: 404 });
  }
  async function writeMac(conn, { mac_id, mac_address, profile, plan_id }, req) {
    const tid = tenantId(req);
    await ensurePlan(conn, plan_id, req);
    await conn.query('INSERT INTO mac_auth_devices (mac_address, mac_id, tenant_id) VALUES (?, ?, ?)', [mac_address, mac_id, tid]);
    await conn.query("DELETE FROM radcheck WHERE username = ? AND attribute = 'Cleartext-Password'" + selected(req).sql, [mac_address, ...selected(req).params]);
    await conn.query("INSERT INTO radcheck (username, attribute, op, value, tenant_id) VALUES (?, 'Cleartext-Password', ':=', ?, ?)", [mac_address, mac_address, tid]);
    await conn.query('DELETE FROM radusergroup WHERE username = ?' + selected(req).sql, [mac_address, ...selected(req).params]);
    if (profile) await conn.query('INSERT INTO radusergroup (username, groupname, priority, tenant_id) VALUES (?, ?, 1, ?)', [mac_address, profile, tid]);
    if (plan_id) await conn.query('INSERT INTO user_plans (username, plan_id, tenant_id) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE plan_id=VALUES(plan_id), tenant_id=VALUES(tenant_id)', [mac_address, plan_id, tid]);
    else await conn.query('DELETE FROM user_plans WHERE username = ?' + selected(req).sql, [mac_address, ...selected(req).params]);
    await conn.query('DELETE FROM user_totp WHERE username = ?' + selected(req).sql, [mac_address, ...selected(req).params]);
  }

  app.get('/api/mac-auth', requireApiAuth('users', 'read-only'), async (req, res) => {
    try {
      const s = scope(req.tenantScope, 'm.tenant_id');
      const paginated = req.query.page !== undefined;
      const page = Math.max(1, parseInt(req.query.page, 10) || 1);
      const pageSize = [25, 50, 100].includes(Number(req.query.page_size)) ? Number(req.query.page_size) : 25;
      const sortColumns = { username: 'm.mac_id', callingstationid: 'm.mac_address', planName: 'p.name', profileName: 'g.groupname' };
      const sort = sortColumns[req.query.sort] || 'm.mac_id';
      const order = req.query.order === 'desc' ? 'DESC' : 'ASC';
      const where = ['1=1' + s.sql]; const params = [...s.params];
      const search = String(req.query.search || '').trim().slice(0, 100);
      if (search) { const like = `%${search}%`; where.push('(m.mac_id LIKE ? OR m.mac_address LIKE ? OR p.name LIKE ? OR g.groupname LIKE ?)'); params.push(like, like, like, like); }
      if (/^\d+$/.test(String(req.query.plan || ''))) { where.push('up.plan_id = ?'); params.push(Number(req.query.plan)); }
      const joins = 'FROM mac_auth_devices m LEFT JOIN radusergroup g ON g.username=m.mac_address AND g.tenant_id <=> m.tenant_id LEFT JOIN user_plans up ON up.username=m.mac_address AND up.tenant_id <=> m.tenant_id LEFT JOIN plans p ON p.id=up.plan_id AND p.tenant_id <=> m.tenant_id';
      const clause = 'WHERE ' + where.join(' AND ');
      const select = 'SELECT m.mac_id,m.mac_address,g.groupname AS profile,up.plan_id,p.name AS plan_name';
      if (!paginated) { const [rows] = await pool.query(`${select} ${joins} ${clause} ORDER BY m.mac_id ASC`, params); return res.json(rows); }
      const [[count]] = await pool.query(`SELECT COUNT(*) AS total ${joins} ${clause}`, params);
      const [rows] = await pool.query(`${select} ${joins} ${clause} ORDER BY ${sort} ${order},m.mac_address ASC LIMIT ? OFFSET ?`, [...params, pageSize, (page - 1) * pageSize]);
      const total = Number(count.total); res.json({ items: rows, total, page: Math.min(page, Math.max(1, Math.ceil(total / pageSize))), pageSize, totalPages: Math.max(1, Math.ceil(total / pageSize)) });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.post('/api/mac-auth', requireApiAuth('users', 'read-write'), async (req, res) => {
    const device = { ...req.body, mac_address: normalize(req.body.mac_address) };
    if (!device.mac_id || !macPattern.test(device.mac_address)) return res.status(400).json({ error: 'Valid MAC ID and Address required' });
    const conn = await pool.getConnection();
    try { await conn.beginTransaction(); await writeMac(conn, device, req); await conn.commit(); await auditLog(req.admin.username, req.origin, `Created MAC device: ${device.mac_id}`, 'success', '', req.ip, req.tenantScope); res.json({ message: 'MAC authenticated device created' }); }
    catch (err) { await conn.rollback(); res.status(err.status || (err.code === 'ER_DUP_ENTRY' ? 400 : 500)).json({ error: err.message }); }
    finally { conn.release(); }
  });

  app.post('/api/mac-auth/bulk', requireApiAuth('users', 'read-write'), async (req, res) => {
    if (!Array.isArray(req.body)) return res.status(400).json({ error: 'Expected array of devices' });
    const conn = await pool.getConnection(); const errors = []; let successCount = 0;
    try { await conn.beginTransaction(); for (let i = 0; i < req.body.length; i++) { const device = { ...req.body[i], mac_address: normalize(req.body[i].mac_address) }; if (!device.mac_id || !macPattern.test(device.mac_address)) { errors.push(`Row ${i + 1}: Invalid MAC ID or address`); continue; } try { await writeMac(conn, device, req); successCount++; } catch (err) { errors.push(`Row ${i + 1}: ${err.message}`); } } await conn.commit(); await auditLog(req.admin.username, req.origin, `Imported ${successCount} MAC devices`, 'success', JSON.stringify({ errors }), req.ip, req.tenantScope); res.json({ message: `Imported ${successCount} MAC devices.`, errors }); }
    catch (err) { await conn.rollback(); res.status(500).json({ error: 'Bulk import failed completely' }); } finally { conn.release(); }
  });

  app.put('/api/mac-auth/:macAddress', requireApiAuth('users', 'read-write'), async (req, res) => {
    const macAddress = normalize(req.params.macAddress); const s = selected(req); const conn = await pool.getConnection();
    try { await conn.beginTransaction(); const [existing] = await conn.query('SELECT * FROM mac_auth_devices WHERE mac_address = ?' + s.sql, [macAddress, ...s.params]); if (!existing.length) { await conn.rollback(); return res.status(404).json({ error: 'MAC device not found in selected tenant' }); } await ensurePlan(conn, req.body.plan_id, req); await conn.query('UPDATE mac_auth_devices SET mac_id=? WHERE mac_address = ?' + s.sql, [req.body.mac_id, macAddress, ...s.params]); await conn.query('DELETE FROM radusergroup WHERE username=?' + s.sql, [macAddress, ...s.params]); if (req.body.profile) await conn.query('INSERT INTO radusergroup (username,groupname,priority,tenant_id) VALUES (?,?,1,?)', [macAddress, req.body.profile, tenantId(req)]); await conn.query('DELETE FROM user_plans WHERE username=?' + s.sql, [macAddress, ...s.params]); if (req.body.plan_id) await conn.query('INSERT INTO user_plans (username,plan_id,tenant_id) VALUES (?,?,?)', [macAddress, req.body.plan_id, tenantId(req)]); await conn.commit(); await auditLog(req.admin.username, req.origin, `Updated MAC device: ${macAddress}`, 'success', '', req.ip, req.tenantScope); res.json({ message: 'MAC authenticated device updated' }); }
    catch (err) { await conn.rollback(); res.status(err.status || (err.code === 'ER_DUP_ENTRY' ? 400 : 500)).json({ error: err.message }); } finally { conn.release(); }
  });

  app.delete('/api/mac-auth/:macAddress', requireApiAuth('users', 'read-write'), async (req, res) => {
    const macAddress = normalize(req.params.macAddress); const s = selected(req); const conn = await pool.getConnection();
    try { await conn.beginTransaction(); const [result] = await conn.query('DELETE FROM mac_auth_devices WHERE mac_address = ?' + s.sql, [macAddress, ...s.params]); if (!result.affectedRows) { await conn.rollback(); return res.status(404).json({ error: 'MAC device not found in selected tenant' }); } for (const table of ['radcheck', 'radusergroup', 'user_plans', 'user_plan_usage', 'user_totp']) await conn.query(`DELETE FROM ${table} WHERE username = ?` + s.sql, [macAddress, ...s.params]); await conn.commit(); await auditLog(req.admin.username, req.origin, `Deleted MAC device: ${macAddress}`, 'success', '', req.ip, req.tenantScope); res.json({ message: 'MAC device deleted' }); }
    catch (err) { await conn.rollback(); res.status(500).json({ error: err.message }); } finally { conn.release(); }
  });
};
