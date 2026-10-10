'use strict';

function createTotpHelpers(pool, crypto, bcrypt) {
  function tenantId(value) {
    const id = Number(value);
    if (!Number.isSafeInteger(id) || id < 1) throw new Error('A valid tenant is required for user TOTP');
    return id;
  }
  async function getRadiusCredential(username) {
    const [rows] = await pool.query(
      "SELECT value, tenant_id FROM radcheck WHERE username = ? AND attribute = 'Cleartext-Password' LIMIT 2", [username]
    );
    if (rows.length !== 1) return null;
    return { value: rows[0].value, tenantId: tenantId(rows[0].tenant_id) };
  }
  async function syncUserTotpToRadius(conn, username, selectedTenant) {
    const id = tenantId(selectedTenant);
    const [rows] = await conn.query('SELECT enabled, secret FROM user_totp WHERE username = ? AND tenant_id = ? LIMIT 1', [username, id]);
    const totp = rows[0];
    await conn.query("DELETE FROM radcheck WHERE username = ? AND attribute = 'TOTP-Secret' AND tenant_id = ?", [username, id]);
    if (totp && Number(totp.enabled) === 1 && totp.secret) {
      await conn.query("INSERT INTO radcheck (username, attribute, op, value, tenant_id) VALUES (?, 'TOTP-Secret', ':=', ?, ?)", [username, totp.secret, id]);
    }
  }
  async function generateEnrollmentCode(conn, username, selectedTenant) {
    const id = tenantId(selectedTenant);
    const plainCode = crypto.randomBytes(24).toString('base64url');
    const hash = await bcrypt.hash(plainCode, 10);
    const [settings] = await conn.query("SELECT setting_value FROM settings WHERE setting_key = 'totp_enrollment_hours'");
    const parsed = settings.length ? Number.parseInt(settings[0].setting_value, 10) : 24;
    const hours = Number.isSafeInteger(parsed) && parsed >= 1 && parsed <= 168 ? parsed : 24;
    const expiry = new Date(Date.now() + hours * 3600000);
    const [result] = await conn.query(
      'UPDATE user_totp SET enrollment_code_hash = ?, enrollment_expires_at = ?, pending_secret = NULL WHERE username = ? AND tenant_id = ?',
      [hash, expiry, username, id]
    );
    if (result.affectedRows !== 1) throw new Error('TOTP user not found in selected tenant');
    return { code: plainCode, expires_at: expiry.toISOString() };
  }
  return { getRadiusCredential, syncUserTotpToRadius, generateEnrollmentCode };
}
module.exports = { createTotpHelpers };
