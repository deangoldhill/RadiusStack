'use strict';

// Use the same calendar boundaries as the FreeRADIUS plan_cycle_baseline policy.
const expired = `((p.reset_period = 'daily' AND DATE(u.cycle_started_at) < CURDATE())
  OR (p.reset_period = 'weekly' AND YEARWEEK(u.cycle_started_at, 1) < YEARWEEK(CURDATE(), 1))
  OR (p.reset_period = 'monthly' AND DATE_FORMAT(u.cycle_started_at, '%Y-%m') < DATE_FORMAT(CURDATE(), '%Y-%m')))`;

function createPlanCycleWorker({pool,isPrimary,logger=console}) {
  let current=null;
  function process() {
    if (!isPrimary()) return Promise.resolve(0);
    if (current) return current;
    current=run().finally(()=>{current=null;});
    return current;
  }
  async function readTotals(row) {
    const [[totals]]=await pool.query(`SELECT DATE_FORMAT(NOW(), '%Y-%m-%d %H:%i:%s') AS started_at,
      COALESCE(SUM(a.acctinputoctets),0) AS total_input,
      COALESCE(SUM(a.acctoutputoctets),0) AS total_output,
      COALESCE(SUM(a.acctsessiontime),0) AS total_time
      FROM radacct a WHERE a.username=? AND a.tenant_id=?`,[row.username,row.tenant_id]);
    return totals;
  }
  async function run() {
    let updated=0;
    try {
      const [rows]=await pool.query(`SELECT u.username,u.tenant_id,u.cycle_started_at
        FROM user_plan_usage u JOIN user_plans up ON up.username=u.username AND up.tenant_id=u.tenant_id
        JOIN plans p ON p.id=up.plan_id AND p.tenant_id=up.tenant_id
        WHERE ${expired} ORDER BY u.cycle_started_at LIMIT ?`,[200]);
      for(const row of rows) {
        if(!isPrimary()) break;
        try {
          // Read totals on the primary, then replicate fixed values rather than
          // letting a lagging HA peer recalculate its own baseline.
          const totals=await readTotals(row);
          if(!isPrimary()) break;
          const [result]=await pool.query(`UPDATE user_plan_usage u
            JOIN user_plans up ON up.username=u.username AND u.tenant_id=up.tenant_id
            JOIN plans p ON p.id=up.plan_id AND p.tenant_id=up.tenant_id
            SET u.cycle_started_at=?,u.base_input_octets=?,
                u.base_output_octets=?,u.base_session_seconds=?
            WHERE u.username=? AND u.tenant_id=? AND u.cycle_started_at=? AND ${expired}`,
            [totals.started_at,totals.total_input,totals.total_output,totals.total_time,
             row.username,row.tenant_id,row.cycle_started_at]);
          updated+=Number(result.affectedRows||0);
        } catch(error) {logger.error('[Plan cycle] reset failed:',error.message);throw error;}
      }
      // Older or failed plan assignments can be missing a baseline entirely.
      const [missing]=await pool.query(`SELECT up.username,up.tenant_id FROM user_plans up
        JOIN plans p ON p.id=up.plan_id AND p.tenant_id=up.tenant_id
        LEFT JOIN user_plan_usage u ON u.username=up.username AND u.tenant_id=up.tenant_id
        WHERE u.username IS NULL ORDER BY up.username LIMIT ?`,[200]);
      for(const row of missing) {
        if(!isPrimary()) break;
        try {
          const totals=await readTotals(row);
          if(!isPrimary()) break;
          const [result]=await pool.query(`INSERT INTO user_plan_usage (username,tenant_id,cycle_started_at,
              base_input_octets,base_output_octets,base_session_seconds)
            SELECT up.username,up.tenant_id,?,?,?,? FROM user_plans up
            JOIN plans p ON p.id=up.plan_id AND p.tenant_id=up.tenant_id
            WHERE up.username=? AND up.tenant_id=? AND NOT EXISTS (
              SELECT 1 FROM user_plan_usage u WHERE u.username=up.username AND u.tenant_id=up.tenant_id)`,
            [totals.started_at,totals.total_input,totals.total_output,totals.total_time,row.username,row.tenant_id]);
          updated+=Number(result.affectedRows||0);
        } catch(error) {logger.error('[Plan cycle] baseline initialization failed:',error.message);throw error;}
      }
    } catch(error) {logger.error('[Plan cycle] scan failed:',error.message);throw error;}
    return updated;
  }
  return {process};
}
module.exports={createPlanCycleWorker};
