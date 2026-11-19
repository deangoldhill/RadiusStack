'use strict';
const {scope} = require('../tenant');
const WINDOWS = Object.freeze({
  hour:{interval:'1 HOUR',seconds:3600,bucket:"DATE_FORMAT(%s, '%Y-%m-%d %H:%i:00')"},
  day:{interval:'1 DAY',seconds:86400,bucket:"DATE_FORMAT(%s, '%Y-%m-%d %H:00:00')"},
  week:{interval:'7 DAY',seconds:604800,bucket:"DATE_FORMAT(%s, '%Y-%m-%d')"},
  month:{interval:'30 DAY',seconds:2592000,bucket:"DATE_FORMAT(%s, '%Y-%m-%d')"},
  year:{interval:'365 DAY',seconds:31536000,bucket:"DATE_FORMAT(%s, '%Y-%m-01')"}
});
const count = value => Number(value) || 0;
module.exports = function registerNasStats(app,pool,requireApiAuth) {
  app.get('/api/nas/:id/stats',requireApiAuth('nas','read-only'),async(req,res)=>{
    const id=String(req.params.id), name=req.query?.window || 'hour';
    if(!/^[1-9][0-9]*$/.test(id) || !Number.isSafeInteger(Number(id)) || !Object.hasOwn(WINDOWS,name))
      return res.status(400).json({error:'Invalid NAS or time window'});
    try {
      const s=scope(req.tenantScope,'n.tenant_id');
      const [nasRows]=await pool.query('SELECT n.id,n.nasname,n.shortname,n.description,n.tenant_id FROM nas n WHERE n.id=?'+s.sql,[Number(id),...s.params]);
      if(!nasRows.length)return res.status(404).json({error:'NAS not found in selected tenant'});
      const nas=nasRows[0], window=WINDOWS[name];
      const restriction=alias=>{
        const tenant=scope(req.tenantScope,`${alias}.tenant_id`);
        return {sql:` WHERE ${alias}.nasipaddress=?${tenant.sql} AND ${alias}.${alias==='p'?'authdate':'acctstarttime'} >= UTC_TIMESTAMP() - INTERVAL ${window.interval}`,
          params:[nas.nasname,...tenant.params]};
      };
      const auth=restriction('p'), acct=restriction('a');
      const authBucket=window.bucket.replace('%s','p.authdate'), acctBucket=window.bucket.replace('%s','a.acctstarttime');
      const [authTotals]=await pool.query("SELECT COUNT(*) AS auth, COALESCE(SUM(p.reply='Access-Accept'),0) AS accept, COALESCE(SUM(p.reply='Access-Reject'),0) AS reject FROM radpostauth p"+auth.sql,auth.params);
      const [acctTotals]=await pool.query('SELECT COUNT(*) AS sessions, COALESCE(SUM(a.acctstoptime IS NULL),0) AS active, COALESCE(SUM(a.acctinputoctets),0) AS input_bytes, COALESCE(SUM(a.acctoutputoctets),0) AS output_bytes FROM radacct a'+acct.sql,acct.params);
      const [authSeries]=await pool.query(`SELECT ${authBucket} AS series_bucket, COUNT(*) AS auth, COALESCE(SUM(p.reply='Access-Accept'),0) AS accept, COALESCE(SUM(p.reply='Access-Reject'),0) AS reject FROM radpostauth p${auth.sql} GROUP BY series_bucket ORDER BY series_bucket`,auth.params);
      const [acctSeries]=await pool.query(`SELECT ${acctBucket} AS series_bucket, COUNT(*) AS sessions FROM radacct a${acct.sql} GROUP BY series_bucket ORDER BY series_bucket`,acct.params);
      const [peaks]=await pool.query("SELECT COALESCE(MAX(requests_in_minute/60),0) AS peak_minute_rps FROM (SELECT COUNT(*) AS requests_in_minute FROM radpostauth p"+auth.sql+" GROUP BY DATE_FORMAT(p.authdate, '%Y-%m-%d %H:%i:00')) AS minute_totals",auth.params);
      const totals={auth:count(authTotals[0]?.auth),accept:count(authTotals[0]?.accept),reject:count(authTotals[0]?.reject),sessions:count(acctTotals[0]?.sessions),active:count(acctTotals[0]?.active),input_bytes:count(acctTotals[0]?.input_bytes),output_bytes:count(acctTotals[0]?.output_bytes)};
      totals.other=Math.max(0,totals.auth-totals.accept-totals.reject);
      const series=new Map();
      for(const row of authSeries)series.set(String(row.series_bucket),{bucket:String(row.series_bucket),auth:count(row.auth),accept:count(row.accept),reject:count(row.reject),sessions:0});
      for(const row of acctSeries){const key=String(row.series_bucket),point=series.get(key)||{bucket:key,auth:0,accept:0,reject:0,sessions:0};point.sessions=count(row.sessions);series.set(key,point);}
      res.json({nas,window:name,duration_seconds:window.seconds,as_of:new Date().toISOString(),source:'this RadiusStack node',metric:'recorded authentication outcomes and accounting sessions',totals,average_rps:Number((totals.auth/window.seconds).toFixed(4)),peak_minute_rps:count(peaks[0]?.peak_minute_rps),series:[...series.values()].sort((a,b)=>a.bucket.localeCompare(b.bucket))});
    }catch(error){console.error('[NAS Stats]',error.message);res.status(503).json({error:'NAS statistics unavailable'});}
  });
};
