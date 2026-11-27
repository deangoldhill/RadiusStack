const fs = require('node:fs/promises');
const path = require('node:path');
const crypto = require('node:crypto');
const {MAX_BACKUP_BYTES} = require('./backup_upload');

// Preserve the existing JSON shape without materialising the entire backup string.
function* backupJsonChunks(backup) {
    yield '{'; let firstRoot=true;
    for (const [key,value] of Object.entries(backup)) {
        if (value === undefined) continue;
        if (!firstRoot) yield ','; firstRoot=false;
        yield JSON.stringify(key)+':';
        if (key !== 'data' || !value || typeof value !== 'object' || Array.isArray(value)) {
            yield JSON.stringify(value); continue;
        }
        yield '{'; let firstTable=true;
        for (const [table,rows] of Object.entries(value)) {
            if (rows === undefined) continue;
            if (!firstTable) yield ','; firstTable=false;
            yield JSON.stringify(table)+':';
            if (!Array.isArray(rows)) {yield JSON.stringify(rows);continue;}
            yield '[';
            for (let i=0;i<rows.length;i++) {if(i)yield ',';yield JSON.stringify(rows[i]) ?? 'null';}
            yield ']';
        }
        yield '}';
    }
    yield '}';
}


function backupFailure(error={}) {
    if(error.code==='BACKUP_TOO_LARGE') return 'Backup exceeds the 700 MB limit. Reduce included logs or their retention.';
    if(['ENOSPC','EDQUOT'].includes(error.code)) return 'Insufficient disk space to save the backup.';
    if(['EACCES','EPERM','EROFS'].includes(error.code)) return 'Backup storage is not writable. Check backup-volume permissions and mount settings.';
    if(error.message==='Primary node required') return 'Primary node required';
    if(error.message==='Job already running or not due') return 'Job already running or not due';
    const tables={radacct:'accounting logs',radpostauth:'authentication logs',admin_audit_log:'audit logs'};
    const code=/^[A-Z0-9_]{2,40}$/.test(error.code||'')?' ('+error.code+')':'';
    if(tables[error.backupTable]) return `Could not back up ${tables[error.backupTable]}${code}. Check database availability and API logs.`;
    return `Backup operation failed${code}. Check database availability, backup storage and API logs.`;
}

function validateJob(input) {
    if (!input || typeof input.name !== 'string' || !input.name.trim() || input.name.length > 100 || /[\x00-\x1f]/.test(input.name)) throw Error('Invalid job name');
    if (!['full','partial'].includes(input.type)) throw Error('Invalid backup type');
    if (!['hourly','daily','weekly','interval_hours'].includes(input.frequency)) throw Error('Invalid frequency');
    if (input.frequency === 'interval_hours' && (!Number.isInteger(input.interval_hours) || input.interval_hours < 1 || input.interval_hours > 720)) throw Error('Invalid interval_hours');
    const acct = input.acct ?? input.include_accounting;
    const auth = input.auth ?? input.include_auth;
    const audit = input.audit ?? input.include_audit;
    const keepCount = input.keep_count ?? input.retention_count;
    if (!Number.isInteger(keepCount) || keepCount < 1 || keepCount > 100) throw Error('Invalid keep_count');
    for (const [flag,value] of Object.entries({acct,auth,audit,enabled:input.enabled})) if (value !== undefined && typeof value !== 'boolean') throw Error('Invalid ' + flag);
    return {name:input.name.trim(),frequency:input.frequency,interval_hours:input.frequency === 'interval_hours' ? input.interval_hours : null,
        type:input.type,acct:!!acct,auth:!!auth,audit:!!audit,keep_count:keepCount,enabled:input.enabled !== false};
}
function nextRun(job, from) {
    return new Date(new Date(from).getTime() + (job.frequency === 'hourly' ? 1 : job.frequency === 'daily' ? 24 : job.frequency === 'weekly' ? 168 : job.interval_hours) * 3600000);
}
function utcMysql(date) {return new Date(date).toISOString().slice(0,23).replace('T',' ');}
function utcIso(value) {
    if (value == null) return null;
    return value instanceof Date ? value.toISOString() : new Date(String(value).replace(' ','T')+'Z').toISOString();
}
function jobView(row) {
    return {id:row.id,name:row.name,frequency:row.frequency,interval_hours:row.interval_hours,type:row.type,
        include_accounting:!!row.acct,include_auth:!!row.auth,include_audit:!!row.audit,retention_count:row.keep_count,
        enabled:!!row.enabled,next_run_at:utcIso(row.next_run),last_run_at:utcIso(row.last_run),status:row.last_error?'error':row.last_run?'success':'idle',last_error:row.last_error};
}
function backupView(row) {return {id:row.id,job_id:row.job_id,job_name:row.job_name||null,type:row.type,created_at:utcIso(row.created_at),size_bytes:row.size,checksum:row.checksum};}
function createLocalBackups({pool,directory='/backups',buildBackup,streamBackup,maxBytes=MAX_BACKUP_BYTES,isPrimary=()=>true}) {
    const file = id => {
        if (typeof id !== 'string' || !/^[0-9a-f]{32}$/.test(id)) throw Error('Invalid backup ID');
        return path.join(directory,id+'.json');
    };
    async function privateDirectory() {
        await fs.mkdir(directory,{recursive:true,mode:0o700});
        const stat=await fs.lstat(directory);
        if (!stat.isDirectory() || stat.isSymbolicLink()) throw Error('Unsafe backup directory');
        await fs.chmod(directory,0o700);
    }
    async function open(id) {
        const [rows] = await pool.query('SELECT * FROM local_backups WHERE id=?',[id]);
        if (!rows.length) throw Error('Backup not found');
        const handle = await fs.open(file(id),fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
        try {
            const stat=await handle.stat();
            if (!stat.isFile()) throw Error('Invalid backup file');
            if (stat.size !== Number(rows[0].size)) throw Error('Backup size/checksum mismatch');
            if (stat.size > maxBytes) {const e=Error('Backup exceeds 700 MB limit');e.code='BACKUP_TOO_LARGE';throw e;}
            const digest=crypto.createHash('sha256');
            for await (const chunk of handle.createReadStream({start:0,autoClose:false})) digest.update(chunk);
            if (digest.digest('hex') !== rows[0].checksum) throw Error('Backup checksum mismatch');
            return {size:stat.size,createReadStream:()=>handle.createReadStream({start:0,autoClose:false}),close:()=>handle.close()};
        } catch(error) {await handle.close();throw error;}
    }
    async function read(id) {
        // Compatibility for small programmatic callers; HTTP routes use open().
        const verified=await open(id);
        try {const chunks=[];for await(const chunk of verified.createReadStream())chunks.push(chunk);return Buffer.concat(chunks);}
        finally {await verified.close();}
    }
    async function list() {
        const [rows] = await pool.query('SELECT * FROM local_backups ORDER BY created_at DESC');
        const [jobs] = await pool.query('SELECT id,name FROM backup_jobs');
        const names=new Map(jobs.map(j=>[Number(j.id),j.name]));
        const result=[];
        for (const row of rows) {
            try {const st=await fs.lstat(file(row.id)); if(st.isFile() && !st.isSymbolicLink()) result.push({...row,job_name:names.get(Number(row.job_id))||null});} catch (_) { /* file exists on a different HA node */ }
        }
        return result;
    }
    async function save(job,backup) {
        if (!isPrimary()) throw Error('Primary node required');
        await privateDirectory();
        const id=crypto.randomBytes(16).toString('hex');
        const chunks=backup?.[Symbol.asyncIterator] ? backup : backupJsonChunks(backup);
        const digest=crypto.createHash('sha256');
        let size=0, checksum;
        const tmp=path.join(directory,'.'+id+'.tmp');
        const target=file(id);
        let renamed=false, cataloged=false;
        try {
            const fd=await fs.open(tmp,'wx',0o600);
            try {
                for await (const chunk of chunks) {
                    const bytes=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk);
                    size+=bytes.length;
                    if(size>maxBytes) {
                        const error=Error('Backup exceeds 700 MB limit');error.code='BACKUP_TOO_LARGE';throw error;
                    }
                    digest.update(bytes);await fd.writeFile(bytes);
                }
                await fd.sync();checksum=digest.digest('hex');
            } finally {await fd.close();}
            await fs.rename(tmp,target); renamed=true;
            const dirfd=await fs.open(directory,'r'); try {await dirfd.sync();} finally {await dirfd.close();}
            const created=new Date();
            await pool.query('INSERT INTO local_backups (id,job_id,type,size,created_at,checksum) VALUES (?,?,?,?,?,?)',[id,job.id,job.type,size,utcMysql(created),checksum]);
            cataloged=true;
            // Retention is scoped to the current job and only follows successful cataloging.
            const [rows]=await pool.query('SELECT * FROM local_backups ORDER BY created_at DESC');
            const eligible=[];
            for(const row of rows.filter(r=>Number(r.job_id)===Number(job.id))) {
                try {const st=await fs.lstat(file(row.id)); if(st.isFile() && !st.isSymbolicLink()) eligible.push(row);}catch(e){if(e.code!=='ENOENT')throw e;}
            }
            for (const old of eligible.slice(job.keep_count)) {
                await fs.unlink(file(old.id));
                await pool.query('DELETE FROM local_backups WHERE id=?',[old.id]);
            }
            return {id,job_id:job.id,type:job.type,size:size,created_at:created,checksum};
        } catch(e) {
            await fs.rm(tmp,{force:true});
            if (renamed && !cataloged) {
                // If catalog insert committed but the ACK was lost, preserve the file.
                const [found]=await pool.query('SELECT * FROM local_backups WHERE id=?',[id]).catch(()=>[[{id}]]);
                if (!found.length) await fs.rm(target,{force:true});
            }
            throw e;
        }
    }
    async function run(job) {
        if (!isPrimary()) throw Error('Primary node required');
        const backup=streamBackup ? streamBackup(job) : await buildBackup(job);
        return save(job,backup);
    }
    return {file,open,read,list,save,run};
}
function createScheduler({pool,local,isPrimary=()=>true,auditLog=async()=>{}}) {
    async function run(job, manual=false) {
        if (!isPrimary()) throw Error('Primary node required');
        const token=crypto.randomBytes(16).toString('hex');
        const [claim]=await pool.query('UPDATE backup_jobs SET lease_until=DATE_ADD(UTC_TIMESTAMP(), INTERVAL 2 HOUR), lease_token=? WHERE id=? AND (lease_until IS NULL OR lease_until < UTC_TIMESTAMP())'+(manual?'':' AND enabled=1 AND next_run <= UTC_TIMESTAMP()'),[token,job.id]);
        if (!claim.affectedRows) throw Error('Job already running or not due');
        let result, error;
        try {result=await local.run(job);} catch(e) {error=e;}
        const scheduled=nextRun(job,new Date());
        await pool.query('UPDATE backup_jobs SET next_run=?, last_run=UTC_TIMESTAMP(), last_error=?, lease_until=NULL, lease_token=NULL WHERE id=? AND lease_token=?',[utcMysql(scheduled),error?backupFailure(error):null,job.id,token]);
        if(!manual) {
            try {
                await auditLog('system','system',error?'Scheduled backup failed':'Scheduled backup completed',error?'error':'success',
                    JSON.stringify({jobId:job.id,type:job.type,...(error?{reason:backupFailure(error)}:{backupId:result?.id,sizeBytes:result?.size})}),
                    '127.0.0.1',{enabled:false});
            } catch(_) {console.error('[Local Backup] Audit event unavailable');}
        }
        if(error) throw error;
        return result;
    }
    async function tick() {
        if(!isPrimary()) return;
        const [jobs]=await pool.query('SELECT * FROM backup_jobs WHERE enabled=1 AND next_run <= UTC_TIMESTAMP() ORDER BY next_run LIMIT 20');
        for(const job of jobs) try {await run(job);} catch(e) {if(e.message !== 'Job already running or not due') console.error('[Local Backup] Job failed:',job.id,e.code||'error');}
    }
    let timer;
    function start(){if(timer)return;const check=()=>tick().catch(e=>console.error('[Local Backup] Scheduler unavailable:',e.code||'error'));timer=setInterval(check,60000);timer.unref?.();check();}
    return {run,tick,start};
}
module.exports={createLocalBackups,validateJob,nextRun,createScheduler,utcMysql,jobView,backupView,backupFailure};
