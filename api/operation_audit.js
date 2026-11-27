'use strict';
// Explicitly audited operator actions only. Never audit replication traffic or polling.
const HA_COMMANDS = {
    pause: ['HA pause', 'Paused HA delivery'],
    resume: ['HA resume', 'Resumed HA delivery'],
    'full-sync': ['HA full sync', 'Queued HA full sync'],
    'log-reconcile': ['HA log reconciliation', 'Started HA log reconciliation'],
    promote: ['HA promotion', 'Promoted HA node'],
    demote: ['HA demotion', 'Demoted HA node'],
    'reset-stats': ['HA statistics reset', 'Reset HA sync statistics'],
    'sync-now': ['HA manual sync', 'Triggered manual HA sync'],
    'radsec-bundle': ['HA certificate sync', 'Synchronized HA RadSec certificates']
};
const clean = (value,max=200) => String(value??'').replace(/[\x00-\x1f\x7f]/g,' ').slice(0,max);
function actor(req) {
    return {username:clean(req.admin?.username||'anonymous',50),origin:['webui','api','system'].includes(req.origin)?req.origin:'api',ip:clean(req.ip||req.socket?.remoteAddress||'',50)};
}
async function safeAudit(auditLog, who, action, result, details, scope, logger=console) {
    try {await auditLog(who.username,who.origin,action,result,JSON.stringify(details),who.ip,scope);}
    catch(error) {logger.error('[Audit] Operation event unavailable:', /^[A-Z0-9_]{2,40}$/.test(error.code||'')?error.code:'error');}
}
function descriptor(method,path) {
    const match=/^\/api\/ha\/([a-z-]+)\/?$/.exec(path);
    if(method==='POST' && match && Object.hasOwn(HA_COMMANDS,match[1])) {
        const [name,success]=HA_COMMANDS[match[1]];return {name,success,scope:'global'};
    }
    const certificate=/^\/api\/certs\/download\/(server-pem|server-cert|server-key|ca-pem|ca-cert|ca-key)\/?$/.exec(path);
    if(method==='GET'&&certificate) {
        const privateMaterial=certificate[1].endsWith('-key');
        return {name:'EAP certificate material download',success:privateMaterial?'Downloaded EAP private key':'Downloaded EAP certificate',scope:'global',
            auditPath:'/api/certs/download/:type',target:{artifactType:certificate[1],privateMaterial},authenticatedOnly:true};
    }
    const ca=/^\/api\/tenant-radsec\/download\/(ca|server-trust-ca)\/?$/.exec(path);
    if(method==='GET'&&ca)return {name:'RadSec CA download',success:ca[1]==='ca'?'Downloaded tenant RadSec CA':'Downloaded RadSec server trust CA',scope:'tenant',
        auditPath:'/api/tenant-radsec/download/:type',target:{artifactType:ca[1]},authenticatedOnly:true};
    const artifact=/^\/api\/nas\/(\d+)\/radsec\/download\/[^/]+\/?$/.exec(path);
    if(method==='GET'&&artifact)return {name:'RadSec client credential download',success:'Downloaded RadSec client credential artifact',scope:'tenant',
        auditPath:'/api/nas/:id/radsec/download/:token',target:{nasId:artifact[1]},authenticatedOnly:true};
    return null;
}
function createOperationAudit({auditLog,logger=console}) {
    return (req,res,next) => {
        const path=(req.originalUrl||req.path||'').split('?')[0];
        const operation=descriptor(req.method,path);
        if(!operation)return next();
        let recorded=false;
        const record=(closed=false)=>{
            if(recorded)return;recorded=true;
            if(operation.authenticatedOnly&&!req.admin?.username)return;
            const status=closed?null:res.statusCode;
            const success=!closed && status>=200 && status<300;
            const result=success?'success':(status===401||status===403?'denied':'error');
            const scope=operation.scope==='tenant'&&req.tenantScope?.enabled
                ? {enabled:true,tenantId:req.tenantScope.tenantId}:{enabled:false};
            void safeAudit(auditLog,actor(req),success?operation.success:operation.name+' '+(closed?'response interrupted':result),result,
                {method:req.method,path:clean(operation.auditPath||path,300),status,...operation.target,...(closed?{outcome:'Connection closed; operation outcome requires review'}:{})},scope,logger);
        };
        res.once('finish',()=>record(false));
        res.once('close',()=>{if(!res.writableFinished)record(true);});
        next();
    };
}
async function runHaReconciliation(req,reconciler,auditLog,logger=console) {
    const who=actor(req);
    try {
        const result=await reconciler.run();
        if(!['completed','partial'].includes(result?.status))throw Error('Reconciliation returned no terminal outcome');
        const counts={};for(const table of ['radacct','radpostauth','admin_audit_log','plan_pod_enforcements']) {
            if(Number.isSafeInteger(result?.counts?.[table])&&result.counts[table]>=0)counts[table]=result.counts[table];
        }
        const partial=result?.status==='partial';
        await safeAudit(auditLog,who,partial?'HA log reconciliation completed with warnings':'HA log reconciliation completed',partial?'warning':'success',
            {runId:/^[0-9a-f]{32}$/.test(result?.runId||'')?result.runId:null,counts}, {enabled:false},logger);
        return result;
    } catch(error) {
        await safeAudit(auditLog,who,'HA log reconciliation failed','error',{reason:'Reconciliation failed; inspect HA status and restricted API logs'}, {enabled:false},logger);
        throw error;
    }
}
module.exports={createOperationAudit,runHaReconciliation};
