'use strict';
const {AsyncLocalStorage}=require('node:async_hooks');
const logWrite=/^\s*(?:INSERT\s+(?:IGNORE\s+)?INTO|REPLACE\s+INTO|UPDATE|DELETE\s+FROM)\s+`?(?:radacct|radpostauth|admin_audit_log|plan_pod_enforcements)`?(?:\s|\(|$)/i;
function createSecondaryLogWriteFence({isSecondary,waitMs=30000}) {
 const internal=new AsyncLocalStorage();
 const active=new Set();const connections=new WeakMap();let fenced=false;
 async function runConnection(conn,sql,execute){
  if(!isSecondary()||!logWrite.test(String(sql))||internal.getStore())return execute();
  if(fenced&&!connections.has(conn))throw new Error('Secondary log writes paused for reconciliation maintenance');
  if(!connections.has(conn)){
   let release;
   const held=new Promise(resolve=>{release=resolve;});
   active.add(held);
   connections.set(conn,true);
   const original=conn.release;
   conn.release=function(...args){
    try{return original.apply(this,args);}
    finally{connections.delete(conn);active.delete(held);release();conn.release=original;}
   };
  }
  const task=Promise.resolve().then(execute);
  active.add(task);
  try{return await task;}finally{active.delete(task);}
 }
 async function run(sql,execute){
  if(!isSecondary()||!logWrite.test(String(sql))||internal.getStore())return execute();
  if(fenced)throw new Error('Secondary log writes paused for reconciliation maintenance');
  const task=Promise.resolve().then(execute);
  active.add(task);
  try{return await task;}finally{active.delete(task);}
 }
 async function runTask(execute){
  if(!isSecondary()||internal.getStore())return execute();
  if(fenced)throw new Error('Secondary log writes paused for reconciliation maintenance');
  const task=Promise.resolve().then(execute);
  active.add(task);
  try{return await task;}finally{active.delete(task);}
 }
 async function withFence(fn){
  if(fenced)throw new Error('Secondary log maintenance already in progress');
  fenced=true;
  try{
   let timer;
   try{
    await Promise.race([Promise.allSettled([...active]),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Secondary log writer drain timed out')),waitMs);})]);
   }finally{clearTimeout(timer);}
   return await internal.run(true,fn);
  }finally{fenced=false;}
 }
 return {run,runTask,runConnection,withFence};
}
module.exports={createSecondaryLogWriteFence};
