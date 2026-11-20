'use strict';
const {execFile}=require('node:child_process');
const {promisify}=require('node:util');
const execFileAsync=promisify(execFile);
async function docker(args) {
 const {stdout}=await execFileAsync('docker',args,{timeout:60000});
 return stdout.trim();
}
async function waitReady(run,sleep){
 for(let i=0;i<30;i++){
  try {if(String(await run(['exec','radius_server','pidof','radiusd'])).trim())return;}
  catch { /* Container may still be starting. */ }
  if(i<29)await sleep(1000);
 }
 throw new Error('Secondary RADIUS did not become ready after reconciliation');
}
async function withSecondaryRadiusMaintenance({run=docker,replace,recordStopped=async()=>{},clearStopped=async()=>{},sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms))}) {
 if(typeof run!=='function'||typeof replace!=='function')throw new TypeError('Maintenance requires runner and replacement');
 const running=String(await run(['inspect','--format','{{.State.Running}}','radius_server'])).trim();
 if(running!=='true'&&running!=='false')throw new Error('Secondary RADIUS running state unavailable');
 const stopped=running==='true';
 if(running==='true'){
  await recordStopped();
  await run(['stop','radius_server']);
 }
 let result,error;
 try {result=await replace();} catch(e){error=e;}
 if(stopped) {
  try {
   await run(['start','radius_server']);
   await waitReady(run,sleep);
   await clearStopped();
  }
  catch(startError) {if(error)startError.cause=error;throw startError;}
 }
 if(error)throw error;
 return result;
}
async function recoverSecondaryRadiusMaintenance({run=docker,marker,clearStopped,sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms))}){
 if(!await marker())return false;
 const running=String(await run(['inspect','--format','{{.State.Running}}','radius_server'])).trim();
 if(running==='false')await run(['start','radius_server']);
 else if(running!=='true')throw new Error('Secondary RADIUS running state unavailable');
 await waitReady(run,sleep);
 await clearStopped();
 return true;
}
module.exports={withSecondaryRadiusMaintenance,recoverSecondaryRadiusMaintenance};
