(function(root){
  'use strict';
  // Match MariaDB DATE(), YEARWEEK(..., 1), and DATE_FORMAT(..., '%Y-%m').
  function planCycleStatus(cycleStart,period,now=new Date()) {
    const start=cycleStart ? new Date(cycleStart) : null;
    let nextReset=null;
    if (start && !Number.isNaN(start.getTime())) {
      if (period==='daily') {
        nextReset=new Date(start);
        nextReset.setHours(0,0,0,0);
        nextReset.setDate(nextReset.getDate()+1);
      } else if (period==='weekly') {
        nextReset=new Date(start);
        nextReset.setHours(0,0,0,0);
        nextReset.setDate(nextReset.getDate()+(((8-nextReset.getDay())%7)||7));
      } else if (period==='monthly') {
        nextReset=new Date(start.getFullYear(),start.getMonth()+1,1);
      }
    }
    const resetPending=!!nextReset && nextReset<=now;
    let timeUntilStr=null;
    if (resetPending) timeUntilStr='Reset pending';
    else if (nextReset) {
      const minutes=Math.ceil((nextReset-now)/60000);
      const days=Math.floor(minutes/1440), hours=Math.floor((minutes%1440)/60), mins=minutes%60;
      timeUntilStr=days ? `${days}d ${hours}h` : `${hours}h ${mins}m`;
    }
    return {nextReset,resetPending,timeUntilStr};
  }
  root.planCycleStatus=planCycleStatus;
  if(typeof module!=='undefined')module.exports={planCycleStatus};
})(typeof window!=='undefined'?window:globalThis);
