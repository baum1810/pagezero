(function(){
if(window.__pzPM)return 'already running ('+window.__pzPM.length+' messages)';
window.__pzPM=[];
window.__pzPMH=function(e){
  try{
    var d=e.data;
    var ds=typeof d==='string'?d:(typeof d==='object'?JSON.stringify(d):'['+typeof d+']');
    window.__pzPM.push({ts:new Date().toISOString(),origin:e.origin,
      data:ds.slice(0,1000),
      src_is_parent:e.source===window.parent,
      src_is_opener:e.source===window.opener});
    if(window.__pzPM.length>500)window.__pzPM=window.__pzPM.slice(-500);
  }catch(err){}
};
window.addEventListener('message',window.__pzPMH,true);
return 'PostMessage sniffer active';
})()