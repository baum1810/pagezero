(function(){
if(!window.__pzPM)return 'not running — start it first';
var msgs=window.__pzPM.slice();
window.__pzPM=[];
return {total:msgs.length,messages:msgs};
})()