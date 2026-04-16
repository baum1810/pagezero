(function(){
if(!window.__pzAM)return 'not running — start it first';
var calls=window.__pzAM.slice();
window.__pzAM=[];
return {total:calls.length,calls:calls};
})()