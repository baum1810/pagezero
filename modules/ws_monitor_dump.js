(function(){
if(!window.__pzWSM)return 'not running — start it first';
var data=window.__pzWSM.slice();
window.__pzWSM=[];
return {connections:data.length,data:data};
})()