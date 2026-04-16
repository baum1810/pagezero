(function(){
if(window.__pzAM)return 'already running ('+window.__pzAM.length+' calls logged)';
window.__pzAM=[];
var _f=window.fetch;
var _oO=XMLHttpRequest.prototype.open,_oS=XMLHttpRequest.prototype.send;
window.fetch=function(url,opts){
  var e={ts:new Date().toISOString(),type:'fetch',method:(opts&&opts.method)||'GET',url:String(url)};
  if(opts&&opts.body)try{e.body=String(opts.body).slice(0,200);}catch(x){}
  if(opts&&opts.headers)try{e.headers=Object.assign({},opts.headers);}catch(x){}
  window.__pzAM.push(e);
  return _f.apply(this,arguments);
};
XMLHttpRequest.prototype.open=function(m,u){this.__pzAMm=m;this.__pzAMu=u;_oO.apply(this,arguments);};
XMLHttpRequest.prototype.send=function(b){
  window.__pzAM.push({ts:new Date().toISOString(),type:'xhr',method:this.__pzAMm,url:String(this.__pzAMu),body:b?String(b).slice(0,200):null});
  _oS.apply(this,arguments);
};
return 'API monitor started';
})()