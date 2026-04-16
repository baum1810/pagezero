(function(){
var raw=[];
document.cookie.split(';').forEach(function(c){
  var p=c.trim().split('=');var v=(p.slice(1).join('='))||'';
  if(v.match(/^eyJ/))raw.push({src:'cookie:'+p[0].trim(),t:v});
});
try{for(var i=0;i<localStorage.length;i++){
  var k=localStorage.key(i);var v=localStorage.getItem(k)||'';
  var m=v.match(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/);
  if(m)raw.push({src:'ls:'+k,t:m[0]});
}}catch(e){}
document.cookie.match(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g);
var results=raw.map(function(r){
  try{
    var parts=r.t.split('.');
    function b64d(s){try{return JSON.parse(atob(s.replace(/-/g,'+').replace(/_/g,'/')));}catch(e){return s;}}
    var hdr=b64d(parts[0]);var pay=b64d(parts[1]);
    var now=Math.floor(Date.now()/1000);
    var expired=pay.exp&&pay.exp<now;
    var alg=hdr.alg||'?';
    var weakAlg=alg==='none'||alg==='HS256';
    return {source:r.src,header:hdr,payload:pay,
      expires:pay.exp?new Date(pay.exp*1000).toISOString():'never',
      expired:expired,alg:alg,
      warnings:(weakAlg?['WEAK ALG: '+alg+' — may be forgeable']:[]
               ).concat(expired?['EXPIRED']:[]
               ).concat(alg==='none'?['alg=none: send unsigned token']:[] )};
  }catch(e){return {source:r.src,error:'decode failed',raw:r.t.slice(0,80)};}
});
return results.length?results:'no JWTs found';
})()