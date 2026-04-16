(function(){
var target='{{param}}';
if(!target)return 'specify target URL';
var origin=location.origin;
fetch(target,{method:'GET',credentials:'include',mode:'cors',
  headers:{'Origin':origin,'X-Custom-Header':'pztest'}})
.then(function(r){
  var acao=r.headers.get('access-control-allow-origin');
  var acac=r.headers.get('access-control-allow-credentials');
  var acah=r.headers.get('access-control-allow-headers');
  var vuln=(acao===origin||acao==='*')&&acac==='true';
  __pzResult({target:target,origin_sent:origin,
    'Access-Control-Allow-Origin':acao,'Access-Control-Allow-Credentials':acac,
    'Access-Control-Allow-Headers':acah,
    VULNERABLE:vuln,
    note:vuln?'CRITICAL: arbitrary origin trusted with credentials — session hijack possible':'not exploitable'});
}).catch(function(e){__pzResult('blocked/error: '+e.message);});
return '__async__';
})()