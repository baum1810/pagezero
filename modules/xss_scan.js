(function(){
var params=new URLSearchParams(location.search);
var html=document.documentElement.innerHTML;
var results=[];
params.forEach(function(val,key){
  if(val.length<3)return;
  var esc=val.replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c];});
  var inHtml=html.indexOf(val)!==-1;
  var inEsc=html.indexOf(esc)!==-1;
  if(inHtml&&!inEsc)results.push({param:key,value:val,status:'UNENCODED in DOM — likely XSS',
    payload:'?'+key+'=<img src=x onerror=alert(1)>'});
  else if(inHtml)results.push({param:key,value:val,status:'encoded — reflected but likely safe'});
  else results.push({param:key,value:val,status:'not reflected'});
});
// Check hash
if(location.hash){
  var h=decodeURIComponent(location.hash.slice(1));
  if(html.indexOf(h)!==-1)results.push({param:'#hash',value:h,status:'hash reflected in DOM — test for XSS'});
}
return results.length?results:'no URL params to test';
})()