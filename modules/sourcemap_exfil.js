(function(){
var scripts=Array.from(document.querySelectorAll('script[src]'));
if(!scripts.length)return 'no external scripts';
var maps=[];var left=scripts.length;
scripts.forEach(function(s){
  fetch(s.src,{cache:'no-store'}).then(function(r){return r.text();})
  .then(function(txt){
    var m=txt.match(/\/\/[#@]\s*sourceMappingURL=([^\s\r\n]+)/);
    if(m){
      var mapUrl=m[1].startsWith('data:')?'(inline)':new URL(m[1],s.src).href;
      maps.push({script:s.src,map:mapUrl,inline:m[1].startsWith('data:')});
    }
    if(!--left)__pzResult(maps.length?maps:'no source maps found');
  }).catch(function(){if(!--left)__pzResult(maps.length?maps:'no source maps found');});
});
return '__async__';
})()