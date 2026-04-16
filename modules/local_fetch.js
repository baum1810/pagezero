(function(){
'use strict';
// Param: "192.168.1.1:8080" or "192.168.1.1:8080/path"
var raw = '{{param}}';
if(!raw){ __pzResult({error:'No target specified. Use format: 192.168.1.1:8080 or 192.168.1.1:8080/path'}); return '__async__'; }

var url = /^https?:\/\//.test(raw) ? raw : 'http://' + raw;
var IS_CHROMIUM = !!window.chrome || /Chrome\//.test(navigator.userAgent);

// ── Attempt 1: CORS fetch — full body when server sends Access-Control-Allow-Origin: * ──
function tryCorsFetch(){
  return fetch(url, {mode:'cors', credentials:'omit', cache:'no-store'})
    .then(async function(r){
      var hdrs={};
      r.headers.forEach(function(v,k){hdrs[k]=v;});
      var body='';
      try{body=await r.text();}catch(e){}
      return {status:r.status, status_text:r.statusText, headers:hdrs,
              body:body.slice(0,100000), body_length:body.length, cors_allowed:true};
    });
}

// ── Attempt 2: PerformanceResourceTiming — byte size + TTFB even when CORS blocks body ──
// Browsers expose transferSize / encodedBodySize for cross-origin resources
// even when CORS blocks JS from reading the response body.
function getTimingFor(targetUrl){
  return new Promise(function(resolve){
    performance.clearResourceTimings();
    var ctrl = new AbortController();
    // Fire the request — we don't care if it errors, we want the timing entry
    fetch(targetUrl, {mode:'no-cors', cache:'no-store', signal:ctrl.signal})
      .catch(function(){});
    // Give the browser ~3s then read the timing API
    setTimeout(function(){
      var entries = performance.getEntriesByName(targetUrl);
      if(!entries.length) { resolve(null); return; }
      var e = entries[entries.length-1];
      resolve({
        duration_ms:   Math.round(e.duration),
        ttfb_ms:       e.responseStart > 0 ? Math.round(e.responseStart - e.requestStart) : null,
        transfer_bytes: e.transferSize    || 0,
        body_bytes:     e.encodedBodySize || 0,
        // Infer service type from size + timing
        hint: (function(){
          var sz = e.transferSize || e.encodedBodySize || 0;
          var ttfb = e.responseStart > 0 ? e.responseStart - e.requestStart : null;
          if(sz === 0) return 'Response blocked or empty';
          if(sz < 200)  return 'Very small response (~'+sz+'B) — bare TCP service or empty page';
          if(sz < 2000) return 'Small response (~'+sz+'B) — API endpoint, simple page, or login form';
          if(sz < 20000)return 'Medium response (~'+sz+'B) — typical web page or dashboard';
          return 'Large response (~'+sz+'B) — full app or static file server';
        })()
      });
    }, 3000);
  });
}

// ── Attempt 3: OPTIONS preflight — may leak Server / Allow headers ─────────────
function tryOptions(){
  return fetch(url, {method:'OPTIONS', mode:'cors', credentials:'omit', cache:'no-store'})
    .then(function(r){
      var hdrs={};
      r.headers.forEach(function(v,k){hdrs[k]=v;});
      return {status:r.status, headers:hdrs};
    })
    .catch(function(){return null;});
}

// ── Attempt 4: img probe (Chromium) ──────────────────────────────────────────
function tryImg(){
  return new Promise(function(resolve){
    var img=new Image(), done=false;
    var t=setTimeout(function(){if(!done){done=true;img.src='';resolve(false);}},2000);
    img.onload=img.onerror=function(){if(!done){done=true;clearTimeout(t);resolve(true);}};
    var u=url.replace(/^https?:\/\//,'');
    img.src='http://'+u+(u.indexOf('/')===-1?'/favicon.ico':'')+('?_='+Date.now());
  });
}

(async function(){
  var result = {target:url, engine: IS_CHROMIUM?'chromium':'gecko/webkit', cors_allowed:false};

  // 1. Try full CORS fetch — returns body if server cooperates
  try {
    var cf = await tryCorsFetch();
    result.cors_allowed = true;
    result.status = cf.status;
    result.status_text = cf.status_text;
    result.headers = cf.headers;
    result.body = cf.body;
    result.body_length = cf.body_length;
    __pzResult(result);
    return;
  } catch(e) {
    result.cors_error = e.message;
  }

  // 2. CORS blocked — run timing probe + OPTIONS in parallel
  var [timing, opts, up] = await Promise.all([
    getTimingFor(url),
    tryOptions(),
    IS_CHROMIUM ? tryImg() : fetch(url,{mode:'no-cors',cache:'no-store'}).then(function(){return true;}).catch(function(e){return e.name!=='AbortError';})
  ]);

  result.up = up;
  if(timing) result.timing = timing;
  if(opts)   result.options_headers = opts.headers;

  __pzResult(result);
})();
})();
return '__async__';
