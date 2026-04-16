(function(){
'use strict';
// Enhanced param format:
//   ""                                → auto-detect subnet, probe port 80
//   "192.168.1"                       → /24 subnet, port 80
//   "192.168.1.0/24"                  → CIDR notation
//   "192.168.1.1-50"                  → range in last octet
//   "192.168.1.1,192.168.1.5"         → individual IPs
//   "192.168.1.0/24 80,443,8080-8090" → with port ranges
var raw = '{{param}}';
var TIMEOUT_MS = 1500;
var MAX_IPS    = 1024;
var MIN_RTT_MS = 80;

// Well-known service names
var SERVICES = {
  20:'FTP-Data',21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',67:'DHCP',
  69:'TFTP',80:'HTTP',110:'POP3',111:'RPCbind',123:'NTP',135:'MSRPC',
  137:'NetBIOS-NS',139:'NetBIOS',143:'IMAP',161:'SNMP',389:'LDAP',443:'HTTPS',
  445:'SMB',465:'SMTPS',500:'ISAKMP',514:'Syslog',515:'LPD',548:'AFP',
  554:'RTSP',587:'Submission',631:'IPP/CUPS',636:'LDAPS',873:'rsync',
  993:'IMAPS',995:'POP3S',1080:'SOCKS',1194:'OpenVPN',1433:'MSSQL',
  1521:'Oracle',1723:'PPTP',1883:'MQTT',2049:'NFS',2181:'ZooKeeper',
  3000:'Grafana',3306:'MySQL',3389:'RDP',4443:'HTTPS-Alt',5060:'SIP',
  5432:'PostgreSQL',5672:'AMQP',5900:'VNC',5984:'CouchDB',6379:'Redis',
  6443:'K8s-API',6881:'BitTorrent',8006:'Proxmox',8080:'HTTP-Alt',
  8443:'HTTPS-Alt',8834:'Nessus',8888:'HTTP-Alt',9090:'Prometheus',
  9200:'Elasticsearch',9443:'VSphere',10000:'Webmin',11211:'Memcached',
  27017:'MongoDB',50000:'SAP'
};

// HTTP ports worth fingerprinting (attempt CORS fetch for body/headers)
var HTTP_PORTS={80:1,443:1,3000:1,4443:1,5984:1,8000:1,8006:1,8080:1,8443:1,
                8834:1,8888:1,9090:1,9200:1,9443:1,10000:1};

// Common device/server fingerprint patterns
var FINGERPRINTS=[
  {re:/fritz[.\s]?box/i, type:'Router', vendor:'AVM'},
  {re:/mikrotik|routeros/i, type:'Router', vendor:'MikroTik'},
  {re:/ubiquiti|unifi|ubnt/i, type:'Network', vendor:'Ubiquiti'},
  {re:/openwrt/i, type:'Router', vendor:'OpenWrt'},
  {re:/dd-?wrt/i, type:'Router', vendor:'DD-WRT'},
  {re:/pfsense/i, type:'Firewall', vendor:'pfSense'},
  {re:/opnsense/i, type:'Firewall', vendor:'OPNsense'},
  {re:/tp-?link/i, type:'Router', vendor:'TP-Link'},
  {re:/netgear/i, type:'Router', vendor:'Netgear'},
  {re:/asus rt-|asus router/i, type:'Router', vendor:'ASUS'},
  {re:/linksys/i, type:'Router', vendor:'Linksys'},
  {re:/synology/i, type:'NAS', vendor:'Synology'},
  {re:/qnap/i, type:'NAS', vendor:'QNAP'},
  {re:/truenas|freenas/i, type:'NAS', vendor:'TrueNAS'},
  {re:/proxmox/i, type:'Hypervisor', vendor:'Proxmox'},
  {re:/esxi|vmware|vsphere/i, type:'Hypervisor', vendor:'VMware'},
  {re:/grafana/i, type:'Monitoring', vendor:'Grafana'},
  {re:/prometheus/i, type:'Monitoring', vendor:'Prometheus'},
  {re:/pihole|pi-hole/i, type:'DNS/AdBlock', vendor:'Pi-hole'},
  {re:/adguard/i, type:'DNS/AdBlock', vendor:'AdGuard'},
  {re:/home\s?assistant|hass/i, type:'IoT Hub', vendor:'Home Assistant'},
  {re:/jellyfin/i, type:'Media Server', vendor:'Jellyfin'},
  {re:/plex/i, type:'Media Server', vendor:'Plex'},
  {re:/emby/i, type:'Media Server', vendor:'Emby'},
  {re:/nextcloud/i, type:'Cloud', vendor:'Nextcloud'},
  {re:/owncloud/i, type:'Cloud', vendor:'ownCloud'},
  {re:/portainer/i, type:'Container Mgmt', vendor:'Portainer'},
  {re:/traefik/i, type:'Reverse Proxy', vendor:'Traefik'},
  {re:/nginx/i, type:'Web Server', vendor:'nginx'},
  {re:/apache/i, type:'Web Server', vendor:'Apache'},
  {re:/iis|microsoft-iis/i, type:'Web Server', vendor:'Microsoft IIS'},
  {re:/lighttpd/i, type:'Web Server', vendor:'lighttpd'},
  {re:/caddy/i, type:'Web Server', vendor:'Caddy'},
  {re:/cups/i, type:'Printer', vendor:'CUPS'},
  {re:/hp\s*(laser|office|desk|photo|envy|smart)/i, type:'Printer', vendor:'HP'},
  {re:/canon/i, type:'Printer', vendor:'Canon'},
  {re:/epson/i, type:'Printer', vendor:'Epson'},
  {re:/brother/i, type:'Printer', vendor:'Brother'},
  {re:/hikvision/i, type:'Camera', vendor:'Hikvision'},
  {re:/dahua/i, type:'Camera', vendor:'Dahua'},
  {re:/reolink/i, type:'Camera', vendor:'Reolink'},
  {re:/unraid/i, type:'NAS', vendor:'Unraid'},
  {re:/elasticsearch/i, type:'Database', vendor:'Elasticsearch'},
  {re:/kibana/i, type:'Monitoring', vendor:'Kibana'},
  {re:/jenkins/i, type:'CI/CD', vendor:'Jenkins'},
  {re:/gitlab/i, type:'DevOps', vendor:'GitLab'},
  {re:/sonarr|radarr|lidarr/i, type:'Media Mgmt', vendor:'*arr'},
  {re:/cockpit/i, type:'Server Mgmt', vendor:'Cockpit'},
  {re:/webmin/i, type:'Server Mgmt', vendor:'Webmin'},
];

function fingerprint(body,headers,url){
  var info={};
  var combined=(body||'')+(JSON.stringify(headers||{}));

  // Extract HTML title
  var tm=(body||'').match(/<title[^>]*>([^<]{1,200})<\/title>/i);
  if(tm) info.title=tm[1].trim();

  // Server header
  if(headers){
    if(headers.server||headers.Server) info.server=headers.server||headers.Server;
    if(headers['x-powered-by']||headers['X-Powered-By']) info.powered_by=headers['x-powered-by']||headers['X-Powered-By'];
  }

  // Match known device/service patterns
  for(var i=0;i<FINGERPRINTS.length;i++){
    if(FINGERPRINTS[i].re.test(combined)){
      info.device_type=FINGERPRINTS[i].type;
      info.vendor=FINGERPRINTS[i].vendor;
      break;
    }
  }

  // Infer from server header if no match yet
  if(!info.device_type && info.server){
    for(var i=0;i<FINGERPRINTS.length;i++){
      if(FINGERPRINTS[i].re.test(info.server)){
        info.device_type=FINGERPRINTS[i].type;
        info.vendor=FINGERPRINTS[i].vendor;
        break;
      }
    }
  }

  // Extract favicon URL hint
  var fav=(body||'').match(/<link[^>]+rel=["'](?:shortcut )?icon["'][^>]+href=["']([^"']+)["']/i);
  if(fav) info.favicon=fav[1];

  // Check for login forms
  if(/<input[^>]+type=["']password["']/i.test(body||''))
    info.has_login=true;

  return info;
}

// ── Parse helpers ───────────────────────────────────────────────────────────
function parsePorts(s){
  var ports=[];
  s.split(',').forEach(function(tok){
    tok=tok.trim();
    var m=tok.match(/^(\d+)-(\d+)$/);
    if(m){
      var lo=parseInt(m[1]),hi=parseInt(m[2]);
      for(var i=lo;i<=hi&&i<65536;i++) if(i>0) ports.push(i);
    }else{
      var n=parseInt(tok);
      if(n>0&&n<65536) ports.push(n);
    }
  });
  return ports;
}

function parseIPs(s){
  var ips=[];
  var cidr=s.match(/^(\d+\.\d+\.\d+)\.(\d+)\/(\d+)$/);
  if(cidr){
    var base=cidr[1],count=Math.min(Math.pow(2,32-parseInt(cidr[3]))-2,MAX_IPS);
    for(var i=1;i<=count&&i<=254;i++) ips.push(base+'.'+i);
    return ips;
  }
  var range=s.match(/^(\d+\.\d+\.\d+)\.(\d+)-(\d+)$/);
  if(range){
    for(var i=parseInt(range[2]);i<=parseInt(range[3])&&i<=254;i++) ips.push(range[1]+'.'+i);
    return ips;
  }
  if(/^\d+\.\d+\.\d+$/.test(s)){
    for(var i=1;i<=254;i++) ips.push(s+'.'+i);
    return ips;
  }
  if(/^\d+\.\d+\.\d+\.\d+$/.test(s)) return [s];
  return ips;
}

var targetIPs=[],paramPorts=[];
if(raw){
  raw.split(/\s+/).forEach(function(p){
    if(/^\d+([,\-]\d+)*$/.test(p)&&p.indexOf('.')===-1){
      paramPorts=parsePorts(p);
    }else{
      p.split(',').forEach(function(spec){
        spec=spec.trim();
        if(spec) parseIPs(spec).forEach(function(ip){targetIPs.push(ip);});
      });
    }
  });
}
var PORTS=paramPorts.length?paramPorts:[80];
var IS_SECURE=location.protocol==='https:';

// ── WebRTC local IP detection ───────────────────────────────────────────────
function getLocalIP(){
  return new Promise(function(resolve){
    try{
      var pc=new RTCPeerConnection({iceServers:[]});
      pc.createDataChannel('');
      var found=false;
      pc.onicecandidate=function(e){
        if(!e||!e.candidate)return;
        var m=e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
        if(m&&!m[1].startsWith('169.254')&&!found){found=true;pc.close();resolve(m[1]);}
      };
      pc.createOffer().then(function(o){return pc.setLocalDescription(o);}).catch(function(){});
      setTimeout(function(){if(!found){pc.close();resolve(null);}},2500);
    }catch(e){resolve(null);}
  });
}

// ── Engine detection ────────────────────────────────────────────────────────
var IS_CHROMIUM=!!window.chrome||/Chrome\//.test(navigator.userAgent);
var BATCH=IS_CHROMIUM?20:6;

// ── Phase 1: Fast TCP probing ───────────────────────────────────────────────
function probeImg(ip,port){
  return new Promise(function(resolve){
    var img=new Image(),done=false,t0=performance.now();
    var t=setTimeout(function(){if(!done){done=true;img.src='';resolve({ip:ip,port:port,up:false});}},TIMEOUT_MS);
    img.onload=function(){if(!done){done=true;clearTimeout(t);resolve({ip:ip,port:port,up:true});}};
    img.onerror=function(){
      if(!done){done=true;clearTimeout(t);resolve({ip:ip,port:port,up:(performance.now()-t0)>=MIN_RTT_MS});}
    };
    var scheme=IS_SECURE?'https://':'http://';
    var portStr=(port===80&&!IS_SECURE)?'':((port===443&&IS_SECURE)?'':':'+port);
    img.src=scheme+ip+portStr+'/favicon.ico?_='+Date.now();
  });
}

function probeFetch(ip,port){
  return new Promise(function(resolve){
    var ctrl=new AbortController();
    var t=setTimeout(function(){ctrl.abort();resolve({ip:ip,port:port,up:false});},TIMEOUT_MS);
    var scheme=IS_SECURE?'https://':'http://';
    var portStr=(port===80&&!IS_SECURE)?'':((port===443&&IS_SECURE)?'':':'+port);
    fetch(scheme+ip+portStr+'/',{mode:'no-cors',cache:'no-store',signal:ctrl.signal})
      .then(function(){clearTimeout(t);resolve({ip:ip,port:port,up:true});})
      .catch(function(){clearTimeout(t);resolve({ip:ip,port:port,up:false});});
  });
}

function probe(ip,port){return IS_CHROMIUM?probeImg(ip,port):probeFetch(ip,port);}

async function scanIPs(ips){
  var pairs=[];
  for(var i=0;i<ips.length;i++)
    for(var j=0;j<PORTS.length;j++) pairs.push({ip:ips[i],port:PORTS[j]});
  var byIP={};
  for(var i=0;i<pairs.length;i+=BATCH){
    var batch=pairs.slice(i,i+BATCH);
    var results=await Promise.all(batch.map(function(p){return probe(p.ip,p.port);}));
    results.forEach(function(r){
      if(r.up){if(!byIP[r.ip])byIP[r.ip]=[];byIP[r.ip].push(r.port);}
    });
  }
  return byIP;
}

// ── Phase 2: Fingerprint each discovered host ───────────────────────────────
// For each host:port that looks like HTTP, do a CORS fetch + timing probe
// to grab headers, body (if CORS allows), title, server banner, etc.
// When CORS blocks body reading, we use every no-CORS trick the browser allows:
// <img> for favicon/image detection, <link> for CSS, PerformanceResourceTiming
// for response sizes/timing, error-based script fingerprinting, and redirect detection.

// ── CORS Bypass Probe Suite ──────────────────────────────────────────────────
// When CORS blocks body reading, these probes extract maximum intel.
//
// Key constraint: Firefox blocks cross-origin <img>, <link>, <script> via
// OpaqueResponseBlocking (ORB) when MIME type doesn't match expectations.
// Firefox also doesn't expose transferSize without Timing-Allow-Origin.
//
// Strategy: Use PerformanceResourceTiming `duration` to distinguish real
// pages from 404s. Real resources and 404 error pages have different sizes,
// which means different transfer times. We measure a 404 baseline duration,
// then compare each probe's duration against it.

// Probe favicon — use no-cors fetch + performance timing (NOT <img> which ORB blocks)
function probeFavicon(baseUrl){
  var paths=['/favicon.ico','/favicon.png','/apple-touch-icon.png','/apple-touch-icon-precomposed.png'];
  // We'll check these during the main path probe — just return empty here
  // Favicon detection is folded into probeResources for efficiency
  return Promise.resolve([]);
}

// Path probing using PerformanceResourceTiming.
// Approach:
// 1. Fetch a random 404 path, record its duration + transferSize
// 2. Fetch all probe paths, record their duration + transferSize
// 3. Compare: if transferSize differs (Chromium) OR duration differs significantly
//    (Firefox fallback), the path likely returns different content than 404
function probeResources(baseUrl){
  var probes=[
    // Favicons (folded in here)
    {path:'/favicon.ico',hint:'Has favicon',cat:'favicon'},
    {path:'/favicon.png',hint:'Has favicon (PNG)',cat:'favicon'},
    {path:'/apple-touch-icon.png',hint:'Has Apple touch icon',cat:'favicon'},
    // Standard web files
    {path:'/robots.txt',hint:'Has robots.txt'},{path:'/sitemap.xml',hint:'Has sitemap'},
    {path:'/.well-known/security.txt',hint:'Has security.txt'},
    {path:'/manifest.json',hint:'PWA manifest'},
    // CMS detection
    {path:'/wp-login.php',hint:'WordPress'},{path:'/wp-includes/js/jquery/jquery.min.js',hint:'WordPress (jQuery)'},
    {path:'/wp-json/wp/v2/posts',hint:'WordPress REST API'},{path:'/wp-content/',hint:'WordPress content'},
    {path:'/wp-admin/',hint:'WordPress admin'},{path:'/xmlrpc.php',hint:'WordPress XML-RPC'},
    {path:'/administrator/',hint:'Joomla'},{path:'/misc/drupal.js',hint:'Drupal'},
    {path:'/user/login',hint:'Drupal login'},{path:'/core/misc/drupal.js',hint:'Drupal 8+'},
    {path:'/typo3/',hint:'TYPO3 CMS'},{path:'/ghost/',hint:'Ghost CMS'},
    // API endpoints
    {path:'/api/',hint:'API endpoint'},{path:'/api/v1/',hint:'REST API v1'},
    {path:'/graphql',hint:'GraphQL API'},
    {path:'/swagger-ui/',hint:'Swagger/OpenAPI docs'},
    {path:'/health',hint:'Health endpoint'},{path:'/metrics',hint:'Metrics (Prometheus)'},
    // Sensitive files
    {path:'/.env',hint:'⚠ .env exposed!'},{path:'/.git/HEAD',hint:'⚠ .git exposed!'},
    {path:'/.svn/entries',hint:'⚠ .svn exposed!'},
    {path:'/composer.json',hint:'PHP composer exposed'},{path:'/package.json',hint:'Node package.json'},
    {path:'/dump.sql',hint:'⚠ SQL dump exposed!'},
    // Server management
    {path:'/server-status',hint:'Apache mod_status'},{path:'/nginx_status',hint:'nginx stub_status'},
    {path:'/phpmyadmin/',hint:'phpMyAdmin'},{path:'/adminer.php',hint:'Adminer DB tool'},
    {path:'/login',hint:'Login page'},{path:'/admin',hint:'Admin panel'},
    {path:'/dashboard',hint:'Dashboard'},
    {path:'/console',hint:'Console endpoint'},{path:'/manager/html',hint:'Tomcat Manager'},
    // DevOps/CI
    {path:'/jenkins/',hint:'Jenkins CI'},{path:'/gitlab/',hint:'GitLab'},
    {path:'/portainer/',hint:'Portainer'},{path:'/grafana/',hint:'Grafana'},
    {path:'/kibana/',hint:'Kibana'},{path:'/prometheus/',hint:'Prometheus'},
    // VPN/Security appliances
    {path:'/remote/login',hint:'FortiGate VPN'},
    {path:'/global-protect/',hint:'Palo Alto GlobalProtect'},
    {path:'/+CSCOE+/logon.html',hint:'Cisco AnyConnect'},
    // Cloud/Auth
    {path:'/.well-known/openid-configuration',hint:'OpenID Connect'},
    {path:'/realms/',hint:'Keycloak'},
    // IoT/Embedded
    {path:'/cgi-bin/luci',hint:'OpenWrt LuCI'},{path:'/HNAP1/',hint:'D-Link HNAP'},
    {path:'/setup.cgi',hint:'Device setup CGI'},
    // Infrastructure
    {path:'/v1/sys/health',hint:'HashiCorp Vault'},
    {path:'/actuator',hint:'Spring Boot Actuator'},
    {path:'/actuator/env',hint:'⚠ Spring env exposed!'},
    {path:'/phpinfo.php',hint:'⚠ phpinfo() exposed!'},
  ];

  return new Promise(function(resolve){
    // Step 1: Fire 3 different 404 baseline requests to get stable baseline
    var nonces=[];
    for(var b=0;b<3;b++) nonces.push('_pz404'+b+'_'+Date.now()+'_'+Math.random().toString(36).slice(2,6));

    performance.clearResourceTimings();
    nonces.forEach(function(n){fetch(baseUrl+'/'+n,{mode:'no-cors',cache:'no-store'}).catch(function(){});});

    setTimeout(function(){
      var entries=performance.getEntriesByType('resource');
      var baselines=[];
      nonces.forEach(function(n){
        for(var i=entries.length-1;i>=0;i--){
          if(entries[i].name.indexOf(n)!==-1){
            baselines.push({
              size:entries[i].transferSize||entries[i].encodedBodySize||0,
              duration:Math.round(entries[i].duration)
            });
            break;
          }
        }
      });

      var hasSizes=baselines.some(function(b){return b.size>0;});
      // Average baseline values
      var baseSize=0,baseDuration=0;
      if(baselines.length){
        baselines.forEach(function(b){baseSize+=b.size;baseDuration+=b.duration;});
        baseSize=Math.round(baseSize/baselines.length);
        baseDuration=Math.round(baseDuration/baselines.length);
      }

      // Step 2: Fire all probe paths with unique query params
      var probeData=probes.map(function(p,idx){
        return {probe:p,qp:'_pzq'+idx+'r'+Math.random().toString(36).slice(2,5)};
      });

      performance.clearResourceTimings();
      // Batch to avoid overload
      var PBATCH=15,bi=0;
      function fireBatch(){
        var batch=probeData.slice(bi,bi+PBATCH);
        batch.forEach(function(pd){
          var sep=pd.probe.path.indexOf('?')!==-1?'&':'?';
          fetch(baseUrl+pd.probe.path+sep+pd.qp+'=1',{mode:'no-cors',cache:'no-store'}).catch(function(){});
        });
        bi+=PBATCH;
        if(bi<probeData.length) setTimeout(fireBatch,150);
        else setTimeout(analyzeResults,2000);
      }

      function analyzeResults(){
        var allE=performance.getEntriesByType('resource');
        var found=[];
        var favicons=[];

        probeData.forEach(function(pd){
          for(var i=allE.length-1;i>=0;i--){
            if(allE[i].name.indexOf(pd.qp)!==-1){
              var sz=allE[i].transferSize||allE[i].encodedBodySize||0;
              var dur=Math.round(allE[i].duration);
              var isDifferent=false;

              if(hasSizes&&baseSize>0){
                // Chromium: use size comparison (most reliable)
                isDifferent=sz>0&&Math.abs(sz-baseSize)>50;
              }else{
                // Firefox fallback: use duration comparison
                // A different page (especially larger) takes measurably longer
                // Threshold: >30% duration difference from baseline, and at least 20ms
                if(baseDuration>0&&dur>0){
                  var durDiff=Math.abs(dur-baseDuration);
                  var durRatio=durDiff/baseDuration;
                  isDifferent=durDiff>20&&durRatio>0.3;
                }
              }

              if(isDifferent){
                var entry={path:pd.probe.path,hint:pd.probe.hint,size:sz,duration:dur};
                if(pd.probe.cat==='favicon') favicons.push(entry);
                else found.push(entry);
              }
              break;
            }
          }
        });

        resolve({found:found,favicons:favicons,baseline_404_size:baseSize,baseline_404_duration:baseDuration,has_sizes:hasSizes});
      }

      fireBatch();
    },1500);
  });
}

// WebSocket probe — connection behavior reveals service type
function probeWebSocket(ip,port){
  return new Promise(function(resolve){
    var scheme=port===443||port===8443?'wss://':'ws://';
    var wsUrl=scheme+ip+':'+port+'/';
    var done=false,t0=performance.now();
    var t=setTimeout(function(){if(!done){done=true;try{ws.close();}catch(e){}resolve({timeout:true,time_ms:Math.round(performance.now()-t0)});}},3000);
    var ws;
    try{ws=new WebSocket(wsUrl);}catch(e){clearTimeout(t);resolve({error:e.message});return;}
    ws.onopen=function(){if(!done){done=true;clearTimeout(t);
      var info={accepts_ws:true,time_ms:Math.round(performance.now()-t0)};
      var msgTimer=setTimeout(function(){ws.close();resolve(info);},1000);
      ws.onmessage=function(e){clearTimeout(msgTimer);info.first_msg=typeof e.data==='string'?e.data.slice(0,200):'[binary]';ws.close();resolve(info);};
    }};
    ws.onerror=function(){};
    ws.onclose=function(e){if(!done){done=true;clearTimeout(t);
      resolve({accepts_ws:false,close_code:e.code,close_reason:e.reason||'',time_ms:Math.round(performance.now()-t0)});
    }};
  });
}

// Error page fingerprinting — already handled by probeResources baseline
function probeErrorPage(baseUrl){
  // Folded into probeResources — just resolve null
  return Promise.resolve(null);
}

// HTTP method probing — detect API endpoints by trying POST, PUT, DELETE
function probeHTTPMethods(baseUrl){
  var methods=['POST','PUT','DELETE','PATCH','HEAD'];
  return Promise.all(methods.map(function(m){
    return fetch(baseUrl+'/',{method:m,mode:'no-cors',cache:'no-store'})
      .then(function(){return {method:m,accepted:true};})
      .catch(function(){return {method:m,accepted:false};});
  })).then(function(results){
    return results.filter(function(r){return r.accepted;});
  });
}

// CORS fetch with credentials — some misconfigured servers respond to credentialed requests
function tryCorsWithCredentials(url){
  return fetch(url,{mode:'cors',credentials:'include',cache:'no-store'})
    .then(function(r){
      var hdrs={};r.headers.forEach(function(v,k){hdrs[k]=v;});
      return {status:r.status,headers:hdrs,ok:true};
    })
    .catch(function(){return null;});
}

function fetchInfo(ip,port){
  var scheme=(port===443||port===8443||port===4443||port===9443)?'https://':'http://';
  if(IS_SECURE) scheme='https://';
  var portStr=':'+port;
  var url=scheme+ip+portStr+'/';
  var baseUrl=scheme+ip+portStr;

  return new Promise(function(resolve){
    var info={ip:ip,port:port,url:url,reachable:false};
    var timer=setTimeout(function(){resolve(info);},20000);

    // Try CORS fetch first (gets full body+headers if server cooperates)
    fetch(url,{mode:'cors',credentials:'omit',cache:'no-store'})
      .then(async function(r){
        clearTimeout(timer);
        var hdrs={};r.headers.forEach(function(v,k){hdrs[k]=v;});
        var body='';try{body=await r.text();}catch(e){}
        info.status=r.status;info.status_text=r.statusText;
        info.headers=hdrs;info.body_preview=body.slice(0,5000);info.body_length=body.length;
        info.cors=true;info.reachable=true;
        var fp=fingerprint(body,hdrs,url);
        Object.keys(fp).forEach(function(k){info[k]=fp[k];});
        resolve(info);
      })
      .catch(function(){
        // Try CORS with credentials as second attempt (some misconfigured servers)
        tryCorsWithCredentials(url).then(function(credResult){
          if(credResult&&credResult.ok&&credResult.headers){
            info.cors_cred=true;info.reachable=true;
            info.status=credResult.status;info.headers=credResult.headers;
            var fp=fingerprint('',credResult.headers,url);
            Object.keys(fp).forEach(function(k){info[k]=fp[k];});
          }

          // ── CORS blocked — run full bypass probe suite ──
          info.cors=false;info.cors_blocked=true;

          Promise.all([
            // 1. no-cors reachability
            fetch(url,{mode:'no-cors',cache:'no-store'}).then(function(){return true;}).catch(function(){return false;}),
            // 2. Timing/size via PerformanceResourceTiming
            getTimingInfo(url),
            // 3. OPTIONS preflight — may leak Server, Allow headers
            tryOptionsHeaders(url),
            // 4. Path + favicon probing with 404 baseline comparison
            probeResources(baseUrl),
            // 5. WebSocket probe — connection behavior reveals service type
            probeWebSocket(ip,port),
            // 6. HTTP method probing — detect API endpoints
            probeHTTPMethods(baseUrl)
          ]).then(function(results){
            clearTimeout(timer);
            var reachable=results[0],timing=results[1],opts=results[2];
            var resourceResult=results[3],wsProbe=results[4],httpMethods=results[5];

            // Extract path probe results
            var resources=(resourceResult&&resourceResult.found)||[];
            var probedFavicons=(resourceResult&&resourceResult.favicons)||[];
            info.probe_method=resourceResult&&resourceResult.has_sizes?'size':'duration';
            if(resourceResult) info.baseline_404_size=resourceResult.baseline_404_size||0;

            info.reachable=reachable;

            // Timing data
            if(timing){
              info.timing=timing;
              info.body_length=timing.body_bytes||timing.transfer_bytes||0;
            }

            // OPTIONS headers
            if(opts&&opts.headers){
              info.options_status=opts.status;
              info.headers=opts.headers;
              var fp=fingerprint('',opts.headers,url);
              Object.keys(fp).forEach(function(k){info[k]=fp[k];});
            }

            // Favicon results from path probing (detected via size/duration diff)
            if(probedFavicons.length){
              info.favicons=probedFavicons.map(function(f){return {path:f.path,exists:true};});
              info.has_favicon=true;
            }

            // Resource/path probing results
            if(resources.length){
              info.detected_paths=resources.map(function(r){return {path:r.path,hint:r.hint};});
              var pathHints=resources.map(function(r){return r.hint;}).join(' ');
              if(!info.device_type){
                if(/WordPress/i.test(pathHints)){info.device_type='CMS';info.vendor='WordPress';}
                else if(/Joomla/i.test(pathHints)){info.device_type='CMS';info.vendor='Joomla';}
                else if(/Drupal/i.test(pathHints)){info.device_type='CMS';info.vendor='Drupal';}
                else if(/TYPO3/i.test(pathHints)){info.device_type='CMS';info.vendor='TYPO3';}
                else if(/Ghost/i.test(pathHints)){info.device_type='CMS';info.vendor='Ghost';}
                else if(/phpMyAdmin|Adminer/i.test(pathHints)){info.device_type='Database Mgmt';info.vendor='phpMyAdmin';}
                else if(/GraphQL/i.test(pathHints)){info.device_type='API Server';info.vendor='GraphQL';}
                else if(/Swagger|OpenAPI|api-doc/i.test(pathHints)){info.device_type='API Server';info.vendor='OpenAPI';}
                else if(/Spring|Actuator/i.test(pathHints)){info.device_type='Java App';info.vendor='Spring Boot';}
                else if(/Jenkins/i.test(pathHints)){info.device_type='CI/CD';info.vendor='Jenkins';}
                else if(/GitLab/i.test(pathHints)){info.device_type='DevOps';info.vendor='GitLab';}
                else if(/Portainer/i.test(pathHints)){info.device_type='Container Mgmt';info.vendor='Portainer';}
                else if(/Grafana/i.test(pathHints)){info.device_type='Monitoring';info.vendor='Grafana';}
                else if(/Kibana/i.test(pathHints)){info.device_type='Monitoring';info.vendor='Kibana';}
                else if(/Prometheus/i.test(pathHints)){info.device_type='Monitoring';info.vendor='Prometheus';}
                else if(/Vault/i.test(pathHints)){info.device_type='Secret Mgmt';info.vendor='HashiCorp Vault';}
                else if(/FortiGate|Pulse|GlobalProtect|AnyConnect|VPN/i.test(pathHints)){info.device_type='VPN Gateway';info.vendor='VPN';}
                else if(/Tomcat|Manager/i.test(pathHints)){info.device_type='App Server';info.vendor='Apache Tomcat';}
                else if(/Keycloak|OpenID/i.test(pathHints)){info.device_type='Auth Server';info.vendor='Identity Provider';}
                else if(/OpenWrt|LuCI/i.test(pathHints)){info.device_type='Router';info.vendor='OpenWrt';}
                else if(/D-Link|HNAP/i.test(pathHints)){info.device_type='Router';info.vendor='D-Link';}
                else if(/Apache.*status|mod_info/i.test(pathHints)){info.device_type='Web Server';info.vendor='Apache';}
                else if(/nginx/i.test(pathHints)){info.device_type='Web Server';info.vendor='nginx';}
              }
              // Security flags
              if(resources.some(function(r){return r.path==='/.env';})) info.exposure_env=true;
              if(resources.some(function(r){return r.path==='/.git/HEAD';})) info.exposure_git=true;
              if(resources.some(function(r){return r.path==='/.svn/entries';})) info.exposure_svn=true;
              if(resources.some(function(r){return /phpinfo|dump\.sql|actuator\/env/.test(r.path);})) info.exposure_sensitive=true;
              if(resources.some(function(r){return /login|auth|sign.?in/i.test(r.path);})) info.has_login=true;
            }

            // WebSocket probe results
            if(wsProbe){
              info.websocket=wsProbe;
              if(wsProbe.accepts_ws&&!info.device_type){
                info.device_type='WebSocket Server';
              }
            }

            // HTTP method support
            if(httpMethods&&httpMethods.length){
              info.http_methods=httpMethods.map(function(m){return m.method;});
              if(!info.device_type&&httpMethods.length>=3){
                info.device_type='API Server';
              }
            }

            resolve(info);
          }).catch(function(){clearTimeout(timer);resolve(info);});
        });
      });
  });
}

function getTimingInfo(targetUrl){
  return new Promise(function(resolve){
    performance.clearResourceTimings();
    fetch(targetUrl+'?_tm='+Date.now(),{mode:'no-cors',cache:'no-store'}).catch(function(){});
    setTimeout(function(){
      var entries=performance.getEntriesByType('resource').filter(function(e){return e.name.indexOf(targetUrl)===0;});
      if(!entries.length){resolve(null);return;}
      var e=entries[entries.length-1];
      resolve({
        duration_ms:Math.round(e.duration),
        ttfb_ms:e.responseStart>0?Math.round(e.responseStart-e.requestStart):null,
        transfer_bytes:e.transferSize||0,
        body_bytes:e.encodedBodySize||0,
        decoded_bytes:e.decodedBodySize||0
      });
    },3000);
  });
}

function tryOptionsHeaders(url){
  return fetch(url,{method:'OPTIONS',mode:'cors',credentials:'omit',cache:'no-store'})
    .then(function(r){
      var hdrs={};r.headers.forEach(function(v,k){hdrs[k]=v;});
      return {status:r.status,headers:hdrs};
    })
    .catch(function(){return null;});
}

// ── Main ────────────────────────────────────────────────────────────────────
(async function(){
  var localIP=await getLocalIP();

  // Build target IP list
  var ips=targetIPs;
  if(!ips.length){
    if(localIP){
      var p=localIP.split('.');
      for(var i=1;i<=254;i++) ips.push(p[0]+'.'+p[1]+'.'+p[2]+'.'+i);
    }
    if(!ips.length){
      for(var i=1;i<=254;i++) ips.push('192.168.1.'+i);
      for(var i=1;i<=254;i++) ips.push('192.168.0.'+i);
    }
  }
  if(ips.length>MAX_IPS) ips=ips.slice(0,MAX_IPS);

  // ── Phase 1: Fast host discovery ──────────────────────────────────────────
  var byIP=await scanIPs(ips);
  var aliveIPs=Object.keys(byIP);

  // Build hosts array with port/service info
  var hosts=aliveIPs.map(function(ip){
    var portList=byIP[ip];
    var services={};
    portList.forEach(function(p){if(SERVICES[p])services[String(p)]=SERVICES[p];});
    return {ip:ip,ports:portList,services:services};
  });

  // ── Phase 2: Fingerprint each alive host on HTTP-like ports ───────────────
  // Run fingerprinting in small batches (3 at a time to avoid overload)
  var FP_BATCH=3;
  var fpTargets=[];
  hosts.forEach(function(h){
    h.ports.forEach(function(p){
      if(HTTP_PORTS[p]||p===8000||p===3000||p===5000||p===8888) fpTargets.push({ip:h.ip,port:p});
    });
    // Also try common HTTP ports even if not in the scan list
    [80,443,8080].forEach(function(p){
      if(h.ports.indexOf(p)===-1) return; // only if port was found open
      var already=fpTargets.some(function(t){return t.ip===h.ip&&t.port===p;});
      if(!already) fpTargets.push({ip:h.ip,port:p});
    });
  });

  var fpResults={};// ip:port -> info
  for(var i=0;i<fpTargets.length;i+=FP_BATCH){
    var batch=fpTargets.slice(i,i+FP_BATCH);
    var infos=await Promise.all(batch.map(function(t){return fetchInfo(t.ip,t.port);}));
    infos.forEach(function(info){
      fpResults[info.ip+':'+info.port]=info;
    });
  }

  // Merge fingerprint data into hosts
  hosts.forEach(function(h){
    h.fingerprints={};
    var anyReachable=false;
    var anyCors=false;
    var allBlocked=true;

    h.ports.forEach(function(p){
      var key=h.ip+':'+p;
      if(fpResults[key]){
        var fp=fpResults[key];
        h.fingerprints[String(p)]=fp;
        if(fp.reachable) anyReachable=true;
        if(fp.cors) anyCors=true;
        if(fp.cors||fp.reachable) allBlocked=false;
      }
    });

    // Set host-level CORS status
    h.cors_blocked=!anyCors&&allBlocked;
    h.reachable=anyReachable||anyCors;

    // Set top-level device info from best fingerprint match
    var bestFP=null;
    Object.values(h.fingerprints).forEach(function(fp){
      if(fp.device_type&&(!bestFP||fp.cors)) bestFP=fp;
    });
    if(!bestFP){
      Object.values(h.fingerprints).forEach(function(fp){
        if(fp.title&&!bestFP) bestFP=fp;
      });
    }
    if(bestFP){
      if(bestFP.device_type) h.device_type=bestFP.device_type;
      if(bestFP.vendor) h.vendor=bestFP.vendor;
      if(bestFP.title) h.title=bestFP.title;
      if(bestFP.server) h.server=bestFP.server;
      if(bestFP.has_login) h.has_login=true;
    }
  });

  // Phase 2 reachability validation — drop hosts where EVERY fingerprint
  // probe returned unreachable (no-cors fetch failed = truly down, not just CORS blocked).
  // Hosts with non-HTTP-only ports OR any reachable probe are kept.
  hosts=hosts.filter(function(h){
    // Keep if any fingerprint probe confirmed reachability
    if(h.reachable) return true;
    // Keep if host has non-HTTP ports (SSH, RDP, etc. — can't be fingerprinted)
    if(h.ports.some(function(p){return !HTTP_PORTS[p];})) return true;
    // Keep if no fingerprinting was attempted (no HTTP ports found)
    if(Object.keys(h.fingerprints).length===0) return true;
    // Drop — all probes returned unreachable (Phase 1 false positive)
    return false;
  });

  // Group by subnet for report
  var bySubnet={};
  hosts.forEach(function(h){
    var p=h.ip.split('.');
    var sn=p[0]+'.'+p[1]+'.'+p[2]+'.0/24';
    if(!bySubnet[sn])bySubnet[sn]=[];
    bySubnet[sn].push(h);
  });

  var report={
    local_ip:localIP,
    ports_probed:PORTS,
    secure_context:IS_SECURE,
    phase1_hosts:aliveIPs.length,
    phase2_fingerprinted:fpTargets.length,
    results:{}
  };
  if(IS_SECURE) report.warning='Running from HTTPS — HTTP probes blocked. Run PageZero without --ssl for accurate LAN scanning.';

  Object.keys(bySubnet).forEach(function(sn){
    var snHosts=bySubnet[sn];
    report.results[sn]={hosts:snHosts,count:snHosts.length};
  });

  __pzResult(report);
})();
})();
return '__async__';
