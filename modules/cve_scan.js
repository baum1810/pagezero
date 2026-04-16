(function(){
// ── CVE database ──────────────────────────────────────────────────────────────
// Fields: max (fixed_in exclusive), id, cvss, type, component, desc,
//         itw (exploited in the wild), poc ('public'|'msf'|'private'|'none'),
//         edb (Exploit-DB IDs), chain (sandbox escape or priv-esc possible),
//         action (operator next step)
var DB={
  chromium:[
    {max:'124.0.6367.201',id:'CVE-2024-4671',cvss:9.6,type:'UAF',component:'Visuals',
     desc:'Use-after-free in Visuals rendering component',itw:true,poc:'public',
     edb:['51952'],chain:'renderer RCE — sandbox escape unconfirmed in public PoC',
     action:'Public PoC available. Combine with sandbox escape (Mojo/IPC CVE) for full chain.'},
    {max:'124.0.6367.82',id:'CVE-2024-3832',cvss:8.8,type:'Object corruption',component:'V8',
     desc:'Object corruption in V8 JIT compiler',itw:false,poc:'public',
     edb:[],chain:'renderer RCE',
     action:'Public PoC on GitHub (search CVE-2024-3832 PoC). Heap spray required.'},
    {max:'123.0.6312.122',id:'CVE-2024-3159',cvss:8.8,type:'OOB Read',component:'V8',
     desc:'Out-of-bounds memory access in V8',itw:false,poc:'public',
     edb:[],chain:'info disclosure → renderer RCE',
     action:'Pair with write primitive for full RCE. public PoC demonstrates OOB read.'},
    {max:'120.0.6099.224',id:'CVE-2024-0519',cvss:8.8,type:'OOB Read',component:'V8',
     desc:'Out-of-bounds memory access in V8 — exploited ITW by threat actors',itw:true,poc:'public',
     edb:['51711'],chain:'renderer RCE',
     action:'EDB-51711. Actively exploited by multiple threat actors. Combine with sandbox escape.'},
    {max:'120.0.6099.129',id:'CVE-2023-7024',cvss:9.8,type:'Heap BOF',component:'WebRTC',
     desc:'Heap buffer overflow in WebRTC — exploited ITW, attributed to commercial spyware',itw:true,poc:'private',
     edb:[],chain:'renderer RCE → potential sandbox escape via IPC',
     action:'No public PoC. Trigger: malformed RTP/RTCP packet via WebRTC offer. See Project Zero writeup.'},
    {max:'119.0.6045.199',id:'CVE-2023-6345',cvss:9.6,type:'Integer overflow',component:'Skia',
     desc:'Integer overflow in Skia graphics library — exploited ITW',itw:true,poc:'private',
     edb:[],chain:'renderer RCE + privilege escalation observed',
     action:'Chained with CVE-2023-6346 (Visuals UAF) ITW. Trigger via crafted SVG/canvas.'},
    {max:'117.0.5938.132',id:'CVE-2023-5217',cvss:8.8,type:'Heap BOF',component:'libvpx/VP8',
     desc:'Heap buffer overflow in VP8 encoding in libvpx — exploited ITW, cross-browser',itw:true,poc:'public',
     edb:['51793'],chain:'renderer RCE',
     action:'EDB-51793. Affects Chrome, Firefox, Edge. Trigger: malformed WebM/VP8 stream via <video>.'},
    {max:'116.0.5845.187',id:'CVE-2023-4863',cvss:9.8,type:'Heap BOF',component:'libwebp',
     desc:'Heap buffer overflow in libwebp — exploited ITW, affects all apps using libwebp',itw:true,poc:'public',
     edb:['51737'],chain:'renderer RCE — affects ALL Electron apps and browsers',
     action:'EDB-51737. Widest-impact 2023 browser CVE. Trigger: crafted .webp image. PoC on GitHub.'},
    {max:'114.0.5735.110',id:'CVE-2023-3079',cvss:8.8,type:'Type confusion',component:'V8',
     desc:'Type confusion in V8 — exploited ITW',itw:true,poc:'private',
     edb:[],chain:'renderer RCE',
     action:'No stable public PoC. Trigger: crafted JS triggering incorrect type assumption in JIT.'},
    {max:'112.0.5615.137',id:'CVE-2023-2136',cvss:9.6,type:'Integer overflow',component:'Skia',
     desc:'Integer overflow in Skia — exploited ITW',itw:true,poc:'private',
     edb:[],chain:'renderer RCE',
     action:'Trigger via compositing operations. Chained with IPC bug ITW for sandbox escape.'},
    {max:'108.0.5359.94',id:'CVE-2022-4262',cvss:8.8,type:'Type confusion',component:'V8',
     desc:'V8 type confusion — exploited ITW',itw:true,poc:'public',
     edb:[],chain:'renderer RCE',
     action:'Public PoC variants exist. Standard V8 type confusion exploitation pattern.'},
    {max:'105.0.5195.102',id:'CVE-2022-3075',cvss:9.6,type:'Insufficient validation',component:'Mojo',
     desc:'Mojo IPC insufficient data validation — exploited ITW, sandbox escape',itw:true,poc:'private',
     edb:[],chain:'FULL CHAIN — renderer RCE + sandbox escape via Mojo IPC',
     action:'Rare: confirmed sandbox escape ITW. Trigger via malformed Mojo IPC message from renderer.'},
    {max:'100.0.4896.127',id:'CVE-2022-1364',cvss:8.8,type:'Type confusion',component:'V8',
     desc:'V8 type confusion — exploited ITW, public PoC available',itw:true,poc:'public',
     edb:['50677'],chain:'renderer RCE',
     action:'EDB-50677. Well-documented exploitation. Good reference for V8 type confusion technique.'},
  ],
  firefox:[
    {max:'124.0.1',id:'CVE-2024-29944',cvss:9.8,type:'Privileged JS exec',component:'JS engine',
     desc:'Event handler wrapping bypass allows privileged JS execution — exploited ITW',itw:true,poc:'private',
     edb:[],chain:'Chrome-equivalent renderer RCE + potential privilege escalation',
     action:'Exploited by state-sponsored actors. No stable public PoC. Trigger via crafted event handler.'},
    {max:'124.0.1',id:'CVE-2024-29943',cvss:9.8,type:'OOB Access',component:'SpiderMonkey',
     desc:'Out-of-bounds access via range analysis bypass in SpiderMonkey JIT',itw:false,poc:'public',
     edb:[],chain:'renderer RCE',
     action:'Chained with CVE-2024-29944 ITW. Trigger: JIT optimization edge case in SpiderMonkey.'},
    {max:'121.0',id:'CVE-2023-6856',cvss:9.8,type:'Heap BOF',component:'WebGL',
     desc:'WebGL heap buffer overflow via DrawElementsInstanced',itw:false,poc:'none',
     edb:[],chain:'renderer RCE',
     action:'Trigger via crafted WebGL draw call. No stable public PoC yet.'},
    {max:'117.0',id:'CVE-2023-5217',cvss:8.8,type:'Heap BOF',component:'libvpx',
     desc:'libvpx VP8 — cross-browser, see Chrome entry',itw:true,poc:'public',
     edb:['51793'],chain:'renderer RCE',
     action:'Same libvpx bug as Chrome CVE-2023-5217. EDB-51793.'},
    {max:'97.0.2',id:'CVE-2022-26485',cvss:9.8,type:'UAF',component:'XSLT',
     desc:'XSLT parameter processing use-after-free — exploited ITW',itw:true,poc:'private',
     edb:[],chain:'renderer RCE',
     action:'Trigger via crafted XSLT document. Exploited alongside CVE-2022-26486.'},
    {max:'97.0.2',id:'CVE-2022-26486',cvss:9.8,type:'UAF',component:'WebGPU IPC',
     desc:'WebGPU IPC framework use-after-free — exploited ITW alongside CVE-2022-26485',itw:true,poc:'private',
     edb:[],chain:'FULL CHAIN — renderer RCE + sandbox escape',
     action:'Rare confirmed sandbox escape pair. Attributed to state-sponsored actor.'},
  ],
  safari:[
    {max:'17.3',id:'CVE-2024-23222',cvss:8.8,type:'Type confusion',component:'WebKit/JavaScriptCore',
     desc:'JSC type confusion — exploited ITW in targeted attacks',itw:true,poc:'private',
     edb:[],chain:'renderer RCE',
     action:'Patched Jan 2024. Trigger via crafted JS in JSC. Attributed to spyware vendor.'},
    {max:'17.1.2',id:'CVE-2023-42917',cvss:9.8,type:'Memory corruption',component:'WebKit',
     desc:'WebKit memory corruption — exploited ITW, RCE',itw:true,poc:'private',
     edb:[],chain:'renderer RCE → iOS kernel exploit chain observed',
     action:'Part of iOS/macOS exploit chain. Trigger: malicious web content.'},
    {max:'17.1.2',id:'CVE-2023-42916',cvss:8.1,type:'OOB Read',component:'WebKit',
     desc:'OOB read — info disclosure chained with CVE-2023-42917 ITW',itw:true,poc:'private',
     edb:[],chain:'info disclosure → feeds memory layout to CVE-2023-42917',
     action:'Used as info leak primitive. Must chain with write primitive for RCE.'},
    {max:'16.5.2',id:'CVE-2023-37450',cvss:9.8,type:'Arbitrary code exec',component:'WebKit',
     desc:'WebKit arbitrary code execution — exploited ITW',itw:true,poc:'private',
     edb:[],chain:'renderer RCE',
     action:'Trigger via specially crafted web content. Patched in Rapid Security Response.'},
    {max:'16.4.1',id:'CVE-2023-32373',cvss:9.8,type:'UAF',component:'WebKit',
     desc:'WebKit use-after-free — exploited ITW, RCE',itw:true,poc:'private',
     edb:[],chain:'renderer RCE → chained with kernel CVE ITW on iOS',
     action:'Part of multi-stage chain. WebKit entry point for kernel privilege escalation.'},
    {max:'15.3',id:'CVE-2022-22620',cvss:9.8,type:'UAF',component:'WebKit',
     desc:'WebKit use-after-free — exploited ITW, RCE',itw:true,poc:'private',
     edb:[],chain:'renderer RCE',
     action:'History of exploitation. Trigger via crafted web content.'},
  ]
};

function cmpVer(a,b){
  var av=String(a).split('.').map(Number),bv=String(b).split('.').map(Number);
  for(var i=0;i<Math.max(av.length,bv.length);i++){
    var d=(av[i]||0)-(bv[i]||0);if(d!==0)return d;
  }return 0;
}

function runScan(browser,version,platform,detMethod,extras){
  var cves=[];
  var db=(/Chrome|Edge|Opera/.test(browser))?DB.chromium:
         (/Firefox/.test(browser))?DB.firefox:
         (/Safari/.test(browser))?DB.safari:[];
  db.forEach(function(c){
    if(cmpVer(version,c.max)<=0)cves.push(c);
  });
  cves.sort(function(a,b){return b.cvss-a.cvss;});

  var pocPublic=cves.filter(function(c){return c.poc==='public'||c.poc==='msf';});
  var itw=cves.filter(function(c){return c.itw;});
  var chains=cves.filter(function(c){return c.chain&&c.chain.indexOf('FULL CHAIN')!==-1;});

  var summary={
    browser:browser, version:version, platform:platform||'unknown',
    detection_method:detMethod,
    version_confidence:detMethod==='client_hints'?'HIGH — Client Hints API (not fakeable by UA spoofing)':'MEDIUM — UA string parsing (may be spoofed)',
    total_cves:cves.length,
    itw_count:itw.length,
    public_poc_count:pocPublic.length,
    full_chain_count:chains.length,
    highest_cvss:cves.length?cves[0].cvss:0,
    top_cve:cves.length?cves[0].id:null,
    verdict:cves.length===0?'PATCHED — no known critical CVEs for this version':
            chains.length?'CRITICAL — full exploit chain CVEs present (renderer RCE + sandbox escape)':
            itw.length?'HIGH — actively exploited CVEs present':
            pocPublic.length?'HIGH — public PoC CVEs present':'MEDIUM — CVEs present, no public PoC',
    edb_refs:cves.reduce(function(a,c){return a.concat((c.edb||[]).map(function(e){return 'EDB-'+e+' ('+c.id+')';}));}, []),
    cves:cves
  };
  if(extras)Object.assign(summary,extras);
  __pzResult(summary);
}

// ── Try Client Hints first (Chromium only, accurate to patch level) ───────────
var ua=navigator.userAgent;
if(navigator.userAgentData&&navigator.userAgentData.getHighEntropyValues){
  navigator.userAgentData.getHighEntropyValues([
    'fullVersionList','platform','platformVersion','model','architecture'
  ]).then(function(h){
    var brands=h.fullVersionList||[];
    var edge=brands.filter(function(b){return b.brand==='Microsoft Edge';})[0];
    var chrome=brands.filter(function(b){return b.brand==='Google Chrome';})[0];
    var opera=brands.filter(function(b){return b.brand==='Opera';})[0];
    var b=edge||chrome||opera;
    if(!b){runScan('Chromium',brands[0]?brands[0].version:'?',h.platform,'client_hints',{raw_brands:brands});return;}
    var name=edge?'Edge':opera?'Opera':'Chrome';
    runScan(name,b.version,h.platform,'client_hints',{
      platform_version:h.platformVersion,
      architecture:h.architecture,
      model:h.model||null,
      raw_brands:brands
    });
  }).catch(function(){
    // Fall back to UA parsing
    var m;
    if(m=ua.match(/Edg\/([\d.]+)/))runScan('Edge',m[1],null,'ua_parser',null);
    else if(m=ua.match(/OPR\/([\d.]+)/))runScan('Opera',m[1],null,'ua_parser',null);
    else if(m=ua.match(/Chrome\/([\d.]+)/))runScan('Chrome',m[1],null,'ua_parser',null);
    else if(m=ua.match(/Firefox\/([\d.]+)/))runScan('Firefox',m[1],null,'ua_parser',null);
    else if(m=ua.match(/Version\/([\d.]+).*Safari/))runScan('Safari',m[1],null,'ua_parser',null);
    else __pzResult({verdict:'UNKNOWN BROWSER',ua:ua});
  });
}else{
  // Firefox / Safari — no Client Hints
  var m;
  if(m=ua.match(/Firefox\/([\d.]+)/))runScan('Firefox',m[1],null,'ua_parser',null);
  else if(m=ua.match(/Version\/([\d.]+).*Safari/))runScan('Safari',m[1],null,'ua_parser',null);
  else __pzResult({verdict:'UNKNOWN BROWSER',ua:ua});
}
return '__async__';
})()