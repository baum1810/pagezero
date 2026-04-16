return (function(){
var findings = {};

// 1. WebDriver flag (headless Selenium, CDP-driven browsers)
findings.webdriver = !!navigator.webdriver;

// 2. GPU renderer — SwiftShader/llvmpipe = VM or headless
try{
  var c=document.createElement('canvas');
  var gl=c.getContext('webgl')||c.getContext('experimental-webgl');
  if(gl){
    var dbg=gl.getExtension('WEBGL_debug_renderer_info');
    findings.gpu_renderer = dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : 'n/a';
    findings.gpu_vendor   = dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL)   : 'n/a';
    findings.gpu_vm = /SwiftShader|llvmpipe|ANGLE.*VMware|Mesa.*softpipe|Microsoft Basic/i.test(findings.gpu_renderer||'');
  }
}catch(e){ findings.gpu_renderer = 'error:'+e.message; }

// 3. Hardware concurrency — AV sandboxes often cap at 1-2
findings.cpu_cores = navigator.hardwareConcurrency || 0;

// 4. performance.now() resolution — some AV hooks clamp to 1ms
var samples=[]; for(var i=0;i<20;i++) samples.push(performance.now());
var diffs=[]; for(var i=1;i<samples.length;i++) diffs.push(samples[i]-samples[i-1]);
var nonzero=diffs.filter(function(d){return d>0;});
findings.perf_resolution_ms = nonzero.length ? Math.min.apply(null,nonzero).toFixed(4) : 'clamped';
findings.perf_clamped = nonzero.length===0 || Math.min.apply(null,nonzero)>=1.0;

// 5. JIT speed anomaly — native JS is ~10-100x faster than interpreted/hooked
var ITERS=500000; var t0=performance.now();
var x=0; for(var j=0;j<ITERS;j++) x+=j*j; // tight arithmetic loop
var jit_ms=performance.now()-t0;
findings.jit_ms      = jit_ms.toFixed(2);
findings.jit_slow    = jit_ms > 80; // >80ms for 500k iterations suggests deoptimisation

// 6. Plugin count — headless usually has 0
findings.plugin_count = navigator.plugins ? navigator.plugins.length : 0;

// 7. Screen — common VM resolutions
var sr = screen.width+'x'+screen.height;
findings.screen = sr;
findings.screen_vm_like = ['800x600','1024x768','1280x720'].indexOf(sr) !== -1;

// 8. Timezone + language mismatch (sandboxes often use UTC/en-US regardless)
findings.timezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
findings.language  = navigator.language;

// ── Verdict ──────────────────────────────────────────────────────────────────
var signals=0;
if(findings.webdriver)     signals+=3;
if(findings.gpu_vm)        signals+=3;
if(findings.jit_slow)      signals+=2;
if(findings.perf_clamped)  signals+=2;
if(findings.cpu_cores<=2)  signals+=1;
if(findings.plugin_count===0) signals+=1;
if(findings.screen_vm_like)   signals+=1;
findings.signal_score = signals;
findings.verdict = signals>=5 ? 'LIKELY_SANDBOX_OR_VM' : signals>=3 ? 'SUSPICIOUS' : 'LIKELY_REAL_USER';

return findings;
})()