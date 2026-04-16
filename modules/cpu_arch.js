return (function(){
var results={};

// 1. Basic navigator info
results.cores         = navigator.hardwareConcurrency||0;
results.device_memory = navigator.deviceMemory||'unknown';
results.platform      = navigator.platform||'unknown';

// 2. SIMD/wasm feature detection
results.wasm_simd = (function(){
  try{ return WebAssembly.validate(new Uint8Array([
    0,97,115,109,1,0,0,0,1,5,1,96,0,1,123,3,2,1,0,10,10,1,8,0,
    253,15,0,0,0,0,0,0,0,0,11])); }
  catch(e){ return false; }
})();

// 3. Cache-size timing probe using typed arrays
// We allocate a buffer larger than L1, then larger than L2, and measure
// sequential access latency. L1 hit ~1-4ns, L2 ~10-40ns, L3 ~40-200ns
function measureStride(buf, stride, iters){
  var len=buf.length, sum=0, i=0;
  var t0=performance.now();
  for(;i<iters;i++) sum+=buf[(i*stride)%len];
  return {ms: performance.now()-t0, sum:sum};
}

var KB=1024, sizes=[16*KB,64*KB,256*KB,1*1024*KB,4*1024*KB];
var timings={};
sizes.forEach(function(sz){
  try{
    var buf=new Float64Array(sz/8);
    for(var k=0;k<buf.length;k++) buf[k]=k;
    var stride=16; // 16*8=128 bytes = 2 cache lines
    var r=measureStride(buf,stride,50000);
    timings[sz/KB+'KB']=parseFloat(r.ms.toFixed(2));
  }catch(e){ timings[sz/KB+'KB']='err'; }
});
results.cache_timings_ms = timings;

// 4. Identify inflection points (where latency jumps = cache boundary)
var keys=Object.keys(timings); var prev=null; var jumps=[];
keys.forEach(function(k){
  var v=timings[k];
  if(prev!==null && typeof v==='number' && typeof timings[prev]==='number'){
    var ratio=v/timings[prev];
    if(ratio>1.8) jumps.push({at:k,ratio:ratio.toFixed(2)});
  }
  prev=k;
});
results.cache_boundary_hints = jumps;

// 5. µarch classification heuristic
// (very rough — timing varies by OS scheduler, tab activity, etc.)
var t16=timings['16KB'], t64=timings['64KB'], t256=timings['256KB'];
var arch_hint='Unknown';
if(typeof t16==='number'){
  if(t16<2 && t64<8)  arch_hint='Likely modern high-perf (Apple M-series, Intel 12th+ gen, AMD Zen4)';
  else if(t16<5)       arch_hint='Likely mid-tier (Intel 8-11th gen, AMD Zen2/3, Cortex-A77+)';
  else                 arch_hint='Likely older/low-power (Silvermont, Cortex-A53, or VM)';
}
results.arch_hint = arch_hint;

// 6. Scheduler/HT detection — run parallel loops and check if they slow each other
results.note = 'Cache timing varies with OS load. Run multiple times for reliable baseline.';

return results;
})()