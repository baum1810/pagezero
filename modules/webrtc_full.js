var interfaces = {};
var raw_candidates = [];

var pc = new RTCPeerConnection({
  iceServers: [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: 'stun:stun1.l.google.com:19302' },
    { urls: 'stun:stun.cloudflare.com:3478' }
  ]
});

pc.createDataChannel('__pz');

pc.onicecandidate = function (ev) {
  if (!ev.candidate) return;
  var c = ev.candidate.candidate;
  raw_candidates.push(c);
  var m = c.match(/candidate:\S+ \d+ \w+ \d+ ([\w.:]+) (\d+) typ (\w+)(?:\s+raddr ([\w.:]+))?/);
  if (m) {
    var ip = m[1], port = m[2], type = m[3], raddr = m[4] || null;
    if (!interfaces[ip]) interfaces[ip] = { ports: [], type: type, raddr: raddr, ipv6: ip.indexOf(':') !== -1 };
    if (interfaces[ip].ports.indexOf(port) === -1) interfaces[ip].ports.push(port);
  }
};

pc.onicegatheringstatechange = function () {
  if (pc.iceGatheringState !== 'complete') return;
  pc.close();

  var summary = [];
  var vpn_likely = false;
  var docker_likely = false;
  Object.keys(interfaces).forEach(function (ip) {
    var inf = interfaces[ip];
    var label = '';
    if (/^10\./.test(ip))                              label = 'RFC1918 (10.x — corp/home LAN)';
    else if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip))   label = 'RFC1918 (172.16-31 — Docker/VPN range)';
    else if (/^192\.168\./.test(ip))                   label = 'RFC1918 (192.168.x — home/office LAN)';
    else if (/^169\.254\./.test(ip))                   label = 'APIPA (link-local — disconnected adapter)';
    else if (/^fe80:/i.test(ip))                       label = 'IPv6 link-local';
    else if (/^fc|^fd/i.test(ip))                      label = 'IPv6 ULA (private)';
    else if (/^::1$/.test(ip))                         label = 'IPv6 loopback';
    else if (/^127\./.test(ip))                        label = 'IPv4 loopback';
    else                                                label = 'Public IP (real egress)';

    if (/^10\.(8|9|10|11|12|13)\./.test(ip) || /^172\.(16|17|18|19|20|21|22|23)\./.test(ip)) vpn_likely = true;
    if (/^172\.1[7-9]\.|^172\.2/.test(ip)) docker_likely = true;

    summary.push({ ip: ip, label: label, type: inf.type, ipv6: inf.ipv6, reflected_from: inf.raddr });
  });

  __pzResult({
    interfaces: summary,
    raw_candidates: raw_candidates,
    vpn_likely: vpn_likely,
    docker_likely: docker_likely,
    total_interfaces: summary.length,
    note: 'Includes all ICE candidates: host, srflx (STUN-reflexive = public IP). Requires no permissions.'
  });
};

pc.createOffer().then(function (o) { return pc.setLocalDescription(o); });

setTimeout(function () {
  if (pc.iceGatheringState !== 'complete') {
    pc.close();
    __pzResult({
      interfaces: Object.keys(interfaces).map(function (ip) { return { ip: ip }; }),
      raw_candidates: raw_candidates,
      note: 'Timed out before gathering complete'
    });
  }
}, 8000);
return '__async__';
