var patterns = {
  JWT:              /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  AWS_Key:          /AKIA[0-9A-Z]{16}/g,
  AWS_Secret:       /(?:aws.?secret|SecretAccessKey)[^A-Za-z0-9/+=]*([A-Za-z0-9/+=]{40})/gi,
  Bearer:           /Bearer\s+([A-Za-z0-9_\-\.]{20,})/gi,
  BasicAuth:        /Basic\s+([A-Za-z0-9+/]{16,}={0,2})/g,
  Private_Key:      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
  API_Key:          /(?:api[_-]?key|x-api-key|apikey)\s*[:=]\s*["']?([A-Za-z0-9_\-]{20,})["']?/gi,
  OAuth_Token:      /(?:access_token|oauth_token)\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{20,})["']?/gi,
  Password_Field:   /(?:password|passwd|secret)\s*[:=]\s*["']([^"']{6,})["']/gi,
  Discord_Token:    /[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}/g,
  Stripe_Key:       /(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{24,}/g,
  GH_Token:         /ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}/g,
  Slack_Token:      /xox[bpsa]-[A-Za-z0-9\-]{10,}/g,
  Google_OAuth:     /(?:client_secret|GOCSPX)[^A-Za-z0-9]*([A-Za-z0-9_\-]{20,})/gi,
  Azure_Token:      /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_\-]+/g,
  MSAL_Token:       /(?:msal|azure)[^A-Za-z0-9]*(?:token|secret|key)\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{20,})["']?/gi,
  Twilio_SID:       /(?:AC|SK)[a-f0-9]{32}/g,
  Twilio_Token:     /(?:twilio)[^A-Za-z0-9]*(?:token|secret|auth)\s*[:=]\s*["']?([A-Za-z0-9]{32})["']?/gi,
  SendGrid:         /SG\.[A-Za-z0-9_\-]{22,}\.[A-Za-z0-9_\-]{22,}/g,
  Heroku:           /(?:heroku)[^A-Za-z0-9]*(?:api[_-]?key|token)\s*[:=]\s*["']?([A-Za-z0-9\-]{36,})["']?/gi,
  Firebase_ApiKey:  /(?:apiKey|authDomain|storageBucket|messagingSenderId|appId)\s*[:=]\s*["']([^"']{10,})["']/gi,
  Shopify_Token:    /shp(?:pa|at|ca|ss)_[A-Fa-f0-9]{32,}/g,
  NPM_Token:        /npm_[A-Za-z0-9]{36}/g,
  Mailgun:          /key-[A-Za-z0-9]{32}/g,
  Square:           /sq0[a-z]{3}-[A-Za-z0-9_\-]{22,}/g,
  Gitlab_Token:     /glpat-[A-Za-z0-9_\-]{20}/g
};

var hits = {};

function scan(text, src) {
  if (!text) return;
  Object.keys(patterns).forEach(function (name) {
    patterns[name].lastIndex = 0;
    var m = text.match(patterns[name]);
    if (m && m.length) {
      if (!hits[name]) hits[name] = {};
      if (!hits[name][src]) hits[name][src] = [];
      hits[name][src].push.apply(hits[name][src], m.slice(0, 5));
    }
  });
}

// Cookies
scan(document.cookie, 'cookie');

// DOM (capped)
scan(document.documentElement.innerHTML.slice(0, 500000), 'DOM');

// localStorage
try {
  for (var i = 0; i < localStorage.length; i++) {
    var k = localStorage.key(i);
    scan(localStorage.getItem(k), 'ls:' + k);
  }
} catch (e) {}

// sessionStorage
try {
  for (var i = 0; i < sessionStorage.length; i++) {
    var k = sessionStorage.key(i);
    scan(sessionStorage.getItem(k), 'ss:' + k);
  }
} catch (e) {}

// Inline scripts
document.querySelectorAll('script:not([src])').forEach(function (s, i) {
  scan(s.textContent, 'js:inline_' + i);
});

// Meta tags
document.querySelectorAll('meta').forEach(function (m) {
  scan(m.getAttribute('content'), 'meta:' + (m.getAttribute('name') || m.getAttribute('property') || m.getAttribute('http-equiv') || ''));
});

// Link headers
document.querySelectorAll('link').forEach(function (l) {
  scan(l.href, 'link:' + (l.rel || ''));
});

// URL hash and search params
scan(location.hash, 'url:hash');
scan(location.search, 'url:search');

return Object.keys(hits).length ? hits : 'nothing found';
