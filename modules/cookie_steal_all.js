var out = {
  url: location.href,
  cookies: document.cookie,
  localStorage: {},
  sessionStorage: {},
  indexedDB_databases: [],
  serviceWorkers: [],
  cacheStorageKeys: []
};
try {
  for (var i = 0; i < localStorage.length; i++) {
    var k = localStorage.key(i);
    out.localStorage[k] = localStorage.getItem(k);
  }
} catch (e) {}
try {
  for (var i = 0; i < sessionStorage.length; i++) {
    var k = sessionStorage.key(i);
    out.sessionStorage[k] = sessionStorage.getItem(k);
  }
} catch (e) {}

var pending = 0;
var done = false;

function finish() {
  if (done) return;
  done = true;
  __pzResult(out);
}

// IndexedDB database names
pending++;
(function () {
  if (!window.indexedDB || !indexedDB.databases) {
    if (!--pending) finish();
    return;
  }
  indexedDB.databases().then(function (list) {
    out.indexedDB_databases = list.map(function (db) {
      return { name: db.name, version: db.version };
    });
    if (!--pending) finish();
  }).catch(function () {
    if (!--pending) finish();
  });
})();

// Service worker registrations
pending++;
(function () {
  if (!navigator.serviceWorker) {
    if (!--pending) finish();
    return;
  }
  navigator.serviceWorker.getRegistrations().then(function (regs) {
    out.serviceWorkers = regs.map(function (r) {
      return { scope: r.scope, scriptURL: r.active ? r.active.scriptURL : (r.installing ? r.installing.scriptURL : null) };
    });
    if (!--pending) finish();
  }).catch(function () {
    if (!--pending) finish();
  });
})();

// Cache storage keys
pending++;
(function () {
  if (!window.caches) {
    if (!--pending) finish();
    return;
  }
  caches.keys().then(function (keys) {
    out.cacheStorageKeys = keys;
    if (!--pending) finish();
  }).catch(function () {
    if (!--pending) finish();
  });
})();

// Timeout fallback
setTimeout(function () { finish(); }, 5000);
return '__async__';
