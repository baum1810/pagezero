(function(){
var features=[
  'camera','microphone','geolocation','payment','usb','bluetooth',
  'serial','midi','xr-spatial-tracking','screen-wake-lock',
  'ambient-light-sensor','accelerometer','gyroscope','magnetometer',
  'clipboard-read','clipboard-write','display-capture','fullscreen',
  'picture-in-picture','web-share','notifications','push','interest-cohort',
  'join-ad-interest-group','run-ad-auction','attribution-reporting',
  'shared-storage','fenced-frames','browsing-topics'
];

var result={policy_api:'none',allowed:[],blocked:[],restricted:[],raw:{}};

// Try document.permissionsPolicy (Chrome 88+)
var pp = document.permissionsPolicy || document.featurePolicy;
if(pp && typeof pp.allowedFeatures === 'function'){
  result.policy_api = document.permissionsPolicy ? 'permissionsPolicy' : 'featurePolicy';
  var allowed = pp.allowedFeatures();
  result.allowed_features = allowed;

  features.forEach(function(f){
    try{
      var state = pp.allowsFeature(f) ? 'allowed' : 'blocked';
      result.raw[f] = state;
      if(state==='allowed') result.allowed.push(f);
      else result.blocked.push(f);
    }catch(e){ result.raw[f]='error'; }
  });

  // Enterprise pattern detection
  var blockCount = result.blocked.length;
  result.enterprise_signals = [];
  if(result.raw['usb']==='blocked')        result.enterprise_signals.push('USB blocked (IT policy)');
  if(result.raw['serial']==='blocked')     result.enterprise_signals.push('Serial blocked (DLP)');
  if(result.raw['bluetooth']==='blocked')  result.enterprise_signals.push('Bluetooth blocked');
  if(result.raw['payment']==='blocked')    result.enterprise_signals.push('Payment API blocked (corporate)');
  if(result.raw['camera']==='blocked' && result.raw['microphone']==='blocked')
    result.enterprise_signals.push('AV blocked (meeting policy)');
  if(result.raw['clipboard-read']==='blocked') result.enterprise_signals.push('Clipboard read blocked (DLP)');
  if(blockCount>=8) result.enterprise_signals.push('Broad policy lockdown ('+blockCount+' features blocked)');

  result.likely_managed = result.enterprise_signals.length >= 2;
  result.verdict = result.likely_managed ? 'MANAGED_ENTERPRISE_DEVICE' : 'UNMANAGED_OR_CONSUMER';
}else{
  // Fallback: permissions query API
  result.policy_api = 'permissions_query_fallback';
  var checks=['camera','microphone','geolocation','clipboard-read','notifications','push'];
  var pending = checks.length;
  checks.forEach(function(name){
    navigator.permissions.query({name:name}).then(function(s){
      result.raw[name]=s.state;
      if(s.state==='granted') result.allowed.push(name);
      else if(s.state==='denied') result.blocked.push(name);
      else result.restricted.push(name);
      if(--pending===0) __pzResult(result);
    }).catch(function(){
      result.raw[name]='unsupported';
      if(--pending===0) __pzResult(result);
    });
  });
  return '__async__';
}

return result;
})()