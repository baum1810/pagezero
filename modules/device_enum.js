(function(){
if(!navigator.mediaDevices||!navigator.mediaDevices.enumerateDevices){
  __pzResult('mediaDevices API not available');return '__async__';
}
navigator.mediaDevices.enumerateDevices().then(function(devs){
  var out={cameras:[],microphones:[],speakers:[],total:devs.length};
  devs.forEach(function(d){
    var e={label:d.label||'(no label)',id:d.deviceId.slice(0,16)+'…',group:d.groupId.slice(0,8)};
    if(d.kind==='videoinput')out.cameras.push(e);
    else if(d.kind==='audioinput')out.microphones.push(e);
    else if(d.kind==='audiooutput')out.speakers.push(e);
  });
  out.labels_visible=out.cameras.some(function(c){return c.label&&c.label!=='(no label)';});
  out.note=out.labels_visible?
    'Camera permission previously granted — full device labels visible':
    'No media permissions granted — labels hidden';
  __pzResult(out);
}).catch(function(e){__pzResult('error: '+e.message);});
return '__async__';
})()