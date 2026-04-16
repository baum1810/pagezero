(function(){
if(window.__pzWSM)return 'already running ('+window.__pzWSM.length+' connections tracked)';
window.__pzWSM=[];
var _WS=window.WebSocket;
function PzWS(url,protocols){
  var ws=protocols?new _WS(url,protocols):new _WS(url);
  var entry={url:String(url),opened:new Date().toISOString(),sent:[],received:[]};
  window.__pzWSM.push(entry);
  var _send=ws.send.bind(ws);
  ws.send=function(data){
    try{entry.sent.push({ts:new Date().toISOString(),
      data:typeof data==='string'?data.slice(0,500):'[binary '+data.byteLength+'b]'});}catch(e){}
    return _send(data);
  };
  ws.addEventListener('message',function(e){
    try{entry.received.push({ts:new Date().toISOString(),
      data:typeof e.data==='string'?e.data.slice(0,500):'[binary]'});}catch(e2){}
  });
  ws.addEventListener('close',function(e){entry.closed=new Date().toISOString();entry.code=e.code;});
  return ws;
}
PzWS.prototype=_WS.prototype;
PzWS.CONNECTING=0;PzWS.OPEN=1;PzWS.CLOSING=2;PzWS.CLOSED=3;
window.WebSocket=PzWS;
return 'WebSocket monitor active';
})()