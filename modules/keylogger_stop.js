(function(){
if(!window.__pzKL)return 'not running';
document.removeEventListener('keydown',window.__pzKL,true);
clearInterval(window.__pzKLT);
delete window.__pzKL;delete window.__pzKLT;delete window.__pzKLBuf;
return 'stopped';
})()