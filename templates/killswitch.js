(function(){
document.querySelectorAll('[id^=__pz]').forEach(function(e){e.remove();});
if(window.__pzKL){document.removeEventListener('keydown',window.__pzKL,true);
  clearInterval(window.__pzKLT);delete window.__pzKL;delete window.__pzKLT;delete window.__pzKLBuf;}
if(window.__pzFG){document.removeEventListener('submit',window.__pzFG,true);delete window.__pzFG;}
if(window.__pzCM){delete window.__pzCM;}
if(window.__pzAM){delete window.__pzAM;}
if(window.__pzWSM){delete window.__pzWSM;}
if(window.__pzPM){window.removeEventListener('message',window.__pzPMH,true);delete window.__pzPM;delete window.__pzPMH;}
if(window.__pzCLIP){document.removeEventListener('copy',undefined,true);document.removeEventListener('cut',undefined,true);delete window.__pzCLIP;}
if(window.__pzDFO){window.__pzDFObs&&window.__pzDFObs.disconnect();delete window.__pzDFO;delete window.__pzDFObs;}
return 'pz_killed';
})();
