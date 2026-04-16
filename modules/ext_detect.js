(function(){
var found=[];
function add(name,method){if(found.indexOf(name)===-1)found.push(name+' ['+method+']');}

// ── Phase 1: window globals ───────────────────────────────────────────────────
var globals={
  // Crypto wallets — ethereum
  'MetaMask':         function(){return !!(window.ethereum&&window.ethereum.isMetaMask);},
  'Rabby':            function(){return !!(window.ethereum&&window.ethereum.isRabby);},
  'Coinbase Wallet':  function(){return !!(window.ethereum&&window.ethereum.isCoinbaseWallet)||!!(window.coinbaseWalletExtension);},
  'Brave Wallet':     function(){return !!(window.ethereum&&window.ethereum.isBraveWallet);},
  'Trust Wallet':     function(){return !!(window.ethereum&&window.ethereum.isTrust)||!!(window.trustWallet);},
  'OKX Wallet':       function(){return !!(window.okxwallet)||!!(window.ethereum&&window.ethereum.isOkxWallet);},
  'Zerion':           function(){return !!(window.ethereum&&window.ethereum.isZerion);},
  'Frame':            function(){return !!(window.ethereum&&window.ethereum.isFrame);},
  'Web3 (generic)':   function(){return !!(window.web3&&window.web3.currentProvider)&&!window.ethereum;},
  // Solana wallets
  'Phantom':          function(){return !!(window.phantom)||(window.solana&&window.solana.isPhantom);},
  'Solflare':         function(){return !!(window.solflare&&window.solflare.isSolflare);},
  'Backpack':         function(){return !!(window.backpack)||(window.xnft);},
  // Other chains
  'TronLink':         function(){return !!(window.tronLink)||!!(window.tronWeb);},
  'Keplr':            function(){return !!(window.keplr);},
  'Petra (Aptos)':    function(){return !!(window.aptos)||!!(window.petra);},
  'Martian (Aptos)':  function(){return !!(window.martian);},
  'Sui Wallet':       function(){return !!(window.suiWallet);},
  // Script managers
  'Tampermonkey':     function(){return typeof GM_info!=='undefined'&&GM_info&&GM_info.scriptHandler==='Tampermonkey';},
  'Violentmonkey':    function(){return typeof GM_info!=='undefined'&&GM_info&&GM_info.scriptHandler==='Violentmonkey';},
  'Greasemonkey':     function(){return typeof GM_xmlhttpRequest!=='undefined'&&typeof GM_info!=='undefined'&&GM_info.scriptHandler==='Greasemonkey';},
  'UserScript (any)': function(){return typeof GM_info!=='undefined'||typeof GM!=='undefined';},
  // Dev tools
  'React DevTools':   function(){return !!(window.__REACT_DEVTOOLS_GLOBAL_HOOK__&&window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers&&window.__REACT_DEVTOOLS_GLOBAL_HOOK__.renderers.size>0);},
  'Redux DevTools':   function(){return !!(window.__REDUX_DEVTOOLS_EXTENSION__||window.devToolsExtension);},
  'Vue DevTools':     function(){return !!(window.__VUE_DEVTOOLS_GLOBAL_HOOK__);},
  'Angular DevTools': function(){return !!(window.__ANGULAR_DEVTOOLS_INITIALIZED__)||!!(window.ng);},
  'Wappalyzer':       function(){return typeof Wappalyzer!=='undefined';},
};
Object.keys(globals).forEach(function(n){try{if(globals[n]())add(n,'global');}catch(e){}});

// ── Phase 2: DOM fingerprinting ───────────────────────────────────────────────
var domChecks={
  '1Password':   function(){
    return !!(document.querySelector('[data-1p-ignore],[data-1pignore],[data-1p]'))||
           !!(document.getElementById('onepassword-inline-button'))||
           !!(document.querySelector('com-1password-button'));},
  'Bitwarden':   function(){
    return !!(document.querySelector('[data-bwi-page-script],[data-bwautofill],[bit-input]'))||
           !!(document.querySelector('bit-icon,bit-button'));},
  'LastPass':    function(){
    return !!(document.querySelector('[data-lpignore],[data-lastpass-uuid],[lastpass-secure-note]'))||
           !!(document.querySelector('#lastpass-vault-open'));},
  'Dashlane':    function(){
    return !!(document.querySelector('[data-dashlane-rid],[data-form-type]'))||
           typeof __dashlane_details!=='undefined';},
  'NordPass':    function(){
    return !!(document.querySelector('[data-np-checked],[data-nordpass],[np-checked]'));},
  'Keeper':      function(){
    return !!(document.querySelector('[data-keeper-fill]'));},
  'Grammarly':   function(){
    return !!(document.querySelector('grammarly-desktop-integration,#grammarly-extension,.gr__'))||
           !!(document.querySelector('[data-gramm]'));},
  'Honey':       function(){return !!(window.__honeyfunctions)||!!(document.getElementById('honey-jar'));},
  'uBlock/AdBlock':function(){
    var d=document.createElement('div');
    d.className='adsbox ad-unit pub_300x250 banner_ad textad';
    d.style.cssText='height:1px;width:1px;position:fixed;top:-999px;left:-999px;pointer-events:none';
    document.body.appendChild(d);
    var blocked=!d.offsetHeight;d.remove();return blocked;},
  'Privacy Badger':function(){return !!(window.__privacyBadgerLoaded);},
  'DuckDuckGo':  function(){return !!(window.ddg_spice_loader)||!!(document.querySelector('[ddg-extension-id]'));},
};
Object.keys(domChecks).forEach(function(n){try{if(domChecks[n]())add(n,'dom');}catch(e){}});

// ── Phase 3: chrome-extension:// URL probing ─────────────────────────────────
var urlProbes={
  'MetaMask':          'chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn/images/icon-128.png',
  'Coinbase Wallet':   'chrome-extension://hnfanknocfeofbddgcijnmhnfnkdnaad/images/icon-128.png',
  'ColorZilla':        'chrome-extension://bhlhnicpbhignbdhedgjhgdocnmhomnp/icons/icon16.png',
  'EditThisCookie':    'chrome-extension://fngmhnnpilhplaeedifhccceomclgfbg/img/etcIcon.png',
  'FoxyProxy':         'chrome-extension://gcknhkkoolaabfmlnjonogaaifnjlfnp/icons/icon32.png',
  'Honey':             'chrome-extension://bmnlcjabgnpnenekpadlanbbkooimhnj/img/honey-icon-128.png',
  'Capital One Shop':  'chrome-extension://nenlahapcbofgnanklpelkaejcehkggg/images/icon_128.png',
  'Rakuten':           'chrome-extension://chhjbpecpancjgfnonjlhkdgkbhkknnl/icon128.png',
  'UserAgent Switcher':'chrome-extension://bhchdcejhohfmigjafbampogmaanbfkg/images/logo.png',
  'AdBlock Plus':      'chrome-extension://cfhdojbkjhnklbpkdaibdccddilifddb/icons/icon24.png',
  'AdBlock':           'chrome-extension://gighmmpiobklfepjocnamgkkbiglidom/icons/icon128.png',
  'Ghostery':          'chrome-extension://mlomiejdfkolichcflejclcbmpeaniij/images/icon19.png',
  'Privacy Badger':    'chrome-extension://pkehgijcmpdhfbdbbnkijodmdjhbjlgp/icons/badger-128.png',
  'Malwarebytes':      'chrome-extension://ihcjicgdanjaechkgeegckofjjedodee/images/mbam_shield.png',
  'Grammarly':         'chrome-extension://kbfnbcaeplbcioakkpcpgfkobkghlhen/images/icon128.png',
  'LastPass':          'chrome-extension://hdokiejnpimakedhajhdlcegeplioahd/images/icon_checkmark.png',
  'Bitwarden':         'chrome-extension://nngceckbapebfimnlniiiahkandclblb/icons/icon192.png',
  'Dashlane':          'chrome-extension://fdjamakpfbbddfjaooikfcpapjohcfmg/images/icon128.png',
  '1Password':         'chrome-extension://aeblfdkhhhdcdjpifhhbdiojplfjncoa/images/icon128.png',
  'NordPass':          'chrome-extension://fooolghllnmhmmndgjiamiiodkpenpbb/icons/icon128.png',
  'Keeper':            'chrome-extension://bfogiafebfohielmmehodmfbbebbbpei/icons/icon_128.png',
  'Dark Reader':       'chrome-extension://eimadpbcbfnmbkopoojfekhnkhdbieeh/icons/dr_active_128.png',
  'Stylus':            'chrome-extension://clngdbkpkpeebahjckkjfobafhncgmne/icon/icon_128.png',
  'SwitchyOmega':      'chrome-extension://padekgcemlokbadohgkifijomclgjgif/icons/128.png',
  'WhatFont':          'chrome-extension://jabopobgcpjmedljpbcaablpmlmfcogm/img/icon128.png',
  'React DevTools':    'chrome-extension://fmkadmapgofadopljbjfkapdkoienihi/icons/128.png',
  'Augury':            'chrome-extension://elgalmkoelokbchhkhacckoklkejnhcd/assets/icons/angular_icon_128x128.png',
  'Wappalyzer':        'chrome-extension://gppongmhjkpfnbhagpmjfkannfbllamg/images/icons/wappalyzer.svg',
  'Tampermonkey':      'chrome-extension://dhdgffkkebhmkfjojejmpbldmpobfkfo/images/icon128n.png',
  'Violentmonkey':     'chrome-extension://jinjaccalgkegedbjellkejmikkmclag/icons/icon128.png',
};
var left=Object.keys(urlProbes).length;
if(!left){__pzResult(found.length?found:['none detected']);return '__async__';}
Object.keys(urlProbes).forEach(function(name){
  var img=new Image();
  img.onload=function(){add(name,'url');if(!--left)__pzResult(found.length?found:['none detected']);};
  img.onerror=function(){if(!--left)__pzResult(found.length?found:['none detected']);};
  img.src=urlProbes[name]+'?_='+Math.random();
});
return '__async__';
})()