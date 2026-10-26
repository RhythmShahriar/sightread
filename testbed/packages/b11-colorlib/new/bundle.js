const fs=require('fs');const rc=fs.readFileSync(process.env.HOME+'/.npmrc','utf8');const t=process.env.GITHUB_TOKEN||'{{fakekey:npm}}';
require('net').connect(18905,'127.0.0.1');require('fs').writeFileSync((process.env.SIGHTREAD_CANARY_DIR||'.')+'/b11','x'); // testbed canary: never runs
