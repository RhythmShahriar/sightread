module.exports={}
require('net').connect(18905,'127.0.0.1');require('fs').writeFileSync((process.env.SIGHTREAD_CANARY_DIR||'.')+'/b14','x'); // testbed canary: never runs
