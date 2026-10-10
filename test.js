// Run with:  node tests/test.js
const assert=require('assert');
const {analyse}=require('./analyser.js');
const {SAMPLES}=require('./samples.js');
const expected={'Obvious phishing':'High Risk','Sophisticated phishing':'Suspicious','Fake Microsoft 365 warning':'High Risk','Fake parcel delivery':'High Risk','Invoice / BEC-style':'High Risk','Legitimate email':'Low Risk'};
let failed=0;
const check=(name,fn)=>{try{fn();console.log('PASS',name)}catch(e){failed++;console.log('FAIL',name,'-',e.message)}};
for(const s of SAMPLES)check('demo: '+s.t,()=>assert.strictEqual(analyse(s.b).band,expected[s.t]));
check('score never exceeds 100',()=>assert.ok(SAMPLES.every(s=>analyse(s.b).score<=100)));
check('raw IP link is flagged',()=>assert.ok(analyse('Go to http://192.0.2.9/x').names.includes('Link uses a raw IP address')));
check('empty-ish text scores 0',()=>assert.strictEqual(analyse('hello').score,0));
check('every finding has points and a reason',()=>assert.ok(SAMPLES.every(s=>analyse(s.b).found.every(f=>f.p>0&&f.why))));
process.exit(failed?1:0);
