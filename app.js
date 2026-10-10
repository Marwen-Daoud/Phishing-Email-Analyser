/* ===== PAGE CODE (only runs in a browser) ===== */
if(typeof document!=='undefined'){
const $=id=>document.getElementById(id),inp=$('inp'),res=$('result');
const el=(t,c,x)=>{const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e};
SAMPLES.forEach(s=>{
  const b=document.createElement('button');
  b.innerHTML='<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path><polyline points="22,6 12,13 2,6"></polyline></svg> <span>'+s.t+'</span>';
  b.onclick=()=>{inp.value=s.b;run()};
  $('samples').append(b)
});
$('clr').onclick=()=>{inp.value='';res.style.display='none';inp.focus()};
$('go').onclick=run;
const qp=s=>/content-transfer-encoding:\s*quoted-printable/i.test(s)?s.replace(/=\r?\n/g,'').replace(/=([0-9A-F]{2})/g,(_,x)=>String.fromCharCode(parseInt(x,16))):s;
$('up').onclick=()=>$('eml').click();
$('eml').onchange=e=>{const f=e.target.files[0];e.target.value='';if(!f)return;
  if(f.size>2e6){res.replaceChildren(el('p','empty','That file is over 2 MB. Please choose a smaller .eml file.'));res.style.display='block';return}
  const rd=new FileReader();rd.onload=()=>{inp.value=qp(String(rd.result));run()};rd.readAsText(f)};
const defang=s=>s.replace(/https?:\/\/\S+/gi,u=>u.replace(/^http/i,'hxxp').replace(/\./g,'[.]'));
function highlight(text,terms){
  const lo=text.toLowerCase(),rg=[];
  for(const t of new Set(terms)){if(!t||t.length<3)continue;const k=t.toLowerCase();let i=lo.indexOf(k);while(i>-1){rg.push([i,i+k.length]);i=lo.indexOf(k,i+k.length)}}
  rg.sort((a,b)=>a[0]-b[0]);const mg=[];
  for(const x of rg){const l=mg[mg.length-1];if(l&&x[0]<=l[1])l[1]=Math.max(l[1],x[1]);else mg.push([...x])}
  const box=el('div','ev hlbox');let p=0;
  for(const [a,b] of mg){box.append(document.createTextNode(text.slice(p,a)),el('mark',null,text.slice(a,b)));p=b}
  box.append(document.createTextNode(text.slice(p)));return box}
function run(){
  const text=inp.value.trim();res.replaceChildren();res.style.display='block';
  if(!text){res.append(el('p','empty','Paste an email above, or choose an example, then select Analyse Email.'));return}
  const r=analyse(text),col=r.score<30?'var(--low)':r.score<60?'var(--sus)':'var(--high)';
  res.style.setProperty('--r',col);
  const top=el('div','top'),C=2*Math.PI*78;
  const g=el('div','gauge');
  g.innerHTML='<svg width="180" height="180" viewBox="0 0 180 180" aria-hidden="true"><circle class="bg" cx="90" cy="90" r="78" fill="none" stroke-width="12"/><circle class="fg" cx="90" cy="90" r="78" fill="none" stroke-width="12" stroke-linecap="round" stroke-dasharray="'+C+'" stroke-dashoffset="'+C+'"/></svg>';
  const gn=el('div','gnum');gn.append(el('b',null,r.score),el('span',null,'out of 100'));g.append(gn);
  const sum=el('div');
  sum.append(el('div','badge',r.band));
  const msg={'Low Risk':'Few warning signs were found. That does not make the email safe, so stay cautious with unexpected requests.','Suspicious':'Several warning signs were found. Treat this email with caution and verify it independently before acting.','High Risk':'Many strong warning signs were found. Do not interact with this email. Verify independently or report it.'}[r.band];
  sum.append(el('p',null,msg));
  const bar=el('div','bar');const mk=el('i');mk.style.left=r.score+'%';bar.append(mk);
  const sc=el('div','scale');['0','Low','Suspicious','High','100'].forEach(x=>sc.append(el('span',null,x)));
  sum.append(bar,sc);top.append(g,sum);res.append(top);
  requestAnimationFrame(()=>requestAnimationFrame(()=>g.querySelector('.fg').style.strokeDashoffset=C*(1-r.score/100)));
  res.append(el('h2',null));
  res.lastChild.innerHTML='<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg> Why this score';
  res.lastChild.style.marginTop='28px';
  if(!r.found.length)res.append(el('p','empty','No warning signs from this tool\'s rule list were detected. Phishing can still be well disguised.'));
  r.found.forEach(x=>{const f=el('div','f'),h=el('header');h.append(el('span',null,x.n),el('span','pts','+'+x.p+' points'));f.append(h,el('p',null,x.why));
    if(x.ev.length)f.append(el('div','ev',x.ev.join('\n')));f.lastChild.style.whiteSpace='pre-wrap';res.append(f)});
  if(r.found.length)res.append(el('p','note','Total of all points: '+r.found.reduce((s,x)=>s+x.p,0)+(r.score===100?' (capped at 100).':'.')+'  Bands: 0 to 29 Low Risk, 30 to 59 Suspicious, 60 to 100 High Risk.'));
  r.skipped.forEach(s=>res.append(el('p','note','Not checked: '+s)));
  const hv=el('h2',null);hv.innerHTML='<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg> Where the warning signs appear';hv.style.marginTop='28px';res.append(hv,highlight(text,r.found.flatMap(x=>x.ev)));
  const h2=el('h2',null);h2.innerHTML='<svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><polyline points="9 12 11 14 15 10"></polyline></svg> What to do next';h2.style.marginTop='28px';res.append(h2);
  const ul=el('ul','rec'),n=r.names,rec=x=>ul.append(el('li',null,x));
  rec('Do not click links, open attachments, or reply to test whether this email is real.');
  rec('Verify independently: go to the organisation\'s official website or app by typing the address yourself, or use a phone number you already know.');
  if(n.includes('Request for a password')||n.includes('Request for MFA or verification code'))rec('Never share passwords or verification codes. If you already did, change your password right away, review account sign-ins, and contact the provider.');
  if(n.includes('Request to change bank details')||n.includes('Payment or gift-card request'))rec('Confirm any payment or bank change by phoning the person or company on a number you already have. Alert your finance team.');
  if(n.includes('Executable attachment')||n.includes('Unusual attachment type or filename')||n.includes('Asks you to enable macros or editing'))rec('Do not open the attachment. If you already did, disconnect from the network and contact your IT or security team.');
  if(r.band!=='Low Risk')rec('Report it: use your email provider\'s "Report phishing" option, or forward it to your IT or security team, then delete it.');
  else rec('If something still feels off, trust that feeling and check with the sender through another channel.');
  res.append(ul);
  const cp=el('button',null);
  cp.innerHTML='<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> <span>Copy report</span>';
  cp.style.marginTop='20px';
  cp.onclick=async()=>{const rep=['Phishing Email Analyser report','Score: '+r.score+'/100 ('+r.band+')',''].concat(r.found.map(x=>'+'+x.p+' '+x.n+(x.ev.length?' ['+x.ev.map(defang).join('; ')+']':'')),['','Educational triage only. Not proof that an email is safe or malicious. Links are defanged.']).join('\n');
    try{await navigator.clipboard.writeText(rep);cp.querySelector('span').textContent='Copied!'}catch(e){cp.querySelector('span').textContent='Copy unavailable'}};
  res.append(cp);res.scrollIntoView({behavior:'smooth',block:'start'});
}}
