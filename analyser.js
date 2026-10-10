/* ===== SCORING RULES: every rule has a fixed point value (p). Edit freely. ===== */
const BRANDS=['microsoft','office365','paypal','apple','amazon','netflix','dhl','fedex','royalmail','hmrc','google','docusign','dropbox'];
const OFFICIAL=['microsoft.com','office.com','live.com','paypal.com','apple.com','icloud.com','amazon.com','netflix.com','dhl.com','fedex.com','royalmail.com','gov.uk','google.com','docusign.com','dropbox.com','sharepoint.com'];
const SHORT=['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','rebrand.ly','cutt.ly','shorturl.at','rb.gy','shrt.example'];
const BADTLD=['top','xyz','click','zip','mov','icu','tk','work','support','cfd','sbs'];
const EXE=['exe','scr','js','jse','vbs','vbe','bat','cmd','msi','jar','ps1','hta','lnk','com','pif'];
const ODD=['zip','rar','7z','iso','img','html','htm','docm','xlsm','pptm','one'];
const m=(t,re)=>[...new Set([...t.matchAll(new RegExp(re.source,'gi'))].map(x=>x[0].trim()))].slice(0,4);
const dom=h=>h.split('.').slice(-2).join('.');
const isOfficial=h=>OFFICIAL.some(d=>h===d||h.endsWith('.'+d));
const RULES=[
{n:'Urgency or pressure language',p:10,why:'Phishers rush you so you act before thinking.',f:c=>m(c.t,/\b(urgent(ly)?|immediately|act now|right away|within (24|48) hours|asap|final (notice|warning)|expires? (today|soon)|last chance)\b/)},
{n:'Threat of account suspension or closure',p:15,why:'Fear of losing access is a classic pressure tactic.',f:c=>m(c.t,/\b(account (will be |has been |is )?(suspended|closed|deactivated|terminated|locked|restricted)|(suspend|deactivate|terminate|lock)(ed)? your (account|mailbox)|mailbox will be (deactivated|deleted)|will be (closed|suspended|deleted|locked))\b/)},
{n:'Request for a password',p:20,why:'Legitimate organisations do not ask you to send or confirm your password by email.',f:c=>m(c.t,/\b(confirm|enter|provide|send|reply with|update|verify|reset)\b[^.\n]{0,40}\bpassword\b|password[^.\n]{0,30}\b(expires?|expired)\b/)},
{n:'Request for MFA or verification code',p:25,why:'Codes are meant for your eyes only. Attackers ask for them to defeat multi-factor protection.',f:c=>m(c.t,/(send|share|reply|provide|enter|confirm|read out|give)[^.\n]{0,50}\b(code|otp|passcode)\b/)},
{n:'Payment or gift-card request',p:20,why:'Unusual payment methods and small "fees" are hard to trace or reverse.',f:c=>m(c.t,/\b(gift cards?|itunes card|google play card|bitcoin|cryptocurrency|wire transfer|western union|redelivery fee|processing fee|pay (a |the )?[£$€]\s?\d+[\d.,]*)/)},
{n:'Request to change bank details',p:25,why:'Changing payee details is the core of business email compromise fraud.',f:c=>m(c.t,/\b(new|updated|changed?|change|update)\b[^.\n]{0,30}\b(bank|account|payment|iban|sort code|routing)\s*(details|number|account|information)\b/)},
{n:'Suspicious web address',p:15,why:'Lookalike brand names, odd endings, hidden "@" signs or many hyphens often disguise the real site.',f:c=>c.urls.filter(u=>{const b=u.host.replace(/[-.]/g,'');return (BRANDS.some(x=>b.includes(x))&&!isOfficial(u.host))||/@/.test(u.href.replace(/^https?:\/\//,'').split('/')[0])||u.host.includes('xn--')||(u.host.match(/-/g)||[]).length>=3||BADTLD.includes(u.host.split('.').pop())||u.host.split('.').length>=5}).map(u=>u.href)},
{n:'Shortened link',p:12,why:'Link shorteners hide the real destination.',f:c=>c.urls.filter(u=>SHORT.includes(u.host)).map(u=>u.href)},
{n:'Link uses a raw IP address',p:20,why:'Real organisations use domain names, not numbers like 192.0.2.1.',f:c=>c.urls.filter(u=>/^\d{1,3}(\.\d{1,3}){3}$/.test(u.host)).map(u=>u.href)},
{n:'Misleading link text',p:20,why:'The visible link text shows one site but the link goes to another.',f:c=>c.urls.filter(u=>u.text&&u.shown&&dom(u.shown)!==dom(u.host)).map(u=>'Shown: '+u.shown+'  →  Goes to: '+u.host)},
{n:'Impersonation language',p:10,why:'Names of well-known brands or authority figures are used to borrow trust.',f:c=>m(c.t,/\b(microsoft|office ?365|paypal|apple id|amazon|netflix|dhl|fedex|royal mail|it (help ?desk|support)|security team|account team|support team|hmrc|irs|your ceo)\b/)},
{n:'Unusual attachment type or filename',p:20,why:'Double extensions (invoice.pdf.exe) and archive or HTML attachments are used to sneak malware past you.',f:c=>c.files.filter(x=>/\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|vbs|bat|cmd|lnk|zip|html?)$/i.test(x)||ODD.includes(x.split('.').pop().toLowerCase()))},
{n:'Executable attachment',p:30,why:'Program files can install malware as soon as they are opened.',f:c=>c.files.filter(x=>EXE.includes(x.split('.').pop().toLowerCase()))},
{n:'Asks you to enable macros or editing',p:25,why:'Macros are a common way to run malicious code from a document.',f:c=>m(c.t,/\benable (editing|content|macros?)\b/)},
{n:'Unexpected invoice or payment language',p:10,why:'Fake invoices rely on you paying without checking.',f:c=>m(c.t,/\b(invoice|payment (due|overdue|advice)|overdue|remittance|purchase order)\b/)},
{n:'Credential-harvesting language',p:12,why:'Phrases that push you to sign in via a link lead to fake login pages.',f:c=>m(c.t,/\b(sign[- ]?in|log[- ]?in|verify your (account|identity|email)|confirm your (identity|account)|update your (details|information|account)|click (here|below|the link))\b/)},
{n:'Display name impersonates a brand',p:15,why:'The name shown in your inbox claims a trusted brand, but the real sending address belongs to a different domain.',f:c=>{const b=c.h.name.toLowerCase().replace(/[^a-z0-9]/g,'');return BRANDS.some(x=>b.includes(x))&&c.h.from&&!isOfficial(c.h.from)?['Display name: '+c.h.name+'  /  Sender domain: '+c.h.from]:[]}},
{n:'Sender and Reply-To domains differ',p:20,why:'Replies would go to a different address than the one that appears to have sent the email.',f:c=>c.h.from&&c.h.reply&&dom(c.h.from)!==dom(c.h.reply)?['From: '+c.h.from+'  /  Reply-To: '+c.h.reply]:[]},
{n:'SPF check failed',p:15,why:'The sending server was not authorised to send for that domain.',f:c=>/spf=(fail|softfail|permerror)|received-spf:\s*(fail|softfail)/i.test(c.t)?[c.t.match(/(spf=\w+|received-spf:\s*\w+)/i)[0]]:[]},
{n:'DKIM check failed',p:12,why:'The message signature did not validate, so it may have been forged or altered.',f:c=>/dkim=(fail|permerror)/i.test(c.t)?['dkim=fail']:[]},
{n:'DMARC check failed',p:15,why:'The sender domain\'s own policy says this message did not pass authentication.',f:c=>/dmarc=(fail|permerror)/i.test(c.t)?['dmarc=fail']:[]}
];
const COMBO={n:'Combination: pressure plus a sensitive request',p:10,why:'Urgency or threats together with a request for credentials, codes or money is the classic phishing pattern.'};
const SENS=['Request for a password','Request for MFA or verification code','Payment or gift-card request','Request to change bank details','Credential-harvesting language'];
const PRESS=['Urgency or pressure language','Threat of account suspension or closure'];

function parse(t){
  const urls=[],seen=new Set();
  const add=(href,text)=>{try{const h=new URL(href).hostname.toLowerCase();if(seen.has(href))return;seen.add(href);
    const mt=text&&text.replace(/<[^>]*>/g,'').match(/(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})/i);
    urls.push({href,host:h,text,shown:mt?mt[1].toLowerCase():''})}catch(e){}};
  for(const a of t.matchAll(/<a\s[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi))add(a[1],a[2]);
  for(const u of t.matchAll(/https?:\/\/[^\s<>"')\]]+/gi))add(u[0].replace(/[.,;]+$/,''),'');
  const noUrl=t.replace(/https?:\/\/\S+/gi,' ');
  const files=[...new Set([...noUrl.matchAll(/[\w\-()]+(?:\.[\w\-]+)*\.(?:exe|scr|js|jse|vbs|vbe|bat|cmd|msi|jar|ps1|hta|lnk|pif|zip|rar|7z|iso|img|html?|docm|xlsm|pptm|one|pdf|docx?|xlsx?)\b/gi)].map(x=>x[0]))];
  const g=re=>{const x=t.match(re);return x?x[1].trim():''};
  const addr=s=>{const x=s.match(/@([a-z0-9.-]+\.[a-z]{2,})/i);return x?x[1].toLowerCase():''};
  return{t,urls,files,h:{name:g(/^from:\s*\"?([^\"<\n]*?)\"?\s*</im),from:addr(g(/^from:\s*(.+)$/im)),reply:addr(g(/^reply-to:\s*(.+)$/im)),
    auth:/(spf|dkim|dmarc)=\w+|received-spf:/i.test(t)}};
}
function analyse(text){
  const c=parse(text),found=[];
  RULES.forEach(r=>{const ev=r.f(c);if(ev&&ev.length)found.push({n:r.n,p:r.p,why:r.why,ev})});
  const names=found.map(x=>x.n);
  if(PRESS.some(x=>names.includes(x))&&SENS.some(x=>names.includes(x)))found.push({...COMBO,ev:[]});
  const score=Math.min(100,found.reduce((s,x)=>s+x.p,0));
  const band=score<30?'Low Risk':score<60?'Suspicious':'High Risk';
  const skipped=[];
  if(!c.h.auth)skipped.push('SPF, DKIM and DMARC were not checked because no authentication headers were found.');
  if(!(c.h.from&&c.h.reply))skipped.push('The sender and Reply-To comparison was skipped because both headers were not present.');
  if(!c.urls.length)skipped.push('No links were found in the pasted text.');
  return{score,band,found,skipped,names};
}


if(typeof module!=='undefined')module.exports={analyse};
