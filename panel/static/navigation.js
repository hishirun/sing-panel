'use strict';
window.panelScope=new AbortController();
window.panelListen=(target,type,listener,options={})=>target.addEventListener(type,listener,{...(typeof options==='boolean'?{capture:options}:options),signal:window.panelScope.signal});
window.panelAsyncForms=true;
(()=>{
 let pending=null,sequence=0,submitting=false;
 const prefix=()=>document.getElementById('admin-content')?.dataset.admin;
 const eligible=url=>url.origin===location.origin&&prefix()!=null&&(url.pathname===prefix()+'/'||url.pathname.startsWith(prefix()+'/'))&&!/\/(login|logout|backup|preview)(\/|$)/.test(url.pathname);
 const loading=value=>{document.getElementById('admin-content')?.setAttribute('aria-busy',String(value));document.body.classList.toggle('page-loading',value);};
 async function render(html,url,{push=true,keepScroll=false}={}){
  const content=document.getElementById('admin-content'),next=html.getElementById('admin-content');
  if(!next||!html.body.classList.contains('admin-shell'))throw Error('session');
  const scripts=[...next.querySelectorAll('script[src]')].map(s=>s.getAttribute('src'));next.querySelectorAll('script').forEach(s=>s.remove());const y=window.scrollY;
  window.panelScope.abort();window.panelScope=new AbortController();document.dispatchEvent(new Event('panel:dispose'));document.querySelectorAll('.select-popup').forEach(n=>n.remove());
  content.replaceChildren(...next.childNodes);content.dataset.admin=next.dataset.admin;document.title=html.title;
  const links=[...html.querySelectorAll('.admin-nav a')];document.querySelectorAll('.admin-nav a').forEach((a,i)=>{if(links[i]){a.href=links[i].href;a.classList.toggle('current',links[i].classList.contains('current'));}});
  if(push&&url!==location.href)history.pushState({panel:true},'',url);
  for(const src of [...scripts,'/static/select.js?v=4'])await new Promise((resolve,reject)=>{const script=document.createElement('script');script.src=src;script.onload=()=>{script.remove();resolve();};script.onerror=reject;document.body.append(script);});
  window.scrollTo(0,keepScroll?y:0);content.querySelector('h1')?.setAttribute('tabindex','-1');content.querySelector('h1')?.focus({preventScroll:true});
 }
 async function navigate(url,push=true){
  const id=++sequence;pending?.abort();pending=new AbortController();loading(true);
  try{const response=await fetch(url,{signal:pending.signal,credentials:'same-origin',cache:'no-store',headers:{'X-Panel-Navigation':'1'}});if(response.status===401){location.assign(prefix()+'/login?expired=1');return;}if(!response.ok||!response.headers.get('content-type')?.includes('text/html'))throw Error('navigation');const html=new DOMParser().parseFromString(await response.text(),'text/html');if(id!==sequence)return;if(!html.body.classList.contains('admin-shell')){location.assign(response.url);return;}await render(html,response.url,{push});}
  catch(error){if(error.name!=='AbortError'&&id===sequence)location.assign(url);}
  finally{if(id===sequence){loading(false);pending=null;}}
 }
 document.addEventListener('click',event=>{const a=event.target.closest('a[href]');if(!a||event.defaultPrevented||event.button!==0||event.ctrlKey||event.metaKey||event.shiftKey||event.altKey||a.target||a.hasAttribute('download'))return;const url=new URL(a.href);if(!eligible(url)||url.hash)return;event.preventDefault();if(!submitting)navigate(url.href);});
 document.addEventListener('submit',async event=>{
  const form=event.target;if(!form.closest('#admin-content')||prefix()==null||event.defaultPrevented)return;
  // Controls named action/method/target shadow HTMLFormElement properties.
  const button=event.submitter,url=new URL(button?.getAttribute('formaction')||form.getAttribute('action')||location.href,location.href),method=(button?.getAttribute('formmethod')||form.getAttribute('method')||'get').toUpperCase();
  if(!eligible(url)||button?.getAttribute('formtarget')||form.getAttribute('target'))return;event.preventDefault();if(submitting)return;
  const data=new FormData(form);if(button?.name)data.append(button.name,button.value);
  if(method==='GET'){url.search=new URLSearchParams(data).toString();navigate(url.href);return;}
  submitting=true;
  if(form.dataset.confirm&&!(await window.panelConfirm(form.dataset.confirm,button?.textContent.trim()||'确认操作'))){submitting=false;return;}
  const buttons=[...form.querySelectorAll('button,input[type=submit]')];const states=buttons.map(b=>b.disabled);buttons.forEach(b=>b.disabled=true);loading(true);
  try{
   const response=await fetch(url,{method,body:data,credentials:'same-origin',headers:{'X-Panel-Navigation':'1'}});
   if(response.status===401){location.assign(prefix()+'/login?expired=1');return;}
   if(!response.headers.get('content-type')?.includes('text/html')){let detail='操作未完成，请稍后重试';try{const result=await response.json();if(typeof result.detail==='string')detail=result.detail;}catch(_){}window.panelToast(detail,true);return;}
   const html=new DOMParser().parseFromString(await response.text(),'text/html'),next=html.getElementById('admin-content');
   if(!next||!html.body.classList.contains('admin-shell')){location.assign(response.url);return;}
   const error=next.querySelector('.alert,[role=alert]'),notice=next.querySelector('[role=status]');const message=error?.textContent.trim()||notice?.textContent.trim();
   const destination=response.redirected?response.url:location.href;
   await render(html,destination,{keepScroll:destination===location.href});
   if(error||!response.ok)window.panelToast(message||'操作未完成，请检查输入',true);
   else if(data.get('intent')!=='import')window.panelToast(message||'操作成功');
  }catch(_){window.panelToast('请求中断，请核对当前状态后再操作',true);}
  finally{buttons.forEach((b,i)=>b.disabled=states[i]);submitting=false;loading(false);}
 });
 window.addEventListener('popstate',()=>{if(eligible(new URL(location.href)))navigate(location.href,false);else location.reload();});
})();
