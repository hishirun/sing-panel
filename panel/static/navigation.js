'use strict';
window.panelScope=new AbortController();
window.panelListen=(target,type,listener,options={})=>target.addEventListener(type,listener,{...(typeof options==='boolean'?{capture:options}:options),signal:window.panelScope.signal});
(()=>{
 let pending=null,sequence=0;
 const prefix=()=>document.getElementById('admin-content')?.dataset.admin;
 const eligible=url=>url.origin===location.origin&&prefix()!=null&&(url.pathname===prefix()+'/'||url.pathname.startsWith(prefix()+'/'))&&!/\/(login|logout|backup|preview)(\/|$)/.test(url.pathname);
 async function navigate(url,push=true){
  const id=++sequence;pending?.abort();pending=new AbortController();const content=document.getElementById('admin-content');content.setAttribute('aria-busy','true');document.body.classList.add('page-loading');
  try{
   const response=await fetch(url,{signal:pending.signal,credentials:'same-origin',cache:'no-store',headers:{'X-Panel-Navigation':'1'}});
   if(!response.ok||!response.headers.get('content-type')?.includes('text/html'))throw Error('navigation');
   const html=new DOMParser().parseFromString(await response.text(),'text/html');const next=html.getElementById('admin-content');
   if(!next||!html.body.classList.contains('admin-shell'))throw Error('session');
   if(id!==sequence)return;
   const scripts=[...next.querySelectorAll('script[src]')].map(s=>s.getAttribute('src'));next.querySelectorAll('script').forEach(s=>s.remove());
   window.panelScope.abort();window.panelScope=new AbortController();document.dispatchEvent(new Event('panel:dispose'));document.querySelectorAll('.select-popup').forEach(n=>n.remove());
   content.replaceChildren(...next.childNodes);document.title=html.title;
   document.querySelectorAll('.admin-nav a').forEach(a=>{const match=[...html.querySelectorAll('.admin-nav a')].find(b=>b.getAttribute('href')===a.getAttribute('href'));a.classList.toggle('current',!!match?.classList.contains('current'));});
   if(push)history.pushState({panel:true},'',response.url);window.scrollTo(0,0);
   for(const src of [...scripts,'/static/select.js?v=4']){
    if(id!==sequence)return;
    await new Promise((resolve,reject)=>{const script=document.createElement('script');script.src=src;script.onload=()=>{script.remove();resolve();};script.onerror=reject;document.body.append(script);});
   }
   content.querySelector('h1')?.setAttribute('tabindex','-1');content.querySelector('h1')?.focus({preventScroll:true});
  }catch(error){if(error.name!=='AbortError'&&id===sequence)location.assign(url);}
  finally{if(id===sequence){content.removeAttribute('aria-busy');document.body.classList.remove('page-loading');pending=null;}}
 }
 document.addEventListener('click',event=>{const a=event.target.closest('a[href]');if(!a||event.defaultPrevented||event.button!==0||event.ctrlKey||event.metaKey||event.shiftKey||event.altKey||a.target||a.hasAttribute('download'))return;const url=new URL(a.href);if(!eligible(url)||url.hash)return;event.preventDefault();navigate(url.href);});
 window.addEventListener('popstate',()=>{if(eligible(new URL(location.href)))navigate(location.href,false);else location.reload();});
})();
