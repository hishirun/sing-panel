'use strict';
(() => {
  let opened=null,serial=0;
  const controls=[];
  const close=()=>{if(!opened)return;opened.popup.remove();opened.button.setAttribute('aria-expanded','false');opened=null;};
  document.querySelectorAll('select').forEach(select=>{
    if(select.name==='geoip' && typeof Intl.DisplayNames==='function'){
      const regions=new Intl.DisplayNames(['zh-CN'],{type:'region'});
      for(const option of select.options){try{option.text=regions.of(option.value.toUpperCase())+' · '+option.value.toUpperCase();}catch(_) {}}
    }
    if(select.name==='geosite'){
      const names={'cn':'中国域名','geolocation-cn':'中国站点','geolocation-!cn':'海外站点','category-ads-all':'广告与追踪','category-ai-!cn':'海外 AI 服务','category-social-media-!cn':'海外社交媒体','category-games':'游戏','category-porn':'成人内容','google':'谷歌','github':'GitHub','openai':'OpenAI','telegram':'Telegram','netflix':'Netflix','youtube':'YouTube','apple':'苹果','microsoft':'微软'};
      for(const option of select.options)if(names[option.value])option.text=names[option.value]+' · '+option.value;
    }
    const root=document.createElement('div');root.className='select-control';
    const button=document.createElement('button');button.type='button';button.className='select-trigger';button.setAttribute('role','combobox');button.setAttribute('aria-haspopup','listbox');button.setAttribute('aria-expanded','false');
    const caption=document.createElement('span');button.append(caption);
    const label=select.closest('label');let name=select.getAttribute('aria-label');
    if(!name && label){const copy=label.cloneNode(true);copy.querySelectorAll('select,input,small,textarea').forEach(x=>x.remove());name=copy.textContent.trim();}
    button.setAttribute('aria-label',name||'选择选项');
    select.after(root);root.append(button);select.classList.add('select-native');
    const popup=document.createElement('div');popup.className='select-popup';popup.id='select-list-'+(++serial);button.setAttribute('aria-controls',popup.id);
    const search=document.createElement('input');search.type='search';search.placeholder='搜索选项…';search.autocomplete='off';search.setAttribute('aria-label','搜索'+(name||'选项'));
    const list=document.createElement('div');list.className='select-options';list.setAttribute('role','listbox');if(select.multiple)list.setAttribute('aria-multiselectable','true');
    const status=document.createElement('div');status.className='select-status';status.setAttribute('aria-live','polite');
    popup.append(search,list,status);
    if(select.multiple){const clear=document.createElement('button');clear.type='button';clear.className='select-clear';clear.textContent='清空选择';clear.addEventListener('click',()=>{for(const option of select.options)option.selected=false;select.dispatchEvent(new Event('change',{bubbles:true}));render();search.focus();});popup.append(clear);}
    const sync=()=>{const chosen=[...select.selectedOptions];caption.textContent=select.multiple?(chosen.length?chosen.slice(0,2).map(o=>o.text).join('、')+(chosen.length>2?' 等 '+chosen.length+' 项':''):select.dataset.placeholder||'选择多个选项'):chosen[0]?.text||'请选择';button.disabled=select.disabled;root.hidden=select.hidden;button.title=chosen.map(o=>o.text).join('、');};controls.push(sync);
    let cursor=0;
    const render=()=>{list.replaceChildren();const query=search.value.trim().toLowerCase();const options=[...select.options].filter(o=>!o.hidden&&o.text.toLowerCase().includes(query));
      options.slice(0,150).forEach(o=>{const item=document.createElement('button');item.type='button';item.className='select-option';item.setAttribute('role','option');item.setAttribute('aria-selected',String(o.selected));item.disabled=o.disabled;item.textContent=o.text;item.addEventListener('click',()=>{if(select.multiple)o.selected=!o.selected;else select.value=o.value;select.dispatchEvent(new Event('input',{bubbles:true}));select.dispatchEvent(new Event('change',{bubbles:true}));sync();if(select.multiple){render();search.focus();}else{close();button.focus();}});list.append(item);});status.textContent=options.length>150?'找到 '+options.length+' 项，请搜索缩小范围':options.length?'共 '+options.length+' 项'+(select.multiple?' · 可多选':''):'没有匹配的选项';cursor=0;};
    const open=()=>{if(opened?.button===button){close();return;}close();document.body.append(popup);opened={button,popup};button.setAttribute('aria-expanded','true');search.value='';search.hidden=select.options.length<7&&!select.multiple;render();const rect=button.getBoundingClientRect();const height=Math.min(360,innerHeight-24);popup.style.width=Math.min(Math.max(rect.width,240),innerWidth-24)+'px';popup.style.left=Math.max(12,Math.min(rect.left,innerWidth-popup.offsetWidth-12))+'px';popup.style.maxHeight=height+'px';popup.style.top=(rect.bottom+height>innerHeight&&rect.top>height?rect.top-Math.min(popup.offsetHeight,height)-6:Math.min(rect.bottom+6,innerHeight-Math.min(popup.offsetHeight,height)-12))+'px';if(!search.hidden)search.focus();else list.querySelector('[aria-selected=true]')?.focus();};
    button.addEventListener('click',open);button.addEventListener('keydown',e=>{if(['ArrowDown','ArrowUp'].includes(e.key)){e.preventDefault();open();}});
    popup.addEventListener('keydown',e=>{const items=[...list.querySelectorAll('button:not(:disabled)')];if(e.key==='Escape'){e.preventDefault();close();button.focus();}else if(e.key==='Tab')close();else if(['ArrowDown','ArrowUp','Home','End'].includes(e.key)){e.preventDefault();const current=items.indexOf(document.activeElement);cursor=e.key==='Home'?0:e.key==='End'?items.length-1:Math.max(0,Math.min(items.length-1,current+(e.key==='ArrowDown'?1:-1)));items[cursor]?.focus();}});
    search.addEventListener('input',render);select.addEventListener('change',sync);select.addEventListener('invalid',e=>{e.preventDefault();button.focus();button.setAttribute('aria-invalid','true');});select.addEventListener('change',()=>button.removeAttribute('aria-invalid'));
    new MutationObserver(sync).observe(select,{childList:true,subtree:true,attributes:true,attributeFilter:['disabled','selected','hidden']});sync();
  });
  document.addEventListener('change',()=>queueMicrotask(()=>controls.forEach(fn=>fn())));
  document.addEventListener('reset',()=>setTimeout(()=>controls.forEach(fn=>fn()),0));
  document.addEventListener('pointerdown',e=>{if(opened&&!opened.popup.contains(e.target)&&!opened.button.contains(e.target))close();});
  window.addEventListener('resize',close);window.addEventListener('scroll',e=>{if(opened&&!opened.popup.contains(e.target))close();},true);
})();
