'use strict';
window.panelPageScripts.register(document.currentScript.src,()=>{
 const root=document.getElementById('diagnostic-panel');if(!root)return;
 const signal=window.panelScope.signal,output=root.querySelector('pre'),search=root.querySelector('[data-log-search]'),level=root.querySelector('[data-log-level]');let paused=false,last='',latest='';
 const bytes=n=>{if(typeof n!=='number')return '—';let i=0;while(n>=1024&&i<4){n/=1024;i++;}return n.toFixed(1)+' '+['B','KiB','MiB','GiB','TiB'][i];};
 const put=(key,value)=>{root.querySelector('[data-live="'+key+'"]').textContent=value;};
 const render=()=>{const query=search.value.toLowerCase(),kind=level.value;const lines=last.split('\n').filter(line=>(!query||line.toLowerCase().includes(query))&&(!kind||new RegExp('\\b'+kind+'\\b','i').test(line)));output.textContent=lines.join('\n')||'暂无匹配日志';};
 window.panelListen(search,'input',render);window.panelListen(level,'change',render);
 window.panelListen(root.querySelector('[data-log-pause]'),'click',event=>{paused=!paused;event.target.textContent=paused?'继续更新':'暂停更新';event.target.setAttribute('aria-pressed',String(paused));if(!paused){last=latest;render();}});
 window.panelListen(root.querySelector('[data-log-copy]'),'click',async()=>{try{await navigator.clipboard.writeText(output.textContent);window.panelToast('日志已复制');}catch(_){window.panelToast('复制失败，请选择日志复制',true);}});
 window.panelStream(root.dataset.url,signal,data=>{if(signal.aborted)return;const m=data.metrics||{};put('cpu',typeof m.cpu==='number'?m.cpu.toFixed(1)+'%':'—');put('memory',m.memory?bytes(m.memory.used)+' / '+bytes(m.memory.total):'—');put('disk',m.disk?bytes(m.disk.used)+' / '+bytes(m.disk.total):'—');put('network','↓ '+bytes(m.rx)+'/s · ↑ '+bytes(m.tx)+'/s');put('total','↓ '+bytes(m.rx_total)+' · ↑ '+bytes(m.tx_total));put('status',data.online?(m.running?'核心运行中':'核心已停止'):'服务器离线');put('updated',data.timestamp?new Date(data.timestamp*1000).toLocaleTimeString():'等待 Agent 上报日志');put('error',data.error||'');latest=data.logs||'';if(!paused){last=latest;render();}},value=>put('connection',value));
});
