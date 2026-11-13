'use strict';
(()=>{
 const list=document.getElementById('fleet-panel'),enroll=document.getElementById('fleet-enroll'),root=list||enroll;
 if(!root)return;
 const signal=window.panelScope?.signal;
 const listen=window.panelListen||((target,type,handler)=>target.addEventListener(type,handler));
 const statusUrl=root.dataset.fleetUrl;
 let timer=null,expiryTimer=null,filter='all',disposed=false,enrolled=false;
 const numeric=value=>typeof value==='number'&&Number.isFinite(value);
 const number=value=>numeric(value)?value:0;
 const bytes=value=>{if(!numeric(value))return '—';const amount=Math.max(0,value);for(const [power,unit] of [[5,'PiB'],[4,'TiB'],[3,'GiB'],[2,'MiB'],[1,'KiB']])if(amount>=1024**power)return (amount/1024**power).toFixed(2)+' '+unit;return Math.round(amount)+' B';};
 const rate=value=>numeric(value)?bytes(value)+'/s':'—';
 const percentage=value=>numeric(value)?value.toFixed(1)+'%':'—';
 const moment=value=>value?new Date(value*1000).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'})+' UTC+8':'';
 const text=(scope,field,value)=>{const target=scope.querySelector('[data-fleet-field="'+field+'"]');if(target&&target.textContent!==String(value))target.textContent=value;};
 const setMeter=(scope,field,value)=>{const target=scope.querySelector('[data-fleet-meter="'+field+'"]');if(!target)return;target.value=numeric(value)?Math.max(0,Math.min(100,value)):0;target.dataset.known=String(numeric(value));target.setAttribute('aria-valuetext',percentage(value));};
 const filterRows=()=>{
  if(!list)return;
  let shown=0;
  list.querySelectorAll('[data-server-id]').forEach(row=>{const online=row.dataset.online==='true';row.hidden=filter==='online'?!online:filter==='offline'?online:false;if(!row.hidden)shown++;});
  const empty=list.querySelector('[data-fleet-empty]');if(empty)empty.hidden=shown>0;
 };
 function stateLabel(row){return row.online?'在线':!row.enabled?'接入已撤销':row.last_seen?'离线':'待接入';}
 function syncLabel(row){
  if(row.traffic?.blocked)return row.online&&row.metrics?.running===false?'超额 · 核心已停':'超额 · 等待停机';
  if(row.error)return '应用异常';
  if(row.is_local)return '本机管理';
  if(row.desired_state==='stopped')return !row.online?'停止待确认':row.metrics?.running===false?'核心已停止':'正在停止';
  if(row.desired_revision&&row.applied_revision===row.desired_revision)return row.online?'已同步':'上次已同步';
  if(!row.desired_revision)return '等待下发';
  return row.online?'同步中':'等待同步';
 }
 function summaryValues(rows,provided){
  const seen=new Set(),physical=[];
  [...rows].sort((a,b)=>Number(Boolean(b.is_local))-Number(Boolean(a.is_local))).forEach(row=>{const key=row.metrics?.boot_id?'boot:'+row.metrics.boot_id:'server:'+row.id;if(!seen.has(key)){seen.add(key);physical.push(row);}});
  const fallback={total:rows.length,online:rows.filter(row=>row.online).length,rx:null,tx:null,monthly_used:0,monthly_rx:0,monthly_tx:0,busy_name:'',busy_cpu:null};
  physical.forEach(row=>{
   const metrics=row.metrics||{},traffic=row.traffic||{};
   for(const [key,value] of [['monthly_used',traffic.used],['monthly_rx',traffic.rx],['monthly_tx',traffic.tx]])fallback[key]+=number(value);
   if(!row.online)return;
   for(const key of ['rx','tx'])if(numeric(metrics[key]))fallback[key]=number(fallback[key])+metrics[key];
   if(numeric(metrics.cpu)&&(!numeric(fallback.busy_cpu)||metrics.cpu>fallback.busy_cpu)){fallback.busy_cpu=metrics.cpu;fallback.busy_name=row.name;}
  });
  return {...fallback,...(provided&&typeof provided==='object'?provided:{})};
 }
 const samples=[];
 function sparkline(rx,tx){
  if(!list)return;
  const now=Date.now();samples.push({time:now,rx:numeric(rx)?rx:null,tx:numeric(tx)?tx:null});
  while(samples.length>36||samples.length&&now-samples[0].time>180000)samples.shift();
  const svg=list.querySelector('[data-fleet-sparkline]');if(!svg)return;
  const valid=samples.filter(point=>numeric(point.rx)||numeric(point.tx));
  const ceiling=Math.max(1,...valid.flatMap(point=>[number(point.rx),number(point.tx)]));
  const first=samples[0]?.time||now,span=Math.max(1,now-first);let drawn=false;
  for(const direction of ['rx','tx']){
   let path='',previous=null,segments=0;
   for(const point of samples){
    if(!numeric(point[direction])){previous=null;continue;}
    const x=2+(point.time-first)/span*296,y=45-Math.max(0,point[direction])/ceiling*40;
    const connect=previous&&point.time-previous.time<=15000;
    path+=(connect?'L':'M')+x.toFixed(1)+','+y.toFixed(1)+' ';if(connect)segments++;previous=point;
   }
   const target=svg.querySelector('[data-fleet-spark="'+direction+'"]');target?.setAttribute('d',segments?path.trim():'');drawn=drawn||segments>0;
  }
  svg.setAttribute('aria-label',drawn?'最近 '+valid.length+' 次真实轮询的接收和发送速率，接收实线，发送虚线':'等待更多真实网速采样');
  const empty=list.querySelector('[data-fleet-spark-empty]');if(empty){empty.hidden=drawn;empty.textContent=valid.length?'正在收集采样':'暂无速率数据';}
  const caption=list.querySelector('[data-fleet-spark-caption]');if(caption)caption.textContent=drawn?'最近 '+valid.length+' 次采样 · 接收实线 / 发送虚线':'接收实线 · 发送虚线';
 }
 function updateSummary(rows,provided){
  const totals=summaryValues(rows,provided);
  const values={...totals,busy_cpu:percentage(totals.busy_cpu),busy_name:totals.busy_name||'等待有效采样',availability:totals.online===totals.total&&totals.total?'全部在线':(totals.total-totals.online)+' 台未连接',rx:rate(totals.rx),tx:rate(totals.tx),monthly_used:bytes(totals.monthly_used),monthly_rx:bytes(totals.monthly_rx),monthly_tx:bytes(totals.monthly_tx)};
  Object.entries(values).forEach(([key,value])=>{const node=list.querySelector('[data-fleet-summary="'+key+'"]');if(node&&node.textContent!==String(value))node.textContent=String(value);});
  Object.entries({all:totals.total,online:totals.online,offline:totals.total-totals.online}).forEach(([key,value])=>{const node=list.querySelector('[data-fleet-count="'+key+'"]');if(node)node.textContent=String(value);});
  sparkline(totals.rx,totals.tx);
 }
 function updateInterfaces(root,items,online){
  const fragment=document.createDocumentFragment(),heading=document.createElement('div');heading.className='fleet-interface-heading';
  for(const caption of ['网卡','接收 / 发送','累计流量']){const cell=document.createElement('span');cell.textContent=caption;heading.append(cell);}fragment.append(heading);
  for(const item of items){
   const row=document.createElement('div');row.className='fleet-interface-row'+(item.billable===false?' not-billable':'');
   const name=document.createElement('span'),hint=document.createElement('small');name.textContent=String(item.name||'—');hint.textContent=item.billable===false?'不计入额度':'计入额度';name.append(hint);
   const rates=document.createElement('span');rates.append(document.createTextNode('↓ '+rate(online?item.rx:null)),document.createElement('br'),document.createTextNode('↑ '+rate(online?item.tx:null)));
   const total=document.createElement('span');total.textContent=numeric(item.rx_total)||numeric(item.tx_total)?bytes(number(item.rx_total)+number(item.tx_total)):'—';row.append(name,rates,total);fragment.append(row);
  }
  if(!items.length){const empty=document.createElement('p');empty.className='muted';empty.textContent='网卡信息等待上报';fragment.append(empty);}
  root.replaceChildren(fragment);
 }
 function updateRows(rows,summary){
  if(!list)return;
  const byId=new Map(rows.map(row=>[row.id,row]));updateSummary(rows,summary);
  list.querySelectorAll('[data-server-id]').forEach(card=>{
   const row=byId.get(card.dataset.serverId);if(!row)return;
   const metrics=row.metrics||{};card.dataset.online=String(Boolean(row.online));
   text(card,'status',stateLabel(row));const state=card.querySelector('.fleet-state');state?.classList.toggle('is-online',Boolean(row.online));state?.classList.toggle('is-offline',!row.online);
   const platform=[metrics.os,metrics.arch].filter(value=>typeof value==='string'&&value).join(' · ');text(card,'platform',platform);const platformNode=card.querySelector('[data-fleet-field="platform"]');if(platformNode)platformNode.hidden=!platform;
   const version=row.core_version||'核心版本待上报';text(card,'core_version',/^\d/.test(version)?'sing-box '+version:version);
   text(card,'core_state',typeof metrics.running==='boolean'?(row.online?'':'上次 · ')+(metrics.running?'核心运行中':'核心已停止'):'核心状态待上报');text(card,'agent_version',row.is_local?'由主面板管理':row.agent_version?'Agent '+row.agent_version:'Agent 待接入');
   text(card,'last_seen',row.is_local?'本机实时状态':row.last_seen?'最近心跳 '+moment(row.last_seen):'尚未收到心跳');
   text(card,'cpu_label','CPU'+(numeric(metrics.cores)&&metrics.cores>0?' '+metrics.cores+' 核':''));
   text(card,'cpu',percentage(metrics.cpu));text(card,'memory',percentage(metrics.memory?.percent));text(card,'disk',percentage(metrics.disk?.percent));
   setMeter(card,'cpu',metrics.cpu);setMeter(card,'memory',metrics.memory?.percent);setMeter(card,'disk',metrics.disk?.percent);
   text(card,'rx',rate(row.online?metrics.rx:null));text(card,'tx',rate(row.online?metrics.tx:null));text(card,'rx_total',bytes(metrics.rx_total));text(card,'tx_total',bytes(metrics.tx_total));
   text(card,'nodes_count',String(number(row.nodes_count)));text(card,'sync',syncLabel(row));const sync=card.querySelector('[data-fleet-field="sync"]');sync?.classList.toggle('fleet-warning',Boolean(row.error)||Boolean(row.traffic?.blocked));
   const error=card.querySelector('[data-fleet-field="error"]');if(error){error.textContent=row.error||'';error.hidden=!row.error;}
   const traffic=row.traffic||{},used=number(traffic.used),quota=number(traffic.quota),quotaPercent=quota?100*used/quota:null;
   text(card,'monthly_usage',bytes(used)+' / '+(quota?bytes(quota):'不限量'));text(card,'monthly_percent',quota?percentage(quotaPercent):'不限量');setMeter(card,'monthly',quotaPercent);
   card.querySelector('.fleet-machine-quota')?.classList.toggle('fleet-quota-blocked',Boolean(traffic.blocked));
   text(card,'traffic_direction',({both:'双向计额',rx:'接收计额',tx:'发送计额'})[traffic.direction||row.traffic_direction]||'双向计额');
   text(card,'monthly_reset','每月 '+(row.reset_day||1)+' 日重置 · UTC+8');const reset=card.querySelector('[data-fleet-field="monthly_reset"]');if(reset)reset.title=traffic.next_reset?'下次重置 '+moment(traffic.next_reset):'';
   text(card,'memory_bytes',bytes(metrics.memory?.used)+' / '+bytes(metrics.memory?.total));text(card,'disk_bytes',bytes(metrics.disk?.used)+' / '+bytes(metrics.disk?.total));
   text(card,'load',Array.isArray(metrics.load)&&metrics.load.length?metrics.load.join(' / '):'负载待上报');
   const uptime=number(metrics.uptime);text(card,'uptime',numeric(metrics.uptime)?(row.online?'运行 ':'上次运行 ')+Math.floor(uptime/86400)+' 天 '+Math.floor(uptime%86400/3600)+' 小时':'运行时间待上报');
   const command=card.querySelector('[data-fleet-field="command_status"]');if(command){const latest=row.last_command;command.hidden=!latest?.action;if(latest?.action){const action={restart:'重启核心',resync:'同步配置',stop:'停止核心',start:'启动核心',update_agent:'更新 Agent'}[latest.action]||'操作';const status={pending:'等待执行',succeeded:'已完成',failed:'失败'}[latest.status]||'等待回报';command.textContent=action+' · '+status+(latest.error?'：'+latest.error:'');command.classList.toggle('fleet-warning',latest.status==='failed');}}
   const interfaces=card.querySelector('[data-fleet-interfaces]');if(interfaces&&Array.isArray(metrics.interfaces))updateInterfaces(interfaces,metrics.interfaces,row.online);
   const power=card.querySelector('button[name="action"][value="stop"],button[name="action"][value="start"]');
   if(power){const stopped=row.desired_state==='stopped';power.value=stopped?'start':'stop';power.textContent=stopped?'启动代理核心':'停止代理核心';power.form.dataset.confirm=stopped?'启动此服务器的代理核心？':'停止此服务器的代理核心？该机节点将暂时无法连接。';}
  });
  filterRows();
 }
 function expiry(){
  if(!enroll||enrolled)return;
  const remaining=Math.max(0,Math.ceil(Number(enroll.dataset.expires)-Date.now()/1000));
  const label=enroll.querySelector('[data-fleet-expiry]');if(label)label.textContent=remaining?'接入码剩余 '+Math.floor(remaining/60)+' 分 '+remaining%60+' 秒':'接入码已过期';
  if(!remaining){enroll.querySelector('[data-fleet-command]').hidden=true;enroll.querySelector('[data-fleet-expired]').hidden=false;}
 }
 function updateEnrollment(rows){
  if(!enroll)return;
  const row=rows.find(item=>item.id===enroll.dataset.serverId);if(!row)return;
  if(row.online&&row.enrollment_consumed&&Number(row.enroll_expires)===Number(enroll.dataset.expires)){
   enrolled=true;
   enroll.querySelector('[data-fleet-enroll-title]').textContent='Agent 已连接';
   enroll.querySelector('[data-fleet-enroll-message]').textContent=row.error?'接入成功，核心配置待处理：'+row.error:'服务器已接入，可以创建并分配节点。';
   const status=enroll.querySelector('[data-fleet-enroll-status]');status.textContent=row.error?'已连接 · 配置待处理':'连接正常';status.classList.add('connected');status.classList.remove('error');
   enroll.querySelector('[data-fleet-enroll-next]').hidden=false;enroll.querySelector('[data-fleet-command]').hidden=true;enroll.querySelector('[data-fleet-expired]').hidden=true;
   enroll.querySelector('[data-fleet-expiry]').textContent='接入完成';
  }else if(enrolled&&!row.online){
   enroll.querySelector('[data-fleet-enroll-title]').textContent='Agent 暂时离线';enroll.querySelector('[data-fleet-enroll-message]').textContent='服务器已接入，正在等待重新连接。';
   const status=enroll.querySelector('[data-fleet-enroll-status]');status.textContent='等待重连';status.classList.remove('connected');status.classList.add('error');
  }
 }
 async function poll(){
  if(disposed||!root.isConnected)return;
  if(document.hidden){timer=setTimeout(poll,5000);return;}
  try{
   const response=await fetch(statusUrl,{credentials:'same-origin',cache:'no-store',signal,headers:{'Accept':'application/json'}});
   if(response.status===401){root.querySelector('[data-fleet-refresh]').textContent='登录已过期，请刷新页面重新登录';disposed=true;return;}
   if(!response.ok||response.redirected)throw Error('status');
   const value=await response.json();if(!Array.isArray(value.servers))throw Error('shape');
   updateRows(value.servers,value.summary);updateEnrollment(value.servers);
   const note=root.querySelector('[data-fleet-refresh]');if(note){note.textContent='刚刚更新 · '+new Date().toLocaleTimeString('zh-CN',{hour12:false});note.classList.remove('fleet-warning');}
  }catch(error){
   if(error.name==='AbortError')return;
   if(list)sparkline(null,null);
   const note=root.querySelector('[data-fleet-refresh]');if(note){note.textContent='状态更新暂不可用，正在重试';note.classList.add('fleet-warning');}
  }finally{if(!disposed&&root.isConnected)timer=setTimeout(poll,5000);}
 }
 listen(root,'click',async event=>{
  const choice=event.target.closest('[data-fleet-filter]');if(choice){filter=choice.dataset.fleetFilter;root.querySelectorAll('[data-fleet-filter]').forEach(button=>button.setAttribute('aria-pressed',String(button===choice)));filterRows();}
  const button=event.target.closest('[data-fleet-copy]');if(!button)return;
  const field=document.getElementById(button.dataset.fleetCopy);if(!field)return;
  let copied=false;
  try{if(navigator.clipboard&&window.isSecureContext){await navigator.clipboard.writeText(field.value);copied=true;}else{field.focus();field.select();copied=document.execCommand('copy');}}catch(_){field.focus();field.select();}
  window.panelToast?.(copied?'安装命令已复制':'复制失败，请手动复制选中的命令',!copied);
 });
 listen(root,'toggle',event=>{if(!event.target.matches('.fleet-more')||!event.target.open)return;root.querySelectorAll('.fleet-more[open]').forEach(menu=>{if(menu!==event.target)menu.open=false;});},true);
 listen(document,'click',event=>{root.querySelectorAll('.fleet-more[open]').forEach(menu=>{if(!menu.contains(event.target))menu.open=false;});});
 listen(root,'keydown',event=>{if(event.key==='Escape'){const menu=event.target.closest('.fleet-more[open]');if(menu){menu.open=false;menu.querySelector('summary').focus();}}});
 const dispose=()=>{disposed=true;clearTimeout(timer);clearInterval(expiryTimer);};signal?.addEventListener('abort',dispose,{once:true});
 if(enroll){expiry();expiryTimer=setInterval(expiry,1000);}
 poll();
})();
