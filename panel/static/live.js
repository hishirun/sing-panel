'use strict';
window.panelStream = async (url, signal, update, state) => {
 let delay=1000;
 while(!signal.aborted){
  if(document.hidden){await new Promise(r=>setTimeout(r,1000));continue;}
  const controller=new AbortController();const stop=()=>controller.abort();signal.addEventListener('abort',stop,{once:true});
  const visibility=()=>{if(document.hidden)controller.abort();};document.addEventListener('visibilitychange',visibility);
  try{
   state('正在连接');
   const response=await fetch(url,{signal:controller.signal,credentials:'same-origin',cache:'no-store',headers:{Accept:'text/event-stream'}});
   if(response.status===401||response.redirected){state('登录已过期，请重新登录');return;}
   if(!response.ok||!response.headers.get('content-type')?.includes('text/event-stream'))throw Error('stream');
   state('实时连接');delay=1000;
   const reader=response.body.getReader(),decoder=new TextDecoder();let buffer='';
   try{while(!signal.aborted){const {value,done}=await reader.read();if(done)break;buffer+=decoder.decode(value,{stream:true});let end;while((end=buffer.indexOf('\n\n'))>=0){const frame=buffer.slice(0,end);buffer=buffer.slice(end+2);if(frame.startsWith('event: expired')){state('登录或服务器状态已变化，请刷新');return;}const line=frame.split('\n').find(s=>s.startsWith('data: '));if(line)update(JSON.parse(line.slice(6)));}}}finally{await reader.cancel().catch(()=>{});}
  }catch(error){if(!signal.aborted&&!document.hidden)state('连接中断，正在重连');}
  finally{controller.abort();signal.removeEventListener('abort',stop);document.removeEventListener('visibilitychange',visibility);}
  if(!signal.aborted){await new Promise(r=>setTimeout(r,delay));delay=Math.min(delay*2,15000);}
 }
};
