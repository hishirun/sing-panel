'use strict';
(() => {
  const select=document.getElementById('hy-obfs');
  const mode=document.querySelector('[name="mode"]');
  const shape=document.querySelector('[name="snell_mode"]');
  const keep=document.querySelector('[name="disable_tcp_keep_alive"]');
  const bbr=document.querySelector('[name="hy_ignore_client_bandwidth"]');
  const refresh=()=>{
    if(select){
      document.querySelectorAll('[data-hy-obfs]').forEach(el=>{el.hidden=select.value==='none';});
      document.querySelectorAll('[data-hy-gecko]').forEach(el=>{el.hidden=select.value!=='gecko';});
    }
    document.querySelectorAll('[data-snell-shared]').forEach(el=>{el.hidden=mode&&mode.value!=='shared';});
    document.querySelectorAll('[data-snell-raw]').forEach(el=>{el.hidden=shape&&shape.value!=='unsafe-raw';});
    if(keep) for(const name of ['keep_alive','keep_alive_interval']){
      const input=document.querySelector(`[name="${name}"]`);if(input) input.closest('label').hidden=keep.value==='true';
    }
    if(bbr) for(const name of ['hy_up_mbps','hy_down_mbps']){
      const input=document.querySelector(`[name="${name}"]`);if(input) input.disabled=bbr.value==='true';
    }
  };
  window.panelListen(document,'change',refresh);refresh();
})();
