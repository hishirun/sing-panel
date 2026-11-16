'use strict';
window.panelPageScripts.register(document.currentScript.src, () => {
'use strict';
(() => {
  const select=document.getElementById('hy-obfs');
  const mode=document.querySelector('[name="mode"]');
  const shape=document.querySelector('[name="snell_mode"]');
  const keep=document.querySelector('[name="disable_tcp_keep_alive"]');
  const bbr=document.querySelector('[name="hy_ignore_client_bandwidth"]');
  const refresh=()=>{
    const transport=document.querySelector('[name="trojan_transport"]');
    for(const kind of ['ws','grpc'])document.querySelectorAll('[data-trojan-'+kind+']').forEach(el=>{el.hidden=transport?.value!==kind;el.querySelectorAll('input').forEach(input=>input.disabled=el.hidden);});
    const method=document.querySelector('[name="ss_method"]');
    if(method&&mode){const shared=mode.querySelector('[value="shared"]');if(shared){shared.disabled=!method.value.startsWith('2022-')||method.value==='2022-blake3-chacha20-poly1305';if(shared.disabled&&mode.value==='shared'){mode.value='compat';mode.dispatchEvent(new Event('change',{bubbles:true}));}}}
    document.querySelectorAll('[data-ss-shared]').forEach(el=>{el.hidden=mode?.value!=='shared';el.querySelectorAll('input').forEach(input=>input.disabled=el.hidden);});
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

});
