'use strict';
window.panelPageScripts.register(document.currentScript.src, () => {
  const form=document.querySelector('[data-personal-admin-form]');if(!form)return;
  const refresh=()=>{
    const kind=form.elements.type.value;
    for(const [selector,show] of [['[data-personal-auth]',kind!=='shadowsocks'],['[data-personal-ss]',kind==='shadowsocks'],['[data-personal-http]',kind==='http']]){
      form.querySelectorAll(selector).forEach(el=>{el.hidden=!show;el.querySelectorAll('input,select').forEach(input=>input.disabled=!show);});
    }
  };
  window.panelListen(form,'submit',event=>{const intent=event.submitter?.value;form.dataset.confirm=intent==='delete'?'确认删除此个人出口？':intent==='toggle'?'确认更改此个人出口的启用状态？':'';},{capture:true});
  window.panelListen(form,'change',refresh);refresh();
});
