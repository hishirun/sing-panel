'use strict';
(() => {
  const form=document.getElementById('outbound-form');if(!form)return;
  const type=form.elements.namedItem('type'),tls=form.elements.namedItem('tls_mode'),transport=form.elements.namedItem('transport');
  let previous=type.value;
  const refresh=()=>{
    const kind=type.value;
    if(previous!==kind){tls.value=['trojan','anytls','hysteria2','tuic'].includes(kind)?'tls':'none';transport.value='tcp';previous=kind;}
    if(['trojan','anytls','hysteria2','tuic'].includes(kind)&&tls.value==='none')tls.value='tls';
    if(kind!=='vless'&&tls.value==='reality')tls.value='tls';
    form.querySelectorAll('[data-up-types]').forEach(el=>{el.hidden=!el.dataset.upTypes.split(',').includes(kind);});
    form.querySelectorAll('[data-up-tls]').forEach(el=>{el.hidden=tls.value==='none';});
    form.querySelectorAll('[data-up-reality]').forEach(el=>{el.hidden=tls.value!=='reality';});
    form.querySelectorAll('[data-up-path]').forEach(el=>{el.hidden=!['ws','httpupgrade'].includes(transport.value);});
    form.querySelectorAll('[data-up-grpc]').forEach(el=>{el.hidden=transport.value!=='grpc';});
  };
  form.addEventListener('change',refresh);refresh();
})();
