'use strict';
window.panelPageScripts.register(document.currentScript.src, () => {
'use strict';
window.panelListen(document,'click', async event => {
  const button = event.target.closest('[data-copy]');
  if (!button) return;
  const text = button.dataset.copy;
  let copied = false;
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      copied = true;
    } else {
      const field = document.createElement('textarea');
      field.value = text;
      field.style.position = 'fixed';
      field.style.opacity = '0';
      document.body.appendChild(field);
      field.select();
      copied = document.execCommand('copy');
      field.remove();
    }
  } catch (_) {}
  window.panelToast(copied ? '链接已复制' : '复制失败，请手动选择链接', !copied);
  const previous = button.textContent;
  button.textContent = copied ? '已复制 ✓' : '复制失败，请手动选择链接';
  setTimeout(() => { button.textContent = previous; }, 1800);
});
(() => {
 const approved=new WeakSet(),pending=new WeakSet();
 window.panelListen(document,'submit',async event=>{
  const form=event.target,message=form.dataset.confirm;if(!message||(window.panelAsyncForms&&form.closest('#admin-content')&&document.getElementById('admin-content').dataset.admin!=null))return;
  if(approved.has(form)){approved.delete(form);return;}
  event.preventDefault();if(pending.has(form))return;pending.add(form);
  const submitter=event.submitter;
  const accepted=await window.panelConfirm(message,submitter?.textContent.trim()||'确认操作');pending.delete(form);
  if(accepted&&form.isConnected){approved.add(form);form.requestSubmit(submitter||undefined);}
 });
})();
window.panelListen(document,'change', event => {
  if (!event.target.matches('[data-select-all]')) return;
  event.target.closest('form').querySelectorAll('input[name="ids"]').forEach(box => { box.checked = event.target.checked; });
});
(() => {
  if (!document.querySelector('#traffic')) return;
  const tip = document.createElement('div');
  tip.className = 'traffic-tooltip';
  tip.id = 'traffic-tooltip';
  tip.setAttribute('role','tooltip');
  tip.hidden = true;
  document.body.appendChild(tip);
  let active;
  const hide = () => { tip.hidden = true; if (active) active.removeAttribute('aria-describedby'); active = null; };
  const show = column => {
    if (active && active !== column) active.removeAttribute('aria-describedby');
    active = column;
    tip.replaceChildren(column.querySelector('template').content.cloneNode(true));
    tip.hidden = false;
    column.setAttribute('aria-describedby',tip.id);
    const box = column.getBoundingClientRect();
    const width = tip.offsetWidth, height = tip.offsetHeight;
    const left = Math.max(12,Math.min(window.innerWidth-width-12,box.left+box.width/2-width/2));
    const top = box.top-height-12 >= 12 ? box.top-height-12 : Math.min(window.innerHeight-height-12,box.bottom+12);
    tip.style.left = `${left}px`;
    tip.style.top = `${Math.max(12,top)}px`;
  };
  window.panelListen(document,'pointerover', event => {
    const column = event.target.closest('[data-traffic-tip]');
    if (column) show(column);
  });
  window.panelListen(document,'pointerout', event => {
    const column = event.target.closest('[data-traffic-tip]');
    if (column && !column.contains(event.relatedTarget) && document.activeElement !== column) hide();
  });
  window.panelListen(document,'focusin', event => {
    const column = event.target.closest('[data-traffic-tip]');
    if (column) show(column);
  });
  window.panelListen(document,'focusout', event => {
    if (event.target.closest('[data-traffic-tip]')) hide();
  });
  window.panelListen(document,'click', event => {
    const column = event.target.closest('[data-traffic-tip]');
    if (column) show(column);
  });
  window.panelListen(document,'click',event => { if (!event.target.closest('[data-traffic-tip]')) hide(); });
  window.panelListen(document,'keydown',event => { if (event.key === 'Escape') hide(); });
  window.panelListen(window,'scroll',hide,true);
  window.panelListen(window,'resize',hide);
})();

(() => {
  let pending;
  const scope = window.panelScope.signal;
  scope.addEventListener('abort', () => pending?.abort(), {once: true});
  async function updateTraffic(url, push) {
    if (pending) pending.abort();
    const controller = new AbortController();
    pending = controller;
    const panel = document.querySelector('#traffic');
    if (!panel) return;
    panel.setAttribute('aria-busy', 'true');
    let message = panel.querySelector('[data-traffic-error]');
    if (message) message.remove();
    try {
      const requested = new URL(url, location.href);
      const share = document.getElementById('customer-content')?.dataset.shareUrl;
      if (!share) throw new Error('Missing share page');
      const endpoint = new URL(share, location.href);
      endpoint.pathname = endpoint.pathname.replace(/\/$/, '') + '/traffic';
      endpoint.search = new URLSearchParams({period: requested.searchParams.get('period') || '7d'}).toString();
      endpoint.hash = '';
      const response = await fetch(endpoint, {signal: controller.signal, credentials: 'same-origin', cache: 'no-store', headers: {'Accept': 'text/html'}});
      if (window.customerAuthRedirect?.(response)) return;
      if (!response.ok || response.redirected) throw new Error('Unavailable');
      const page = new DOMParser().parseFromString(await response.text(), 'text/html');
      const next = page.querySelector('#traffic');
      if (!next) throw new Error('Missing traffic');
      if (scope.aborted || controller.signal.aborted || pending !== controller || !panel.isConnected) return;
      const expanded = panel.querySelector('details')?.open;
      if (expanded && next.querySelector('details')) next.querySelector('details').open = true;
      const focused = panel.contains(document.activeElement);
      document.querySelector('#traffic-tooltip')?.setAttribute('hidden', '');
      panel.replaceWith(next);
      if (push) history.pushState(null, '', url);
      if (focused) next.querySelector('.period-switch .selected')?.focus({preventScroll: true});
    } catch (error) {
      if (error.name !== 'AbortError' && !scope.aborted && panel.isConnected) {
        message = document.createElement('p');
        message.dataset.trafficError = '';
        message.className = 'bad';
        message.setAttribute('role', 'alert');
        message.textContent = '用量刷新失败，请点击时间范围重试。';
        panel.appendChild(message);
      }
    } finally {
      if (pending === controller) {
        document.querySelector('#traffic')?.removeAttribute('aria-busy');
        pending = null;
      }
    }
  }
  window.panelListen(document,'click', event => {
    const link = event.target.closest('#traffic .period-switch a');
    if (!link || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    updateTraffic(link.href, true);
  });
  window.panelListen(window,'popstate', () => {
    const selected = document.querySelector('#traffic .period-switch .selected');
    if (!selected) return;
    const current = new URL(selected.href).searchParams.get('period') || '7d';
    const requested = new URL(location.href).searchParams.get('period') || '7d';
    if (current !== requested) updateTraffic(location.href, false);
  });
})();

});
