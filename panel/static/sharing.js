'use strict';
document.addEventListener('click', async event => {
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
  const previous = button.textContent;
  button.textContent = copied ? '已复制 ✓' : '复制失败，请手动选择链接';
  setTimeout(() => { button.textContent = previous; }, 1800);
});
document.addEventListener('submit', event => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) event.preventDefault();
});
document.addEventListener('change', event => {
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
  document.addEventListener('pointerover', event => {
    const column = event.target.closest('[data-traffic-tip]');
    if (column) show(column);
  });
  document.addEventListener('pointerout', event => {
    const column = event.target.closest('[data-traffic-tip]');
    if (column && !column.contains(event.relatedTarget) && document.activeElement !== column) hide();
  });
  document.addEventListener('focusin', event => {
    const column = event.target.closest('[data-traffic-tip]');
    if (column) show(column);
  });
  document.addEventListener('focusout', event => {
    if (event.target.closest('[data-traffic-tip]')) hide();
  });
  document.addEventListener('click', event => {
    const column = event.target.closest('[data-traffic-tip]');
    if (column) show(column);
  });
  document.addEventListener('click',event => { if (!event.target.closest('[data-traffic-tip]')) hide(); });
  document.addEventListener('keydown',event => { if (event.key === 'Escape') hide(); });
  window.addEventListener('scroll',hide,true);
  window.addEventListener('resize',hide);
})();

(() => {
  let pending;
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
      const response = await fetch(url, {signal: controller.signal, cache: 'no-store'});
      if (!response.ok || response.redirected) throw new Error('Unavailable');
      const page = new DOMParser().parseFromString(await response.text(), 'text/html');
      const next = page.querySelector('#traffic');
      if (!next) throw new Error('Missing traffic');
      const expanded = panel.querySelector('details')?.open;
      if (expanded && next.querySelector('details')) next.querySelector('details').open = true;
      const focused = panel.contains(document.activeElement);
      document.querySelector('#traffic-tooltip')?.setAttribute('hidden', '');
      panel.replaceWith(next);
      if (push) history.pushState(null, '', url);
      if (focused) next.querySelector('.period-switch .selected')?.focus({preventScroll: true});
    } catch (error) {
      if (error.name !== 'AbortError') {
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
  document.addEventListener('click', event => {
    const link = event.target.closest('#traffic .period-switch a');
    if (!link || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    updateTraffic(link.href, true);
  });
  window.addEventListener('popstate', () => {
    if (document.querySelector('#traffic')) updateTraffic(location.href, false);
  });
})();
