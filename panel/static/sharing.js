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
  const columns = document.querySelectorAll('[data-traffic-tip]');
  if (!columns.length) return;
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
  columns.forEach(column => {
    column.addEventListener('pointerenter',() => show(column));
    column.addEventListener('pointerleave',() => { if (document.activeElement !== column) hide(); });
    column.addEventListener('focus',() => show(column));
    column.addEventListener('blur',hide);
    column.addEventListener('click',() => show(column));
  });
  document.addEventListener('click',event => { if (!event.target.closest('[data-traffic-tip]')) hide(); });
  document.addEventListener('keydown',event => { if (event.key === 'Escape') hide(); });
  window.addEventListener('scroll',hide,true);
  window.addEventListener('resize',hide);
})();
