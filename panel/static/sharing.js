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
