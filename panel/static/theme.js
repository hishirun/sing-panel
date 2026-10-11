'use strict';
(() => {
  const labels = {dark:'深色',glass:'浅色玻璃',retro:'暖橙复古'};
  const themes = Object.keys(labels);
  let selected = themes.find(t => document.body.classList.contains(`theme-${t}`)) || 'dark';
  try { const saved = localStorage.getItem('sing-panel-theme'); if (themes.includes(saved)) selected = saved; } catch (_) {}
  const apply = theme => {
    selected = theme;
    themes.forEach(t => document.body.classList.toggle(`theme-${t}`,t === theme));
    const caption = document.getElementById('theme-current');
    if (caption) caption.textContent = labels[theme];
    document.querySelectorAll('[data-theme]').forEach(b => b.setAttribute('aria-pressed',String(b.dataset.theme === theme)));
  };
  apply(selected);
  document.addEventListener('DOMContentLoaded', () => {
    const menu = document.getElementById('theme-menu');
    if (!menu) return;
    const trigger = menu.querySelector('summary');
    apply(selected);
    menu.querySelectorAll('[data-theme]').forEach(button => button.addEventListener('click', () => {
      if (!themes.includes(button.dataset.theme)) return;
      apply(button.dataset.theme);
      try { localStorage.setItem('sing-panel-theme',selected); } catch (_) {}
      menu.open = false;
      trigger.focus();
    }));
    document.addEventListener('click', event => { if (!menu.contains(event.target)) menu.open = false; });
    document.addEventListener('keydown', event => { if (event.key === 'Escape' && menu.open) { menu.open = false; trigger.focus(); } });
    window.addEventListener('storage', event => { if (event.key === 'sing-panel-theme' && themes.includes(event.newValue)) apply(event.newValue); });
  });
})();
