'use strict';
(() => {
  const themes = ['dark', 'glass', 'retro'];
  let selected = themes.find(theme => document.body.classList.contains(`theme-${theme}`)) || 'dark';
  try {
    const saved = localStorage.getItem('sing-panel-theme');
    if (themes.includes(saved)) selected = saved;
  } catch (_) {}
  const apply = theme => {
    themes.forEach(name => document.body.classList.toggle(`theme-${name}`, name === theme));
  };
  apply(selected);
  document.addEventListener('DOMContentLoaded', () => {
    const picker = document.getElementById('theme-picker');
    if (!picker) return;
    picker.value = selected;
    picker.addEventListener('change', () => {
      if (!themes.includes(picker.value)) return;
      apply(picker.value);
      try { localStorage.setItem('sing-panel-theme', picker.value); } catch (_) {}
    });
  });
})();
