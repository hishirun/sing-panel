'use strict';
// Share-page event scope, independent of administrator navigation.
window.panelScope = new AbortController();
window.panelListen = (target, type, listener, options = {}) => target.addEventListener(type, listener, {...(typeof options === 'boolean' ? {capture: options} : options), signal: window.panelScope.signal});

// Authentication redirects replace the whole page so protected chrome and data
// are never left behind after expiry, logout or an administrator password reset.
window.customerAuthRedirect = response => {
  const destination = response.headers.get('X-Customer-Login') || (response.redirected ? response.url : '');
  const share = document.getElementById('customer-content')?.dataset.shareUrl;
  if (!destination || !share) return false;
  let url, base;
  try { url = new URL(destination, location.href); base = new URL(share, location.href).pathname.replace(/\/$/, ''); }
  catch (_) { return false; }
  if (url.origin !== location.origin || ![base + '/login', base + '/setup'].includes(url.pathname)) return false;
  window.customerCanLeave = null;
  document.dispatchEvent(new Event('panel:dispose'));
  const main = document.getElementById('customer-content');
  if (main) { const note = document.createElement('p'); note.setAttribute('role', 'status'); note.textContent = '请重新登录'; main.replaceChildren(note); }
  document.querySelectorAll('.traffic-tooltip').forEach(node => node.remove());
  location.replace(url.href);
  return true;
};

document.addEventListener('click', event => {
  const link = event.target.closest('[data-client-import]');
  if (!link) return;
  window.panelToast('正在打开 ' + link.dataset.clientImport + '；若未打开，请先安装客户端');
});

// Keep the masthead in place while switching between the overview and routing.
(() => {
  let pending = null, sequence = 0, displayedURL = location.href;
  const content = () => document.getElementById('customer-content');
  const eligible = url => {
    const value = content()?.dataset.shareUrl;
    if (!value || url.origin !== location.origin) return false;
    const base = new URL(value, location.href).pathname.replace(/\/$/, '');
    return url.pathname === base || url.pathname === base + '/routing';
  };
  async function navigate(url, push = true) {
    if (window.customerCanLeave && !(await window.customerCanLeave())) {
      if (!push) history.pushState(null, '', displayedURL);
      return;
    }
    const id = ++sequence;
    pending?.abort(); pending = new AbortController();
    content()?.setAttribute('aria-busy', 'true');
    try {
      const response = await fetch(url, {signal: pending.signal, credentials: 'same-origin', cache: 'no-store', headers: {'Accept': 'text/html'}});
      if (window.customerAuthRedirect(response)) return;
      if (!response.ok || !response.headers.get('content-type')?.includes('text/html')) throw new Error('页面加载失败，请重试');
      const html = new DOMParser().parseFromString(await response.text(), 'text/html');
      const next = html.getElementById('customer-content');
      if (!next || id !== sequence) return;
      const scripts = [...next.querySelectorAll('script[src]')].map(script => script.getAttribute('src'));
      next.querySelectorAll('script[src]').forEach(script => script.remove());
      document.dispatchEvent(new Event('panel:dispose'));
      window.panelScope.abort(); window.panelScope = new AbortController();
      document.querySelectorAll('.traffic-tooltip').forEach(node => node.remove());
      content().replaceChildren(...next.childNodes); content().dataset.shareUrl = next.dataset.shareUrl;
      document.title = html.title;
      const nextLinks = [...html.querySelectorAll('.page-nav a')];
      document.querySelectorAll('.page-nav a').forEach((link, index) => { const value = nextLinks[index]?.getAttribute('aria-current'); if (value) link.setAttribute('aria-current', value); else link.removeAttribute('aria-current'); });
      if (push) history.pushState(null, '', url);
      displayedURL = url;
      const scope = window.panelScope.signal;
      await window.panelPageScripts.activate(scripts, {signal: scope});
      if (scope.aborted || id !== sequence) return;
      const target = new URL(url).hash ? document.getElementById(decodeURIComponent(new URL(url).hash.slice(1))) : null;
      if (target) target.scrollIntoView({behavior: 'instant'}); else window.scrollTo(0, 0);
      const heading = content().querySelector('h1'); heading?.setAttribute('tabindex', '-1'); heading?.focus({preventScroll: true});
    } catch (error) {
      if (error.name !== 'AbortError' && id === sequence) window.panelToast('页面加载失败，请再次点击重试', true);
    } finally { if (id === sequence) { content()?.removeAttribute('aria-busy'); pending = null; } }
  }
  document.addEventListener('click', event => {
    const link = event.target.closest('[data-customer-nav]');
    if (!link || event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.altKey || event.shiftKey) return;
    const url = new URL(link.href);
    if (!eligible(url) || (url.pathname === location.pathname && url.hash)) return;
    event.preventDefault(); if (url.href !== location.href) navigate(url.href);
  });
  window.addEventListener('popstate', () => {
    const url = new URL(location.href), previous = new URL(displayedURL);
    if (url.pathname === previous.pathname) { displayedURL = url.href; return; }
    if (eligible(url)) navigate(url.href, false);
  });
})();
