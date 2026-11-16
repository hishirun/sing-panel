'use strict';
// Fetch each version once. Re-run only its page initializer after scoped disposal.
(() => {
  const initializers = new Map(), loaded = new Map(), initialized = new WeakMap();
  const normalize = source => {
    const url = new URL(source, location.href);
    if (url.origin !== location.origin || !url.pathname.startsWith('/static/') || !url.pathname.endsWith('.js')) throw new Error('Invalid page script');
    return url.href;
  };
  const load = source => {
    const url = normalize(source);
    if (loaded.has(url)) return loaded.get(url);
    if (initializers.has(url)) return Promise.resolve();
    const promise = new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = url;
      script.onload = () => { script.remove(); resolve(); };
      script.onerror = () => { script.remove(); loaded.delete(url); reject(new Error('Page script unavailable')); };
      document.body.append(script);
    });
    loaded.set(url, promise);
    return promise;
  };
  const initialize = (url, signal) => {
    if (signal?.aborted || !initializers.has(url)) return;
    if (signal) {
      let active = initialized.get(signal);
      if (!active) { active = new Set(); initialized.set(signal, active); }
      if (active.has(url)) return;
      active.add(url);
    }
    initializers.get(url)();
  };
  window.panelPageScripts = {
    register(source, initialize) { initializers.set(normalize(source), initialize); },
    async activate(sources, {signal} = {}) {
      const urls = [...new Set(sources.map(normalize))];
      await Promise.all(urls.map(load));
      for (const url of urls) {
        if (signal?.aborted) return;
        initialize(url, signal);
      }
    },
  };
  document.addEventListener('DOMContentLoaded', () => {
    const sources = [...document.querySelectorAll('script[src]')].map(script => script.src);
    for (const source of sources) {
      try { loaded.set(normalize(source), Promise.resolve()); } catch (_) {}
    }
    // All deferred scripts have registered before DOMContentLoaded.
    for (const source of sources) initialize(source, window.panelScope?.signal);
  }, {once: true});
})();
