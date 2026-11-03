'use strict';
// Share-page event scope, independent of administrator navigation.
window.panelScope = new AbortController();
window.panelListen = (target, type, listener, options = {}) => target.addEventListener(type, listener, {...(typeof options === 'boolean' ? {capture: options} : options), signal: window.panelScope.signal});

window.panelListen(document, 'click', event => {
  const link = event.target.closest('[data-client-import]');
  if (!link) return;
  window.panelToast('正在打开 ' + link.dataset.clientImport + '；若未打开，请先安装客户端');
});
