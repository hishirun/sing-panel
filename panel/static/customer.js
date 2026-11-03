'use strict';
// Share-page event scope, independent of administrator navigation.
window.panelScope = new AbortController();
window.panelListen = (target, type, listener, options = {}) => target.addEventListener(type, listener, {...(typeof options === 'boolean' ? {capture: options} : options), signal: window.panelScope.signal});
