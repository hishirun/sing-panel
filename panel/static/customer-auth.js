'use strict';
(() => {
  if (window.customerAuthControlsInstalled) return;
  window.customerAuthControlsInstalled = true;
  const toast = (message, error = false) => window.panelToast?.(message, error);
  const pendingResets = new WeakSet();
  let disposePasswordDialog = null;
  const validConfirmation = form => {
    const password = form.elements.namedItem('password');
    const confirmation = form.elements.namedItem('password_confirm');
    if (password?.hasAttribute('data-password-bounds')) {
      const length = Array.from(password.value).length;
      password.setCustomValidity(password.value && (length < 10 || length > 128) ? '登录密码需要 10–128 个字符' : '');
    }
    if (confirmation) confirmation.setCustomValidity(confirmation.value && confirmation.value !== password.value ? '两次输入的密码不一致' : '');
  };
  document.addEventListener('input', event => {
    const form = event.target.closest('[data-customer-auth-form]');
    if (form) validConfirmation(form);
  });
  document.addEventListener('submit', event => {
    const form = event.target.closest('[data-customer-auth-form]');
    if (!form || event.defaultPrevented) return;
    validConfirmation(form);
    if (!form.reportValidity()) { event.preventDefault(); return; }
    if (form.dataset.submitting) { event.preventDefault(); return; }
    form.dataset.submitting = '1';
    form.setAttribute('aria-busy', 'true');
    form.querySelector('[type=submit]').disabled = true;
    form.querySelector('.customer-auth-progress').hidden = false;
  });
  window.addEventListener('pageshow', () => {
    document.querySelectorAll('[data-customer-auth-form]').forEach(form => {
      delete form.dataset.submitting;
      form.removeAttribute('aria-busy');
      form.querySelector('[type=submit]').disabled = false;
      form.querySelector('.customer-auth-progress').hidden = true;
    });
  });
  function showPassword(password, name, trigger) {
    disposePasswordDialog?.();
    const dialog = document.createElement('dialog');
    dialog.className = 'portal-password-dialog';
    dialog.setAttribute('aria-labelledby', 'portal-password-title');
    dialog.setAttribute('aria-describedby', 'portal-password-description');
    const caption = document.createElement('p'); caption.className = 'portal-password-caption'; caption.textContent = 'PANEL ACCESS';
    const heading = document.createElement('h2'); heading.id = 'portal-password-title'; heading.textContent = '登录密码已重置';
    const description = document.createElement('p'); description.id = 'portal-password-description'; description.textContent = name + ' · 仅用于用户面板登录';
    const value = document.createElement('input'); value.className = 'portal-password-value'; value.type = 'text'; value.readOnly = true; value.value = password; value.autocomplete = 'off'; value.spellcheck = false; value.setAttribute('aria-label', '新面板登录密码');
    const note = document.createElement('p'); note.className = 'portal-password-warning'; note.textContent = '仅显示这一次，请复制后交给用户。节点连接密码保持不变。';
    const actions = document.createElement('div'); actions.className = 'portal-password-actions';
    const close = document.createElement('button'); close.type = 'button'; close.textContent = '关闭';
    const copy = document.createElement('button'); copy.type = 'button'; copy.className = 'primary'; copy.textContent = '复制登录密码';
    let closed = false;
    const dispose = () => {
      if (closed) return;
      closed = true; value.value = ''; password = ''; dialog.close(); dialog.remove();
      if (disposePasswordDialog === dispose) disposePasswordDialog = null;
      document.removeEventListener('panel:dispose', dispose);
      if (trigger.isConnected) trigger.focus();
    };
    close.addEventListener('click', dispose);
    dialog.addEventListener('cancel', event => { event.preventDefault(); dispose(); });
    document.addEventListener('panel:dispose', dispose, {once: true});
    disposePasswordDialog = dispose;
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(value.value);
        copy.textContent = '已复制'; toast('登录密码已复制');
      } catch (_) { value.focus(); value.select(); toast('请复制已选中的登录密码'); }
    });
    actions.append(close, copy); dialog.append(caption, heading, description, value, note, actions);
    document.body.append(dialog); dialog.showModal(); copy.focus();
  }
  document.addEventListener('click', async event => {
    const toggle = event.target.closest('[data-password-toggle]');
    if (toggle) {
      const input = document.getElementById(toggle.dataset.passwordToggle);
      if (!input) return;
      const show = input.type === 'password'; input.type = show ? 'text' : 'password';
      toggle.textContent = show ? '隐藏' : '显示'; toggle.setAttribute('aria-pressed', String(show));
      toggle.setAttribute('aria-label', (show ? '隐藏' : '显示') + (input.labels?.[0]?.childNodes[0]?.textContent?.trim() || '密码'));
      return;
    }
    const button = event.target.closest('[data-portal-password-reset]');
    if (!button || button.disabled || pendingResets.has(button)) return;
    pendingResets.add(button);
    const name = button.dataset.userName || '此用户';
    if (window.panelConfirm && !(await window.panelConfirm('重置 ' + name + ' 的面板登录密码？其他浏览器将退出登录，节点连接不受影响。', '生成新密码'))) { pendingResets.delete(button); return; }
    button.disabled = true; button.setAttribute('aria-busy', 'true');
    try {
      const endpoint = new URL(button.dataset.portalPasswordReset, location.href);
      if (endpoint.origin !== location.origin) throw new Error('invalid_origin');
      const body = new FormData(); body.set('token', button.dataset.token || '');
      const response = await fetch(endpoint, {method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: {'Accept': 'application/json'}, body});
      if (response.status === 401) {
        const prefix = document.getElementById('admin-content')?.dataset.admin;
        if (prefix != null) location.assign(prefix + '/login?expired=1');
        return;
      }
      const result = await response.json();
      if (!response.ok || !result.ok || typeof result.password !== 'string') {
        toast(typeof result.detail === 'string' ? result.detail : '重置未完成，请稍后重试', true); return;
      }
      if (!button.isConnected) {
        result.password = '';
        toast('登录密码已重置。请返回用户管理重新生成并查看。');
        return;
      }
      const scope = button.closest('tr') || button.closest('.portal-password-section');
      const status = scope?.querySelector('[data-portal-password-status]');
      if (status) { status.textContent = '已设置登录密码'; status.classList.remove('pending'); }
      showPassword(result.password, name, button); result.password = '';
    } catch (_) { toast('请求中断，请核对登录密码状态后重试', true); }
    finally { pendingResets.delete(button); button.disabled = false; button.removeAttribute('aria-busy'); }
  });
  document.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    document.querySelectorAll('.customer-account-menu[open]').forEach(menu => { menu.open = false; menu.querySelector('summary').focus(); });
  });
  document.addEventListener('click', event => {
    document.querySelectorAll('.customer-account-menu[open]').forEach(menu => { if (!menu.contains(event.target)) menu.open = false; });
  });
})();
