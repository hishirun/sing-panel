'use strict';
(() => {
  const root = document.getElementById('customer-routing');
  if (!root) return;
  const $ = id => document.getElementById(id);
  const copy = value => JSON.parse(JSON.stringify(value));
  const scope = window.panelScope.signal;
  const listen = (target, type, fn, options = {}) => target.addEventListener(type, fn, {...options, signal: scope});
  let state = JSON.parse($('routing-initial-state').textContent);
  let draft = copy(state.policy.draft || {enabled: true, rules: []});
  let generation = 0, savedGeneration = 0, saving = null, saveTimer, pollTimer, saveError = '', disposed = false;
  let editorRule = null, editorChanged = false, editorPrevious = null, dragged = null;
  let valuePicker = null, targetPicker = null, previewPicker = null, previewNode = '', previewNodeSignature = '';
  const editor = $('routing-editor');
  const labels = new Map();
  const kinds = {geosite: 'GeoSite', geoip: 'GeoIP', domain_suffix: '域名', ip_cidr: 'IP / CIDR'};
  const popular = {
    geosite: [['category-ai-!cn', 'AI 服务'], ['netflix', 'Netflix'], ['youtube', 'YouTube'], ['telegram', 'Telegram'], ['google', 'Google'], ['apple', 'Apple']],
    geoip: [['us', '美国'], ['jp', '日本'], ['hk', '香港'], ['sg', '新加坡'], ['cn', '中国'], ['tw', '台湾']]
  };
  for (const [kind, values] of Object.entries(popular)) for (const [key, label] of values) labels.set(kind + ':' + key, label);
  const regionNames = typeof Intl.DisplayNames === 'function' ? new Intl.DisplayNames(['zh-CN'], {type: 'region'}) : null;
  let geoIpCatalog = null, geoIpRequest = null;
  const valueLabel = (kind, value) => {
    if (labels.has(kind + ':' + value)) return labels.get(kind + ':' + value);
    if (kind === 'geoip' && regionNames) { try { return regionNames.of(value.toUpperCase()); } catch (_) {} }
    return value;
  };
  const base = state.share_url.replace(/\/$/, '') + '/routing';
  const busy = () => ['queued', 'applying'].includes(state.policy.status);
  const canEdit = () => !!state.editable && !state.locked && !busy();
  const changed = () => generation !== savedGeneration || state.policy.revision !== state.policy.applied_revision;
  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };
  const button = (text, className, fn, disabled = false) => {
    const node = el('button', className, text); node.type = 'button'; node.disabled = disabled;
    if (fn) node.addEventListener('click', fn);
    return node;
  };
  const formatTime = value => {
    if (!value) return '尚未检测';
    const date = new Date(typeof value === 'number' ? value * 1000 : value);
    return Number.isNaN(date.getTime()) ? '' : date.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'}) + ' 检测';
  };
  async function api(path, payload, method = 'POST') {
    const options = {method, credentials: 'same-origin', cache: 'no-store', signal: scope, headers: {'Accept': 'application/json'}};
    if (method !== 'GET') { options.headers['Content-Type'] = 'application/json'; options.body = JSON.stringify({csrf: state.csrf, ...payload}); }
    const response = await fetch(base + path, options);
    let data;
    try { data = await response.json(); } catch (_) { throw new Error('请求未完成，请稍后重试'); }
    if (!response.ok) {
      const message = typeof data.detail === 'string' ? data.detail : '操作未完成，请检查输入后重试';
      if (response.status === 403 && !disposed) {
        // Refresh permission/CSRF state after an administrator change without
        // replaying the rejected mutation or discarding still-authorized edits.
        try {
          const fresh = await fetch(base + '/api', {credentials: 'same-origin', cache: 'no-store', signal: scope, headers: {'Accept': 'application/json'}});
          if (fresh.ok) {
            const next = await fresh.json();
            if (!next.policy.allowed) { clearTimeout(saveTimer); await closeEditor(true); generation = savedGeneration = 0; saveError = ''; }
            acceptState(next, !!next.policy.allowed && generation !== savedGeneration);
          }
        } catch (_) {}
      }
      const error = new Error(message); error.status = response.status;
      throw error;
    }
    return data;
  }
  function acceptState(next, keepDraft = false) {
    state = next;
    if (!keepDraft) draft = copy(next.policy.draft || {enabled: true, rules: []});
    render();
    if (busy()) schedulePoll();
  }
  function schedulePoll() {
    clearTimeout(pollTimer);
    if (disposed || !busy()) return;
    pollTimer = setTimeout(async () => {
      try {
        const previous = state.policy.status;
        const next = await api('/api', null, 'GET');
        if (disposed) return;
        acceptState(next, generation !== savedGeneration);
        if (['queued', 'applying'].includes(previous) && !busy()) {
          if (state.policy.status === 'failed') window.panelToast(state.policy.error || '应用失败，继续使用原配置', true);
          else window.panelToast('分流配置已生效');
        }
      } catch (error) {
        if (!disposed && error.name !== 'AbortError') { $('routing-notice').hidden = false; $('routing-notice').textContent = '暂时无法确认应用结果，正在重新连接…'; schedulePoll(); }
      }
    }, 1400);
  }
  function markChanged() {
    generation++; saveError = ''; render();
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => flushDraft().catch(() => {}), 550);
  }
  async function flushDraft() {
    clearTimeout(saveTimer);
    if (saving) return saving;
    if (generation === savedGeneration) return;
    saving = (async () => {
      while (generation !== savedGeneration && !disposed) {
        const sendingGeneration = generation;
        const snapshot = copy(draft);
        try {
          const next = await api('/draft', {revision: state.policy.revision, document: snapshot});
          savedGeneration = sendingGeneration; saveError = '';
          acceptState(next, generation !== sendingGeneration);
        } catch (error) {
          saveError = error.status === 409 ? '另一页面已修改配置，请重新加载后合并你的更改。' : error.message;
          if (!disposed) window.panelToast(saveError, true);
          throw error;
        }
      }
    })();
    renderStatus();
    try { return await saving; } finally { saving = null; if (!disposed) renderStatus(); }
  }
  function closeMenus(restoreFocus = false) { const previous = root.querySelector('.routing-more-button[aria-expanded=true]'); root.querySelectorAll('.routing-rule-menu').forEach(node => node.remove()); root.querySelectorAll('.routing-more-button').forEach(node => node.setAttribute('aria-expanded', 'false')); if (restoreFocus) previous?.focus(); }
  function mutate(fn) { if (!canEdit()) return; fn(); markChanged(); }
  function moveRule(id, offset) {
    mutate(() => { const index = draft.rules.findIndex(rule => rule.id === id), next = index + offset; if (next < 0 || next >= draft.rules.length) return; [draft.rules[index], draft.rules[next]] = [draft.rules[next], draft.rules[index]]; });
  }
  function renderStatus() {
    const pending = busy(), hasChanges = changed();
    let status = !state.policy.allowed ? '暂未开放' : !state.editable ? '只读' : pending ? (state.policy.status === 'queued' ? '等待应用' : '应用中') : saveError ? '草稿未保存' : state.policy.status === 'failed' ? '应用失败' : hasChanges ? '未应用更改' : draft.enabled ? '已生效' : '跟随管理员';
    $('routing-status').textContent = status;
    $('routing-status').dataset.state = saveError ? 'error' : state.policy.status;
    $('routing-savebar').hidden = state.locked || (!hasChanges && !pending && state.policy.status !== 'failed');
    document.body.classList.toggle('routing-has-savebar', !$('routing-savebar').hidden);
    $('routing-save-title').textContent = pending ? (state.policy.status === 'queued' ? '变更已提交' : '正在应用分流') : state.policy.status === 'failed' ? '上次应用未成功' : '有未应用更改';
    $('routing-save-caption').textContent = saveError || (saving ? '正在保存草稿…' : pending ? '页面可继续查看，状态将自动更新' : '草稿已保存 · 当前连接仍使用原配置');
    $('routing-retry').hidden = !saveError;
    $('routing-apply').disabled = !canEdit() || !!saving || !!saveError;
    $('routing-discard').disabled = !canEdit() || !!saving;
    $('routing-retry').disabled = !canEdit() || !!saving;
  }
  function render() {
    const focusRow = document.activeElement?.closest('[data-rule-id]');
    const focusId = focusRow?.dataset.ruleId;
    const focusAction = document.activeElement?.classList.contains('routing-switch-button') ? '.routing-switch-button' : document.activeElement?.classList.contains('routing-edit-button') ? '.routing-edit-button' : document.activeElement?.classList.contains('routing-more-button') ? '.routing-more-button' : null;
    closeMenus(); renderStatus();
    const editable = canEdit();
    $('routing-rule-count').textContent = draft.rules.filter(rule => rule.enabled).length + ' / ' + draft.rules.length;
    $('routing-add').disabled = !editable || draft.rules.length >= (state.policy.max_rules ?? 6);
    root.querySelectorAll('[data-routing-add]').forEach(node => node.disabled = !editable || !(state.outbounds || []).some(out => out.usable));
    $('routing-enable').disabled = !editable;
    $('routing-enable').setAttribute('aria-checked', String(!!draft.enabled));
    $('routing-access-panel').hidden = !!state.policy.allowed;
    $('routing-access-description').textContent = state.reason || '请联系管理员开启自定义分流。';
    const notices = [];
    if (state.reason && !state.locked) notices.push(state.reason);
    if (state.policy.status === 'failed' && state.policy.error) notices.push(state.policy.error);
    const lockedNodes = (state.nodes || []).filter(node => node.locked);
    if (!state.locked && lockedNodes.length) notices.push(lockedNodes.map(node => node.name).join('、') + ' 使用管理员固定出口。');
    $('routing-notice').hidden = !notices.length;
    $('routing-notice').textContent = notices.join('\n');
    const list = $('routing-rule-list'); list.replaceChildren();
    $('routing-empty').hidden = !!draft.rules.length || state.locked;
    for (const [index, rule] of draft.rules.entries()) {
      const out = (state.outbounds || []).find(item => item.id === rule.target);
      const invalid = rule.target !== 'reject' && (!out || !out.usable);
      const row = el('div', 'routing-rule-row' + (!rule.enabled ? ' is-disabled' : '') + (invalid ? ' is-invalid' : '')); row.dataset.ruleId = rule.id;
      const position = el('div', 'routing-rule-position');
      const handle = el('span', 'routing-drag-handle', '⠿'); handle.draggable = editable; handle.setAttribute('aria-hidden', 'true'); handle.title = '拖动调整顺序';
      position.append(handle, document.createTextNode(String(index + 1).padStart(2, '0')));
      const description = el('div', 'routing-rule-description'); description.append(el('strong', '', rule.name));
      const selected = rule.values.map(value => valueLabel(rule.kind, value));
      description.append(el('p', '', (kinds[rule.kind] || rule.kind) + ' · ' + selected.slice(0, 3).join('、') + (selected.length > 3 ? ' 等 ' + selected.length + ' 项' : '')));
      if (rule.node_ids.length) description.append(el('p', '', '适用于 ' + rule.node_ids.length + ' 个节点'));
      const target = el('div', 'routing-rule-target'); target.append(el('strong', '', rule.target === 'reject' ? '拦截连接' : out?.name || '出口已不可用'));
      if (invalid) target.append(el('small', 'routing-row-error', '请替换出口 · 命中时拦截'));
      else if (out?.region) target.append(el('small', '', out.region));
      const actions = el('div', 'routing-rule-actions');
      const toggle = button('', 'routing-switch-button', () => mutate(() => { rule.enabled = !rule.enabled; }), !editable); toggle.setAttribute('role', 'switch'); toggle.setAttribute('aria-checked', String(!!rule.enabled)); toggle.setAttribute('aria-label', '启用规则 ' + rule.name); toggle.append(el('span', 'routing-switch-track')); toggle.firstChild.setAttribute('aria-hidden', 'true');
      const edit = button('编辑', 'routing-edit-button', () => openEditor(rule), !editable); edit.setAttribute('aria-label', '编辑 ' + rule.name);
      const more = button('⋯', 'routing-more-button', () => {
        const wasOpen = more.getAttribute('aria-expanded') === 'true'; closeMenus(); if (wasOpen) return;
        more.setAttribute('aria-expanded', 'true');
        const menu = el('div', 'routing-rule-menu'); menu.setAttribute('role', 'menu');
        const addAction = (label, action, disabled, danger = false) => { const item = button(label, danger ? 'routing-delete' : '', () => { closeMenus(); action(); }, disabled); item.setAttribute('role', 'menuitem'); menu.append(item); };
        addAction('上移', () => moveRule(rule.id, -1), index === 0);
        addAction('下移', () => moveRule(rule.id, 1), index === draft.rules.length - 1);
        addAction('复制规则', () => { const duplicate = copy(rule); duplicate.id = ''; duplicate.name = rule.name.slice(0, 74) + ' 副本'; openEditor(duplicate); }, draft.rules.length >= (state.policy.max_rules ?? 6));
        addAction('删除规则', async () => { if (await window.panelConfirm('删除“' + rule.name + '”？应用更改后生效。', '删除规则')) mutate(() => { draft.rules = draft.rules.filter(item => item.id !== rule.id); }); }, false, true);
        row.append(menu); menu.querySelector('button:not(:disabled)')?.focus();
      }, !editable); more.setAttribute('aria-label', rule.name + ' 更多操作'); more.setAttribute('aria-haspopup', 'menu'); more.setAttribute('aria-expanded', 'false');
      actions.append(toggle, edit, more); row.append(position, description, el('span', 'routing-rule-arrow', '→'), target, actions); list.append(row);
      handle.addEventListener('dragstart', event => { if (!canEdit()) { event.preventDefault(); return; } dragged = rule.id; event.dataTransfer.effectAllowed = 'move'; event.dataTransfer.setData('text/plain', rule.id); row.classList.add('is-dragging'); });
      row.addEventListener('dragover', event => { if (!dragged || dragged === rule.id) return; event.preventDefault(); row.classList.add('is-drop-target'); });
      row.addEventListener('dragleave', () => row.classList.remove('is-drop-target'));
      row.addEventListener('drop', event => { event.preventDefault(); if (!dragged || dragged === rule.id) return; const source = dragged; dragged = null; mutate(() => { const from = draft.rules.findIndex(item => item.id === source), to = draft.rules.findIndex(item => item.id === rule.id); if (from < 0 || to < 0) return; const [moving] = draft.rules.splice(from, 1); draft.rules.splice(to, 0, moving); }); });
      handle.addEventListener('dragend', () => { dragged = null; root.querySelectorAll('.is-dragging,.is-drop-target').forEach(node => node.classList.remove('is-dragging', 'is-drop-target')); });
    }
    renderOutbounds(); renderPreviewNode();
    $('routing-preview-form').querySelector('button[type=submit]').disabled = state.locked || !state.policy.allowed || !(state.nodes || []).length;
    if (focusId && focusAction) list.querySelector('[data-rule-id="' + CSS.escape(focusId) + '"] ' + focusAction)?.focus({preventScroll: true});
  }
  function renderOutbounds() {
    const container = $('routing-egresses'); container.replaceChildren();
    const outs = state.outbounds || [];
    $('routing-egress-count').textContent = state.locked ? '' : outs.filter(out => out.usable).length + ' 个可用';
    if (!outs.length) { container.append(el('p', 'routing-footnote', state.locked ? '管理员开启自定义分流后，可查看已授权出口。' : '管理员尚未授权出口。')); return; }
    for (const out of outs) {
      const row = el('div', 'routing-egress-row');
      const info = el('div', 'routing-egress-description'); info.append(el('strong', '', out.name));
      if (out.region) info.append(el('span', 'routing-egress-region', out.region));
      info.append(el('p', '', !out.usable ? '当前不可使用' : out.description || '已授权使用'));
      const latency = el('div', 'routing-egress-latency');
      const test = button(out.delay != null ? out.delay + ' ms' : '测试延迟', '', async () => {
        test.disabled = true; test.textContent = '检测中…';
        try { const result = await api('/latency/' + encodeURIComponent(out.id), {}); out.delay = result.delay; out.checked_at = result.checked_at || result.timestamp || Date.now() / 1000; renderOutbounds(); window.panelToast(result.delay == null ? '出口不可达或检测超时' : out.name + ' · ' + result.delay + ' ms', result.delay == null); }
        catch (error) { test.disabled = false; test.textContent = '重新检测'; if (!disposed) window.panelToast(error.message, true); }
      }, !state.editable || !out.usable); test.setAttribute('aria-label', '测试 ' + out.name + ' 出口延迟');
      latency.append(test, el('small', '', formatTime(out.checked_at))); row.append(info, latency); container.append(row);
    }
  }
  // One searchable chooser supports local destinations and paginated Geo catalogs.
  class Picker {
    constructor(container, {label, placeholder, multiple = false, selected, source, onSelect}) {
      this.container = container; this.selected = selected; this.source = source; this.onSelect = onSelect; this.multiple = multiple; this.opened = false; this.serial = 0; this.items = []; this.total = 0; this.query = ''; this.controller = new AbortController();
      this.root = el('div', 'routing-picker');
      this.trigger = button('', 'routing-picker-trigger', () => this.toggle());
      this.caption = el('span', '', placeholder || '请选择'); this.trigger.append(this.caption); this.trigger.setAttribute('role', 'combobox'); this.trigger.setAttribute('aria-haspopup', 'listbox'); this.trigger.setAttribute('aria-expanded', 'false'); this.trigger.setAttribute('aria-label', label);
      this.popup = el('div', 'routing-picker-popup'); this.popup.hidden = true;
      this.search = el('input'); this.search.type = 'search'; this.search.placeholder = '搜索名称或标识…'; this.search.autocomplete = 'off'; this.search.setAttribute('aria-label', '搜索' + label);
      this.list = el('div', 'routing-picker-options'); this.list.setAttribute('role', 'listbox'); this.list.setAttribute('aria-label', label); if (multiple) this.list.setAttribute('aria-multiselectable', 'true');
      this.list.id = 'routing-options-' + Math.random().toString(36).slice(2); this.trigger.setAttribute('aria-controls', this.list.id);
      this.meta = el('div', 'routing-picker-meta'); this.meta.setAttribute('aria-live', 'polite');
      this.more = button('加载更多', 'routing-picker-more', () => this.load(true)); this.more.hidden = true;
      this.popup.append(this.search, this.list, this.more, this.meta); this.root.append(this.trigger, this.popup); container.replaceChildren(this.root);
      this.search.addEventListener('input', () => { clearTimeout(this.timer); this.timer = setTimeout(() => { this.query = this.search.value.trim(); this.load(); }, 180); }, {signal: this.controller.signal});
      document.addEventListener('pointerdown', event => { if (!this.root.contains(event.target)) this.close(); }, {signal: this.controller.signal});
      this.root.addEventListener('keydown', event => {
        if (event.key === 'Escape' && this.opened) { event.preventDefault(); event.stopPropagation(); this.close(); this.trigger.focus(); return; }
        if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
          event.preventDefault();
          if (!this.opened) { this.open(); return; }
          const items = [...this.list.querySelectorAll('button:not(:disabled)')];
          const current = items.indexOf(document.activeElement);
          const index = event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1 : Math.max(0, Math.min(items.length - 1, current + (event.key === 'ArrowDown' ? 1 : -1)));
          items[index]?.focus();
        }
        if (event.key === 'Tab') setTimeout(() => { if (!this.root.contains(document.activeElement)) this.close(); }, 0);
      }, {signal: this.controller.signal});
    }
    setCaption(value) { this.caption.textContent = value || '请选择'; }
    toggle() { this.opened ? this.close() : this.open(); }
    open() {
      if (this.trigger.disabled) return;
      this.opened = true; this.popup.hidden = false; this.trigger.setAttribute('aria-expanded', 'true'); this.search.value = ''; this.query = '';
      const rect = this.trigger.getBoundingClientRect(), boundary = this.root.closest('.routing-drawer-body')?.getBoundingClientRect();
      const above = rect.top - (boundary?.top || 0) - 12, below = (boundary?.bottom || innerHeight) - rect.bottom - 12;
      const useAbove = below < 280 && above > below;
      this.popup.classList.toggle('is-above', useAbove);
      this.list.style.maxHeight = Math.max(80, Math.min(215, (useAbove ? above : below) - 110)) + 'px';
      this.load(); this.search.focus({preventScroll: true});
    }
    close() { this.opened = false; this.popup.hidden = true; this.trigger.setAttribute('aria-expanded', 'false'); }
    destroy() { this.serial++; clearTimeout(this.timer); this.controller.abort(); this.close(); }
    async load(append = false) {
      const sequence = ++this.serial;
      if (!append) { this.items = []; this.list.replaceChildren(el('div', 'routing-catalog-loading', '正在加载…')); }
      this.more.disabled = true;
      try {
        const result = await this.source(this.query, append ? this.items.length : 0);
        if (sequence !== this.serial || this.controller.signal.aborted) return;
        this.items = append ? [...this.items, ...result.items] : result.items;
        this.total = result.total; this.renderItems();
      } catch (error) {
        if (sequence !== this.serial || this.controller.signal.aborted) return;
        this.list.replaceChildren(el('div', 'routing-catalog-loading', '加载失败，请重新搜索')); this.meta.textContent = error.message;
      } finally { if (sequence === this.serial) this.more.disabled = false; }
    }
    renderItems() {
      this.list.replaceChildren();
      if (!this.items.length) this.list.append(el('div', 'routing-catalog-loading', '没有匹配的选项'));
      for (const item of this.items) {
        const option = button('', '', () => {
          this.onSelect(item); if (!this.multiple) { this.close(); this.trigger.focus(); } else { this.renderItems(); this.search.focus(); }
        }, !!item.disabled);
        option.setAttribute('role', 'option'); option.setAttribute('aria-selected', String(this.selected().includes(item.value)));
        const name = el('span', '', item.label); option.append(name);
        if (item.detail && item.detail !== item.label) name.append(el('small', '', ' · ' + item.detail));
        this.list.append(option);
      }
      this.meta.textContent = '共 ' + this.total + ' 项' + (this.multiple ? ' · 可多选，任意一项命中即匹配' : '');
      this.more.hidden = this.items.length >= this.total;
    }
  }
  function localSource(values) { return async (query, offset) => { const filtered = values.filter(item => (item.label + ' ' + (item.detail || '')).toLowerCase().includes(query.toLowerCase())); return {items: filtered.slice(offset, offset + 60), total: filtered.length}; }; }
  async function countryCatalog(query, offset) {
    if (!geoIpCatalog) {
      if (!geoIpRequest) geoIpRequest = (async () => {
        const first = await api('/catalog?kind=geoip', null, 'GET');
        const size = first.items.length || 80;
        const pages = await Promise.all(Array.from({length: Math.ceil(Math.max(0, first.total - size) / size)}, (_, index) => api('/catalog?' + new URLSearchParams({kind: 'geoip', offset: String((index + 1) * size)}), null, 'GET')));
        geoIpCatalog = [...first.items, ...pages.flatMap(page => page.items)].map(item => {
          if (regionNames) { try { item.label = regionNames.of(item.value.toUpperCase()); } catch (_) {} }
          labels.set('geoip:' + item.value, item.label);
          return {...item, detail: item.value};
        });
      })().finally(() => { geoIpRequest = null; });
      await geoIpRequest;
    }
    return localSource(geoIpCatalog)(query, offset);
  }
  function renderPreviewNode() {
    const nodes = state.nodes || [];
    const signature = JSON.stringify([state.locked, nodes]);
    if (previewPicker && signature === previewNodeSignature) return;
    previewNodeSignature = signature; previewPicker?.destroy();
    if (!nodes.some(node => node.id === previewNode)) previewNode = nodes[0]?.id || '';
    previewPicker = new Picker($('routing-preview-node'), {label: '使用节点', selected: () => [previewNode], source: localSource(nodes.map(node => ({value: node.id, label: node.name, detail: node.locked ? '固定出口' : ''}))), onSelect: item => { previewNode = item.value; previewPicker.setCaption(item.label); }});
    previewPicker.setCaption(nodes.find(node => node.id === previewNode)?.name || '暂无可用节点');
    previewPicker.trigger.disabled = state.locked || !nodes.length;
  }
  function buildValuePicker() {
    valuePicker?.destroy(); valuePicker = null;
    const kind = editorRule.kind, catalog = ['geoip', 'geosite'].includes(kind);
    $('routing-catalog-field').hidden = !catalog; $('routing-manual-field').hidden = catalog;
    root.querySelectorAll('[data-kind]').forEach(node => node.setAttribute('aria-pressed', String(node.dataset.kind === kind)));
    if (!catalog) {
      $('routing-manual-values').value = editorRule.values.join('\n');
      $('routing-manual-values').placeholder = kind === 'domain_suffix' ? 'example.com\nexample.org' : '203.0.113.0/24\n2001:db8::/32';
      $('routing-manual-help').textContent = kind === 'domain_suffix' ? '每行一个域名，同时匹配它的子域名。' : '每行一个 IP 或 CIDR 网段。';
      return;
    }
    $('routing-values-label').textContent = kind === 'geosite' ? '选择网站与服务' : '选择目标 IP 国家／地区';
    valuePicker = new Picker($('routing-values-picker'), {
      label: kind === 'geosite' ? '网站与服务' : '目标 IP 国家／地区', placeholder: '搜索并选择…', multiple: true,
      selected: () => editorRule.values,
      source: async (query, offset) => {
        if (kind === 'geoip') return countryCatalog(query, offset);
        const result = await api('/catalog?' + new URLSearchParams({kind, q: query, offset: String(offset)}), null, 'GET');
        for (const item of result.items) {
          if (kind === 'geoip' && regionNames) { try { item.label = regionNames.of(item.value.toUpperCase()); } catch (_) {} }
          labels.set(kind + ':' + item.value, item.label); item.detail = item.value;
        }
        return result;
      },
      onSelect: item => { toggleValue(item.value); }
    });
    $('routing-popular').replaceChildren(...popular[kind].map(([value, label]) => button(label, '', () => { toggleValue(value); valuePicker?.renderItems(); })));
    renderChips();
  }
  function toggleValue(value) {
    const index = editorRule.values.indexOf(value);
    if (index >= 0) editorRule.values.splice(index, 1); else if (editorRule.values.length < 64) editorRule.values.push(value); else { window.panelToast('每条规则最多选择 64 项', true); return; }
    editorChanged = true; renderChips();
  }
  function renderChips() {
    const chips = $('routing-selected-values'); chips.replaceChildren();
    for (const value of editorRule.values) {
      const chip = el('span', 'routing-chip'); chip.append(document.createTextNode(valueLabel(editorRule.kind, value)));
      const remove = button('×', '', () => { toggleValue(value); valuePicker?.renderItems(); }); remove.setAttribute('aria-label', '移除 ' + valueLabel(editorRule.kind, value)); chip.append(remove); chips.append(chip);
    }
    valuePicker?.setCaption(editorRule.values.length ? '已选择 ' + editorRule.values.length + ' 项，继续添加' : '搜索并选择…');
  }
  function openEditor(rule) {
    if (!canEdit()) return;
    closeMenus(); editorPrevious = document.activeElement;
    editorRule = rule ? copy(rule) : {id: '', name: '', enabled: true, kind: 'geosite', values: [], target: '', node_ids: []};
    editorChanged = false;
    $('routing-editor-title').textContent = editorRule.id ? '编辑规则' : '添加规则';
    $('routing-rule-name').value = editorRule.name;
    $('routing-rule-error').hidden = true;
    buildValuePicker();
    targetPicker?.destroy();
    const choices = (state.outbounds || []).map(out => ({value: out.id, label: out.name, detail: out.region || (!out.usable ? '不可使用' : ''), disabled: !out.usable}));
    choices.push({value: 'reject', label: '拦截连接', detail: '不发送流量'});
    targetPicker = new Picker($('routing-target-picker'), {label: '使用出口', selected: () => [editorRule.target], source: localSource(choices), onSelect: item => { editorRule.target = item.value; editorChanged = true; targetPicker.setCaption(item.label); renderTargetHint(); }});
    targetPicker.setCaption(choices.find(item => item.value === editorRule.target)?.label || '选择一个已授权出口');
    renderTargetHint();
    const options = $('routing-node-options'); options.replaceChildren();
    for (const node of state.nodes || []) {
      const label = el('label', 'routing-node-option'); const field = el('input'); field.type = 'checkbox'; field.value = node.id; field.checked = editorRule.node_ids.includes(node.id);
      field.addEventListener('change', () => { editorRule.node_ids = [...options.querySelectorAll('input:checked')].map(item => item.value); editorChanged = true; });
      label.append(el('span', '', node.name)); if (node.locked) label.append(el('small', '', '固定出口')); label.append(field); options.append(label);
    }
    editor.showModal(); $('routing-rule-name').blur(); editor.querySelector('[data-kind="' + editorRule.kind + '"]').focus();
  }
  function renderTargetHint() {
    const out = (state.outbounds || []).find(item => item.id === editorRule.target);
    $('routing-target-hint').textContent = out ? (out.usable ? out.description || '' : '此出口不可用，请选择其他出口。') : editorRule.target === 'reject' ? '命中这条规则的连接将被拦截。' : '';
  }
  async function closeEditor(force = false) {
    if (!editor.open) return true;
    if (!force && editorChanged && !(await window.panelConfirm('这条规则尚未保存到草稿，放弃编辑？', '放弃编辑'))) return false;
    editor.close(); valuePicker?.destroy(); targetPicker?.destroy(); editorChanged = false;
    if (editorPrevious?.isConnected) editorPrevious.focus();
    return true;
  }
  listen($('routing-rule-form'), 'submit', async event => {
    event.preventDefault(); if (!editorRule || !canEdit()) return;
    if (!['geoip', 'geosite'].includes(editorRule.kind)) editorRule.values = [...new Set($('routing-manual-values').value.split(/[\n,]+/).map(value => value.trim()).filter(Boolean))];
    const error = $('routing-rule-error');
    if (!editorRule.values.length || !editorRule.target) { error.hidden = false; error.textContent = !editorRule.values.length ? '请至少选择或填写一个匹配内容。' : '请选择使用的出口。'; return; }
    if (editorRule.values.length > 64) { error.hidden = false; error.textContent = '每条规则最多填写 64 项。'; return; }
    if (editorRule.target !== 'reject' && !(state.outbounds || []).some(out => out.id === editorRule.target && out.usable)) { error.hidden = false; error.textContent = '所选出口不可使用，请重新选择。'; return; }
    const row = copy(editorRule);
    row.name = $('routing-rule-name').value.trim() || row.values.slice(0, 2).map(value => valueLabel(row.kind, value)).join('、').slice(0, 80);
    if (!row.id) row.id = crypto.randomUUID ? crypto.randomUUID().replaceAll('-', '') : 'rule' + Date.now().toString(36) + Math.random().toString(36).slice(2);
    const before = copy(draft);
    const index = draft.rules.findIndex(item => item.id === row.id);
    if (index >= 0) draft.rules[index] = row; else draft.rules.push(row);
    generation++; saveError = '';
    const submit = event.submitter; submit.disabled = true;
    try { await flushDraft(); await closeEditor(true); window.panelToast('规则已保存到草稿'); }
    catch (failure) {
      // Keep the failed editor visible and let the user correct the submitted values.
      if (!state.locked) draft = before;
      generation = savedGeneration; saveError = ''; render();
      error.hidden = false; error.textContent = failure.message; editorChanged = true;
      if (!state.locked) { error.setAttribute('tabindex', '-1'); error.focus(); }
    } finally { submit.disabled = false; }
  });
  listen($('routing-rule-name'), 'input', () => { editorChanged = true; });
  listen($('routing-manual-values'), 'input', () => { editorChanged = true; });
  root.querySelectorAll('[data-kind]').forEach(node => listen(node, 'click', async () => {
    if (editorRule.kind === node.dataset.kind) return;
    const currentValues = ['geoip', 'geosite'].includes(editorRule.kind) ? editorRule.values.length : $('routing-manual-values').value.trim();
    if (currentValues && !(await window.panelConfirm('更换匹配类型将清空当前匹配内容。', '更换类型'))) return;
    editorRule.kind = node.dataset.kind; editorRule.values = []; editorChanged = true; buildValuePicker();
  }));
  listen($('routing-editor-close'), 'click', () => closeEditor());
  listen($('routing-editor-cancel'), 'click', () => closeEditor());
  listen(editor, 'cancel', event => { event.preventDefault(); closeEditor(); });
  listen(editor, 'click', event => { if (event.target === editor) { const rect = editor.getBoundingClientRect(); if (event.clientX < rect.left || event.clientX > rect.right) closeEditor(); } });
  listen($('routing-add'), 'click', () => openEditor());
  root.querySelectorAll('[data-routing-add]').forEach(node => listen(node, 'click', () => openEditor()));
  listen($('routing-enable'), 'click', () => mutate(() => { draft.enabled = !draft.enabled; }));
  listen($('routing-retry'), 'click', () => flushDraft().catch(() => {}));
  listen($('routing-discard'), 'click', async () => {
    if (!canEdit() || !(await window.panelConfirm('放弃未应用的更改，恢复当前生效的配置？', '放弃更改'))) return;
    try { await flushDraft(); const next = await api('/discard', {revision: state.policy.revision}); generation = savedGeneration = 0; saveError = ''; acceptState(next); window.panelToast('已恢复当前生效配置'); }
    catch (error) { if (!disposed) window.panelToast(error.message, true); }
  });
  listen($('routing-apply'), 'click', async () => {
    if (!canEdit()) return;
    if (!(await window.panelConfirm('应用分流需要重新加载服务，现有连接可能短暂重连。', '应用更改'))) return;
    $('routing-apply').disabled = true;
    try { await flushDraft(); const next = await api('/apply', {revision: state.policy.revision}); acceptState(next); window.panelToast('已提交应用，正在更新配置'); }
    catch (error) { if (!disposed) { window.panelToast(error.message, true); render(); } }
  });
  listen($('routing-preview-form'), 'submit', async event => {
    event.preventDefault(); const submit = event.submitter, result = $('routing-preview-result'); submit.disabled = true; result.hidden = false; result.classList.remove('is-error'); result.textContent = '正在检查匹配…';
    try {
      await flushDraft();
      const data = await api('/preview', {destination: $('routing-destination').value.trim(), node_id: previewNode});
      result.textContent = [data.summary || (data.rule_name && data.outbound_name ? data.rule_name + ' → ' + data.outbound_name : ''), data.outbound_name === '待确定' && data.rule_name ? '待确认规则：' + data.rule_name : '', data.warning && !data.warning.startsWith('依据已保存草稿') ? data.warning : ''].filter(Boolean).join('\n') || '未找到可用匹配结果';
    } catch (error) { if (!disposed) { result.classList.add('is-error'); result.textContent = error.message; } }
    finally { submit.disabled = false; }
  });
  listen(document, 'click', event => { if (!event.target.closest('.routing-rule-menu,.routing-more-button')) closeMenus(); });
  listen(document, 'keydown', event => { if (event.key === 'Escape') closeMenus(true); });
  const canLeave = async () => {
    if (!(await closeEditor())) return false;
    try { await flushDraft(); return true; }
    catch (_) { return window.panelConfirm('草稿尚未保存，离开后将丢失本地更改。', '离开页面'); }
  };
  window.customerCanLeave = canLeave;
  listen(window, 'beforeunload', event => { if (editorChanged || generation !== savedGeneration) { event.preventDefault(); event.returnValue = ''; } });
  scope.addEventListener('abort', () => {
    disposed = true; clearTimeout(saveTimer); clearTimeout(pollTimer); valuePicker?.destroy(); targetPicker?.destroy(); previewPicker?.destroy();
    if (window.customerCanLeave === canLeave) delete window.customerCanLeave;
    document.body.classList.remove('routing-has-savebar');
    if (editor.open) editor.close();
  }, {once: true});
  render(); if (busy()) schedulePoll();
})();
