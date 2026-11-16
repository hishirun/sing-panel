'use strict';
window.panelPageScripts.register(document.currentScript.src, () => {
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
  let conflictState = null, actionPending = false, polling = false, presetLoading = false, lastSaved = 0;
  let previewMode = 'draft', previewHit = null, previewSerial = 0, editorScope = 'all';
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
  const canEdit = () => !!state.editable && !state.locked && !busy() && !actionPending && !conflictState;
  const cleanDocument = value => ({enabled: !!value?.enabled, rules: (value?.rules || []).map(rule => ({
    id: rule.id || '', name: rule.name || '', enabled: !!rule.enabled, kind: rule.kind,
    values: [...(rule.values || [])].sort(), target: rule.target, node_ids: [...(rule.node_ids || [])].sort()
  }))});
  const sameDocument = (left, right) => JSON.stringify(cleanDocument(left)) === JSON.stringify(cleanDocument(right));
  const changed = () => !sameDocument(draft, state.policy.applied);
  const unsaved = () => generation !== savedGeneration;
  const syncing = () => state.policy.rollout?.state === 'syncing' || state.policy.status === 'syncing';
  const capacity = () => Math.max(0, Number(state.policy.max_rules ?? 6));
  const canAdd = () => canEdit() && draft.rules.length < capacity() && !presetLoading;
  const availableNodes = () => (state.nodes || []).filter(node => !node.locked && node.available !== false && node.enabled !== false && node.server_enabled !== false);
  const serverName = node => node.server_name || (node.server_id === 'local' || !node.server_id ? '主面板' : '服务器');
  const nodeReason = node => node.locked ? '管理员固定出口' : node.server_enabled === false ? '机器已停用' : node.available === false || node.enabled === false ? '节点已停用' : node.online === false ? '机器离线，恢复后同步' : '';
  const protocolName = value => ({shadowsocks: 'SS', socks: 'SOCKS5', hysteria2: 'Hysteria 2', anytls: 'AnyTLS', vless: 'VLESS', trojan: 'Trojan', vmess: 'VMess', http: 'HTTP', direct: '直连'}[value] || value || '');
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
    if (window.customerAuthRedirect?.(response)) throw new DOMException('登录状态已失效', 'AbortError');
    let data;
    try { data = await response.json(); } catch (_) { throw new Error('请求未完成，请稍后重试'); }
    if (!response.ok) {
      const message = typeof data.detail === 'string' ? data.detail : '操作未完成，请检查输入后重试';
      if (response.status === 403 && !disposed) {
        // Refresh permission/CSRF state after an administrator change without
        // replaying the rejected mutation or discarding still-authorized edits.
        try {
          const fresh = await fetch(base + '/api', {credentials: 'same-origin', cache: 'no-store', signal: scope, headers: {'Accept': 'application/json'}});
          if (window.customerAuthRedirect?.(fresh)) throw new DOMException('登录状态已失效', 'AbortError');
          if (fresh.ok) {
            const next = await fresh.json();
            if (!next.policy.allowed) { clearTimeout(saveTimer); await closeEditor(true); generation = savedGeneration = 0; conflictState = null; saveError = ''; }
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
    const structuralChange = JSON.stringify([state.nodes, state.outbounds, state.presets, state.editable, state.locked, state.policy.max_rules, state.policy.warnings, busy()]) !== JSON.stringify([next.nodes, next.outbounds, next.presets, next.editable, next.locked, next.policy.max_rules, next.policy.warnings, ['queued', 'applying'].includes(next.policy.status)]);
    const draftChange = !keepDraft && !sameDocument(draft, next.policy.draft);
    state = next;
    if (draftChange) draft = copy(next.policy.draft || {enabled:true, rules:[]});
    if (structuralChange || draftChange) render(); else { renderStatus(); renderRollout(); }
    if (editor.open && structuralChange) { renderTargetHint(); renderNodeScope(); }
    schedulePoll();
  }
  function schedulePoll(immediate = false) {
    clearTimeout(pollTimer);
    if (disposed) return;
    pollTimer = setTimeout(refreshState, immediate ? 0 : document.hidden ? 30000 : busy() || syncing() ? 1800 : 12000);
  }
  async function refreshState() {
    if (disposed || polling) { schedulePoll(); return; }
    if (saving || actionPending) { schedulePoll(); return; }
    polling = true;
    const requestedRevision = state.policy.revision, requestedGeneration = generation;
    const wasPending = busy() || syncing();
    try {
      const next = await api('/api', null, 'GET');
      if (disposed || saving || actionPending || requestedRevision !== state.policy.revision || requestedGeneration !== generation) return;
      if (!next.policy.allowed) {
        clearTimeout(saveTimer); await closeEditor(true); generation = savedGeneration = 0; conflictState = null; saveError = ''; acceptState(next);
      } else if (next.policy.revision !== requestedRevision && (unsaved() || editor.open)) {
        clearTimeout(saveTimer); conflictState = next; saveError = '另一页面更新了草稿，请先载入最新版本。'; renderStatus();
      } else {
        acceptState(next, unsaved());
        if (wasPending && !busy() && !syncing()) {
          if (state.policy.status === 'failed' || state.policy.rollout?.state === 'failed') window.panelToast('部分配置未生效，请查看发布状态', true);
          else window.panelToast(state.policy.rollout?.total === 0 ? '已发布，暂无适用节点' : '相关机器已确认分流配置');
        }
      }
    } catch (error) {
      if (!disposed && error.name !== 'AbortError') { $('routing-saved-at').textContent = '连接中断，稍后重试'; }
    } finally { polling = false; schedulePoll(); }
  }
  function markChanged() {
    generation++; saveError = ''; clearPreview(); render();
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => flushDraft().catch(() => {}), 550);
  }
  async function flushDraft() {
    clearTimeout(saveTimer);
    if (saving) return saving;
    if (conflictState) throw new Error(saveError || '请载入最新草稿');
    if (generation === savedGeneration) return;
    saving = (async () => {
      while (generation !== savedGeneration && !disposed) {
        const sendingGeneration = generation;
        const snapshot = copy(draft);
        try {
          const next = await api('/draft', {revision: state.policy.revision, document: snapshot});
          savedGeneration = sendingGeneration; saveError = ''; lastSaved = Date.now();
          acceptState(next, generation !== sendingGeneration);
        } catch (error) {
          saveError = error.message;
          if (error.status === 409) {
            try { const fresh = await api('/api', null, 'GET'); if (fresh.policy.revision !== state.policy.revision) { conflictState = fresh; saveError = '另一页面更新了草稿，请先载入最新版本。'; } } catch (_) {}
          }
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
    const pending = busy(), hasChanges = changed(), failed = state.policy.status === 'failed' || state.policy.rollout?.state === 'failed';
    let status = !state.policy.allowed ? '暂未开放' : !state.editable ? '只读' : saveError ? '草稿未保存' : saving ? '正在保存草稿' : unsaved() ? '等待保存草稿' : pending ? '正在发布' : hasChanges ? '草稿已保存 · 未发布' : syncing() ? '等待机器同步' : failed || state.policy.rollout?.state === 'failed' ? '发布未完成' : !(state.policy.applied?.rules || []).length ? '暂无已发布规则' : state.policy.rollout?.total === 0 ? '已发布 · 暂无适用节点' : draft.enabled ? '已生效' : '跟随管理员';
    $('routing-status').textContent = status;
    $('routing-status').dataset.state = saveError || failed || state.policy.rollout?.state === 'failed' ? 'error' : hasChanges || unsaved() || saving ? 'draft' : syncing() || pending ? 'syncing' : 'applied';
    $('routing-saved-at').textContent = lastSaved && !unsaved() && !saveError ? new Date(lastSaved).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'}) + ' 已保存' : '';
    $('routing-savebar').hidden = state.locked || (!hasChanges && !unsaved() && !saveError && !pending && !failed);
    document.body.classList.toggle('routing-has-savebar', !$('routing-savebar').hidden);
    $('routing-save-title').textContent = pending ? '正在发布分流' : failed ? '上次发布未成功' : '有未发布更改';
    $('routing-save-caption').textContent = saveError || (saving ? '正在保存草稿…' : unsaved() ? '等待保存草稿…' : pending ? '机器确认结果会自动更新' : syncing() ? '草稿已保存 · 上一版本仍在同步' : '草稿已保存，发布后生效');
    $('routing-retry').hidden = !saveError;
    $('routing-retry').textContent = conflictState ? '载入最新草稿' : '重试保存';
    $('routing-apply').textContent = failed && !hasChanges ? '重新同步 ↗' : '发布更改 ↗';
    $('routing-apply').disabled = !canEdit() || !!saving || !!saveError || (!hasChanges && !failed);
    $('routing-discard').disabled = !canEdit() || !!saving || (!hasChanges && !unsaved());
    $('routing-retry').disabled = !state.editable || state.locked || busy() || actionPending || !!saving;
    $('routing-rule-form').querySelector('[type=submit]').disabled = !canEdit() || !!saving;
  }
  function renderRollout() {
    const rollout = state.policy.rollout, targets = rollout?.targets || [];
    $('routing-rollout').hidden = !state.policy.allowed || !rollout || (!targets.length && !rollout.revision);
    if ($('routing-rollout').hidden) return;
    $('routing-rollout-count').textContent = rollout.total === 0 ? '暂无适用节点' : (rollout.confirmed || 0) + ' / ' + (rollout.total ?? targets.length) + ' 已确认';
    $('routing-rollout-count').dataset.state = rollout.state === 'failed' ? 'error' : rollout.state;
    $('routing-rollout-caption').textContent = '已发布版本 ' + rollout.revision + (changed() ? ' · 当前草稿尚未发布' : '');
    const container = $('routing-rollout-targets'); container.replaceChildren();
    const names = {applied:'已生效',pending:'等待确认',offline:'离线待同步',paused:'机器已暂停',failed:'应用失败'};
    for (const target of targets) {
      const row = el('div', 'routing-rollout-row');
      const info = el('div'); info.append(el('strong', '', target.name));
      if (target.message) info.append(el('small', '', target.message));
      const badge = el('span', 'routing-machine-status', names[target.status] || '等待确认'); badge.dataset.state = target.status;
      row.append(info, badge); container.append(row);
    }
  }
  function render() {
    const focusRow = document.activeElement?.closest('[data-rule-id]');
    const focusId = focusRow?.dataset.ruleId;
    const focusAction = document.activeElement?.classList.contains('routing-switch-button') ? '.routing-switch-button' : document.activeElement?.classList.contains('routing-edit-button') ? '.routing-edit-button' : document.activeElement?.classList.contains('routing-more-button') ? '.routing-more-button' : null;
    closeMenus(); renderStatus(); renderRollout();
    const editable = canEdit();
    $('routing-rule-count').textContent = '已用 ' + draft.rules.length + ' / ' + capacity() + ' · 启用 ' + draft.rules.filter(rule => rule.enabled).length + ' 条';
    $('routing-add').disabled = !canAdd();
    root.querySelectorAll('[data-routing-add]').forEach(node => node.disabled = !canAdd());
    $('routing-capacity').hidden = state.locked || draft.rules.length < capacity();
    $('routing-capacity').textContent = draft.rules.length > capacity() ? '规则数量超过当前上限，请删减至 ' + capacity() + ' 条后发布。' : '已达到 ' + capacity() + ' 条上限，可编辑或删除现有规则。';
    root.querySelector('.routing-list-head').hidden = !draft.rules.length || state.locked;
    renderPresets();
    $('routing-enable').disabled = !editable;
    $('routing-enable').setAttribute('aria-checked', String(!!draft.enabled));
    $('routing-access-panel').hidden = !!state.policy.allowed;
    $('routing-access-description').textContent = state.reason || '请联系管理员开启自定义分流。';
    const notices = [];
    if (state.reason && !state.locked) notices.push(state.reason);
    if (state.policy.status === 'failed' && state.policy.error) notices.push(state.policy.error);
    if (!state.locked && !availableNodes().length && (state.nodes || []).length) notices.push('当前节点均已停用或使用管理员固定出口。');
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
      description.append(el('p', 'routing-rule-scope', ruleScopeText(rule)));
      for (const warning of state.policy.warnings || []) if (warning.rule_id === rule.id) description.append(el('p', 'routing-row-warning', warning.message));
      if (previewHit?.id === rule.id) { row.classList.add('is-preview-hit'); description.append(el('span', 'routing-hit-label', previewHit.mode === 'applied' ? '已发布规则命中' : '草稿命中')); }
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
        const addAction = (label, action, disabled, danger = false) => { const item = button(label, danger ? 'routing-delete' : '', () => { closeMenus(true); action(); }, disabled); item.setAttribute('role', 'menuitem'); menu.append(item); };
        addAction('上移', () => moveRule(rule.id, -1), index === 0);
        addAction('下移', () => moveRule(rule.id, 1), index === draft.rules.length - 1);
        addAction('复制规则', () => { const duplicate = copy(rule); duplicate.id = ''; duplicate.name = rule.name.slice(0, 74) + ' 副本'; openEditor(duplicate); }, draft.rules.length >= capacity());
        addAction('删除规则', async () => { if (await window.panelConfirm('删除“' + rule.name + '”？应用更改后生效。', '删除规则')) mutate(() => { draft.rules = draft.rules.filter(item => item.id !== rule.id); }); }, false, true);
        menu.addEventListener('keydown', event => {
          if (!['ArrowDown','ArrowUp','Home','End'].includes(event.key)) return;
          event.preventDefault(); const items = [...menu.querySelectorAll('button:not(:disabled)')], current = items.indexOf(document.activeElement);
          const next = event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1 : (current + (event.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length;
          items[next]?.focus();
        });
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
  function ruleScopeText(rule) {
    const explicit = rule.node_ids?.length;
    const nodes = explicit ? (state.nodes || []).filter(node => rule.node_ids.includes(node.id)) : availableNodes();
    const machines = [...new Set(nodes.map(serverName))];
    const label = machines.length === 1 ? machines[0] : machines.length + ' 台机器';
    return (explicit ? '指定范围 · ' : '全部授权 · ') + label + ' / ' + nodes.length + ' 个节点';
  }
  function renderPresets() {
    const container = $('routing-presets'); container.replaceChildren();
    const presets = state.presets || []; container.hidden = state.locked || !presets.length;
    if (!presets.length) return;
    container.append(el('span', 'routing-presets-label', '快速开始'));
    for (const preset of presets) {
      const choice = button(preset.name, '', () => openPreset(preset), !canAdd());
      if (preset.label) choice.title = preset.label;
      container.append(choice);
    }
  }
  const catalogChecks = new Map();
  async function validCatalogValues(kind, values) {
    const checked = await Promise.all(values.map(async value => {
      const key = kind + ':' + value;
      if (!catalogChecks.has(key)) catalogChecks.set(key, api('/catalog?' + new URLSearchParams({kind, q:value}), null, 'GET').then(result => {
        const item = result.items.find(item => item.value === value);
        if (item) labels.set(key, item.label);
        return !!item;
      }).catch(error => { catalogChecks.delete(key); throw error; }));
      return await catalogChecks.get(key) ? value : null;
    }));
    return checked.filter(Boolean);
  }
  async function openPreset(preset) {
    if (!canAdd()) return;
    presetLoading = true; render();
    try {
      const values = await validCatalogValues(preset.kind, preset.values || []);
      if (disposed || !canEdit()) return;
      if (!values.length) throw new Error('此预设暂不可用，请从目录选择匹配内容。');
      if (draft.rules.length >= capacity()) throw new Error('规则数量已达到上限。');
      openEditor({id:'', name:preset.name, enabled:true, kind:preset.kind, values, target:'', node_ids:[]});
    } catch (error) { if (!disposed) window.panelToast(error.message, true); }
    finally { presetLoading = false; if (!disposed) render(); }
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
      info.append(el('p', '', [protocolName(out.type), !out.usable ? (out.enabled === false ? '管理员已停用' : '暂不可选择') : out.description].filter(Boolean).join(' · ')));
      const latency = el('div', 'routing-egress-latency');
      const test = button(out.delay != null ? out.delay + ' ms' : out.checked_at ? '重新检测' : '测试延迟', '', async () => {
        test.disabled = true; test.textContent = '检测中…';
        try { const result = await api('/latency/' + encodeURIComponent(out.id), {}); out.delay = result.delay; out.checked_at = result.checked_at || result.timestamp || Date.now() / 1000; renderOutbounds(); window.panelToast(result.delay == null ? '出口不可达或检测超时' : out.name + ' · ' + result.delay + ' ms', result.delay == null); }
        catch (error) { test.disabled = false; test.textContent = '重新检测'; if (!disposed) window.panelToast(error.message, true); }
      }, !state.editable || !out.usable); test.setAttribute('aria-label', '测试 ' + out.name + ' 出口延迟');
      latency.append(test, el('small', '', (out.delay == null && out.checked_at ? '未连通 · ' : '') + formatTime(out.checked_at))); row.append(info, latency); container.append(row);
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
        this.list.replaceChildren(el('div', 'routing-catalog-loading', '目录加载失败'), button('重新加载', 'routing-picker-retry', () => this.load())); this.meta.textContent = error.message; this.more.hidden = true;
      } finally { if (sequence === this.serial) this.more.disabled = false; }
    }
    renderItems() {
      this.list.replaceChildren();
      if (!this.items.length) this.list.append(el('div', 'routing-catalog-loading', '没有匹配的选项'));
      let lastGroup;
      for (const item of this.items) {
        if (item.group && item.group !== lastGroup) { this.list.append(el('div', 'routing-picker-group', item.group)); lastGroup = item.group; }
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
  function localSource(values) { return async (query, offset) => { const filtered = values.filter(item => (item.label + ' ' + (item.detail || '') + ' ' + (item.group || '')).toLowerCase().includes(query.toLowerCase())); return {items: filtered.slice(offset, offset + 60), total: filtered.length}; }; }
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
    previewPicker = new Picker($('routing-preview-node'), {label: '使用节点', selected: () => [previewNode], source: localSource([...nodes].sort((a,b) => serverName(a).localeCompare(serverName(b))).map(node => ({value: node.id, label: node.name, group:serverName(node), detail:nodeReason(node)}))), onSelect: item => { previewNode = item.value; previewPicker.setCaption(item.group + ' / ' + item.label); clearPreview(); }});
    const selected = nodes.find(node => node.id === previewNode);
    previewPicker.setCaption(selected ? serverName(selected) + ' / ' + selected.name : '暂无授权节点');
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
    $('routing-popular').replaceChildren();
    const currentEditor = editorRule;
    validCatalogValues(kind, popular[kind].map(([value]) => value)).then(valid => {
      if (disposed || editorRule !== currentEditor || editorRule.kind !== kind || !editor.open) return;
      $('routing-popular').replaceChildren(...popular[kind].filter(([value]) => valid.includes(value)).map(([value, label]) => button(label, '', () => { toggleValue(value); valuePicker?.renderItems(); })));
    }).catch(() => {});
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
  function buildTargetPicker() {
    targetPicker?.destroy();
    const choicesNow = () => [...(state.outbounds || []).map(out => ({value:out.id, label:out.name, detail:[out.region, protocolName(out.type), !out.usable ? '不可选择' : out.delay != null ? out.delay + ' ms · 主控参考' : ''].filter(Boolean).join(' · '), disabled:!out.usable})), {value:'reject', label:'拦截连接', detail:'不发送流量'}];
    const choices = choicesNow();
    targetPicker = new Picker($('routing-target-picker'), {label:'使用出口', selected:() => [editorRule.target], source:(query, offset) => localSource(choicesNow())(query, offset), onSelect:item => { editorRule.target = item.value; editorChanged = true; targetPicker.setCaption(item.label); renderTargetHint(); }});
    targetPicker.setCaption(choices.find(item => item.value === editorRule.target)?.label || (editorRule.target ? '原出口已不可用，请重新选择' : '选择一个已授权出口'));
    targetPicker.trigger.disabled = !canEdit(); renderTargetHint();
  }
  function renderNodeScope() {
    const focusedNode = document.activeElement?.closest('.routing-node-option')?.querySelector('input')?.value;
    const selected = editorScope === 'selected', query = $('routing-node-search').value.trim().toLowerCase();
    root.querySelectorAll('[data-scope]').forEach(node => node.setAttribute('aria-pressed', String(node.dataset.scope === editorScope)));
    $('routing-node-selection').hidden = !selected;
    const valid = availableNodes(), chosen = valid.filter(node => editorRule.node_ids.includes(node.id));
    const invalidCount = editorRule.node_ids.filter(id => !valid.some(node => node.id === id)).length;
    $('routing-scope-summary').textContent = selected ? '已选择 ' + new Set(chosen.map(node => node.server_id || 'local')).size + ' 台机器 / ' + chosen.length + ' 个节点' + (invalidCount ? ' · ' + invalidCount + ' 个不可用选择需移除' : '') : '覆盖 ' + new Set(valid.map(node => node.server_id || 'local')).size + ' 台机器 / ' + valid.length + ' 个节点，后续授权节点自动加入。';
    const container = $('routing-node-options'); container.replaceChildren();
    if (!selected) return;
    const groups = new Map();
    for (const node of state.nodes || []) {
      if (!([serverName(node), node.name].join(' ').toLowerCase().includes(query))) continue;
      const id = node.server_id || 'local'; if (!groups.has(id)) groups.set(id, {name:serverName(node), nodes:[]}); groups.get(id).nodes.push(node);
    }
    const missing = editorRule.node_ids.filter(id => !(state.nodes || []).some(node => node.id === id));
    if (missing.length) {
      const row = el('div', 'routing-missing-selection'); row.append(el('span', '', missing.length + ' 个节点已取消授权'), button('移除', '', () => { editorRule.node_ids = editorRule.node_ids.filter(id => !missing.includes(id)); editorChanged = true; renderNodeScope(); })); container.append(row);
    }
    for (const [id, group] of groups) {
      const section = el('section', 'routing-node-group'); section.dataset.serverId = id; const heading = el('div', 'routing-node-group-heading');
      const choices = group.nodes.filter(node => valid.some(item => item.id === node.id));
      const selectedCount = choices.filter(node => editorRule.node_ids.includes(node.id)).length;
      const title = el('div'); title.append(el('strong', '', group.name), el('small', '', selectedCount + ' / ' + choices.length + ' 已选'));
      const actions = el('div', 'routing-node-group-actions');
      actions.append(button(query ? '选中结果' : '全选', '', () => { editorRule.node_ids = [...new Set([...editorRule.node_ids, ...choices.map(node => node.id)])]; editorChanged = true; renderNodeScope(); $('routing-node-options').querySelector('[data-server-id="' + CSS.escape(id) + '"] button:not(:disabled)')?.focus({preventScroll:true}); }, !choices.length || selectedCount === choices.length), button('清空', '', () => { editorRule.node_ids = editorRule.node_ids.filter(value => !group.nodes.some(node => node.id === value)); editorChanged = true; renderNodeScope(); $('routing-node-options').querySelector('[data-server-id="' + CSS.escape(id) + '"] button:not(:disabled)')?.focus({preventScroll:true}); }, !group.nodes.some(node => editorRule.node_ids.includes(node.id))));
      heading.append(title, actions); section.append(heading);
      for (const node of group.nodes) {
        const allowed = valid.some(item => item.id === node.id), checked = editorRule.node_ids.includes(node.id);
        const label = el('label', 'routing-node-option' + (!allowed ? ' is-unavailable' : ''));
        const field = el('input'); field.type = 'checkbox'; field.value = node.id; field.checked = checked; field.disabled = !allowed || !canEdit();
        field.addEventListener('change', () => { editorRule.node_ids = field.checked ? [...new Set([...editorRule.node_ids, node.id])] : editorRule.node_ids.filter(value => value !== node.id); editorChanged = true; renderNodeScope(); container.querySelector('input[value="' + CSS.escape(node.id) + '"]')?.focus({preventScroll:true}); });
        const info = el('span'); info.append(el('strong', '', node.name)); if (nodeReason(node)) info.append(el('small', '', nodeReason(node)));
        label.append(info, field); section.append(label);
        if (checked && !allowed) section.append(button('移除「' + node.name + '」', 'routing-remove-selection', () => { editorRule.node_ids = editorRule.node_ids.filter(value => value !== node.id); editorChanged = true; renderNodeScope(); }));
      }
      container.append(section);
    }
    if (!groups.size) container.append(el('p', 'routing-field-hint', query ? '没有匹配的机器或节点' : '暂无授权节点'));
    if (focusedNode) container.querySelector('input[value="' + CSS.escape(focusedNode) + '"]:not(:disabled)')?.focus({preventScroll:true});
  }
  function openEditor(rule) {
    if (!canEdit() || (!rule?.id && draft.rules.length >= capacity())) return;
    closeMenus(); editorPrevious = document.activeElement;
    editorRule = rule ? copy(rule) : {id:'', name:'', enabled:true, kind:'geosite', values:[], target:'', node_ids:[]};
    editorScope = editorRule.node_ids.length ? 'selected' : 'all';
    editorChanged = !editorRule.id && !!editorRule.values.length;
    $('routing-editor-title').textContent = editorRule.id ? '编辑规则' : '添加规则';
    $('routing-rule-name').value = editorRule.name;
    $('routing-rule-error').hidden = true; $('routing-node-search').value = '';
    buildValuePicker(); buildTargetPicker(); renderNodeScope();
    editor.showModal(); editor.querySelector('.routing-drawer-body').scrollTop = 0;
    editor.querySelector('[data-kind="' + editorRule.kind + '"]').focus(); renderStatus();
  }
  function renderTargetHint() {
    const out = (state.outbounds || []).find(item => item.id === editorRule.target);
    $('routing-target-hint').textContent = out ? (out.usable ? out.description || '' : '此出口不可用，请选择其他出口。') : editorRule.target === 'reject' ? '命中这条规则的连接将被拦截。' : '';
  }
  async function closeEditor(force = false) {
    if (!editor.open) return true;
    if (!force && editorChanged && !(await window.panelConfirm('这条规则尚未保存到草稿，放弃编辑？', '放弃编辑'))) return false;
    editor.close(); valuePicker?.destroy(); targetPicker?.destroy(); editorChanged = false;
    if (editorPrevious?.isConnected && editorPrevious !== document.body) editorPrevious.focus(); else $('routing-add').focus({preventScroll:true});
    return true;
  }
  listen($('routing-rule-form'), 'submit', async event => {
    event.preventDefault(); if (!editorRule || !canEdit()) return;
    if (!['geoip', 'geosite'].includes(editorRule.kind)) editorRule.values = [...new Set($('routing-manual-values').value.split(/[\n,]+/).map(value => value.trim()).filter(Boolean))];
    const error = $('routing-rule-error');
    const showError = message => { error.hidden = false; error.textContent = message; error.setAttribute('tabindex','-1'); error.focus(); };
    if (!editorRule.values.length || !editorRule.target) { showError(!editorRule.values.length ? '请至少选择或填写一个匹配内容。' : '请选择使用的出口。'); return; }
    if (editorRule.values.length > 64) { showError('每条规则最多填写 64 项。'); return; }
    if (editorRule.target !== 'reject' && !(state.outbounds || []).some(out => out.id === editorRule.target && out.usable)) { showError('所选出口不可使用，请重新选择。'); return; }
    if (!editorRule.id && draft.rules.length >= capacity()) { showError('规则数量已达到 ' + capacity() + ' 条上限。'); return; }
    if (editorScope === 'selected') {
      if (!editorRule.node_ids.length) { showError('指定范围至少选择一个节点，或切换为全部授权节点。'); return; }
      const valid = availableNodes();
      if (editorRule.node_ids.some(id => !valid.some(node => node.id === id))) { showError('请先移除已停用、固定出口或取消授权的节点。'); return; }
    }
    const row = copy(editorRule);
    row.node_ids = editorScope === 'all' ? [] : [...new Set(editorRule.node_ids)];
    row.name = $('routing-rule-name').value.trim() || row.values.slice(0, 2).map(value => valueLabel(row.kind, value)).join('、').slice(0, 80);
    if (!row.id) row.id = crypto.randomUUID ? crypto.randomUUID().replaceAll('-', '') : 'rule' + Date.now().toString(36) + Math.random().toString(36).slice(2);
    const before = copy(draft), beforeGeneration = generation, beforeSavedGeneration = savedGeneration;
    const index = draft.rules.findIndex(item => item.id === row.id);
    if (index >= 0) draft.rules[index] = row; else draft.rules.push(row);
    generation++; saveError = ''; clearPreview();
    const submit = event.submitter; submit.disabled = true;
    try { await flushDraft(); await closeEditor(true); render(); window.panelToast('规则已保存到草稿'); }
    catch (failure) {
      // Keep the failed editor visible and let the user correct the submitted values.
      if (!state.locked) draft = before;
      generation = beforeGeneration; savedGeneration = beforeSavedGeneration; if (!conflictState) saveError = ''; render();
      error.hidden = false; error.textContent = failure.message; editorChanged = true;
      if (!state.locked) { error.setAttribute('tabindex', '-1'); error.focus(); }
    } finally { renderStatus(); }
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
  root.querySelectorAll('[data-scope]').forEach(node => listen(node, 'click', () => {
    if (editorScope === node.dataset.scope) return;
    editorScope = node.dataset.scope; editorChanged = true; renderNodeScope();
  }));
  listen($('routing-node-search'), 'input', renderNodeScope);
  root.querySelectorAll('[data-preview-mode]').forEach(node => listen(node, 'click', () => {
    previewMode = node.dataset.previewMode;
    root.querySelectorAll('[data-preview-mode]').forEach(choice => choice.setAttribute('aria-pressed', String(choice.dataset.previewMode === previewMode)));
    clearPreview();
  }));
  listen($('routing-destination'), 'input', clearPreview);
  listen($('routing-retry'), 'click', async () => {
    if (!conflictState) { flushDraft().catch(() => {}); return; }
    if (!(await window.panelConfirm('载入最新草稿会替换本页尚未保存的修改。', '载入最新草稿'))) return;
    try {
      const next = await api('/api', null, 'GET');
      await closeEditor(true); clearTimeout(saveTimer); conflictState = null; saveError = ''; generation = savedGeneration = 0; clearPreview(); acceptState(next); window.panelToast('已载入最新草稿');
    } catch (error) { if (!disposed) window.panelToast(error.message, true); }
  });
  listen($('routing-discard'), 'click', async () => {
    if (!canEdit() || !(await window.panelConfirm('放弃当前草稿更改，恢复最近发布的规则？', '放弃更改'))) return;
    clearTimeout(saveTimer); actionPending = true; render();
    try {
      if (saving) await saving;
      const next = await api('/discard', {revision:state.policy.revision});
      generation = savedGeneration = 0; saveError = ''; clearPreview(); acceptState(next); window.panelToast('已恢复最近发布的规则');
    } catch (error) { if (!disposed) window.panelToast(error.message, true); }
    finally { actionPending = false; if (!disposed) render(); }
  });
  listen($('routing-apply'), 'click', async () => {
    if (!canEdit()) return;
    if (!(await window.panelConfirm('发布到相关机器，现有连接可能短暂重连。', '发布分流'))) return;
    actionPending = true; render();
    try {
      await flushDraft();
      const next = await api('/apply', {revision:state.policy.revision}); acceptState(next);
      window.panelToast('已提交发布，等待机器确认');
    } catch (error) { if (!disposed) window.panelToast(error.message, true); }
    finally { actionPending = false; if (!disposed) render(); }
  });
  function clearPreview() {
    previewSerial++; previewHit = null;
    $('routing-preview-result').hidden = true;
    root.querySelectorAll('.is-preview-hit').forEach(node => node.classList.remove('is-preview-hit'));
    root.querySelectorAll('.routing-hit-label').forEach(node => node.remove());
  }
  function markPreviewHit(data) {
    if (data.matched !== true) return false;
    const rule = draft.rules.find(rule => rule.id === data.rule_id);
    const appliedRule = state.policy.applied?.rules?.find(rule => rule.id === data.rule_id);
    if (!rule || (data.mode === 'applied' && !sameDocument({enabled:true,rules:[rule]}, {enabled:true,rules:appliedRule ? [appliedRule] : []}))) return false;
    previewHit = {id:rule.id, mode:data.mode};
    const row = root.querySelector('[data-rule-id="' + CSS.escape(rule.id) + '"]');
    if (!row) return false;
    row.classList.add('is-preview-hit');
    row.querySelector('.routing-rule-description').append(el('span', 'routing-hit-label', data.mode === 'applied' ? '已发布规则命中' : '草稿命中'));
    return true;
  }
  listen($('routing-preview-form'), 'submit', async event => {
    event.preventDefault();
    clearPreview(); const sequence = previewSerial, mode = previewMode;
    const submit = event.submitter, result = $('routing-preview-result'); submit.disabled = true; result.hidden = false; result.classList.remove('is-error'); result.textContent = '正在检查匹配…';
    try {
      if (mode === 'draft') await flushDraft();
      const data = await api('/preview', {destination:$('routing-destination').value.trim(), node_id:previewNode, mode, revision:mode === 'draft' ? state.policy.revision : state.policy.applied_revision});
      if (disposed || sequence !== previewSerial) return;
      result.replaceChildren();
      result.append(el('small', 'routing-preview-meta', [data.mode === 'applied' ? '已发布配置' : '当前草稿', data.revision != null ? '版本 ' + data.revision : '', data.server_name, data.node_name].filter(Boolean).join(' · ')));
      result.append(el('strong', '', data.summary || (data.rule_name && data.outbound_name ? data.rule_name + ' → ' + data.outbound_name : '') || '未找到可用匹配结果'));
      if (data.outbound_name === '待确定' && data.rule_name) result.append(el('p', '', '待确认规则：' + data.rule_name));
      if (data.warning && !data.warning.startsWith('依据已保存草稿')) result.append(el('p', '', data.warning));
      if (markPreviewHit(data)) result.append(button('查看命中规则 ↑', 'routing-preview-jump', () => {
        const row = root.querySelector('[data-rule-id="' + CSS.escape(data.rule_id) + '"]');
        row?.scrollIntoView({block:'center', behavior:matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth'});
        row?.querySelector('.routing-edit-button')?.focus({preventScroll:true});
      }));
      else if (data.matched === true && data.rule_id && data.mode === 'applied' && state.policy.applied?.rules?.some(rule => rule.id === data.rule_id)) result.append(el('small', 'routing-preview-meta', '该规则已在当前草稿中修改或移除'));
    } catch (error) {
      if (!disposed && sequence === previewSerial) { result.classList.add('is-error'); result.textContent = error.message; }
    } finally { if (!disposed) submit.disabled = state.locked || !state.policy.allowed || !(state.nodes || []).length; }
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
  listen(document, 'visibilitychange', () => schedulePoll(!document.hidden));
  render(); schedulePoll();
})();

});
