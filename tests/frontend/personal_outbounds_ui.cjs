'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

class FakeElement {
  constructor(tag, ownerDocument) {
    this.tagName = String(tag).toUpperCase();
    this.ownerDocument = ownerDocument;
    this.children = [];
    this.parentNode = null;
    this.attributes = new Map();
    this.dataset = {};
    this.style = {};
    this.listeners = new Map();
    this.hidden = false;
    this.disabled = false;
    this.checked = false;
    this.indeterminate = false;
    this.open = false;
    this.value = '';
    this.type = '';
    this.name = '';
    this.id = '';
    this._className = '';
    this._text = '';
    this.classList = {
      contains: cls => this._classes().includes(cls),
      add: (...items) => { const s = new Set(this._classes()); items.forEach(x => x && s.add(x)); this._className = [...s].join(' '); },
      remove: (...items) => { const rm = new Set(items); this._className = this._classes().filter(x => !rm.has(x)).join(' '); },
      toggle: (cls, force) => {
        const has = this._classes().includes(cls);
        const next = force === undefined ? !has : !!force;
        if (next) this.classList.add(cls); else this.classList.remove(cls);
        return next;
      },
    };
  }
  _classes() { return this._className.split(/\s+/).filter(Boolean); }
  get className() { return this._className; }
  set className(v) { this._className = String(v || ''); }
  get innerHTML() { throw new Error('Unsafe innerHTML read'); }
  set innerHTML(_) { throw new Error('Unsafe innerHTML write is forbidden'); }
  set outerHTML(_) { throw new Error('Unsafe outerHTML write is forbidden'); }
  insertAdjacentHTML() { throw new Error('Unsafe insertAdjacentHTML is forbidden'); }
  get textContent() {
    if (this.children.length === 0) return this._text;
    return this._text + this.children.map(c => c.textContent).join('');
  }
  set textContent(v) {
    this.children.forEach(c => { c.parentNode = null; });
    this.children = [];
    this._text = String(v ?? '');
  }
  get firstChild() { return this.children[0] || null; }
  get isConnected() {
    let cur = this;
    while (cur) { if (cur === this.ownerDocument.body) return true; cur = cur.parentNode; }
    return false;
  }
  setAttribute(k, v) {
    const val = String(v);
    this.attributes.set(k, val);
    if (k === 'id') { this.id = val; this.ownerDocument._index(this); }
    if (k === 'class') this._className = val;
    if (k === 'name') this.name = val;
    if (k === 'type') this.type = val;
    if (k === 'value') this.value = val;
    if (k === 'hidden') this.hidden = true;
    if (k === 'disabled') this.disabled = true;
    if (k.startsWith('data-')) {
      const prop = k.slice(5).replace(/-([a-z])/g, (_, ch) => ch.toUpperCase());
      this.dataset[prop] = val;
    }
  }
  getAttribute(k) { return this.attributes.get(k) ?? null; }
  append(...nodes) {
    for (const item of nodes) {
      const node = typeof item === 'string' ? this.ownerDocument.createTextNode(item) : item;
      if (node.parentNode) node.parentNode.children = node.parentNode.children.filter(x => x !== node);
      node.parentNode = this;
      this.children.push(node);
      this.ownerDocument._indexTree(node);
    }
  }
  replaceChildren(...nodes) {
    this.children.forEach(c => { c.parentNode = null; });
    this.children = [];
    this._text = '';
    this.append(...nodes);
  }
  remove() {
    if (this.parentNode) {
      this.parentNode.children = this.parentNode.children.filter(x => x !== this);
      this.parentNode = null;
    }
  }
  focus() { this.ownerDocument.activeElement = this; }
  click() {
    if (this.disabled) return;
    if (this.tagName === 'INPUT' && this.type === 'checkbox') {
      this.checked = !this.checked;
      this.dispatchEvent({type: 'change', target: this});
      return;
    }
    this.dispatchEvent({type: 'click', target: this});
  }
  showModal() { this.open = true; }
  close() { this.open = false; }
  getBoundingClientRect() { return {top: 100, bottom: 500, left: 100, right: 600}; }
  contains(target) {
    let cur = target;
    while (cur) { if (cur === this) return true; cur = cur.parentNode; }
    return false;
  }
  closest(selector) {
    let cur = this;
    while (cur && cur instanceof FakeElement) {
      if (matchesSelector(cur, selector)) return cur;
      cur = cur.parentNode;
    }
    return null;
  }
  addEventListener(type, fn, options = {}) {
    if (options.signal?.aborted) return;
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    const list = this.listeners.get(type);
    list.push(fn);
    if (options.signal) options.signal.addEventListener('abort', () => {
      const idx = list.indexOf(fn);
      if (idx >= 0) list.splice(idx, 1);
    }, {once: true});
  }
  dispatchEvent(event) {
    const evt = {
      preventDefault() { this.defaultPrevented = true; },
      stopPropagation() {},
      target: this,
      ...event,
    };
    for (const fn of [...(this.listeners.get(evt.type) || [])]) fn(evt);
    return evt;
  }
  querySelectorAll(selector) {
    const results = [];
    const parts = selector.split(',').map(s => s.trim()).filter(Boolean);
    const walk = node => {
      for (const child of node.children || []) {
        if (child instanceof FakeElement) {
          if (parts.some(sel => matchesChain(child, sel, this))) results.push(child);
          walk(child);
        }
      }
    };
    walk(this);
    return results;
  }
  querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
  get elements() {
    const self = this;
    return {
      namedItem: name => self.querySelectorAll('input,textarea,select').find(n => n.name === name) || null,
    };
  }
}

function matchesSingle(el, token) {
  let rest = token.trim();
  if (!rest) return false;
  const attrRe = /\[([a-zA-Z0-9_-]+)(?:="([^"]*)"|=([^\]]+))?\]/g;
  let m;
  while ((m = attrRe.exec(rest)) !== null) {
    const [, key, qv, uv] = m;
    const expected = qv !== undefined ? qv : uv;
    const actual = key === 'type' ? (el.type || el.getAttribute('type')) :
      key === 'value' ? (el.value || el.getAttribute('value')) :
      key === 'hidden' ? (el.hidden ? '' : null) : el.getAttribute(key);
    if (expected === undefined) { if (actual === null) return false; }
    else if (String(actual) !== expected) return false;
  }
  rest = rest.replace(attrRe, '');
  if (rest.includes(':not(:disabled)')) {
    if (el.disabled) return false;
    rest = rest.replace(':not(:disabled)', '');
  }
  const idMatch = rest.match(/#([a-zA-Z0-9_-]+)/);
  if (idMatch) {
    if (el.id !== idMatch[1]) return false;
    rest = rest.replace(idMatch[0], '');
  }
  const classes = [...rest.matchAll(/\.([a-zA-Z0-9_-]+)/g)].map(x => x[1]);
  for (const cls of classes) if (!el.classList.contains(cls)) return false;
  rest = rest.replace(/\.[a-zA-Z0-9_-]+/g, '').trim();
  if (rest && el.tagName !== rest.toUpperCase()) return false;
  return true;
}

function matchesSelector(el, selector) {
  return selector.split(',').some(part => matchesSingle(el, part));
}

function matchesChain(el, chainSelector, scopeRoot) {
  const parts = chainSelector.trim().split(/\s+/);
  if (!matchesSingle(el, parts[parts.length - 1])) return false;
  let cur = el.parentNode;
  for (let i = parts.length - 2; i >= 0; i--) {
    while (cur && cur !== scopeRoot.parentNode && !(cur instanceof FakeElement && matchesSingle(cur, parts[i]))) {
      cur = cur.parentNode;
    }
    if (!cur || cur === scopeRoot.parentNode) return false;
    cur = cur.parentNode;
  }
  return true;
}

class FakeDocument {
  constructor() {
    this.byId = new Map();
    this.listeners = new Map();
    this.body = new FakeElement('body', this);
    this.activeElement = this.body;
    this.hidden = false;
    this.currentScript = {src: 'http://localhost/static/customer-routing.js?v=test'};
  }
  _index(el) { if (el.id) this.byId.set(el.id, el); }
  _indexTree(node) {
    if (node instanceof FakeElement) {
      this._index(node);
      for (const c of node.children) this._indexTree(c);
    }
  }
  createElement(tag) { return new FakeElement(tag, this); }
  createTextNode(text) { return {textContent: String(text ?? ''), children: [], parentNode: null}; }
  getElementById(id) { return this.byId.get(id) || null; }
  addEventListener(type, fn, options = {}) { this.body.addEventListener(type, fn, options); }
  querySelectorAll(sel) { return this.body.querySelectorAll(sel); }
  querySelector(sel) { return this.body.querySelector(sel); }
}

function parseTemplate(html, doc, initialState) {
  const bodyHtml = html
    .replace(/\{%[\s\S]*?%\}/g, '')
    .replace('{{ routing_state|tojson }}', () => JSON.stringify(initialState).replace(/</g, '\\u003c'))
    .replace(/\{\{[\s\S]*?\}\}/g, 'Alice');
  const voidTags = new Set(['input', 'img', 'br', 'hr', 'meta', 'link']);
  const stack = [doc.body];
  const tokenRe = /<!--[\s\S]*?-->|<\/([a-zA-Z0-9-]+)>|<([a-zA-Z0-9-]+)([^>]*)>|([^<]+)/g;
  let match;
  while ((match = tokenRe.exec(bodyHtml)) !== null) {
    const [, closeTag, openTag, attrStr, text] = match;
    if (closeTag) {
      if (stack.length > 1) stack.pop();
    } else if (openTag) {
      const el = doc.createElement(openTag);
      const attrRe = /([a-zA-Z0-9_:-]+)(?:="([^"]*)")?/g;
      let am;
      while ((am = attrRe.exec(attrStr)) !== null) {
        el.setAttribute(am[1], am[2] !== undefined ? am[2] : '');
      }
      stack[stack.length - 1].append(el);
      if (!voidTags.has(openTag.toLowerCase()) && !attrStr.trim().endsWith('/')) stack.push(el);
    } else if (text && stack.length > 0) {
      const parent = stack[stack.length - 1];
      if (parent.tagName === 'SCRIPT') parent._text += text;
      else if (text.trim()) parent.append(doc.createTextNode(text));
    }
  }
}

async function main() {
  const doc = new FakeDocument();
  const xssName = '"><img src=x onerror=alert(1)>香港';
  const initialState = {
    csrf: 'csrf-token-1',
    share_url: 'http://localhost/s/tok',
    locked: false,
    editable: true,
    reason: '',
    personal_outbound_limit: 10,
    personal_outbounds: [
      {id: 'personal-1', name: xssName, type: 'http', server: '2001:4860:4860::8888', server_port: 8443, tls_mode: 'tls', sni: 'cdn.example.com', enabled: true, revision: 1, has_password: true},
      {id: 'personal-2', name: '东京 SOCKS', type: 'socks', server: '1.1.1.1', server_port: 1080, tls_mode: 'none', sni: '', enabled: false, revision: 1, has_password: false},
    ],
    policy: {
      allowed: true, max_rules: 6, revision: 1, applied_revision: 1, status: 'applied', error: '', applied_at: 0,
      draft: {enabled: true, rules: []}, applied: {enabled: true, rules: []},
      rollout: {revision: 0, total: 0, confirmed: 0, state: 'idle', targets: []}, warnings: [],
    },
    outbounds: [
      {id: 'personal-1', name: xssName, type: 'http', enabled: true, usable: true, personal: true},
      {id: 'personal-2', name: '东京 SOCKS', type: 'socks', enabled: false, usable: false, personal: true},
    ],
    nodes: [{id: 'n1', name: 'Node 1', server_id: 'local', server_name: '主面板', available: true, enabled: true, server_enabled: true, online: true, locked: false}],
    presets: [],
  };

  const template = fs.readFileSync('panel/templates/customer_routing.html', 'utf8');
  parseTemplate(template, doc, initialState);

  const apiCalls = [];
  const downloads = [];
  const revokedUrls = [];
  const toasts = [];
  let initializer = null, refreshTimer = null;

  const fetchMock = async (url, options = {}) => {
    const body = options.body ? JSON.parse(options.body) : null;
    apiCalls.push({url, options, body});
    if (url.endsWith('/personal/import/preview')) {
      return {
        ok: true, status: 200,
        json: async () => ({
          source: 'uri', total_count: 3, parsed_count: 2, importable_count: 1, duplicate_count: 1, error_count: 0,
          existing_count: initialState.personal_outbounds.length, limit: 10, remaining_quota: 8, after_remaining_quota: 7,
          exceeds_quota: false, can_import: true,
          items: [
            {line: 1, name: '<script>bad()</script>美国', type: 'socks', server: '8.8.8.8', server_port: 1080, tls_mode: 'none', sni: '', resolved_ip: '8.8.8.8', enabled: true, status: 'ready'},
            {line: 2, name: '东京 SOCKS', type: 'socks', server: '1.1.1.1', server_port: 1080, tls_mode: 'none', sni: '', resolved_ip: '1.1.1.1', enabled: true, status: 'duplicate'},
          ],
          errors: [],
        }),
      };
    }
    if (url.endsWith('/personal/import')) {
      const added = {id: 'personal-3', name: '<script>bad()</script>美国', type: 'socks', server: '8.8.8.8', server_port: 1080, tls_mode: 'none', sni: '', enabled: true, revision: 1, has_password: true};
      const next = JSON.parse(JSON.stringify(initialState));
      next.personal_outbounds.push(added);
      return {
        ok: true, status: 200,
        json: async () => ({...next, import_result: {imported_count: 1, duplicate_count: 1, ids: ['personal-3']}}),
      };
    }
    if (url.endsWith('/personal/export')) {
      return {
        ok: true, status: 200,
        headers: {get: name => name.toLowerCase() === 'content-disposition' ? 'attachment; filename="personal-outbounds-20261117-120000.json"' : 'private, no-store'},
        blob: async () => ({size: 128}),
      };
    }
    return {ok: true, status: 200, json: async () => initialState};
  };

  // Spy on dynamic <a download> click
  const origCreate = doc.createElement.bind(doc);
  doc.createElement = tag => {
    const el = origCreate(tag);
    if (String(tag).toLowerCase() === 'a') {
      el.click = () => downloads.push({href: el.href, download: el.download});
    }
    return el;
  };

  const scope = new AbortController();
  const context = vm.createContext({
    console, JSON, Math, Date, Number, String, Boolean, Array, Object, Set, Map, RegExp, Error, DOMException, Promise,
    URL, URLSearchParams, AbortController, Intl,
    CSS: {escape: s => String(s).replace(/[^a-zA-Z0-9_-]/g, '\\$&')},
    FormData: class { constructor() {} *[Symbol.iterator]() {} },
    setTimeout: fn => { if (String(fn).includes('revokeObjectURL')) fn(); else if(fn.name==='refreshState')refreshTimer=fn; return 1; },
    clearTimeout: () => {},
    matchMedia: () => ({matches: true}),
    innerHeight: 900,
    fetch: fetchMock,
    document: doc,
    addEventListener: () => {},
  });
  context.window = context;
  context.URL = Object.assign(function URLWrap(...args) { return new URL(...args); }, {
    createObjectURL: () => 'blob:personal-export-1',
    revokeObjectURL: u => revokedUrls.push(u),
  });
  context.panelScope = scope;
  context.panelPageScripts = {register: (_src, fn) => { initializer = fn; }};
  context.panelToast = (msg, isErr) => toasts.push({msg, isErr: !!isErr});
  context.panelConfirm = async () => true;

  vm.runInContext(fs.readFileSync('panel/static/customer-routing.js', 'utf8'), context);
  assert.equal(typeof initializer, 'function');
  initializer();

  // 1. Verify initial render, IPv6 formatting, XSS-safe textContent & selection toolbar
  const list = doc.getElementById('personal-egress-list');
  assert.equal(list.children.length, 2);
  assert.ok(list.textContent.includes(xssName), 'XSS payload must render literally via textContent');
  assert.ok(list.textContent.includes('[2001:4860:4860::8888]:8443'), 'IPv6 host must be bracketed');
  assert.ok(list.textContent.includes('HTTPS'), 'HTTPS protocol label must distinguish TLS HTTP');
  assert.equal(doc.getElementById('personal-egress-selection').hidden, false);

  // 2. Check one item -> open Export -> defaults to selected scope -> explicit download with no-store & revokeObjectURL
  const checks = list.querySelectorAll('.personal-egress-check');
  assert.equal(checks.length, 2);
  checks[0].click();
  assert.ok(doc.getElementById('personal-selection-summary').textContent.includes('1 / 2'));
  doc.getElementById('personal-egress-export').click();
  assert.equal(doc.getElementById('personal-egress-exporter').open, true);
  assert.ok(doc.getElementById('personal-egress-exporter').textContent.includes('连接密码'));
  await doc.getElementById('personal-export-form').dispatchEvent({type: 'submit'});
  await new Promise(r => setImmediate(r));
  const exportCall = apiCalls.find(c => c.url.endsWith('/personal/export'));
  assert.ok(exportCall);
  assert.equal(exportCall.options.cache, 'no-store');
  assert.deepEqual(exportCall.body, {csrf: 'csrf-token-1', scope: 'selected', format: 'json', ids: ['personal-1']});
  assert.deepEqual(downloads, [{href: 'blob:personal-export-1', download: 'personal-outbounds-20261117-120000.json'}]);
  assert.deepEqual(revokedUrls, ['blob:personal-export-1']);

  // 3. Select all & clear selection
  const selectAll = doc.getElementById('personal-select-all');
  selectAll.checked = true;
  selectAll.dispatchEvent({type: 'change', target: selectAll});
  assert.ok(doc.getElementById('personal-selection-summary').textContent.includes('2 / 2'));
  doc.getElementById('personal-selection-clear').click();
  assert.equal(doc.getElementById('personal-selection-clear').hidden, true);

  // 4. Batch Import: preview -> edit invalidates -> re-preview -> commit updates DOM without reload
  doc.getElementById('personal-egress-import').click();
  const importDialog = doc.getElementById('personal-egress-importer');
  const importSubmit = doc.getElementById('personal-import-submit');
  const importText = doc.getElementById('personal-import-text');
  assert.equal(importDialog.open, true);
  assert.equal(importSubmit.disabled, true);

  importText.value = 'socks5://8.8.8.8:1080#US\nsocks5://1.1.1.1:1080#Dup';
  importText.dispatchEvent({type: 'input', target: importText});
  doc.getElementById('personal-import-preview-btn').click();
  await new Promise(r => setImmediate(r));

  const previewBox = doc.getElementById('personal-import-preview');
  assert.equal(previewBox.hidden, false);
  assert.ok(previewBox.textContent.includes('<script>bad()</script>美国'), 'Preview must render untrusted names as plain text');
  assert.ok(previewBox.textContent.includes('跳过重复'));
  assert.equal(importSubmit.disabled, false);

  // Editing text after preview immediately disables commit until re-previewed
  importText.value += '\n';
  importText.dispatchEvent({type: 'input', target: importText});
  assert.equal(importSubmit.disabled, true);

  doc.getElementById('personal-import-preview-btn').click();
  await new Promise(r => setImmediate(r));
  assert.equal(importSubmit.disabled, false);

  doc.getElementById('personal-import-form').dispatchEvent({type: 'submit'});
  await new Promise(r => setImmediate(r));
  await new Promise(r => setImmediate(r));

  assert.equal(importDialog.open, false);
  assert.equal(doc.getElementById('personal-egress-list').children.length, 3);
  assert.ok(doc.getElementById('personal-egress-list').textContent.includes('<script>bad()</script>美国'));

  // 5. A late file read must never overwrite a newer file or manual input.
  doc.getElementById('personal-egress-import').click();
  const fileInput=doc.getElementById('personal-import-file');
  let resolveOldFile;
  fileInput.files=[{name:'older.txt',size:64,text:()=>new Promise(resolve=>{resolveOldFile=resolve;})}];
  fileInput.dispatchEvent({type:'change'});
  const latest='socks5://9.9.9.9:1080#Latest';
  fileInput.files=[{name:'latest.txt',size:64,text:async()=>latest}];
  fileInput.dispatchEvent({type:'change'});
  await new Promise(r=>setImmediate(r));await new Promise(r=>setImmediate(r));
  resolveOldFile('socks5://1.1.1.1:1080#OLD');
  await new Promise(r=>setImmediate(r));
  assert.equal(importText.value,latest);
  assert.equal(doc.getElementById('personal-import-filename').textContent,'latest.txt');
  fileInput.files=[{name:'slow.txt',size:64,text:()=>new Promise(resolve=>{resolveOldFile=resolve;})}];
  fileInput.dispatchEvent({type:'change'});
  importText.value='socks5://8.8.8.8:1080#Manual';importText.dispatchEvent({type:'input'});
  resolveOldFile('socks5://1.1.1.1:1080#OLD');await new Promise(r=>setImmediate(r));
  assert.equal(importText.value,'socks5://8.8.8.8:1080#Manual');
  doc.getElementById('personal-import-cancel').click();await new Promise(r=>setImmediate(r));

  // 6. Losing the selected records must not silently broaden export to all.
  const third=doc.getElementById('personal-egress-list').querySelector('.personal-egress-check[value="personal-3"]');
  third.checked=true;third.dispatchEvent({type:'change'});
  doc.getElementById('personal-egress-export').click();
  assert.equal(doc.body.querySelector('[data-export-scope="selected"]').getAttribute('aria-pressed'),'true');
  await refreshTimer(); // fresh server state has only the original two records
  assert.equal(doc.getElementById('personal-export-submit').disabled,true);
  assert.equal(doc.body.querySelector('[data-export-scope="selected"]').getAttribute('aria-pressed'),'true');
  assert.equal(downloads.length,1);

  scope.abort();
  console.log('Personal outbounds UI: XSS-safe DOM, selection, preview gating, import & no-store export passed');
}

main().catch(err => { console.error(err); process.exitCode = 1; });
