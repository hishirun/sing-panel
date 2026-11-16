'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const initial = 'http://localhost/static/initial.js?v=1';
const once = 'http://localhost/static/global.js?v=1';
const elements = [{src: initial}, {src: once}];
const listeners = new Map(), requests = [], calls = [];
let downloads = [];
const context = vm.createContext({URL, Map, WeakMap, Set, Promise, AbortController, location: {href: 'http://localhost/users', origin: 'http://localhost'}});
context.window = context;
context.document = {
  addEventListener: (type, callback) => listeners.set(type, callback),
  querySelectorAll: () => elements,
  createElement: () => ({remove() {}}),
  body: {append(script) { requests.push(script.src); downloads.push(script); }},
};
context.panelScope = new AbortController();
vm.runInContext(fs.readFileSync('panel/static/page-scripts.js', 'utf8'), context);
const registry = context.panelPageScripts;
registry.register(initial, () => calls.push('initial'));
listeners.get('DOMContentLoaded')();

async function run() {
  assert.deepEqual(calls, ['initial']);
  await registry.activate([initial, initial, once], {signal: context.panelScope.signal});
  assert.deepEqual(calls, ['initial'], 'same page must not initialize twice');
  assert.equal(requests.length, 0, 'initial HTML assets must not be downloaded again');

  context.panelScope.abort();
  context.panelScope = new AbortController();
  await registry.activate([initial], {signal: context.panelScope.signal});
  assert.deepEqual(calls, ['initial', 'initial'], 'new page must reinitialize an already loaded module');

  const a = 'http://localhost/static/a.js?v=2', b = 'http://localhost/static/b.js?v=2';
  const activation = registry.activate([a, b], {signal: context.panelScope.signal});
  assert.deepEqual(requests, [a, b], 'independent missing modules must start in parallel');
  const pending = downloads; downloads = [];
  registry.register(b, () => calls.push('b')); pending[1].onload();
  registry.register(a, () => calls.push('a')); pending[0].onload();
  await activation;
  assert.deepEqual(calls.slice(-2), ['a', 'b'], 'initializers preserve template order regardless of download order');

  context.panelScope.abort(); context.panelScope = new AbortController();
  const c = 'http://localhost/static/c.js?v=3';
  const first = registry.activate([c], {signal: context.panelScope.signal});
  const second = registry.activate([c], {signal: context.panelScope.signal});
  assert.equal(requests.filter(value => value === c).length, 1, 'concurrent navigations deduplicate a download');
  context.panelScope.abort();
  registry.register(c, () => calls.push('c')); downloads.pop().onload();
  await Promise.all([first, second]);
  assert.ok(!calls.includes('c'), 'an abandoned page must not initialize after download');
  context.panelScope = new AbortController();
  await registry.activate([c], {signal: context.panelScope.signal});
  assert.equal(calls.filter(value => value === 'c').length, 1);

  const failed = 'http://localhost/static/retry.js?v=1';
  const attempt = registry.activate([failed]); downloads.pop().onerror();
  await assert.rejects(attempt, /unavailable/);
  const retry = registry.activate([failed]);
  registry.register(failed, () => calls.push('retry')); downloads.pop().onload(); await retry;
  assert.equal(requests.filter(value => value === failed).length, 2);
  await assert.rejects(registry.activate(['https://elsewhere.invalid/static/a.js']), /Invalid page script/);
  await assert.rejects(registry.activate(['/users/delete']), /Invalid page script/);
  console.log('Page lifecycle: load-once, parallel order, scope disposal, retry and URL restrictions passed');
}
run().catch(error => { console.error(error); process.exitCode = 1; });
