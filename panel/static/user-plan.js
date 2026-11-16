'use strict';
window.panelPageScripts.register(document.currentScript.src, () => {
'use strict';
(() => {
  const amount = document.getElementById('quota-amount');
  if (!amount) return;
  const form = amount.form;
  const input = name => form.elements.namedItem(name);
  const refresh = () => {
    const mode = input('reset_mode').value;
    const value = Number(amount.value);
    const days = input('reset_days').value;
    const weekday = ['','周一','周二','周三','周四','周五','周六','周日'][Number(input('reset_weekday').value)];
    const names = {none:'一次性总额度 / GiB（0 不限量）',daily:'每天可用流量 / GiB',weekly:'每周可用流量 / GiB',monthly:'每月可用流量 / GiB',days:'每个周期可用流量 / GiB'};
    document.getElementById('quota-amount-label').textContent = names[mode];
    amount.min = mode === 'none' ? '0' : '0.01';
    form.querySelectorAll('[data-quota-field]').forEach(field => { field.hidden = field.dataset.quotaField !== mode; });
    const title = document.getElementById('quota-plan-title');
    const note = document.getElementById('quota-plan-note');
    if (!Number.isFinite(value) || value < 0 || (mode !== 'none' && value === 0)) {
      title.textContent = '请填写大于 0 的周期额度';
    } else {
      title.textContent = mode === 'none' ? (value === 0 ? '不限流量' : `一次性 ${value} GiB`) : `${{daily:'每天',weekly:'每周',monthly:'每月',days:`每 ${days} 天`}[mode]} ${value} GiB`;
    }
    note.textContent = ({none:'所有授权节点共享；不自动重置。',daily:'每天 00:00 UTC（北京时间 08:00）恢复额度。',weekly:`每${weekday} 00:00 UTC（北京时间 08:00）恢复额度。`,monthly:`每月 ${input('reset_day').value} 日 00:00 UTC 恢复额度，不足该日按月末。`,days:`从本次周期起每 ${days} 天恢复额度。`})[mode] + (mode === 'none' ? '' : '未用额度不累积，用尽后等待下次重置。');
    const renewal = input('renew_mode').value;
    form.querySelectorAll('[data-renew-field]').forEach(field => { field.hidden = field.dataset.renewField === 'enabled' ? renewal === 'none' : field.dataset.renewField !== renewal; });
  };
  form.addEventListener('input',refresh);
  form.addEventListener('change',refresh);
  refresh();
})();

});
