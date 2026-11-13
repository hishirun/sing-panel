'use strict';
(()=>{
 const root=document.getElementById('user-node-picker');if(!root)return;
 const groups=[...root.querySelectorAll('[data-node-group]')];
 const boxes=()=>[...root.querySelectorAll('input[name="node_ids"]')];
 const refresh=()=>{
  const count=boxes().filter(box=>box.checked).length;
  const caption=root.querySelector('[data-node-selection-count]');if(caption)caption.textContent='已选 '+count+' 个';
  for(const group of groups){
   const choices=[...group.querySelectorAll('input[name="node_ids"]')],checked=choices.filter(box=>box.checked).length,toggle=group.querySelector('[data-node-group-toggle]');
   toggle.checked=choices.length>0&&checked===choices.length;toggle.indeterminate=checked>0&&checked<choices.length;
   group.querySelector('[data-node-group-count]').textContent=checked+' / '+choices.length;
  }
 };
 const search=()=>{
  const query=(root.querySelector('[data-node-search]')?.value||'').trim().toLocaleLowerCase();let matches=0;
  for(const group of groups){
   let visible=0;
   group.querySelectorAll('[data-node-option]').forEach(row=>{row.hidden=!row.dataset.searchText.includes(query);if(!row.hidden)visible++;});
   group.hidden=visible===0;matches+=visible;
  }
  const empty=root.querySelector('[data-node-no-results]');if(empty)empty.hidden=matches>0;
 };
 window.panelListen(root,'change',event=>{
  const toggle=event.target.closest('[data-node-group-toggle]');
  if(toggle)toggle.closest('[data-node-group]').querySelectorAll('input[name="node_ids"]').forEach(box=>box.checked=toggle.checked);
  refresh();
 });
 window.panelListen(root,'input',event=>{if(event.target.matches('[data-node-search]'))search();});
 window.panelListen(root,'click',event=>{
  const choose=event.target.closest('[data-node-select-visible]'),clear=event.target.closest('[data-node-clear-visible]');
  if(!choose&&!clear)return;
  root.querySelectorAll('[data-node-option]').forEach(row=>{if(!row.hidden&&!row.closest('[data-node-group]').hidden)row.querySelector('input[name="node_ids"]').checked=Boolean(choose);});refresh();
 });
 window.panelListen(root.closest('form'),'reset',()=>queueMicrotask(()=>{refresh();search();}));
 refresh();search();
})();
