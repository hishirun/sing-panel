(()=>{
 window.panelToast=(message,error=false)=>{
  document.querySelector('.panel-toast')?.remove();const box=document.createElement('div');box.className='panel-toast'+(error?' toast-error':'');box.setAttribute('role',error?'alert':'status');
  const icon=document.createElement('span');icon.className='feedback-icon';icon.textContent=error?'!':'✓';const text=document.createElement('span');text.textContent=message;const close=document.createElement('button');close.type='button';close.textContent='×';close.setAttribute('aria-label','关闭提示');close.onclick=()=>box.remove();box.append(icon,text,close);document.body.append(box);setTimeout(()=>box.remove(),4500);
 };
 window.panelConfirm=(message,action='确认操作')=>new Promise(resolve=>{
  const previous=document.activeElement;const dialog=document.createElement('dialog');dialog.className='panel-dialog';dialog.setAttribute('aria-labelledby','panel-confirm-title');dialog.setAttribute('aria-describedby','panel-confirm-message');
  const icon=document.createElement('div');icon.className='feedback-icon';icon.textContent='!';const title=document.createElement('h2');title.id='panel-confirm-title';title.textContent='请确认此操作';const description=document.createElement('p');description.id='panel-confirm-message';description.textContent=message;
  const actions=document.createElement('div');actions.className='feedback-actions';const cancel=document.createElement('button');cancel.type='button';cancel.textContent='取消';cancel.autofocus=true;const confirm=document.createElement('button');confirm.type='button';confirm.className=/删除|清空|重置/.test(message)?'danger':'primary';confirm.textContent=action;
  let finished=false;const finish=value=>{if(finished)return;finished=true;dialog.close();dialog.remove();if(previous?.isConnected)previous.focus();resolve(value);};cancel.onclick=()=>finish(false);confirm.onclick=()=>finish(true);dialog.addEventListener('cancel',e=>{e.preventDefault();finish(false);});dialog.addEventListener('click',e=>{if(e.target===dialog){const r=dialog.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)finish(false);}});document.addEventListener('panel:dispose',()=>finish(false),{once:true});actions.append(cancel,confirm);dialog.append(icon,title,description,actions);document.body.append(dialog);dialog.showModal();cancel.focus();
 });
})();
