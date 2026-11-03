"""Separated administration pages and transactional bulk operations."""
import json
import math
import secrets
import sqlite3
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse, Response
from .core import connect, records, reason, set_memberships, random_port
from .management import audit, bounded, policy_input, external_input, refresh_external, SCHEMES, maintain
from urllib.parse import urlsplit


def install(app,m):
    def redirect(path):return RedirectResponse(path,status_code=303)
    def raw_user(raw,old=None):
        quota,expires=m.validate_limits(float(raw.get('quota_gib',0)),str(raw.get('expiry','')))
        if not math.isfinite(float(raw.get('quota_gib',0))):raise ValueError('额度必须是有限数值')
        p=policy_input(raw,json.loads(old['policy']) if old else None)
        if p['reset_mode']!='none' and quota<=0:raise ValueError('周期套餐请填写大于 0 的流量额度；不限量请选择一次性额度并填 0')
        if old and old['activated_at'] and p['first_use_days']!=json.loads(old['policy']).get('first_use_days',0):
            raise ValueError('已激活用户请直接调整到期日，不能重新设为首次使用激活')
        if p['first_use_days'] and not (old and old['activated_at']):expires=0
        group=str(raw.get('group_name','')).strip();comment=str(raw.get('comment','')).strip()
        if len(group)>60 or len(comment)>500:raise ValueError('分组最多 60 字，备注最多 500 字')
        links=external_input(str(raw.get('external_links','')))
        direct='\n'.join(x for x in links.splitlines() if urlsplit(x).scheme in SCHEMES)
        credentials={}
        if str(raw.get('secret','')).strip():
            secret=str(raw['secret']).strip()
            import re
            if not re.fullmatch(r'[A-Za-z0-9._~-]{12,255}',secret):raise ValueError('Snell 密码格式无效')
            credentials['secret']=secret
        if str(raw.get('uuid','')).strip():credentials['uuid']=str(uuid.UUID(str(raw['uuid']).strip()))
        return dict(**credentials,name=m.valid_name(str(raw.get('name',''))),quota=quota,expires=expires,group_name=group,comment=comment,
                    max_ips=bounded(raw,'max_ips',0,0,1000),policy=json.dumps(p),external_links=links,
                    external_cache=direct if not old or old['external_links']!=links else old['external_cache'])
    def form_context(request,user=None,error=''):
        user=user or dict(name='',quota=0,expires=0,group_name='',comment='',max_ips=0,external_links='',activated_at=0)
        user=dict(user);user['expiry_text']=datetime.fromtimestamp(user['expires'],timezone.utc).strftime('%Y-%m-%d') if user['expires'] else ''
        p={'first_use_days':0,'renew_mode':'none','renew_days':30,'renew_day':1,'renew_weekday':1,'renew_limit':0,'renew_count':0,
           'reset_mode':'none','reset_days':30,'reset_day':1,'reset_weekday':1,**json.loads(user.get('policy','{}'))}
        user['policy_values']=p
        memberships=records(m.DB,'memberships');user['node_ids']=[x['node_id'] for x in memberships if x['user_id']==user.get('id')]
        ips=[]
        if user.get('id'):
            with connect(m.DB) as db:ips=[dict(r) for r in db.execute('SELECT * FROM client_ips WHERE user_id=? ORDER BY last_seen DESC',(user['id'],))]
        return m.render(request,'user_editor.html',user=user,nodes=records(m.DB,'nodes'),ips=ips,error=error)

    @app.get('/users')
    def users_page(request:Request,q:str='',group:str='',state:str=''):
        m.authenticated(request)
        users=records(m.DB,'users');nodes=records(m.DB,'nodes');members=records(m.DB,'memberships')
        groups=sorted({u['group_name'] for u in users if u['group_name']})
        for u in users:
            u['state']=reason(u);u['online']=m.runtime.online.get(u['id'],{'ips':[],'connections':0})
            u['node_names']=[n['name'] for n in nodes if any(x['node_id']==n['id'] and x['user_id']==u['id'] for x in members)]
            u['expiry_text']=datetime.fromtimestamp(u['expires'],timezone.utc).strftime('%Y-%m-%d') if u['expires'] else '未激活' if json.loads(u['policy']).get('first_use_days') and not u['activated_at'] else '长期'
        users=[u for u in users if (not q or q.casefold() in (' '.join((u['name'],u['comment'],u['group_name']))).casefold()) and (not group or u['group_name']==group)
               and (not state or state=='online' and u['online']['connections'] or state=='disabled' and u['state'] or state=='active' and not u['state'])]
        return m.render(request,'users.html',users=users,nodes=nodes,groups=groups,q=q,group=group,state=state,
                        share_base=m.read_settings(m.DB)['public_url'] or str(request.base_url).rstrip('/'))

    @app.get('/users/new')
    def new_user(request:Request):m.authenticated(request);return form_context(request)

    @app.get('/users/{identity}/edit')
    def edit_user(request:Request,identity:str):
        m.authenticated(request)
        user=next((u for u in records(m.DB,'users') if u['id']==identity),None)
        if not user:raise HTTPException(404)
        return form_context(request,user)

    async def save(request,identity=None):
        m.authenticated(request);form=await request.form();raw=dict(form);m.csrf(request,str(raw.get('token','')))
        old=next((u for u in records(m.DB,'users') if u['id']==identity),None)
        if identity and not old:raise HTTPException(404)
        try:
            values=raw_user(raw,old);quantity=1 if old else bounded(raw,'quantity',1,1,200)
            ids=form.getlist('node_ids')
            with m.runtime.lock,connect(m.DB) as db:
                db.execute('BEGIN IMMEDIATE')
                if not set(ids)<={n['id'] for n in db.execute('SELECT id FROM nodes')}:raise ValueError('授权节点不存在')
                for index in range(quantity):
                    uid=identity or uuid.uuid4().hex
                    current={**values,'name':values['name']+(f'-{index+1:03}' if quantity>1 else '')}
                    if len(current['name'])>80:raise ValueError('批量用户名称过长')
                    if old:
                        db.execute('UPDATE users SET '+','.join(k+'=?' for k in current)+' WHERE id=?',(*current.values(),uid))
                    else:
                        current.update(id=uid,secret=current.get('secret',secrets.token_urlsafe(24)),uuid=current.get('uuid',str(uuid.uuid4())),token=secrets.token_urlsafe(32),activated_at=0 if json.loads(values['policy'])['first_use_days'] else int(time.time()))
                        db.execute('INSERT INTO users('+','.join(current)+') VALUES('+','.join('?' for _ in current)+')',tuple(current.values()))
                    set_memberships(db,uid,ids,(m.STATS_PORT,m.STATS_PORT+1,18889))
                audit(db,'编辑用户' if old else '创建用户',values['name']+f' × {quantity}')
            return redirect('/users')
        except (ValueError,OverflowError) as e:raise HTTPException(422,str(e))

    @app.post('/users/create')
    async def create(request:Request):return await save(request)
    @app.post('/users/save/{identity}')
    async def update(request:Request,identity:str):return await save(request,identity)

    @app.post('/users/bulk')
    async def bulk(request:Request):
        m.authenticated(request);form=await request.form();m.csrf(request,str(form.get('token','')))
        ids=list(dict.fromkeys(form.getlist('ids')));action=str(form.get('action',''))
        if not ids or len(ids)>200:raise HTTPException(422,'请选择 1–200 位用户')
        try:
            if action=='refresh_external':
                selected=[u for u in records(m.DB,'users') if u['id'] in ids]
                caches={u['id']:(u['external_links'],refresh_external(u['external_links'])) for u in selected}
            with m.runtime.lock:
                if action in ('reset','cleanup'):m.runtime.sample()
                if action=='disconnect':
                    for identity in ids:m.runtime.disconnect(identity)
                with connect(m.DB) as db:
                    db.execute('BEGIN IMMEDIATE')
                    if not set(ids)<={r['id'] for r in db.execute('SELECT id FROM users')}:raise ValueError('用户不存在')
                    for identity in ids:
                        u=dict(db.execute('SELECT * FROM users WHERE id=?',(identity,)).fetchone())
                        if action in ('enable','disable'):db.execute('UPDATE users SET enabled=? WHERE id=?',(action=='enable',identity))
                        elif action=='delete':db.execute('DELETE FROM users WHERE id=?',(identity,))
                        elif action=='reset':db.execute('UPDATE users SET upload=0,download=0 WHERE id=?',(identity,))
                        elif action=='rotate':db.execute('UPDATE users SET token=? WHERE id=?',(secrets.token_urlsafe(32),identity))
                        elif action=='credentials':db.execute('UPDATE users SET secret=?,uuid=? WHERE id=?',(secrets.token_urlsafe(24),str(uuid.uuid4()),identity))
                        elif action=='clear_ips':db.execute('DELETE FROM client_ips WHERE user_id=?',(identity,))
                        elif action=='group':
                            value=str(form.get('group_name','')).strip()
                            if len(value)>60:raise ValueError('分组最多 60 字')
                            db.execute('UPDATE users SET group_name=? WHERE id=?',(value,identity))
                        elif action=='adjust':
                            days=bounded(form,'add_days',0,0,36500);gib=float(form.get('add_gib',0) or 0)
                            if not math.isfinite(gib) or not 0<=gib<=1000000:raise ValueError('追加流量无效')
                            if gib and not u['quota']:raise ValueError('不限量用户请先设置有限额度，再追加流量')
                            p=json.loads(u['policy'])
                            if days and p.get('first_use_days') and not u['activated_at']:
                                p['first_use_days']+=days
                                db.execute('UPDATE users SET policy=? WHERE id=?',(json.dumps(p),identity))
                                expiry=0
                            else:expiry=max(u['expires'],int(time.time()))+days*86400 if days else u['expires']
                            db.execute('UPDATE users SET expires=?,quota=quota+? WHERE id=?',(expiry,int(gib*1024**3),identity))
                        elif action in ('attach','detach'):
                            current={r['node_id'] for r in db.execute('SELECT node_id FROM memberships WHERE user_id=?',(identity,))}
                            selected=set(form.getlist('node_ids'))
                            set_memberships(db,identity,current|selected if action=='attach' else current-selected,(m.STATS_PORT,m.STATS_PORT+1,18889))
                        elif action=='refresh_external':
                            if caches[identity][0]!=u['external_links']:raise ValueError('外部链接已修改，请重新刷新')
                            db.execute('UPDATE users SET external_cache=? WHERE id=?',(caches[identity][1],identity))
                        elif action=='cleanup':
                            p=json.loads(u['policy'])
                            if reason(u) in ('已到期','额度耗尽') and p.get('renew_mode','none')=='none':db.execute('DELETE FROM users WHERE id=?',(identity,))
                        elif action=='orphan_cleanup':
                            if not db.execute('SELECT 1 FROM memberships WHERE user_id=?',(identity,)).fetchone():db.execute('DELETE FROM users WHERE id=?',(identity,))
                        elif action!='disconnect':raise ValueError('不支持的批量操作')
                    audit(db,'用户操作 '+action,f'{len(ids)} 位用户')
            return redirect('/users')
        except (ValueError,OSError) as e:raise HTTPException(422,str(e))

    @app.get('/nodes')
    def nodes_page(request:Request,q:str='',group:str=''):
        m.authenticated(request);nodes=records(m.DB,'nodes');members=records(m.DB,'memberships')
        groups=sorted({n['group_name'] for n in nodes if n['group_name']})
        for n in nodes:n['members']=sum(x['node_id']==n['id'] for x in members)
        nodes=[n for n in nodes if (not q or q.casefold() in (n['name']+' '+n['comment']).casefold()) and (not group or n['group_name']==group)]
        return m.render(request,'nodes.html',nodes=nodes,groups=groups,q=q,group=group,host=m.PUBLIC_HOST,error=m.runtime.error)

    @app.post('/nodes/bulk')
    async def nodes_bulk(request:Request):
        m.authenticated(request);form=await request.form();m.csrf(request,str(form.get('token','')))
        ids=list(dict.fromkeys(form.getlist('ids')));action=form.get('action')
        if not ids or len(ids)>200:raise HTTPException(422,'请选择 1–200 个节点')
        with m.runtime.lock,connect(m.DB) as db:
            db.execute('BEGIN IMMEDIATE')
            if not set(ids)<={r['id'] for r in db.execute('SELECT id FROM nodes')}:raise HTTPException(422,'节点不存在')
            for identity in ids:
                if action in ('enable','disable'):db.execute('UPDATE nodes SET enabled=? WHERE id=?',(action=='enable',identity))
                elif action=='delete':db.execute('DELETE FROM nodes WHERE id=?',(identity,))
                elif action=='randomize':m.rotate_ports(db,identity,(m.STATS_PORT,m.STATS_PORT+1,18889))
                elif action=='clone':
                    n=dict(db.execute('SELECT * FROM nodes WHERE id=?',(identity,)).fetchone());n.update(id=uuid.uuid4().hex,name=n['name'][:70]+' 副本',port=random_port(db,(m.STATS_PORT,m.STATS_PORT+1,18889)),enabled=0)
                    db.execute('INSERT INTO nodes('+','.join(n)+') VALUES('+','.join('?' for _ in n)+')',tuple(n.values()))
                else:raise HTTPException(422,'不支持的节点操作')
            audit(db,'节点操作 '+action,f'{len(ids)} 个节点')
        return redirect('/nodes')

    @app.get('/system/status')
    def system_page(request:Request):
        m.authenticated(request)
        with connect(m.DB) as db:logs=[dict(r) for r in db.execute('SELECT * FROM audit_log ORDER BY id DESC LIMIT 100')]
        return m.render(request,'system.html',error=m.runtime.error,online=m.runtime.online,logs=logs,
                        version='sing-box 1.14.3',running=bool(m.runtime.process and m.runtime.process.poll() is None))

    @app.post('/system/restart')
    async def restart(request:Request):
        m.authenticated(request);form=await request.form();m.csrf(request,str(form.get('token','')))
        with m.runtime.lock:
            m.runtime.sample();m.runtime.terminate();m.runtime.apply()
            with connect(m.DB) as db:audit(db,'重启核心','管理员手动重启')
        return redirect('/system/status')

    @app.get('/system/backup')
    def backup(request:Request):
        m.authenticated(request)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'panel.db'
            with m.runtime.lock,connect(m.DB) as source,sqlite3.connect(path) as destination:source.backup(destination)
            return Response(path.read_bytes(),media_type='application/octet-stream',headers={'Content-Disposition':'attachment; filename="sing-panel-backup.db"'})

    @app.post('/system/password')
    async def password(request:Request):
        m.authenticated(request);form=await request.form();m.csrf(request,str(form.get('token','')))
        try:m.ph.verify(m.auth['password_hash'],str(form.get('current_password','')))
        except Exception:raise HTTPException(403,'当前密码不正确')
        value=str(form.get('new_password',''))
        if len(value)<12 or len(value)>256:raise HTTPException(422,'新密码须为 12–256 个字符')
        updated={**m.auth,'password_hash':m.ph.hash(value),'revision':m.auth.get('revision',0)+1}
        path=m.AUTH.with_suffix('.tmp');path.write_text(json.dumps(updated));path.chmod(0o600);path.replace(m.AUTH);m.auth.update(updated);request.session['auth_revision']=updated['revision']
        with connect(m.DB) as db:audit(db,'修改管理员密码','管理员')
        return redirect('/system/status')
