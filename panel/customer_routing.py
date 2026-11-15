"""Customer routing scoped by the share token, administrator grants and CSRF."""
import json
import threading
import time

from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool

from .core import connect, reason
from .sharing import read_settings
from . import routing, user_routing as ur
from .customer_routing_scope import nodes as scoped_nodes

SERVICE_NAMES = {'category-ai-!cn':'海外 AI 服务','openai':'OpenAI','anthropic':'Claude / Anthropic',
    'google':'Google 谷歌','github':'GitHub','telegram':'Telegram','netflix':'Netflix 奈飞',
    'youtube':'YouTube','apple':'Apple 苹果','microsoft':'Microsoft 微软','cn':'中国站点',
    'geolocation-cn':'中国站点','geolocation-!cn':'海外站点','category-ads-all':'广告与追踪',
    'category-games':'游戏','category-social-media-!cn':'海外社交媒体','spotify':'Spotify','disney':'Disney+'}
REGION_NAMES = {'cn':'中国','us':'美国','jp':'日本','hk':'香港','tw':'台湾','sg':'新加坡','kr':'韩国',
    'gb':'英国','de':'德国','fr':'法国','ca':'加拿大','au':'澳大利亚','nl':'荷兰','ru':'俄罗斯',
    'in':'印度','tr':'土耳其','br':'巴西','my':'马来西亚','th':'泰国','id':'印度尼西亚','vn':'越南',
    'ph':'菲律宾','it':'意大利','es':'西班牙','ch':'瑞士','se':'瑞典','fi':'芬兰','no':'挪威'}


def presets():
    choices = [('ai', 'AI 服务', ['category-ai-!cn'], 'ChatGPT · Claude 等'),
               ('streaming', '流媒体', ['netflix','youtube','disney','spotify'], '视频与音乐'),
               ('social', '社交', ['category-social-media-!cn','telegram'], '海外社交与通讯'),
               ('games', '游戏', ['category-games'], '游戏平台与服务'),
               ('ads', '广告', ['category-ads-all'], '广告与追踪')]
    return [{'id': key, 'name': name, 'kind': 'geosite', 'values': valid, 'label': label}
            for key, name, values, label in choices
            if (valid := [value for value in values if value in routing.GEO_CATALOG['geosite']])]


def rule_warnings(document, nodes):
    """Definite shadowing only; different sets may overlap without being equal."""
    assigned = {node['id'] for node in nodes if node['available'] and not node['locked']}
    prior = []
    warnings = []
    if not document.get('enabled'):
        return warnings
    for rule in document.get('rules', []):
        if not rule.get('enabled'):
            continue
        scope = set(rule.get('node_ids') or assigned) & assigned
        if not scope:
            warnings.append({'rule_id': rule['id'], 'message': '当前没有可覆盖的可用节点'})
        for previous, previous_scope in prior:
            if (scope and scope <= previous_scope and rule['kind'] == previous['kind']
                    and set(rule['values']) <= set(previous['values'])):
                warnings.append({'rule_id': rule['id'], 'message': '匹配内容已被前面的「' + previous['name'] + '」覆盖'})
                break
        prior.append((rule, scope))
    return warnings


def install(app, m):
    limits = {}
    rate_lock = threading.Lock()
    preview_gate = threading.BoundedSemaphore(2)
    preview_users = set()

    def limited(key, count, window):
        now = time.monotonic()
        with rate_lock:
            for k in list(limits):
                limits[k] = [t for t in limits[k] if now-t < 600]
                if not limits[k]:
                    del limits[k]
            hits = [t for t in limits.get(key, []) if now-t < window]
            if len(hits) >= count:
                raise HTTPException(429, '操作过于频繁，请稍后再试')
            limits[key] = hits + [now]

    def identity(request, token, require_access=False, write=False):
        user = m.user_authenticated(request,token,m.DB)
        policy = ur.get_policy(m.DB, user['id'])
        allowed = bool(policy['allowed'])
        if require_access and not allowed:
            raise HTTPException(403, '管理员尚未开启自定义分流')
        if write and (not allowed or reason(user)):
            raise HTTPException(403, reason(user) or '管理员尚未开启自定义分流')
        return user, policy, allowed

    async def body(request):
        chunks = bytearray()
        async for chunk in request.stream():
            chunks.extend(chunk)
            if len(chunks) > 256*1024:
                raise HTTPException(413, '分流配置过大')
        try:
            value = json.loads(chunks)
        except (ValueError, UnicodeError):
            raise HTTPException(400, '请求格式无效')
        if not isinstance(value, dict):
            raise HTTPException(400, '请求格式无效')
        m.csrf(request, str(value.get('csrf', '')))
        return value

    def state(request, token):
        user, policy, allowed = identity(request, token)
        settings = read_settings(m.DB)
        root = (settings['public_url'] or str(request.base_url).rstrip('/')) + settings['share_path'] + '/' + token
        request.session.setdefault('csrf', m.secrets.token_urlsafe(32))
        safe = {key:policy[key] for key in ('allowed','max_rules','revision','applied_revision','status','error','applied_at')}
        for key in ('draft', 'applied'):
            safe[key] = json.loads(json.dumps(policy[key])) if allowed else {'enabled':False,'rules':[]}
        data = routing.load(m.DB)
        nodes = scoped_nodes(m.DB, user['id'], data) if allowed else []
        outs = [{**out,'usable':out['selectable'],**out['latency']} for out in ur.public_outbounds(m.DB,user,data)] if allowed else []
        # Mark references that were revoked without revealing private metadata.
        usable = {out['id'] for out in outs if out['usable']}
        if allowed:
            for key in ('draft', 'applied'):
                for rule in safe[key]['rules']:
                    if rule['target'] != 'reject' and rule['target'] not in usable:
                        rule['unavailable'] = True
            from .routing_rollout import public_status
            safe['rollout'] = public_status(m.DB, user['id'])
        else:
            safe['rollout'] = {'revision': 0, 'total': 0, 'confirmed': 0, 'state': 'idle', 'targets': []}
        safe['warnings'] = rule_warnings(safe['draft'], nodes)
        why = reason(user) or ('' if policy['allowed'] else '管理员尚未开启自定义分流')
        return {'csrf':request.session['csrf'],'share_url':root,'locked':not allowed,
                'editable':bool(allowed and not why),'reason':why,
                'policy':safe,'outbounds':outs,'nodes':nodes,'presets':presets() if allowed else []}

    def busy(policy):
        if policy['status'] in ('queued','applying'):
            raise HTTPException(409, '正在应用，请完成后再修改')

    def convert(error):
        return HTTPException(409 if isinstance(error, ur.RevisionConflict) else 422, str(error))

    @app.get('/s/{token}/routing')
    def page(request:Request, token:str):
        user = m.user_authenticated(request,token,m.DB)
        data = state(request, token)
        return m.render(request,'customer_routing.html',user={'name':user['name']},
                        share_url=data['share_url'],routing_state=data,customer_authenticated=True,subtoken=token)

    @app.get('/s/{token}/routing/api')
    def api(request:Request, token:str):
        return state(request, token)

    @app.post('/s/{token}/routing/draft')
    async def draft(request:Request, token:str):
        raw = await body(request)
        user, _, _ = identity(request, token, True, True)
        def save():
            with m.runtime.lock:
                identity(request, token, True, True)
                ur.save_draft(m.DB,user['id'],raw.get('document'),raw.get('revision'))
        try:
            await run_in_threadpool(save)
        except ValueError as error:
            raise convert(error)
        return state(request, token)

    @app.post('/s/{token}/routing/discard')
    async def discard(request:Request, token:str):
        raw = await body(request)
        user, _, _ = identity(request, token, True, True)
        def restore():
            with m.runtime.lock, connect(m.DB) as db:
                identity(request, token, True, True)
                db.execute('BEGIN IMMEDIATE')
                policy = db.execute('SELECT * FROM user_routing WHERE user_id=?', (user['id'],)).fetchone()
                busy(policy)
                if type(raw.get('revision')) is not int or raw['revision'] != policy['revision']:
                    raise HTTPException(409, '规则已在其他页面更新，请刷新后重试')
                # Revision is an edit token; applied_revision identifies an
                # actual publication and must not invalidate machine receipts.
                db.execute("UPDATE user_routing SET draft=applied,revision=revision+1,status='applied',error='' WHERE user_id=?", (user['id'],))
        await run_in_threadpool(restore)
        return state(request, token)

    @app.post('/s/{token}/routing/apply')
    async def apply(request:Request, token:str):
        raw = await body(request)
        user, _, _ = identity(request, token, True, True)
        if type(raw.get('revision')) is not int:
            raise HTTPException(422, '页面版本无效')
        try:
            def enqueue():
                with m.runtime.lock:
                    identity(request, token, True, True)
                    return m.routing_publisher.enqueue(user['id'],raw['revision'])
            await run_in_threadpool(enqueue)
        except ValueError as error:
            raise convert(error)
        return state(request, token)

    @app.get('/s/{token}/routing/catalog')
    def catalog(request:Request, token:str, kind:str='geosite', q:str='', offset:int=0):
        identity(request, token, True)
        if kind not in ('geoip','geosite') or len(q)>100 or not 0<=offset<=5000:
            raise HTTPException(422, '查询条件无效')
        labels = SERVICE_NAMES if kind=='geosite' else REGION_NAMES
        items = [{'value':value,'label':labels.get(value,value.upper() if kind=='geoip' else value)} for value in routing.GEO_CATALOG[kind]]
        items.sort(key=lambda item:(item['value'] not in labels,item['label']))
        query=q.strip().lower()
        items=[item for item in items if query in (item['label']+' '+item['value']).lower()]
        return {'items':items[offset:offset+80],'total':len(items),'offset':offset,'has_more':offset+80<len(items)}

    @app.post('/s/{token}/routing/latency/{identity_id}')
    async def latency(request:Request, token:str, identity_id:str):
        await body(request)
        user, policy, _ = identity(request, token, True, True)
        limited(('latency',user['id']), 8, 60)
        from .latency import probe, cached
        out=next((out for out in routing.load(m.DB)['outbounds'] if out['id']==identity_id and ur.allowed_outbound(out,user,policy)),None)
        if out is None:
            raise HTTPException(404, '出口不可用或未授权')
        previous=cached(m.DB,out)
        if time.time()-previous.get('checked_at',0)<30:
            return {key:previous[key] for key in ('delay','checked_at') if key in previous}
        return await run_in_threadpool(probe,m.DB,m.runtime,out)

    @app.post('/s/{token}/routing/preview')
    async def preview(request:Request, token:str):
        raw=await body(request)
        user, policy, _=identity(request, token, True)
        limited(('preview',user['id']),10,60)
        with rate_lock:
            if user['id'] in preview_users or not preview_gate.acquire(blocking=False):
                raise HTTPException(429,'正在计算匹配结果，请稍后再试')
            preview_users.add(user['id'])
        from .routing_preview import preview as calculate
        try:
            return await run_in_threadpool(calculate,m,user,policy,raw.get('destination'),raw.get('node_id'),raw.get('mode','draft'))
        except ValueError as error:
            raise HTTPException(422,str(error))
        finally:
            with rate_lock:
                preview_users.discard(user['id'])
                preview_gate.release()
