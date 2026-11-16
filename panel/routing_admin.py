"""Authenticated CRUD and transactional runtime application for routing."""
import copy,json,uuid
from urllib.parse import quote
from fastapi import Request,HTTPException
from fastapi.responses import RedirectResponse,Response
from starlette.concurrency import run_in_threadpool
from . import routing as r
from .core import records,config,connect
from .management import audit

def public_values(row=None,raw=None):
    """Form values are separate from upstream connection credentials."""
    value={'visible':False,'name':'','region':'','description':'','audience':'all','user_ids':[],'groups':[],'allow_use':True,'order':0}
    value.update((row or {}).get('public',{}))
    if raw is not None and raw.get('public_present')=='1':
        for key in ('name','region','description','audience'):
            value[key]=str(raw.get('public_'+key,''))
        for key in ('visible','allow_use'):
            value[key]=r.truth(raw.get('public_'+key))
        value['order']=raw.get('public_order',0)
        for key in ('user_ids','groups'):
            value[key]=raw.getlist('public_'+key) if hasattr(raw,'getlist') else raw.get('public_'+key,[])
    return value

def public_input(raw,users,old=None):
    value=public_values(old,raw)
    for key,limit in (('name',80),('region',40),('description',200)):
        value[key]=r.text(value,key,limit)
    value['order']=r.number(value,'order',0,-999,999)
    if value['audience'] not in ('all','selected'):
        raise ValueError('请选择有效的出口授权范围')
    known_ids={u['id'] for u in users}
    known_groups={u.get('group_name','') for u in users if u.get('group_name')}
    for key,known in (('user_ids',known_ids),('groups',known_groups)):
        values=value[key]
        if not isinstance(values,list) or not all(isinstance(x,str) for x in values) or not set(values)<=known:
            raise ValueError('出口授权中的用户或分组已不存在，请重新选择')
        value[key]=list(dict.fromkeys(values))
    if value['visible'] and value['audience']=='selected' and not value['user_ids'] and not value['groups']:
        raise ValueError('请至少选择一个授权用户或分组')
    return value

def install(app,m):
    def page(request,error='',notice=''):
        data=r.load(m.DB)
        data['rules'].sort(key=lambda row:row.get('priority','forced')=='default')
        from .latency import cached
        for out in data['outbounds']:out['latency']=cached(m.DB,out)
        labels={'direct':'服务器直连','reject':'拦截',**{o['id']:o['name'] for o in data['outbounds']}}
        return m.render(request,'routing.html',routing=data,targets=labels,types=r.TYPES,nodes=records(m.DB,'nodes'),error=error,notice=notice)
    def outbound_form(request,row=None,values=None,error='',public=None):
        users=records(m.DB,'users')
        return m.render(request,'routing_outbound.html',row=row,values=values or r.edit_values(row),public=public or public_values(row),users=users,groups=sorted({u['group_name'] for u in users if u.get('group_name')}),types=r.TYPES,methods=r.SS_METHODS,error=error)
    def rule_form(request,row=None,values=None,error=''):
        data=r.load(m.DB)
        if values is None:
            values={'name':'','target':'direct','network':'','node_ids':[],'match_all':False,'priority':'forced'}
            if row:
                values.update(row)
                for k,v in row['match'].items():values[k]=v if k in ('geoip','geosite') else ','.join(str(x) for x in v) if isinstance(v,list) else v
                if row['match'].get('port_range'):values['port']=','.join(filter(None,[values.get('port',''),','.join(row['match']['port_range'])]))
                values['match_all']=not row['match'] and not row.get('node_ids')
        return m.render(request,'routing_rule.html',row=row,values=values,geo_catalog=r.GEO_CATALOG,targets={'direct':'服务器直连','reject':'拦截',**{o['id']:o['name'] for o in data['outbounds'] if o['enabled']}},nodes=records(m.DB,'nodes'),error=error)
    def authorize(request,token):
        m.authenticated(request)
        m.csrf(request,token)
    def documents(settings):
        from .user_routing import compose
        nodes,users,members=(records(m.DB,table) for table in ('nodes','users','memberships'))
        result={}
        for server in sorted({'local'}|{node.get('server_id','local') for node in nodes}):
            if server!='local':
                from .server_publish import input_signature
                result[server]={'_remote':server,'_inputs':input_signature(m.DB,server),'_settings':settings}
                continue
            owned=[node for node in nodes if node.get('server_id','local')==server]
            identities={node['id'] for node in owned}
            document=compose(config(owned,users,[row for row in members if row['node_id'] in identities],
                                    m.STATS_PORT if server=='local' else 19190),m.DB,settings=settings)
            r.set_rule_paths(document,m.DIRECTORY)
            result[server]=document
        return result
    def signature(value):
        return json.dumps(value,sort_keys=True,separators=(',',':'))
    def apply_change(request,token,change,action=None,detail='',expected=None):
        # Snapshot only while holding the runtime lock. Slow network downloads
        # and subprocess validation must not pause traffic accounting or WSS.
        with m.runtime.lock:
            authorize(request,token)
            old=r.load(m.DB);new=copy.deepcopy(old)
            if expected is not None and old!=expected:
                raise HTTPException(409,'分流配置已变化，请刷新后重试')
            change(new)
            prepared=documents(new)
            validated=signature(prepared)
        for document in prepared.values():
            if document.get('_remote'):continue
            r.prepare_rule_sets(document,m.DIRECTORY,m.BINARY)
            m.check_document(document)
        with m.runtime.lock:
            authorize(request,token)
            if r.load(m.DB)!=old:
                raise HTTPException(409,'分流配置已变化，请刷新后重试')
            # Repeat reference/permission checks, then compare semantic core
            # configuration. Routine traffic counters do not invalidate edits.
            current=copy.deepcopy(old)
            change(current)
            if current!=new or signature(documents(current))!=validated:
                raise HTTPException(409,'节点或用户分流配置已变化，请刷新后重试')
            r.write(m.DB,new)
            try:m.runtime.apply()
            except Exception:
                r.write(m.DB,old)
                try:m.runtime.apply()
                except Exception:pass
                raise ValueError('应用失败，已恢复原分流设置；请检查上游配置或核心状态')
            if action:log(action,detail)
    def log(action,detail):
        with connect(m.DB) as db:audit(db,action,detail)
    async def form(request):
        m.authenticated(request);raw=await request.form();m.csrf(request,str(raw.get('token','')));return raw
    def find(items,identity):
        row=next((x for x in items if x['id']==identity),None)
        if not row:raise HTTPException(404)
        return row

    def user_policy_page(request,identity,error='',notice='',values=None):
        from .user_routing import get_policy,public_outbounds
        user=find(records(m.DB,'users'),identity)
        policy=get_policy(m.DB,identity)
        settings=r.load(m.DB)
        targets={o['id']:o.get('public',{}).get('name') or o['name'] for o in settings['outbounds']}
        targets['reject']='拦截'
        # Only these fields are rendered; never place a password hash in HTML.
        safe={k:policy.get(k) for k in ('allowed','max_rules','revision','applied_revision','status','error','applied_at')}
        safe['applied']=policy['applied']
        return m.render(request,'user_routing_admin.html',user=user,policy=safe,values=values or safe,
                        exits=public_outbounds(m.DB,user,settings=settings),targets=targets,error=error,notice=notice)

    @app.get('/users/{identity}/routing')
    def user_policy(request:Request,identity:str):
        m.authenticated(request)
        return user_policy_page(request,identity)

    @app.post('/users/{identity}/routing')
    async def user_policy_save(request:Request,identity:str):
        raw=await form(request)
        user=find(records(m.DB,'users'),identity)
        from .user_routing import get_policy,configure_user,restore_policy
        def update_policy():
            if raw.get('intent')=='reset':
                authorize(request,str(raw.get('token','')))
                m.routing_publisher.reset_user(identity,authorize=lambda:authorize(request,str(raw.get('token',''))))
                log('恢复用户默认分流',user['name'])
                return '默认策略已发布，相关机器确认后生效'
            with m.runtime.lock:
                authorize(request,str(raw.get('token','')))
                old=get_policy(m.DB,identity)
                if old.get('status') in ('queued','applying'):
                    raise ValueError('用户策略正在应用，请完成后再修改权限')
                allowed=r.truth(raw.get('allowed'))
                maximum=r.number(raw,'max_rules',6,1,50)
                configure_user(m.DB,identity,allowed,maximum)
                try:
                    m.runtime.apply()
                except Exception:
                    restore_policy(m.DB,identity,old)
                    try:m.runtime.apply()
                    except Exception:pass
                    raise ValueError('应用失败，已恢复原用户分流权限')
            log('修改用户分流权限',user['name'])
            return '用户分流权限已保存'
        try:
            notice=await run_in_threadpool(update_policy)
            return user_policy_page(request,identity,notice=notice)
        except (ValueError,TypeError) as e:
            return user_policy_page(request,identity,error=str(e),values={'allowed':r.truth(raw.get('allowed')),'max_rules':raw.get('max_rules',6)})

    @app.get('/routing')
    def index(request:Request):m.authenticated(request);return page(request)

    @app.get('/routing/outbounds/new')
    def new_outbound(request:Request):m.authenticated(request);return outbound_form(request)

    @app.get('/routing/outbounds/{identity}/edit')
    def edit_outbound(request:Request,identity:str):
        m.authenticated(request);return outbound_form(request,find(r.load(m.DB)['outbounds'],identity))

    @app.post('/routing/outbounds/save')
    async def save_outbound(request:Request):
        raw=await form(request);identity=str(raw.get('id',''))
        expected=r.load(m.DB)
        old=find(expected['outbounds'],identity) if identity else None
        try:
            if raw.get('intent')=='import':
                values=r.parse_uri(str(raw.get('uri','')))
                return outbound_form(request,old,values,error='',public=public_values(old,raw))
            name=r.text(raw,'name',80)
            if not name:raise ValueError('请输入出口名称')
            settings=r.build_outbound(raw,old['settings'] if old else None)
            await run_in_threadpool(m.check_document,{'outbounds':[{**settings,'tag':'validation'}]})
            disclosure=public_input(raw,records(m.DB,'users'),old)
            entry={'id':identity or uuid.uuid4().hex,'name':name,'enabled':old['enabled'] if old else True,'settings':settings,'public':disclosure}
            def change(data):
                public_input(raw,records(m.DB,'users'),old)
                if old:data['outbounds'][data['outbounds'].index(find(data['outbounds'],identity))]=entry
                else:
                    if len(data['outbounds'])>=100:raise ValueError('最多添加 100 个上游出口')
                    data['outbounds'].append(entry)
            await run_in_threadpool(apply_change,request,str(raw.get('token','')),change,'保存分流出口',name,expected)
            return RedirectResponse('/routing',303)
        except (ValueError,TypeError) as e:return outbound_form(request,old,dict(raw),str(e),public=public_values(old,raw))

    @app.get('/routing/outbounds/{identity}/{action}')
    def outbound_action_link(request:Request,identity:str,action:str):
        m.authenticated(request)
        if action not in ('toggle','delete','test'):raise HTTPException(404)
        find(r.load(m.DB)['outbounds'],identity)
        return RedirectResponse('/routing',303)

    @app.post('/routing/outbounds/{identity}/{action}')
    async def outbound_action(request:Request,identity:str,action:str):
        raw=await form(request)
        try:
            data=r.load(m.DB);entry=find(data['outbounds'],identity)
            if action=='test':
                if not entry['enabled']:raise ValueError('请先启用出口')
                from .latency import probe
                result=await run_in_threadpool(probe,m.DB,m.runtime,entry)
                if result['delay'] is None:raise ValueError('出口不可达或测速超时')
                return page(request,notice=entry['name']+' · '+str(result['delay'])+' ms')
            if action not in ('toggle','delete'):raise HTTPException(404)
            def change(data):
                row=find(data['outbounds'],identity)
                referenced=data['final']==identity or any(x['target']==identity for x in data['rules'])
                if referenced and (action=='delete' or row['enabled']):raise ValueError('此出口正被规则或默认出口引用，请先修改引用')
                from .user_routing import applied_references
                if (action=='delete' or row['enabled']) and applied_references(m.DB,identity):
                    raise ValueError('此出口正被用户已应用的规则引用，请先调整对应用户的规则或恢复其默认分流')
                if action=='delete':data['outbounds'].remove(row)
                else:row['enabled']=not row['enabled']
            await run_in_threadpool(apply_change,request,str(raw.get('token','')),change,'分流出口 '+action,entry['name'],data)
            return RedirectResponse('/routing',303)
        except ValueError as e:return page(request,error=str(e))

    @app.get('/routing/rules/new')
    def new_rule(request:Request):m.authenticated(request);return rule_form(request)

    @app.get('/routing/rules/{identity}/edit')
    def edit_rule(request:Request,identity:str):m.authenticated(request);return rule_form(request,find(r.load(m.DB)['rules'],identity))

    @app.post('/routing/rules/save')
    async def save_rule(request:Request):
        raw=await form(request);identity=str(raw.get('id',''));data=r.load(m.DB)
        old=find(data['rules'],identity) if identity else None
        try:
            values=r.rule_input(raw,records(m.DB,'nodes'),data['outbounds'])
            priority=str(raw.get('priority',old.get('priority','forced') if old else 'forced'))
            if priority not in ('forced','default'):raise ValueError('请选择有效的规则优先级')
            row={'id':identity or uuid.uuid4().hex,'enabled':old['enabled'] if old else True,'priority':priority,**values}
            def change(data):
                r.rule_input(raw,records(m.DB,'nodes'),data['outbounds'])
                if old:data['rules'][data['rules'].index(find(data['rules'],identity))]=row
                else:
                    if len(data['rules'])>=200:raise ValueError('最多添加 200 条规则')
                    data['rules'].append(row)
            await run_in_threadpool(apply_change,request,str(raw.get('token','')),change,'保存分流规则',row['name'],data)
            return RedirectResponse('/routing',303)
        except (ValueError,TypeError) as e:
            values=dict(raw);values['node_ids']=raw.getlist('node_ids');values['geoip']=raw.getlist('geoip');values['geosite']=raw.getlist('geosite');return rule_form(request,old,values,str(e))

    @app.get('/routing/rules/{identity}/{action}')
    def rule_action_link(request:Request,identity:str,action:str):
        m.authenticated(request)
        if action not in ('toggle','delete','up','down'):raise HTTPException(404)
        find(r.load(m.DB)['rules'],identity)
        return RedirectResponse('/routing',303)

    @app.post('/routing/rules/{identity}/{action}')
    async def rule_action(request:Request,identity:str,action:str):
        raw=await form(request)
        try:
            if action not in ('toggle','delete','up','down'):raise HTTPException(404)
            def change(data):
                row=find(data['rules'],identity);index=data['rules'].index(row)
                if action=='delete':data['rules'].remove(row)
                elif action=='toggle':row['enabled']=not row['enabled']
                else:
                    same=[i for i,x in enumerate(data['rules']) if x.get('priority','forced')==row.get('priority','forced')]
                    position=same.index(index)+(-1 if action=='up' else 1)
                    if 0<=position<len(same):
                        other=same[position]
                        data['rules'][index],data['rules'][other]=data['rules'][other],data['rules'][index]
            await run_in_threadpool(apply_change,request,str(raw.get('token','')),change,'分流规则 '+action,identity)
            return RedirectResponse('/routing',303)
        except ValueError as e:return page(request,error=str(e))

    @app.post('/routing/settings')
    async def settings(request:Request):
        raw=await form(request)
        try:
            def change(data):data.update(final=str(raw.get('final','direct')),sniff=r.truth(raw.get('sniff')))
            await run_in_threadpool(apply_change,request,str(raw.get('token','')),change,'修改默认出口')
            return RedirectResponse('/routing',303)
        except ValueError as e:return page(request,error=str(e))

    @app.post('/routing/latency/{identity}')
    async def outbound_latency(request:Request,identity:str):
        await form(request)
        entry=find(r.load(m.DB)['outbounds'],identity)
        if not entry['enabled']:raise HTTPException(422,'出口未启用')
        from .latency import probe
        return await run_in_threadpool(probe,m.DB,m.runtime,entry)

    @app.get('/routing/preview')
    def preview(request:Request):
        m.authenticated(request)
        from .core import current_config
        d=current_config(m.DB,m.STATS_PORT)
        safe={'route':d.get('route',{}),'outbounds':[{k:o[k] for k in ('tag','type','server','server_port') if k in o} for o in d['outbounds']]}
        return Response(json.dumps(safe,ensure_ascii=False,indent=2),media_type='application/json')
