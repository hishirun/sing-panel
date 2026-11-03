"""Authenticated CRUD and transactional runtime application for routing."""
import copy,json,uuid
from urllib.parse import quote
from fastapi import Request,HTTPException
from fastapi.responses import RedirectResponse,Response
from . import routing as r
from .core import records,config,connect
from .management import audit

def install(app,m):
    def page(request,error='',notice=''):
        data=r.load(m.DB)
        from .latency import cached
        for out in data['outbounds']:out['latency']=cached(m.DB,out)
        labels={'direct':'服务器直连','reject':'拦截',**{o['id']:o['name'] for o in data['outbounds']}}
        return m.render(request,'routing.html',routing=data,targets=labels,types=r.TYPES,nodes=records(m.DB,'nodes'),error=error,notice=notice)
    def outbound_form(request,row=None,values=None,error=''):
        return m.render(request,'routing_outbound.html',row=row,values=values or r.edit_values(row),types=r.TYPES,methods=r.SS_METHODS,error=error)
    def rule_form(request,row=None,values=None,error=''):
        data=r.load(m.DB)
        if values is None:
            values={'name':'','target':'direct','network':'','node_ids':[],'match_all':False}
            if row:
                values.update(row)
                for k,v in row['match'].items():values[k]=v if k in ('geoip','geosite') else ','.join(str(x) for x in v) if isinstance(v,list) else v
                if row['match'].get('port_range'):values['port']=','.join(filter(None,[values.get('port',''),','.join(row['match']['port_range'])]))
                values['match_all']=not row['match'] and not row.get('node_ids')
        return m.render(request,'routing_rule.html',row=row,values=values,geo_catalog=r.GEO_CATALOG,targets={'direct':'服务器直连','reject':'拦截',**{o['id']:o['name'] for o in data['outbounds'] if o['enabled']}},nodes=records(m.DB,'nodes'),error=error)
    def apply_change(change):
        with m.runtime.lock:
            old=r.load(m.DB);new=copy.deepcopy(old)
            change(new)
            document=r.compile_into(config(records(m.DB,'nodes'),records(m.DB,'users'),records(m.DB,'memberships'),m.STATS_PORT),new)
            r.prepare_rule_sets(document,m.DIRECTORY,m.BINARY)
            m.check_document(document)
            r.write(m.DB,new)
            try:m.runtime.apply()
            except Exception:
                r.write(m.DB,old)
                try:m.runtime.apply()
                except Exception:pass
                raise ValueError('应用失败，已恢复原分流设置；请检查上游配置或核心状态')
    def log(action,detail):
        with connect(m.DB) as db:audit(db,action,detail)
    async def form(request):
        m.authenticated(request);raw=await request.form();m.csrf(request,str(raw.get('token','')));return raw
    def find(items,identity):
        row=next((x for x in items if x['id']==identity),None)
        if not row:raise HTTPException(404)
        return row

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
        old=find(r.load(m.DB)['outbounds'],identity) if identity else None
        try:
            if raw.get('intent')=='import':
                values=r.parse_uri(str(raw.get('uri','')))
                return outbound_form(request,old,values, error='')
            name=r.text(raw,'name',80)
            if not name:raise ValueError('请输入出口名称')
            settings=r.build_outbound(raw,old['settings'] if old else None)
            m.check_document({'outbounds':[{**settings,'tag':'validation'}]})
            entry={'id':identity or uuid.uuid4().hex,'name':name,'enabled':old['enabled'] if old else True,'settings':settings}
            def change(data):
                if old:data['outbounds'][data['outbounds'].index(find(data['outbounds'],identity))]=entry
                else:
                    if len(data['outbounds'])>=100:raise ValueError('最多添加 100 个上游出口')
                    data['outbounds'].append(entry)
            apply_change(change);log('保存分流出口',name)
            return RedirectResponse('/routing',303)
        except (ValueError,TypeError) as e:return outbound_form(request,old,dict(raw),str(e))

    @app.get('/routing/outbounds/{identity}/{action}')
    def outbound_action_link(request:Request,identity:str,action:str):
        m.authenticated(request)
        if action not in ('toggle','delete','test'):raise HTTPException(404)
        find(r.load(m.DB)['outbounds'],identity)
        return RedirectResponse('/routing',303)

    @app.post('/routing/outbounds/{identity}/{action}')
    async def outbound_action(request:Request,identity:str,action:str):
        await form(request)
        try:
            data=r.load(m.DB);entry=find(data['outbounds'],identity)
            if action=='test':
                if not entry['enabled']:raise ValueError('请先启用出口')
                from .latency import probe
                from starlette.concurrency import run_in_threadpool
                result=await run_in_threadpool(probe,m.DB,m.runtime,entry)
                if result['delay'] is None:raise ValueError('出口不可达或测速超时')
                return page(request,notice=entry['name']+' · '+str(result['delay'])+' ms')
            if action not in ('toggle','delete'):raise HTTPException(404)
            def change(data):
                row=find(data['outbounds'],identity)
                referenced=data['final']==identity or any(x['target']==identity for x in data['rules'])
                if referenced and (action=='delete' or row['enabled']):raise ValueError('此出口正被规则或默认出口引用，请先修改引用')
                if action=='delete':data['outbounds'].remove(row)
                else:row['enabled']=not row['enabled']
            apply_change(change);log('分流出口 '+action,entry['name'])
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
            row={'id':identity or uuid.uuid4().hex,'enabled':old['enabled'] if old else True,**values}
            def change(data):
                if old:data['rules'][data['rules'].index(find(data['rules'],identity))]=row
                else:
                    if len(data['rules'])>=200:raise ValueError('最多添加 200 条规则')
                    data['rules'].append(row)
            apply_change(change);log('保存分流规则',row['name']);return RedirectResponse('/routing',303)
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
        await form(request)
        try:
            if action not in ('toggle','delete','up','down'):raise HTTPException(404)
            def change(data):
                row=find(data['rules'],identity);index=data['rules'].index(row)
                if action=='delete':data['rules'].remove(row)
                elif action=='toggle':row['enabled']=not row['enabled']
                else:
                    other=index+(-1 if action=='up' else 1)
                    if 0<=other<len(data['rules']):data['rules'][index],data['rules'][other]=data['rules'][other],data['rules'][index]
            apply_change(change);log('分流规则 '+action,identity);return RedirectResponse('/routing',303)
        except ValueError as e:return page(request,error=str(e))

    @app.post('/routing/settings')
    async def settings(request:Request):
        raw=await form(request)
        try:
            def change(data):data.update(final=str(raw.get('final','direct')),sniff=r.truth(raw.get('sniff')))
            apply_change(change);log('修改默认出口','');return RedirectResponse('/routing',303)
        except ValueError as e:return page(request,error=str(e))

    @app.post('/routing/latency/{identity}')
    async def outbound_latency(request:Request,identity:str):
        await form(request)
        entry=find(r.load(m.DB)['outbounds'],identity)
        if not entry['enabled']:raise HTTPException(422,'出口未启用')
        from .latency import probe
        from starlette.concurrency import run_in_threadpool
        return await run_in_threadpool(probe,m.DB,m.runtime,entry)

    @app.get('/routing/preview')
    def preview(request:Request):
        m.authenticated(request)
        from .core import current_config
        d=current_config(m.DB,m.STATS_PORT)
        safe={'route':d.get('route',{}),'outbounds':[{k:o[k] for k in ('tag','type','server','server_port') if k in o} for o in d['outbounds']]}
        return Response(json.dumps(safe,ensure_ascii=False,indent=2),media_type='application/json')
