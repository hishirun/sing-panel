"""Owner-scoped egress credentials, public-IP pinning and transactional updates."""
import base64,ipaddress,json,re,socket,tempfile,threading,time,uuid
from concurrent.futures import ThreadPoolExecutor,TimeoutError
from datetime import datetime,timezone
from pathlib import Path
from urllib.parse import parse_qs,quote,unquote,urlencode,urlsplit
from .core import connect,current_config
from . import routing

TYPES={'http':'HTTP / HTTPS','socks':'SOCKS5','shadowsocks':'Shadowsocks / SS2022'}
MAXIMUM=10
MAX_BATCH=50
EXPORT_FORMAT='sing-panel-personal-outbounds'
EXPORT_VERSION=1
EXPORT_ITEM_KEYS={'name','type','server','server_port','enabled','username','password','method','tls_mode','sni'}
_pool=ThreadPoolExecutor(max_workers=4,thread_name_prefix='personal-egress-dns')
_slots=threading.BoundedSemaphore(4)
_mutations=threading.BoundedSemaphore(2)
_mutation_lock=threading.Lock()
_mutation_users=set()


def migrate(db):
    db.execute('''CREATE TABLE IF NOT EXISTS personal_outbounds (
      id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,enabled INTEGER NOT NULL,settings TEXT NOT NULL,address TEXT NOT NULL,
      revision INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)''')


def rows(path,user_id=None):
    with connect(path) as db:
        result=db.execute('SELECT * FROM personal_outbounds'+(' WHERE user_id=?' if user_id is not None else '')+' ORDER BY created_at,id',
                          (user_id,) if user_id is not None else ()).fetchall()
    return [{**dict(row),'owner_id':row['user_id'],'enabled':bool(row['enabled']),'settings':json.loads(row['settings'])} for row in result]


def find(path,uid,identity):
    row=next((row for row in rows(path,uid) if row['id']==identity),None)
    if row is None:raise ValueError('个人出口不存在')
    return row


def public_ip(value):
    if '%' in value:raise ValueError('个人出口地址不能指定本机网卡')
    address=ipaddress.ip_address(value)
    if address.version==6 and address.ipv4_mapped:address=address.ipv4_mapped
    if not address.is_global or address.is_multicast:raise ValueError('个人出口仅支持公网地址，不能访问本机、内网或保留地址')
    return str(address)


def resolve(address):
    try:return public_ip(address)
    except ValueError:
        try:ipaddress.ip_address(address)
        except ValueError:pass
        else:raise
    if not _slots.acquire(blocking=False):raise ValueError('地址查询繁忙，请稍后再试')
    released=threading.Event()
    def _done(_):
        _slots.release();released.set()
    future=_pool.submit(socket.getaddrinfo,address,None,0,socket.SOCK_STREAM)
    future.add_done_callback(_done)
    try:
        answers=future.result(timeout=4)
        released.wait(timeout=1)
    except (TimeoutError,OSError):raise ValueError('无法解析出口地址，请检查域名或填写公网 IP') from None
    addresses={public_ip(answer[4][0]) for answer in answers}
    if not addresses:raise ValueError('出口域名没有可用公网地址')
    return sorted(addresses,key=lambda value:(':' in value,value))[0]


def build(raw,old=None,blocked_ports=(),resolved=None):
    if not isinstance(raw,dict):raise ValueError('出口配置格式无效')
    kind=raw.get('type')
    if not isinstance(kind,str) or kind not in TYPES:raise ValueError('个人出口支持 HTTP、SOCKS5 和 Shadowsocks')
    for key in ('name','server','method','tls_mode','sni'):
        if key in raw and raw[key] is not None and not isinstance(raw[key],str):raise ValueError('出口配置格式无效')
    if isinstance(raw.get('server_port'),bool):raise ValueError('server_port 必须为整数')
    name=routing.text(raw,'name',80)
    if not name or any(ord(c)<32 or ord(c)==127 for c in name):raise ValueError('出口名称需要 1–80 个可见字符')
    address=routing.host(routing.text(raw,'server'))
    port=routing.number(raw,'server_port',0,1,65535)
    if port in {18889,19090,19091,19190,19191,*blocked_ports}:raise ValueError('不能使用面板管理或统计端口')
    allowed={key:raw[key] for key in ('type','username','password','method','tls_mode','sni','clear_password') if key in raw}
    allowed.update(server=address,server_port=port)
    if allowed.get('tls_mode','none') not in ('none','tls') or kind!='http' and allowed.get('tls_mode','none')!='none':
        raise ValueError('仅 HTTP 出口支持 TLS')
    for key in ('username','password'):
        if key in allowed and (not isinstance(allowed[key],str) or any(ord(c)<32 or ord(c)==127 for c in allowed[key])):
            raise ValueError('认证信息不能包含控制字符')
    settings=routing.build_outbound(allowed,old['settings'] if old else None)
    # Resolve once, reject mixed public/private answers, then dial the literal.
    if resolved is not None and address in resolved:
        settings['server']=resolved[address]
    else:
        pinned=resolve(address)
        if resolved is not None:resolved[address]=pinned
        settings['server']=pinned
    if kind=='shadowsocks' and settings['method'].startswith('2022-'):
        from .protocols import validate_key
        for key in settings['password'].split(':'):validate_key(key,settings['method'])
    return dict(name=name,address=address,settings=settings)


def projection(row):
    values=routing.edit_values(row)
    values['server']=row['address']
    return {**values,'id':row['id'],'revision':row['revision'],'enabled':row['enabled'],
            'has_password':bool(row['settings'].get('password')),'resolved_ip':row['settings']['server']}


def references(path,uid,identity):
    from .user_routing import get_policy
    policy=get_policy(path,uid)
    return any(rule.get('target')==identity for key in ('draft','applied') for rule in policy[key].get('rules',[]))


def protect_managed_listener(m,entry):
    with connect(m.DB) as db:
        hosts={row['id']:row['host'] for row in db.execute('SELECT id,host FROM servers')}
        hosts['local']=m.PUBLIC_HOST
        ports={}
        for row in db.execute('SELECT node_id,port FROM memberships'):
            ports.setdefault(row['node_id'],set()).add(row['port'])
        for node in db.execute('SELECT id,port,server_id,options FROM nodes'):
            candidates={hosts.get(node['server_id'],''),json.loads(node['options']).get('connect_host','')}
            if entry['settings']['server_port'] in ports.get(node['id'],set())|{node['port']} and (entry['address'] in candidates or entry['settings']['server'] in candidates):
                raise ValueError('不能将面板节点作为个人出口，以免形成循环连接')


def _put(path,entry):
    with connect(path) as db:
        if entry is None:raise ValueError('出口配置不存在')
        db.execute('INSERT INTO personal_outbounds VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,enabled=excluded.enabled,settings=excluded.settings,address=excluded.address,revision=excluded.revision,updated_at=excluded.updated_at',
          (entry['id'],entry['user_id'],entry['name'],int(entry['enabled']),json.dumps(entry['settings']),entry['address'],entry['revision'],entry['created_at'],entry['updated_at']))


def mutate(m,uid,identity,raw,authorize,action='save'):
    with _mutation_lock:
        if uid in _mutation_users or not _mutations.acquire(blocking=False):
            raise ValueError('个人出口正在保存，请稍后重试')
        _mutation_users.add(uid)
    try:return _mutate(m,uid,identity,raw,authorize,action)
    finally:
        with _mutation_lock:_mutation_users.discard(uid)
        _mutations.release()


def _mutate(m,uid,identity,raw,authorize,action='save'):
    """Validate outside the accounting lock; reauthorize and compare before commit."""
    authorize()
    if action not in ('save','toggle','delete'):raise ValueError('操作无效')
    old=find(m.DB,uid,identity) if identity else None
    if old and (type(raw.get('revision')) is not int or raw['revision']!=old['revision']):raise ValueError('出口已被修改，请刷新后重试')
    prepared=build(raw,old,(m.STATS_PORT,m.STATS_PORT+1)) if action=='save' else None
    stamp=int(time.time())
    entry={**(old or {}),**(prepared or {}),'id':identity or 'personal-'+uuid.uuid4().hex,'user_id':uid,
           'enabled':not old['enabled'] if action=='toggle' else old['enabled'] if old else True,
           'revision':old['revision']+1 if old else 1,'created_at':old['created_at'] if old else stamp,'updated_at':stamp}
    if action=='save':
        try:m.check_document({'outbounds':[{**entry['settings'],'tag':'validation'}]})
        except Exception:raise ValueError('出口核心校验未通过，请检查协议、加密方式和认证信息') from None
    def eligible():
        authorize()
        current=find(m.DB,uid,identity) if identity else None
        if current!=old:raise ValueError('出口已被修改，请刷新后重试')
        if old is None and len(rows(m.DB,uid))>=MAXIMUM:raise ValueError(f'最多添加 {MAXIMUM} 个个人出口')
        if action=='save':protect_managed_listener(m,entry)
        if action=='delete' and references(m.DB,uid,identity):raise ValueError('出口仍被草稿或已发布规则引用，请先更换出口并发布规则')
    def change(path):
        if action=='delete':
            with connect(path) as db:db.execute('DELETE FROM personal_outbounds WHERE id=? AND user_id=?',(identity,uid))
        else:_put(path,entry)
    def signature(path):return json.dumps(current_config(path,m.STATS_PORT),sort_keys=True,separators=(',',':'))
    with tempfile.TemporaryDirectory(prefix='personal-egress-',dir=m.DIRECTORY) as folder:
        candidate=Path(folder)/'panel.db'
        with m.runtime.lock:
            eligible();before=signature(m.DB)
            with connect(m.DB) as source,connect(candidate) as target:source.backup(target)
        candidate.chmod(0o600);change(candidate)
        document=current_config(candidate,m.STATS_PORT)
        routing.prepare_rule_sets(document,m.DIRECTORY,m.BINARY,30)
        try:m.check_document(document)
        except Exception:raise ValueError('运行配置校验未通过，原配置保持不变，请联系管理员') from None
        with m.runtime.lock:
            eligible()
            if signature(m.DB)!=before:raise ValueError('运行配置已变化，请重试保存')
            change(m.DB)
            try:m.runtime.apply()
            except Exception:
                if old:_put(m.DB,old)
                else:
                    with connect(m.DB) as db:db.execute('DELETE FROM personal_outbounds WHERE id=?',(entry['id'],))
                try:m.runtime.apply()
                except Exception:pass
                raise ValueError('应用未完成，已恢复原出口设置，请联系管理员') from None
            from .management import audit
            with connect(m.DB) as db:audit(db,'个人出口 '+action,uid+' · '+entry['name'])
    return entry['id']


def fingerprint(address,settings):
    kind=settings['type'];tls=settings.get('tls') or {}
    return (kind,address,int(settings['server_port']),
            settings.get('username','') if kind!='shadowsocks' else '',
            settings.get('password',''),
            settings.get('method','') if kind=='shadowsocks' else '',
            'tls' if tls.get('enabled') else 'none',
            tls.get('server_name','') if tls.get('enabled') else '')


def _decode_b64(value):
    cleaned=value.strip()
    if not cleaned or len(cleaned)%4==1 or not re.fullmatch(r'[A-Za-z0-9+/_-]+={0,2}',cleaned):
        raise ValueError('分享链接编码无效')
    normalized=cleaned.replace('-','+').replace('_','/')
    normalized+='='*((-len(normalized))%4)
    try:return base64.b64decode(normalized,validate=True).decode('utf-8')
    except Exception:raise ValueError('分享链接编码无效') from None


def parse_personal_uri(line):
    if not isinstance(line,str) or len(line)>8192 or any(ord(c)<32 or ord(c)==127 for c in line):
        raise ValueError('链接长度或字符无效')
    text_line=line.strip()
    if '://' not in text_line:raise ValueError('节点链接格式无效')
    scheme=text_line.split('://',1)[0].lower()
    if scheme not in ('http','https','socks','socks5','ss'):
        raise ValueError('个人出口仅支持 HTTP、HTTPS、SOCKS5 和 SS/SS2022 链接')
    if scheme=='ss':
        rest=text_line.split('://',1)[1]
        rest,fragment=rest.split('#',1) if '#' in rest else (rest,'')
        main,query_str=rest.split('?',1) if '?' in rest else (rest,'')
        if query_str:
            params=parse_qs(query_str,keep_blank_values=True)
            if any(k in params for k in ('insecure','allowInsecure','allow_insecure','skip-cert-verify','skip_cert_verify')):
                raise ValueError('不支持跳过证书校验')
            if any(k in params for k in ('plugin','shadow-tls','v2ray-plugin','obfs')):
                raise ValueError('不支持 SIP003 插件或附加混淆传输')
            if any(k in params for k in ('detour','interface','bind_interface','routing_mark')):
                raise ValueError('不支持链式代理或网卡绑定')
            raise ValueError('SS 链接包含不支持的参数')
        if '@' not in main:
            decoded=_decode_b64(main)
            if '@' not in decoded:raise ValueError('Shadowsocks 链接格式无效')
            credentials,address=decoded.rsplit('@',1)
            if ':' not in credentials:raise ValueError('Shadowsocks 认证信息格式无效')
            method,password=credentials.split(':',1)
        else:
            credentials,address=main.rsplit('@',1)
            if ':' not in credentials:
                decoded=_decode_b64(credentials)
                if ':' not in decoded:raise ValueError('Shadowsocks 认证信息格式无效')
                method,password=decoded.split(':',1)
            else:
                raw_method,raw_password=credentials.split(':',1)
                method,password=unquote(raw_method),unquote(raw_password)
        address=address.rstrip('/')
        try:
            parsed=urlsplit('ss://'+address)
            host_val=unquote(parsed.hostname or '')
            port_val=parsed.port
        except ValueError:
            raise ValueError('服务器地址或端口格式无效') from None
        if not host_val or parsed.username is not None or parsed.path not in ('','/'):
            raise ValueError('服务器地址格式无效')
        if not port_val:raise ValueError('请填写有效端口')
        frag_name=unquote(fragment).strip()
        if any(ord(c)<32 or ord(c)==127 for c in frag_name):raise ValueError('出口名称包含非法字符')
        explicit_name=bool(frag_name)
        display_host=f'[{host_val}]' if ':' in host_val else host_val
        name=(frag_name[:80] if explicit_name else f'SS {display_host}:{port_val}'[:80])
        return {'name':name,'type':'shadowsocks','server':host_val,'server_port':port_val,
                'method':method,'password':password,'tls_mode':'none'},explicit_name,True
    try:
        u=urlsplit(text_line)
        port_val=u.port
    except ValueError:
        raise ValueError('节点链接地址或端口格式无效') from None
    host_val=unquote(u.hostname or '')
    if not host_val:raise ValueError('缺少服务器地址')
    if u.path not in ('','/'):raise ValueError('个人出口链接不支持路径参数')
    if port_val is None:
        port_val=443 if scheme=='https' else 80 if scheme=='http' else 1080
    if u.query:
        params=parse_qs(u.query,keep_blank_values=True)
        if not params:raise ValueError('链接查询参数无效')
        for key in ('insecure','allowInsecure','allow_insecure','skip-cert-verify','skip_cert_verify'):
            if key in params:
                if scheme!='https' or any(v.lower() not in ('0','false') for v in params[key]):
                    raise ValueError('不支持跳过证书校验')
        if any(k in params for k in ('detour','interface','bind_interface','routing_mark','netns')):
            raise ValueError('不支持链式代理或网卡绑定')
        if any(k in params for k in ('plugin','type','transport','path','serviceName','obfs','ws','grpc')):
            raise ValueError('包含不支持的传输或插件参数')
        if scheme=='https':
            if 'security' in params and any(v.lower()!='tls' for v in params['security']):
                raise ValueError('TLS 模式无效')
            if set(params)-{'sni','peer','insecure','allowInsecure','allow_insecure','security'}:
                raise ValueError('HTTPS 链接包含不支持的参数')
            if len(params.get('sni',[]))>1 or len(params.get('peer',[]))>1:
                raise ValueError('SNI 参数重复')
            sni=(params.get('sni') or params.get('peer') or [''])[-1].strip()
        else:
            if any(k in params for k in ('sni','peer','tls','security')):
                raise ValueError('仅 HTTPS 出口支持 TLS / SNI')
            raise ValueError('链接包含不支持的参数')
    else:
        sni=''
    raw_user,raw_pass=u.username,u.password
    if scheme in ('socks','socks5') and raw_user and raw_pass is None and '%' not in raw_user:
        try:
            decoded=_decode_b64(raw_user)
            if ':' in decoded and not any(ord(c)<32 or ord(c)==127 for c in decoded):
                username,password=decoded.split(':',1)
            else:
                username,password=unquote(raw_user),''
        except ValueError:
            username,password=unquote(raw_user),''
    else:
        username=unquote(raw_user) if raw_user is not None else ''
        password=unquote(raw_pass) if raw_pass is not None else ''
    frag_name=unquote(u.fragment).strip()
    if any(ord(c)<32 or ord(c)==127 for c in frag_name):raise ValueError('出口名称包含非法字符')
    explicit_name=bool(frag_name)
    kind='http' if scheme in ('http','https') else 'socks'
    label='HTTPS' if scheme=='https' else 'HTTP' if scheme=='http' else 'SOCKS5'
    display_host=f'[{host_val}]' if ':' in host_val else host_val
    name=(frag_name[:80] if explicit_name else f'{label} {display_host}:{port_val}'[:80])
    return {'name':name,'type':kind,'server':host_val,'server_port':port_val,
            'username':username,'password':password,
            'tls_mode':'tls' if scheme=='https' else 'none','sni':sni},explicit_name,True


def _validate_json_item(item):
    if not isinstance(item,dict):raise ValueError('出口条目须为 JSON 对象')
    if any(k in item for k in ('insecure','allow_insecure','allowInsecure','skip_cert_verify')) or (isinstance(item.get('tls'),dict) and item['tls'].get('insecure')):
        raise ValueError('不支持跳过证书校验')
    if 'detour' in item:raise ValueError('不支持 detour 链式代理')
    if set(item)&{'bind_interface','inet4_bind_address','inet6_bind_address','routing_mark','reuse_addr','netns','dialer'}:
        raise ValueError('不支持网卡绑定或自定义拨号参数')
    if set(item)-EXPORT_ITEM_KEYS:
        raise ValueError('包含不支持的配置字段')
    if 'enabled' in item and type(item['enabled']) is not bool:
        raise ValueError('启用状态须为布尔值')
    if type(item.get('server_port')) is not int:
        raise ValueError('端口须为 1–65535 的整数')
    for key in ('name','type','server','username','password','method','tls_mode','sni'):
        if key in item and not isinstance(item[key],str):
            raise ValueError('配置字段类型无效')
    kind=item.get('type','')
    tls_mode=item.get('tls_mode','none')
    sni=item.get('sni','').strip()
    if kind!='http' and (tls_mode!='none' or sni):
        raise ValueError('仅 HTTP 出口支持 TLS / SNI')
    if kind=='http' and tls_mode=='none' and sni:
        raise ValueError('未开启 HTTPS 时不能设置 SNI')
    if kind=='shadowsocks' and item.get('username','').strip():
        raise ValueError('Shadowsocks 不使用用户名字段')
    raw={k:item[k] for k in ('name','type','server','server_port','username','password','method','tls_mode','sni') if k in item}
    return raw,True,item.get('enabled',True)


def parse_import_source(text_content):
    if not isinstance(text_content,str):raise ValueError('导入内容格式无效')
    if len(text_content)>131072 or '\x00' in text_content:raise ValueError('导入内容过大或包含非法字符')
    cleaned=text_content.lstrip('\ufeff')
    stripped=cleaned.strip()
    if not stripped:raise ValueError('请粘贴节点链接或选择导出文件')
    if stripped[0] in ('{','['):
        try:doc=json.loads(stripped)
        except ValueError:raise ValueError('JSON 格式无效，请导入本面板导出的个人出口 JSON 文件') from None
        if isinstance(doc,dict) and any(k in doc for k in ('outbounds','inbounds','route','dns')):
            raise ValueError('不支持导入任意 sing-box 配置，仅支持本面板导出的个人出口文件')
        if (not isinstance(doc,dict) or doc.get('format')!=EXPORT_FORMAT
                or type(doc.get('version')) is not int or doc.get('version')!=EXPORT_VERSION
                or not isinstance(doc.get('items'),list)):
            raise ValueError('仅支持本面板导出的个人出口 JSON（版本 1）')
        if set(doc)-{'format','version','exported_at','items'}:
            raise ValueError('导出文件包含不支持的顶层字段')
        if not doc['items']:raise ValueError('导出文件中没有个人出口条目')
        if len(doc['items'])>MAX_BATCH:raise ValueError(f'单次最多导入 {MAX_BATCH} 条记录')
        return 'json',list(enumerate(doc['items'],1))
    entries=[(idx,line.strip()) for idx,line in enumerate(cleaned.splitlines(),1)
             if line.strip() and not line.lstrip().startswith('#')]
    if not entries:raise ValueError('请粘贴至少一条节点链接')
    if len(entries)>MAX_BATCH:raise ValueError(f'单次最多导入 {MAX_BATCH} 条记录')
    return 'uri',entries


def _evaluate_batch(m,existing,text_content):
    source_kind,raw_items=parse_import_source(text_content)
    seen_conn={fingerprint(row['address'],row['settings']) for row in existing}
    seen_named={(row['name'],fingerprint(row['address'],row['settings'])) for row in existing}
    dns_cache={}
    blocked=(m.STATS_PORT,m.STATS_PORT+1)
    preview_items=[];candidates=[];errors=[]
    duplicate_count=0
    deadline=time.monotonic()+30
    for line_no,raw_item in raw_items:
        if time.monotonic()>=deadline:
            raise ValueError('批量校验超时，请减少条目或检查域名后重试（整批未导入）')
        try:
            raw,explicit_name,enabled=(_validate_json_item(raw_item) if source_kind=='json' else parse_personal_uri(raw_item))
            built=build(raw,None,blocked,resolved=dns_cache)
            protect_managed_listener(m,built)
            try:m.check_document({'outbounds':[{**built['settings'],'tag':'validation'}]})
            except Exception:raise ValueError('出口核心校验未通过，请检查协议、加密方式和认证信息') from None
            fp=fingerprint(built['address'],built['settings'])
            is_dup=((built['name'],fp) in seen_named) if explicit_name else (fp in seen_conn)
            tls=built['settings'].get('tls') or {}
            preview_items.append({
                'line':line_no,
                'name':built['name'],
                'type':built['settings']['type'],
                'server':built['address'],
                'server_port':int(built['settings']['server_port']),
                'tls_mode':'tls' if tls.get('enabled') else 'none',
                'sni':tls.get('server_name','') if tls.get('enabled') else '',
                'resolved_ip':built['settings']['server'],
                'enabled':bool(enabled),
                'status':'duplicate' if is_dup else 'ready',
            })
            if is_dup:
                duplicate_count+=1
            else:
                seen_conn.add(fp)
                seen_named.add((built['name'],fp))
                candidates.append({**built,'enabled':bool(enabled)})
        except ValueError as error:
            errors.append({'line':line_no,'message':str(error)})
    if time.monotonic()>=deadline:
        raise ValueError('批量校验超时，请减少条目或检查域名后重试（整批未导入）')
    return source_kind,len(raw_items),preview_items,candidates,duplicate_count,errors


def preview_import(m,uid,text_content):
    existing=rows(m.DB,uid)
    source_kind,total,items,candidates,duplicate_count,errors=_evaluate_batch(m,existing,text_content)
    remaining=max(0,MAXIMUM-len(existing))
    importable=len(candidates)
    exceeds=len(existing)+importable>MAXIMUM
    return {
        'source':source_kind,
        'total_count':total,
        'parsed_count':len(items),
        'importable_count':importable,
        'duplicate_count':duplicate_count,
        'error_count':len(errors),
        'existing_count':len(existing),
        'limit':MAXIMUM,
        'remaining_quota':remaining,
        'after_remaining_quota':max(0,remaining-importable),
        'exceeds_quota':exceeds,
        'can_import':bool(importable>0 and not errors and not exceeds),
        'items':items,
        'errors':errors,
    }


def import_batch(m,uid,text_content,authorize):
    with _mutation_lock:
        if uid in _mutation_users or not _mutations.acquire(blocking=False):
            raise ValueError('个人出口正在保存，请稍后重试')
        _mutation_users.add(uid)
    try:return _import_batch(m,uid,text_content,authorize)
    finally:
        with _mutation_lock:_mutation_users.discard(uid)
        _mutations.release()


def _import_batch(m,uid,text_content,authorize):
    """Atomically validate and apply an entire batch without holding the stats lock during checks."""
    authorize()
    initial_rows=rows(m.DB,uid)
    source_kind,_,_items,candidates,duplicate_count,errors=_evaluate_batch(m,initial_rows,text_content)
    if errors:
        unit='项' if source_kind=='json' else '行'
        first=errors[0]
        suffix=f'（共 {len(errors)} 处错误，整批未导入）' if len(errors)>1 else '（整批未导入）'
        raise ValueError(f"第 {first['line']} {unit}：{first['message']}{suffix}")
    if len(initial_rows)+len(candidates)>MAXIMUM:
        raise ValueError(f'最多添加 {MAXIMUM} 个个人出口（当前已有 {len(initial_rows)} 个，待导入 {len(candidates)} 个）')
    if not candidates:
        with m.runtime.lock:
            authorize()
            if rows(m.DB,uid)!=initial_rows:raise ValueError('个人出口已被修改，请刷新后重试')
        return {'imported_count':0,'duplicate_count':duplicate_count,'ids':[]}
    stamp=int(time.time())
    entries=[{**item,'id':f'personal-{idx:02x}{uuid.uuid4().hex[:30]}','user_id':uid,
              'revision':1,'created_at':stamp,'updated_at':stamp}
             for idx,item in enumerate(candidates)]
    def eligible():
        authorize()
        current=rows(m.DB,uid)
        if current!=initial_rows:raise ValueError('个人出口已被修改，请刷新后重试')
        if len(current)+len(entries)>MAXIMUM:raise ValueError(f'最多添加 {MAXIMUM} 个个人出口')
        for entry in entries:protect_managed_listener(m,entry)
    def insert_all(path):
        with connect(path) as db:
            db.execute('BEGIN IMMEDIATE')
            db.executemany('INSERT INTO personal_outbounds VALUES(?,?,?,?,?,?,?,?,?)',
                [(e['id'],e['user_id'],e['name'],int(e['enabled']),json.dumps(e['settings']),
                  e['address'],e['revision'],e['created_at'],e['updated_at']) for e in entries])
    def remove_all(path):
        with connect(path) as db:
            db.execute('BEGIN IMMEDIATE')
            db.executemany('DELETE FROM personal_outbounds WHERE id=? AND user_id=?',
                [(e['id'],uid) for e in entries])
    def signature(path):return json.dumps(current_config(path,m.STATS_PORT),sort_keys=True,separators=(',',':'))
    with tempfile.TemporaryDirectory(prefix='personal-egress-',dir=m.DIRECTORY) as folder:
        candidate=Path(folder)/'panel.db'
        with m.runtime.lock:
            eligible();before=signature(m.DB)
            with connect(m.DB) as source,connect(candidate) as target:source.backup(target)
        candidate.chmod(0o600);insert_all(candidate)
        document=current_config(candidate,m.STATS_PORT)
        routing.prepare_rule_sets(document,m.DIRECTORY,m.BINARY,30)
        try:m.check_document(document)
        except Exception:raise ValueError('运行配置校验未通过，原配置保持不变，请联系管理员') from None
        with m.runtime.lock:
            eligible()
            if signature(m.DB)!=before:raise ValueError('运行配置已变化，请重试保存')
            insert_all(m.DB)
            try:m.runtime.apply()
            except Exception:
                remove_all(m.DB)
                try:m.runtime.apply()
                except Exception:pass
                raise ValueError('应用未完成，已恢复原出口设置，请联系管理员') from None
            from .management import audit
            with connect(m.DB) as db:audit(db,'个人出口 import',f'{uid} · {len(entries)} 项')
    return {'imported_count':len(entries),'duplicate_count':duplicate_count,'ids':[e['id'] for e in entries]}


def export_item(row):
    """Explicit credential allowlist for the owner's own personal outbound only."""
    settings=row['settings'];kind=settings['type']
    item={'name':row['name'],'type':kind,'server':row['address'],
          'server_port':int(settings['server_port']),'enabled':bool(row['enabled'])}
    if kind=='shadowsocks':
        item['method']=settings['method']
        item['password']=settings['password']
    else:
        item['username']=settings.get('username','')
        item['password']=settings.get('password','')
        if kind=='http':
            tls=settings.get('tls') or {}
            item['tls_mode']='tls' if tls.get('enabled') else 'none'
            item['sni']=tls.get('server_name','') if tls.get('enabled') else ''
    return item


def format_personal_uri(row):
    settings=row['settings'];kind=settings['type'];addr=row['address']
    host_part=f'[{addr}]' if ':' in addr else addr
    port=int(settings['server_port'])
    frag=quote(row['name'],safe='')
    if kind=='shadowsocks':
        method=settings['method'];password=settings['password']
        if method.startswith('2022-'):
            cred=f"{method}:{quote(password,safe='')}"
        else:
            cred=base64.urlsafe_b64encode(f'{method}:{password}'.encode('utf-8')).decode('ascii').rstrip('=')
        return f'ss://{cred}@{host_part}:{port}#{frag}'
    tls=settings.get('tls') or {}
    scheme='https' if kind=='http' and tls.get('enabled') else 'http' if kind=='http' else 'socks5'
    username=settings.get('username','');password=settings.get('password','')
    auth=f"{quote(username,safe='')}:{quote(password,safe='')}@" if (username or password) else ''
    query=''
    if scheme=='https':
        sni=tls.get('server_name','')
        if sni and sni!=addr:query='?'+urlencode({'sni':sni})
    return f'{scheme}://{auth}{host_part}:{port}{query}#{frag}'


def export_personal(path,uid,ids=None,fmt='json'):
    if fmt not in ('json','uri'):raise ValueError('导出格式无效')
    owned=rows(path,uid)
    by_id={row['id']:row for row in owned}
    if ids is None:
        if not owned:raise ValueError('暂无可导出的个人出口')
        selected=owned
    else:
        if not isinstance(ids,list):raise ValueError('导出选择无效')
        if not ids:raise ValueError('请先勾选要导出的个人出口')
        if len(ids)>MAXIMUM or any(not isinstance(x,str) or not 1<=len(x)<=64 for x in ids):
            raise ValueError('导出选择无效')
        unique_ids=list(dict.fromkeys(ids))
        if any(oid not in by_id for oid in unique_ids):
            raise LookupError('个人出口不存在')
        selected=[by_id[oid] for oid in unique_ids]
    stamp=datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
    if fmt=='json':
        payload={'format':EXPORT_FORMAT,'version':EXPORT_VERSION,'items':[export_item(row) for row in selected]}
        return json.dumps(payload,ensure_ascii=False,indent=2)+'\n',f'personal-outbounds-{stamp}.json','application/json; charset=utf-8'
    return '\n'.join(format_personal_uri(row) for row in selected)+'\n',f'personal-outbounds-{stamp}.txt','text/plain; charset=utf-8'
