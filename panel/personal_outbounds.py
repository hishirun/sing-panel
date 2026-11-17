"""Owner-scoped egress credentials, public-IP pinning and transactional updates."""
import ipaddress,json,socket,tempfile,threading,time,uuid
from concurrent.futures import ThreadPoolExecutor,TimeoutError
from pathlib import Path
from .core import connect,current_config
from . import routing

TYPES={'http':'HTTP / HTTPS','socks':'SOCKS5','shadowsocks':'Shadowsocks / SS2022'}
MAXIMUM=10
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
    future=_pool.submit(socket.getaddrinfo,address,None,0,socket.SOCK_STREAM)
    future.add_done_callback(lambda _: _slots.release())
    try:answers=future.result(timeout=4)
    except (TimeoutError,OSError):raise ValueError('无法解析出口地址，请检查域名或填写公网 IP') from None
    addresses={public_ip(answer[4][0]) for answer in answers}
    if not addresses:raise ValueError('出口域名没有可用公网地址')
    return sorted(addresses,key=lambda value:(':' in value,value))[0]


def build(raw,old=None,blocked_ports=()):
    if not isinstance(raw,dict):raise ValueError('出口配置格式无效')
    kind=raw.get('type')
    if not isinstance(kind,str) or kind not in TYPES:raise ValueError('个人出口支持 HTTP、SOCKS5 和 Shadowsocks')
    name=routing.text(raw,'name',80)
    if not name or any(ord(c)<32 for c in name):raise ValueError('出口名称需要 1–80 个可见字符')
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
    settings['server']=resolve(address)
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
