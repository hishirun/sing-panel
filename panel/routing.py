"""Server egress routing. Upstream credentials are admin-only, never subscriptions."""
import base64,copy,ipaddress,json,re,uuid
from pathlib import Path
GEO_CATALOG=json.loads(Path(__file__).with_name("geo_catalog.json").read_text())
from urllib.parse import urlsplit,parse_qs,unquote
from .core import connect
KEY='server_routing'
TYPES={'socks':'SOCKS5','http':'HTTP / HTTPS','shadowsocks':'Shadowsocks / SS2022','vmess':'VMess','vless':'VLESS / Reality','trojan':'Trojan','anytls':'AnyTLS','hysteria2':'Hysteria2','tuic':'TUIC','snell':'Snell'}
SS_METHODS=('aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305','2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305','xchacha20-ietf-poly1305')
DEFAULT={'outbounds':[],'rules':[],'final':'direct','sniff':False}

def load(path):
    with connect(path) as db:
        row=db.execute('SELECT value FROM settings WHERE key=?',(KEY,)).fetchone()
    return json.loads(row[0]) if row else copy.deepcopy(DEFAULT)

def write(path,value):
    with connect(path) as db:db.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',(KEY,json.dumps(value,ensure_ascii=False)))

def text(raw,key,limit=255):
    value=str(raw.get(key,'')).strip()
    if len(value)>limit or '\x00' in value:raise ValueError('字段过长或含非法字符：'+key)
    return value

def number(raw,key,default,lo,hi):
    try:value=int(raw.get(key,default) or default)
    except (ValueError,TypeError):raise ValueError(key+' 必须为整数')
    if not lo<=value<=hi:raise ValueError(key+' 超出允许范围')
    return value

def truth(value):return value in (True,'true','1','on')

def host(value):
    value=value.strip().strip('[]')
    try:return str(ipaddress.ip_address(value))
    except ValueError:
        if value=='localhost':return value
        from .options import domain
        return domain(value)

def fields(value):return list(dict.fromkeys(x.strip() for x in re.split(r'[,\n]+',value) if x.strip()))

def build_outbound(raw,old=None):
    kind=text(raw,'type');old=old if old and old.get('type')==kind else {}
    if kind not in TYPES:raise ValueError('上游协议无效')
    out={'type':kind,'server':host(text(raw,'server')),'server_port':number(raw,'server_port',0,1,65535)}
    def secret(key='password'):
        value=text(raw,key,4096) or old.get(key,old.get('psk','') if key=='password' else '')
        if truth(raw.get('clear_password')):value=''
        return value
    password=secret()
    if kind in ('socks','http'):
        if kind=='socks':out['version']='5'
        username='' if truth(raw.get('clear_password')) else text(raw,'username')
        if username or password:out.update(username=username,password=password)
    elif kind=='shadowsocks':
        method=text(raw,'method')
        if method not in SS_METHODS:raise ValueError('请选择支持的 Shadowsocks 加密方式')
        if not password:raise ValueError('请填写 Shadowsocks 密钥')
        out.update(method=method,password=password)
    elif kind in ('trojan','anytls','hysteria2','tuic','snell'):
        if not password:raise ValueError('请填写上游密码')
        out['password' if kind!='snell' else 'psk']=password
    if kind in ('vmess','vless','tuic'):
        value=text(raw,'uuid') or old.get('uuid','')
        try:out['uuid']=str(uuid.UUID(value))
        except ValueError:raise ValueError('请填写有效 UUID')
        if kind=='vmess':out.update(security='auto',alter_id=number(raw,'alter_id',0,0,65535))
        if kind=='vless':
            flow=text(raw,'flow')
            if flow not in ('','xtls-rprx-vision'):raise ValueError('VLESS Flow 无效')
            if flow:out['flow']=flow
    tls_mode=text(raw,'tls_mode') or ('tls' if kind in ('trojan','anytls','hysteria2','tuic') else 'none')
    if tls_mode not in ('none','tls','reality'):raise ValueError('TLS 模式无效')
    if kind in ('trojan','anytls','hysteria2','tuic') and tls_mode!='tls':raise ValueError('此协议必须使用 TLS')
    if tls_mode=='reality' and kind!='vless':raise ValueError('Reality 仅用于 VLESS')
    if tls_mode!='none':
        if kind in ('socks','shadowsocks','snell'):raise ValueError('此协议不支持此 TLS 配置')
        tls={'enabled':True,'server_name':host(text(raw,'sni') or out['server'])}
        if truth(raw.get('insecure')):tls['insecure']=True
        alpn=fields(text(raw,'alpn'))
        if alpn:
            if any(not re.fullmatch(r'[\w./-]{1,32}',v) for v in alpn):raise ValueError('ALPN 格式无效')
            tls['alpn']=alpn
        if kind=='hysteria2':tls['alpn']=['h3']
        if tls_mode=='reality':
            public=text(raw,'public_key');sid=text(raw,'short_id')
            if not re.fullmatch(r'[A-Za-z0-9_-]{43}',public):raise ValueError('Reality 公钥须为 43 字符')
            if not re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}',sid):raise ValueError('Short ID 格式无效')
            fp=text(raw,'fingerprint') or 'chrome'
            from .options import FINGERPRINTS
            if fp not in FINGERPRINTS:raise ValueError('TLS 指纹无效')
            tls['utls']={'enabled':True,'fingerprint':fp};tls['reality']={'enabled':True,'public_key':public,'short_id':sid}
            if tls.get('insecure'):raise ValueError('Reality 不能关闭校验')
        out['tls']=tls
    transport=text(raw,'transport') or 'tcp'
    if transport!='tcp':
        if kind not in ('vmess','vless','trojan') or transport not in ('ws','grpc','httpupgrade'):raise ValueError('该协议不支持此传输方式')
        tr={'type':transport}
        if transport=='grpc':tr['service_name']=text(raw,'service_name')
        else:
            tr['path']=text(raw,'path',2048) or '/'
            if not tr['path'].startswith('/'):raise ValueError('传输路径须以 / 开头')
            if text(raw,'transport_host'):tr['headers' if transport=='ws' else 'host']={'Host':text(raw,'transport_host')} if transport=='ws' else text(raw,'transport_host')
        if out.get('flow'):raise ValueError('Vision Flow 请使用 TCP 传输')
        out['transport']=tr
    if kind=='anytls':out.update(idle_session_check_interval=f"{number(raw,'idle_check',30,1,3600)}s",idle_session_timeout=f"{number(raw,'idle_timeout',30,1,3600)}s",min_idle_session=number(raw,'min_idle',0,0,128))
    if kind=='hysteria2':
        for key in ('up_mbps','down_mbps'):
            value=number(raw,key,0,0,100000)
            if value:out[key]=value
        obfs=text(raw,'obfs') or 'none'
        if obfs not in ('none','salamander'):raise ValueError('URI 上游支持无混淆或 Salamander')
        if obfs!='none':
            value=text(raw,'obfs_password',255) or old.get('obfs',{}).get('password','')
            if not value:raise ValueError('请填写混淆密码')
            out['obfs']={'type':obfs,'password':value}
    if kind=='tuic':
        cc=text(raw,'congestion_control') or 'cubic'
        if cc not in ('cubic','new_reno','bbr'):raise ValueError('拥塞控制无效')
        out['congestion_control']=cc
    if kind=='snell':
        key=text(raw,'userkey',4096) or old.get('userkey','')
        if key:out['userkey']=key
        out['version']=number(raw,'snell_version',6,4,6)
        if out['version']==5:raise ValueError('sing-box Snell v5 服务端对应出站 version=4')
        out['reuse']=truth(raw.get('reuse'))
        if out['version']==4:
            obfs=text(raw,'snell_obfs') or 'none'
            if obfs not in ('none','http'):raise ValueError('Snell 混淆类型无效')
            out['obfs_mode']=obfs
            if obfs=='http' and text(raw,'snell_host'):out['obfs_host']=host(text(raw,'snell_host'))
        if out['version']==6:
            mode=text(raw,'snell_mode') or 'default'
            if mode not in ('default','unshaped'):raise ValueError('不支持未加密的上游模式')
            out['mode']=mode
    return out

def edit_values(row=None):
    o=copy.deepcopy(row['settings']) if row else {}
    kind=o.get('type','socks');tls=o.get('tls',{});tr=o.get('transport',{});obfs=o.get('obfs',{})
    return dict(name=row['name'] if row else '',type=kind,server=o.get('server',''),server_port=o.get('server_port',1080),username=o.get('username',''),password='',userkey='',snell_obfs=o.get('obfs_mode','none'),snell_host=o.get('obfs_host',''),uuid='',method=o.get('method','chacha20-ietf-poly1305'),alter_id=o.get('alter_id',0),flow=o.get('flow',''),tls_mode='reality' if tls.get('reality') else 'tls' if tls else 'none',sni=tls.get('server_name',''),alpn=','.join(tls.get('alpn',[])),insecure=tls.get('insecure',False),public_key=tls.get('reality',{}).get('public_key',''),short_id=tls.get('reality',{}).get('short_id',''),fingerprint=tls.get('utls',{}).get('fingerprint','chrome'),transport=tr.get('type','tcp'),path=tr.get('path','/'),transport_host=tr.get('headers',{}).get('Host',tr.get('host','')),service_name=tr.get('service_name',''),idle_check=int(str(o.get('idle_session_check_interval','30s')).removesuffix('s')),idle_timeout=int(str(o.get('idle_session_timeout','30s')).removesuffix('s')),min_idle=o.get('min_idle_session',0),up_mbps=o.get('up_mbps',0),down_mbps=o.get('down_mbps',0),obfs=obfs.get('type','none'),obfs_password='',congestion_control=o.get('congestion_control','cubic'),snell_version=o.get('version',6) if kind=='snell' else 6,snell_mode=o.get('mode','default'),reuse=o.get('reuse',False))

def decode64(value):
    try:return base64.urlsafe_b64decode(value+'='*((-len(value))%4)).decode()
    except Exception:raise ValueError('分享链接编码无效')

def parse_uri(uri):
    if len(uri)>16384 or any(c in uri for c in ('\n','\r','\x00')):raise ValueError('请粘贴一条节点链接')
    u=urlsplit(uri.strip());scheme=u.scheme.lower();q={k:v[0] for k,v in parse_qs(u.query).items()}
    raw=edit_values();raw['name']=unquote(u.fragment)[:80]
    if scheme=='vmess':
        try:d=json.loads(decode64(uri.split('://',1)[1]))
        except Exception:raise ValueError('VMess 链接格式无效')
        raw.update(type='vmess',name=str(d.get('ps',''))[:80],server=d.get('add',''),server_port=d.get('port',0),uuid=d.get('id',''),alter_id=d.get('aid',0),tls_mode='tls' if d.get('tls')=='tls' else 'none',sni=d.get('sni') or d.get('host',''),transport=d.get('net','tcp'),path=d.get('path','/'),transport_host=d.get('host',''),service_name=d.get('path',''))
        return raw
    if scheme=='ss':
        main=uri.split('://',1)[1].split('#',1)[0].split('?',1)[0].rstrip('/')
        if '@' not in main:main=decode64(main)
        credentials,address=main.rsplit('@',1)
        if ':' not in credentials:credentials=decode64(credentials)
        method,password=credentials.split(':',1);server=urlsplit('ss://'+address)
        raw.update(type='shadowsocks',server=server.hostname or '',server_port=server.port or 0,method=method,password=unquote(password))
        if q.get('plugin'):raise ValueError('暂不支持带 SIP003 插件的 SS 链接')
        return raw
    if scheme=='snell':
        main=uri.split('://',1)[1].split('#',1)[0].split('?',1)[0].rstrip('/')
        if '@' not in main:main=decode64(main)
        credentials,address=main.rsplit('@',1);server=urlsplit('snell://'+address)
        raw.update(type='snell',server=server.hostname or '',server_port=server.port or 0,password=unquote(credentials.split(':',1)[-1]),snell_version=4 if q.get('version') in ('4','5') else 6,snell_mode=q.get('mode','default'),reuse=truth(q.get('reuse')),snell_obfs=q.get('obfs','none'),snell_host=q.get('obfs-host',''))
        return raw
    kinds={'socks':'socks','socks5':'socks','http':'http','https':'http','vless':'vless','trojan':'trojan','anytls':'anytls','hy2':'hysteria2','hysteria2':'hysteria2','tuic':'tuic'}
    if scheme not in kinds:raise ValueError('支持 SOCKS5、HTTP(S)、SS、VMess、VLESS、Trojan、AnyTLS、Hysteria2、TUIC 链接、Snell 链接')
    kind=kinds[scheme];raw.update(type=kind,server=u.hostname or '',server_port=u.port or (443 if scheme=='https' else 1080 if kind=='socks' else 0),tls_mode='tls' if scheme=='https' or kind in ('trojan','anytls','hysteria2','tuic') else q.get('security','none'),sni=q.get('sni') or q.get('peer',''),alpn=q.get('alpn',''),insecure=q.get('insecure',q.get('allowInsecure','0')) in ('1','true'),transport=q.get('type','tcp'),path=q.get('path','/'),transport_host=q.get('host',''),service_name=q.get('serviceName',''))
    username=unquote(u.username or '');password=unquote(u.password or '')
    if kind=='socks' and username and not password:
        try:
            decoded=decode64(username)
            if ':' in decoded:username,password=decoded.split(':',1)
        except ValueError:pass
    if kind in ('vless','tuic'):raw.update(uuid=username,password=password,flow=q.get('flow',''),public_key=q.get('pbk',''),short_id=q.get('sid',''),fingerprint=q.get('fp','chrome'))
    elif kind in ('socks','http'):raw.update(username=username,password=password)
    else:raw['password']=username+(':'+password if password else '')
    if kind=='hysteria2':raw.update(obfs=q.get('obfs','none'),obfs_password=q.get('obfs-password',''))
    return raw

def rule_input(raw,nodes,outbounds):
    target=text(raw,'target') or 'direct'
    if target not in ('direct','reject') and target not in {o['id'] for o in outbounds if o['enabled']}:raise ValueError('请选择已启用的出口')
    match={}
    for field in ('domain','domain_suffix','domain_keyword','ip_cidr','port','protocol'):
        items=fields(text(raw,field,8192))
        if len(items)>256:raise ValueError('单项最多 256 条')
        if field in ('domain','domain_suffix'):
            items=[host(x.lstrip('.')) for x in items]
        if field=='ip_cidr':
            try:items=[str(ipaddress.ip_network(x,strict=False)) for x in items]
            except ValueError:raise ValueError('IP / CIDR 格式无效')
        if field=='port':
            exact=[];ranges=[]
            for item in items:
                if item.isdigit() and 1<=int(item)<=65535:exact.append(int(item));continue
                m=re.fullmatch(r'(\d+)[-:](\d+)',item)
                if not m or not 1<=int(m[1])<=int(m[2])<=65535:raise ValueError('端口填写 443 或 1000-2000')
                ranges.append(m[1]+':'+m[2])
            if exact:match['port']=exact
            if ranges:match['port_range']=ranges
        elif items:
            if field=='protocol' and not set(items)<={'http','tls','quic','dns','bittorrent','ssh'}:raise ValueError('嗅探协议无效')
            match[field]=items
    for kind in ('geoip','geosite'):
        selected=raw.getlist(kind) if hasattr(raw,'getlist') else raw.get(kind,[])
        if isinstance(selected,str):selected=[selected] if selected else []
        if len(selected)>64 or not set(selected)<=set(GEO_CATALOG[kind]):raise ValueError('请选择有效的 '+kind+' 规则，最多 64 项')
        if selected:match[kind]=list(dict.fromkeys(selected))
    network=text(raw,'network')
    if network not in ('','tcp','udp'):raise ValueError('网络类型无效')
    if network:match['network']=network
    node_ids=raw.getlist('node_ids') if hasattr(raw,'getlist') else raw.get('node_ids',[])
    if isinstance(node_ids,str):node_ids=[node_ids]
    if not set(node_ids)<={n['id'] for n in nodes}:raise ValueError('来源节点不存在')
    if truth(raw.get('ip_is_private')):match['ip_is_private']=True
    if not match and not node_ids and not truth(raw.get('match_all')):raise ValueError('至少填写一个条件，或明确勾选匹配全部流量')
    name=text(raw,'name',80)
    if not name:raise ValueError('请输入规则名称')
    return dict(name=name,target=target,match=match,node_ids=list(dict.fromkeys(node_ids)))

def compile_into(document,settings):
    outs=[o for o in settings['outbounds'] if o['enabled']]
    ids={o['id'] for o in outs}
    if settings['final'] not in ids|{'direct'}:raise ValueError('默认出口不可用')
    document['outbounds'].extend({**copy.deepcopy(o['settings']),'tag':'up-'+o['id']} for o in outs)
    rules=[];sets={}
    if settings.get('sniff'):rules.append({'action':'sniff','timeout':'300ms'})
    for rule in settings['rules']:
        if not rule['enabled']:continue
        match=copy.deepcopy(rule['match'])
        if rule.get('node_ids'):
            tags=[i['tag'] for i in document['inbounds'] if i['tag'].split(':',1)[0] in rule['node_ids']]
            if not tags:continue
            match['inbound']=tags
        if match.get('protocol') and not settings.get('sniff'):raise ValueError('使用协议条件时请开启协议嗅探')
        geo=[]
        for kind in ('geosite','geoip'):
            selected=match.pop(kind,[])
            if selected:
                tags=[]
                for value in selected:
                    if value not in GEO_CATALOG[kind]:raise ValueError('无效规则集：'+kind+':'+value)
                    tag=kind+'-'+value;tags.append(tag)
                    sets[tag]={'type':'remote','tag':tag,'format':'binary','url':'https://raw.githubusercontent.com/SagerNet/sing-'+kind+'/rule-set/'+tag+'.srs','http_client':{'detour':'direct'},'update_interval':'24h'}
                geo.append({'rule_set':tags})
        if geo:
            parts=([match] if match else [])+geo
            match=parts[0] if len(parts)==1 else {'type':'logical','mode':'and','rules':parts}
        target=rule['target']
        if target not in ids|{'direct','reject'}:raise ValueError('规则引用了不可用出口')
        if match.get('protocol') and not settings.get('sniff'):raise ValueError('使用协议条件时请开启协议嗅探')
        rules.append({**match,'action':'reject'} if target=='reject' else {**match,'action':'route','outbound':'direct' if target=='direct' else 'up-'+target})
    document['route']={'rules':rules,'final':'direct' if settings['final']=='direct' else 'up-'+settings['final']}
    if sets:
        document['route']['rule_set']=list(sets.values())
        document.setdefault('experimental',{}).setdefault('cache_file',{})['enabled']=True
    return document

def prepare_rule_sets(document,directory,binary):
    """Seed remote rules before applying; a failed download never changes routing."""
    import os,subprocess,tempfile
    from urllib.request import urlopen
    set_rule_paths(document,directory)
    directory=Path(directory)/'rule-sets';directory.mkdir(mode=0o700,exist_ok=True)
    for entry in document.get('route',{}).get('rule_set',[]):
        destination=directory/(entry['tag']+'.srs')
        entry['initial_path']=str(destination)
        if destination.exists():continue
        temporary=None
        try:
            with urlopen(entry['url'],timeout=15) as response:
                data=response.read(32*1024*1024+1)
            if len(data)>32*1024*1024:raise ValueError('规则集文件过大')
            with tempfile.NamedTemporaryFile(dir=directory,delete=False) as f:
                temporary=Path(f.name);f.write(data)
            result=subprocess.run([binary,'rule-set','decompile',str(temporary),'-o',os.devnull],capture_output=True,timeout=15)
            if result.returncode:raise ValueError('规则集格式校验失败')
            temporary.replace(destination)
        except Exception as exc:raise ValueError('无法加载规则集 '+entry['tag']+'，设置未保存，请稍后重试') from exc
        finally:
            if temporary and temporary.exists():temporary.unlink()

def set_rule_paths(document,directory):
    entries=document.get('route',{}).get('rule_set',[])
    if entries:
        document['experimental']['cache_file']['path']=str(Path(directory)/'routing-cache.db')
        for entry in entries:entry['initial_path']=str(Path(directory)/'rule-sets'/(entry['tag']+'.srs'))
    return document
