import hmac
import json
import os
import re
import secrets
import sqlite3
import ssl
import subprocess
import time
import tempfile
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from urllib.parse import urlencode, quote

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from .paths import EntryPaths
from .assets import asset_url, asset_is_versioned
from .sharing import share_context, read_settings, save_settings, qr_image, Monitor
from starlette.middleware.sessions import SessionMiddleware
from starlette.concurrency import run_in_threadpool
from .core import init_db, connect, records, reason, PROTOCOLS, set_memberships, random_port, port_available, rotate_ports
from .runtime import Runtime
from .backups import Manager as BackupManager
from .subscriptions import outbounds
from .customer_auth import require_customer as user_authenticated
from .protocols import SS_CLASSIC, SS_2022, new_key, validate_key
from .options import NodeOptions, PRESETS, FINGERPRINTS, options, domain, import_key, probe_tls
from pydantic import ValidationError

DIRECTORY = Path(os.environ.get('PANEL_DATA', 'data')).resolve()
DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
DIRECTORY.chmod(0o700)
AUTH = DIRECTORY / 'auth.json'
DB = DIRECTORY / 'panel.db'
BINARY = os.environ.get('SING_BOX', 'sing-box')
STATS_PORT = int(os.environ.get('PANEL_STATS_PORT', '19090'))
PUBLIC_HOST = os.environ.get('PANEL_PUBLIC_HOST', '')
init_db(DB)
runtime = Runtime(BINARY, DIRECTORY, STATS_PORT)
backup_manager = BackupManager(DB,DIRECTORY)
ph = PasswordHasher()
templates = Jinja2Templates(directory=str(Path(__file__).parent / 'templates'))
templates.env.globals['asset_url'] = asset_url
templates.env.filters['bytes'] = lambda n: f'{n / 1024**3:.2f} GiB'
templates.env.filters['traffic_bytes'] = lambda n: f'{n / 1024**3:.2f} GiB' if n>=1024**3 else f'{n / 1024**2:.2f} MiB' if n>=1024**2 else f'{n / 1024:.2f} KiB' if n>=1024 else f'{n} B'
templates.env.filters['datetime'] = lambda n: datetime.fromtimestamp(n,timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC') if n else '暂无'
attempts = {}

@asynccontextmanager
async def lifespan(app):
    if not AUTH.exists():
        raise RuntimeError('Run python -m panel.setup to create administrator credentials first')
    routing_publisher.recover()
    runtime.start()
    routing_publisher.start()
    monitor.start()
    backup_manager.start()
    yield
    await fleet_shutdown()
    backup_manager.stop()
    routing_publisher.stop()
    monitor.stop()
    runtime.stop()

# Startup fails without setup; no default credentials.
auth = json.loads(AUTH.read_text()) if AUTH.exists() else {}
app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
monitor = Monitor(DB)
app.mount('/static', StaticFiles(directory=str(Path(__file__).parent / 'static')), name='static')
app.add_middleware(SessionMiddleware, secret_key=auth.get('session_key', secrets.token_hex(32)),
                   max_age=3600*8, same_site='strict',
                   https_only=os.environ.get('PANEL_SECURE_COOKIE', '0') == '1')

app.add_middleware(EntryPaths, db=DB)

@app.middleware('http')
async def headers(request, call_next):
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    if request.url.path.startswith('/static/') and request.method in ('GET','HEAD'):
        # Static files are public and must not refresh or cache an admin session.
        if 'set-cookie' in response.headers:del response.headers['set-cookie']
        versioned=await run_in_threadpool(asset_is_versioned,request.url.path,request.query_params.get('v'))
        if response.status_code in (200,304) and versioned:
            response.headers['Cache-Control'] = 'public, max-age=31536000, immutable'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'inline-speculation-rules'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    return response

@app.exception_handler(HTTPException)
async def http_error(request: Request, error: HTTPException):
    from fastapi.exception_handlers import http_exception_handler
    if error.status_code == 401 and error.detail == '用户面板需要登录':
        browser = ('text/html' in request.headers.get('accept', '') or
                   request.headers.get('sec-fetch-dest') == 'document')
        if request.method in ('GET', 'HEAD') and browser:
            return RedirectResponse(error.headers['X-Customer-Login'], status_code=303)
    if error.status_code == 401 and error.detail == '请先登录':
        browser = ('text/html' in request.headers.get('accept', '') or
                   request.headers.get('sec-fetch-dest') == 'document' or
                   request.headers.get('x-panel-navigation') == '1')
        if request.method in ('GET', 'HEAD') and browser:
            return RedirectResponse('/login?expired=1', status_code=303)
    response = await http_exception_handler(request, error)
    if response.headers.get('content-type', '').startswith('application/json'):
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
    return response

def authenticated(request):
    if not request.session.get('admin') or request.session.get('auth_revision',0)!=auth.get('revision',0):
        request.session.clear()
        raise HTTPException(401, '请先登录')

def csrf(request, token):
    expected = request.session.get('csrf', '')
    if (not isinstance(expected,str) or not expected or not isinstance(token,str) or len(token)>256
            or not hmac.compare_digest(expected.encode('utf-8'),token.encode('utf-8'))):
        raise HTTPException(403, '页面已过期，请刷新后重试')

def render(request, name, **context):
    request.session.setdefault('csrf', secrets.token_urlsafe(32))
    settings=read_settings(DB)
    return templates.TemplateResponse(request=request, name=name,
        context={'csrf': request.session['csrf'], 'branding':settings, 'admin_path':settings['admin_path'], 'share_path':settings['share_path'], **context})

@app.get('/login', response_class=HTMLResponse)
def login_page(request: Request):
    return render(request, 'login.html', notice='登录状态已失效，请重新登录' if request.query_params.get('expired') == '1' else '')

@app.post('/login')
def login(request: Request, password: str = Form(...), token: str = Form(...), username: str = Form('')):
    csrf(request, token)
    ip = request.client.host
    now = time.monotonic()
    for key in list(attempts):
        attempts[key] = [t for t in attempts[key] if now-t < 300]
        if not attempts[key]:
            del attempts[key]
    if len(attempts.get(ip, [])) >= 10:
        raise HTTPException(429, '请五分钟后重试')
    attempts.setdefault(ip, []).append(now)
    username = username.strip()
    expected_username = auth.get('username', 'admin')
    username_matches = (0 < len(username) <= 64 and isinstance(expected_username, str)
                        and hmac.compare_digest(username.encode('utf-8'), expected_username.encode('utf-8')))
    password_matches = False
    try:
        if len(password) <= 1024:
            password_matches = ph.verify(auth['password_hash'], password)
    except (VerificationError, KeyError):
        pass
    if not username_matches or not password_matches:
        return render(request, 'login.html', error='账号或密码不正确', login_username=username[:64])
    attempts.pop(ip, None)
    request.session.clear()
    request.session.update(admin=True, csrf=secrets.token_urlsafe(32),auth_revision=auth.get('revision',0))
    return RedirectResponse('/', status_code=303)

@app.post('/logout')
def logout(request: Request, token: str = Form(...)):
    csrf(request, token)
    request.session.clear()
    return RedirectResponse('/login', status_code=303)

@app.get('/', response_class=HTMLResponse)
def dashboard(request: Request):
    if not request.session.get('admin'):
        return RedirectResponse('/login', status_code=303)
    authenticated(request)
    users = records(DB, 'users')
    nodes = records(DB, 'nodes')
    memberships = records(DB, 'memberships')
    for u in users:
        u['state'] = reason(u)
        u['node_ids'] = [m['node_id'] for m in memberships if m['user_id']==u['id']]
        u['expires_text'] = datetime.fromtimestamp(u['expires'], timezone.utc).strftime('%Y-%m-%d') if u['expires'] else ''
    period=request.query_params.get('period','7d')
    if period not in ('24h','7d','30d'):period='7d'
    now=datetime.now(timezone.utc)
    hourly=period=='24h';count=24 if hourly else 7 if period=='7d' else 30
    dates=[now-timedelta(hours=i) if hourly else now-timedelta(days=i) for i in reversed(range(count))]
    keys=[d.strftime('%Y-%m-%dT%H:00' if hourly else '%Y-%m-%d') for d in dates]
    with connect(DB) as db:
        if hourly:
            rows=db.execute('SELECT hour,SUM(upload+download) FROM node_hourly WHERE hour>=? AND hour<=? GROUP BY hour',(keys[0],keys[-1])).fetchall()
        else:
            rows=db.execute('SELECT day,SUM(upload+download) FROM daily WHERE day>=? AND day<=? GROUP BY day',(keys[0],keys[-1])).fetchall()
        today_total=db.execute('SELECT COALESCE(SUM(upload+download),0) FROM daily WHERE day=?',(now.strftime('%Y-%m-%d'),)).fetchone()[0]
    totals=dict(rows)
    daily=[{'day':key,'label':key[11:16] if hourly else key[5:],'total':totals.get(key,0)} for key in keys]
    maximum=max((d['total'] for d in daily),default=0) or 1
    for d in daily:d['height']=max(1,d['total']/maximum*100) if d['total'] else 0
    from .machine import snapshot
    machine=snapshot(DIRECTORY)
    return render(request, 'dashboard.html', period=period,today_total=today_total, machine=machine, online=len(runtime.online), connections=len(runtime.connections), running=bool(runtime.process and runtime.process.poll() is None), users=users, nodes=nodes, daily=daily,
                  error=runtime.error, total=sum(u['upload']+u['download'] for u in users),
                  active=sum(not u['state'] for u in users), host=PUBLIC_HOST,
                  share_base=read_settings(DB)['public_url'] or str(request.base_url).rstrip('/'))


@app.get('/system/metrics')
def machine_metrics(request:Request):
    authenticated(request)
    from .machine import snapshot
    return {**snapshot(DIRECTORY),'online':len(runtime.online),'connections':len(runtime.connections),'running':bool(runtime.process and runtime.process.poll() is None)}

def validate_limits(quota_gib, expiry):
    if not 0 <= quota_gib <= 1_000_000:
        raise HTTPException(422, '额度必须介于 0 和 1,000,000 GiB')
    try:
        expires = int(datetime.strptime(expiry, '%Y-%m-%d').replace(tzinfo=timezone.utc).timestamp()) if expiry else 0
    except ValueError:
        raise HTTPException(422, '日期格式应为 YYYY-MM-DD')
    return int(quota_gib * 1024**3), expires

def valid_name(name):
    name=name.strip()
    if not name or len(name)>80:
        raise HTTPException(422,'名称需要 1–80 个字符')
    return name

def server_choices():
    from .fleet import list_servers
    return [{'id':'local','name':'主面板本机','host':PUBLIC_HOST}]+[
        {'id':s['id'],'name':s['name'],'host':s['host']} for s in list_servers(DB) if s['enabled']]

def editor(request, node=None, values=None, error='', notice='', status=200):
    context={'name':'','protocol':'snell6','port':'','mode':'compat','server_name':'','server_id':'local',
             **NodeOptions().model_dump()}
    if node:
        context.update(node)
        context.update(options(node))
    if values:
        context.update(values)
    # Never echo imported keys or PSKs into responses.
    context.pop('private_key',None)
    context.pop('psk',None)
    context.pop('ss_server_key',None)
    response=render(request,'node_editor.html',node=node,values=context,error=error,notice=notice,
                    presets=PRESETS,fingerprints=FINGERPRINTS,ss_methods=SS_2022 if context['protocol']=='ss2022' else SS_CLASSIC,servers=server_choices())
    response.status_code=status
    return response

@app.get('/nodes/new',response_class=HTMLResponse)
def new_node(request: Request, protocol: str='snell6', server_id: str='local'):
    authenticated(request)
    if protocol not in PROTOCOLS:
        raise HTTPException(422,'协议无效')
    if server_id not in {s['id'] for s in server_choices()}:
        raise HTTPException(422,'请选择可用的服务器')
    values={'protocol':protocol,'server_name':'www.cloudflare.com' if protocol=='reality' else '', 'server_id':server_id}
    if protocol=='ss2022':values.update(ss_method=SS_2022[0],mode='shared')
    if protocol in ('hysteria2','anytls','trojan') and (DIRECTORY/'tls/fullchain.pem').exists():
        from urllib.parse import urlsplit
        values.update(certificate_path=str(DIRECTORY/'tls/fullchain.pem'),key_path=str(DIRECTORY/'tls/privkey.pem'),server_name=urlsplit(read_settings(DB)['public_url']).hostname or '')
    return editor(request,values=values)

@app.get('/nodes/{identity}/edit',response_class=HTMLResponse)
def edit_node(request: Request,identity: str):
    authenticated(request)
    node=next((n for n in records(DB,'nodes') if n['id']==identity),None)
    if not node:raise HTTPException(404)
    return editor(request,node)

def check_document(document):
    with tempfile.NamedTemporaryFile(mode='w',suffix='.json',dir=DIRECTORY) as f:
        json.dump(document,f);f.flush()
        check=subprocess.run([BINARY,'check','-c',f.name],capture_output=True,text=True,timeout=15)
    if check.returncode:raise ValueError('核心配置校验失败：'+check.stderr[-1200:])

async def save_node(request,identity=None):
    authenticated(request)
    raw=dict(await request.form())
    return await run_in_threadpool(save_node_sync,request,raw,identity)

def save_node_sync(request,raw,identity=None):
    authenticated(request)
    csrf(request,str(raw.get('token','')))
    node=next((n for n in records(DB,'nodes') if n['id']==identity),None) if identity else None
    if identity and not node:raise HTTPException(404)
    try:
        server_id=str(raw.get('server_id',node.get('server_id','local') if node else 'local'))
        if node and server_id != node.get('server_id','local'):
            raise ValueError('已有节点不能直接迁移服务器，请在目标服务器新建节点')
        if server_id not in {s['id'] for s in server_choices()}:
            raise ValueError('请选择已启用的服务器')
        protocol=node['protocol'] if node else str(raw.get('protocol','snell6'))
        if protocol not in PROTOCOLS:raise ValueError('协议无效')
        defaults={'ss_method':options(node)['ss_method'] if node else SS_2022[0] if protocol=='ss2022' else SS_CLASSIC[2]}
        settings=NodeOptions.model_validate({**defaults,**raw})
        mode='shared' if protocol in ('reality','hysteria2','anytls','trojan') else 'compat' if protocol=='ss' else str(raw.get('mode','shared' if protocol=='ss2022' else 'compat'))
        if mode not in ('shared','compat'):raise ValueError('用户模式无效')
        if protocol in ('ss','ss2022'):
            if settings.ss_method not in (SS_CLASSIC if protocol=='ss' else SS_2022):raise ValueError('加密方式与节点协议不匹配')
            if protocol=='ss2022' and mode=='shared' and settings.ss_method==SS_2022[2]:raise ValueError('ChaCha20 SS2022 请使用独立端口模式')
        sni=domain(str(raw.get('server_name',''))) if protocol in ('reality','hysteria2','anytls','trojan') else ''
        if protocol in ('hysteria2','anytls','trojan'):
            if not settings.certificate_path or not settings.key_path:raise ValueError('请填写证书链与私钥文件路径')
            certificate_check=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            certificate_check.load_cert_chain(settings.certificate_path,settings.key_path)
            for args in [('-checkend','0'),('-checkhost',sni)]:
                result=subprocess.run(['openssl','x509','-in',settings.certificate_path,'-noout',*args],capture_output=True,text=True,timeout=10)
                if result.returncode:raise ValueError('证书已过期或未覆盖该 SNI 域名')
            if protocol=='hysteria2' and settings.tls_min_version!='1.3':raise ValueError('Hysteria2 使用 TLS 1.3')
            if protocol=='hysteria2' and settings.tls_alpn and settings.tls_alpn!='h3':raise ValueError('Hysteria2 ALPN 请留空或填写 h3')
        if raw.get('intent')=='probe':
            if protocol!='reality':raise ValueError('只有 Reality 节点需要 TLS 握手检测')
            result=probe_tls(settings.handshake_host or sni,settings.handshake_port,sni)
            authenticated(request)
            return editor(request,node,raw,notice=result)
        name=valid_name(str(raw.get('name','')))
        with connect(DB) as db:
            port=int(raw['port']) if str(raw.get('port','')).strip() else (node['port'] if node else random_port(db,(STATS_PORT,STATS_PORT+1,18889)))
        if not 1024<=port<=65535 or port in (STATS_PORT,STATS_PORT+1,18889,19190,19191):
            raise ValueError('节点端口须为 1024–65535，且不能占用面板或统计 API 端口')
        if protocol=='snell6' and settings.snell_mode=='unsafe-raw' and raw.get('acknowledge_raw')!='1':
            raise ValueError('unsafe-raw 不加密；请明确勾选风险确认，或使用 default / unshaped')
        candidate=dict(node) if node else {'id':uuid.uuid4().hex,'enabled':1,'private_key':'',
            'public_key':'','short_id':secrets.token_hex(8),'secret':secrets.token_urlsafe(24)}
        if protocol=='ss2022':
            supplied=str(raw.get('ss_server_key','')).strip()
            if supplied:candidate['secret']=validate_key(supplied,settings.ss_method)
            elif not node or options(node)['ss_method']!=settings.ss_method or raw.get('rotate_ss_key')=='1':candidate['secret']=new_key(settings.ss_method)
        supplied_psk=str(raw.get('psk','')).strip()
        if supplied_psk:
            if not re.fullmatch(r'[A-Za-z0-9._~-]{12,255}',supplied_psk):
                raise ValueError('PSK 需为 12–255 个字母、数字或 . _ ~ - 字符')
            candidate['secret']=supplied_psk
        if protocol=='reality':
            imported=str(raw.get('private_key','')).strip()
            if imported:
                candidate['private_key'],candidate['public_key']=import_key(imported)
            elif not candidate['private_key'] or raw.get('rotate_key')=='1':
                keys=subprocess.run([BINARY,'generate','reality-keypair'],check=True,
                    capture_output=True,text=True,timeout=10).stdout
                candidate['private_key']=re.search(r'PrivateKey:\s*(\S+)',keys)[1]
                candidate['public_key']=re.search(r'PublicKey:\s*(\S+)',keys)[1]
        group_name=str(raw.get('group_name','')).strip();comment=str(raw.get('comment','')).strip()
        if len(group_name)>60 or len(comment)>500:raise ValueError('分组最多 60 字，备注最多 500 字')
        candidate.update(server_id=server_id,group_name=group_name,comment=comment,name=name,protocol=protocol,port=port,mode=mode,server_name=sni,
                         options=json.dumps(settings.model_dump()))
        # Check a populated inbound, including nodes that currently have no users.
        from .core import config
        test_user={'id':'validation','enabled':1,'quota':0,'expires':0,'upload':0,'download':0,
                   'secret':'validation-user-key-012345','uuid':'11111111-1111-4111-8111-111111111111'}
        document=config([candidate],[test_user],[{'node_id':candidate['id'],'user_id':'validation','port':port}],STATS_PORT)
        check_document(document)
        with runtime.lock, connect(DB) as db:
            authenticated(request)
            csrf(request,str(raw.get('token','')))
            db.execute('BEGIN IMMEDIATE')
            current=db.execute('SELECT * FROM nodes WHERE id=?',(identity,)).fetchone() if identity else None
            if node and (not current or any(current[key]!=node[key] for key in current.keys())):
                raise HTTPException(409,'节点已被修改，请刷新后重试')
            if server_id!='local' and not db.execute('SELECT 1 FROM servers WHERE id=? AND enabled=1',(server_id,)).fetchone():
                raise HTTPException(409,'服务器状态已变更，请刷新后重试')
            if server_id=='local' and (not node or port != node['port']) and not port_available(port):
                raise ValueError('该端口已被系统中的服务占用')
            grants=db.execute('SELECT count(*) FROM memberships WHERE node_id=?',(candidate['id'],)).fetchone()[0]
            if node and grants and (mode!=node['mode'] or (node['mode']=='compat' and port!=node['port'])):
                raise ValueError('节点已有用户：请先撤销授权，再更改用户模式或独立端口')
            if db.execute('SELECT 1 FROM nodes WHERE port=? AND id<>?',(port,candidate['id'])).fetchone():
                raise ValueError('该端口已用于其他节点')
            if db.execute('SELECT 1 FROM memberships WHERE port=? AND node_id<>?',(port,candidate['id'])).fetchone():
                raise ValueError('该端口已分配给其他节点的用户')
            fields=('name','protocol','port','secret','private_key','public_key','short_id','server_name','mode','options','group_name','comment','server_id')
            if node:
                db.execute('UPDATE nodes SET '+','.join(k+'=?' for k in fields)+' WHERE id=?',
                           tuple(candidate[k] for k in fields)+(candidate['id'],))
            else:
                db.execute('INSERT INTO nodes(id,'+','.join(fields)+') VALUES('+','.join('?' for _ in range(len(fields)+1))+')',
                           (candidate['id'],)+tuple(candidate[k] for k in fields))
        return RedirectResponse('/nodes',status_code=303)
    except (OSError, ssl.SSLError) as e:
        return editor(request,node,raw,error='证书不可读取或证书与私钥不匹配：'+str(e),status=422)
    except ValidationError as e:
        error='；'.join('.'.join(map(str,x['loc']))+': '+x['msg'] for x in e.errors())
    except (ValueError,subprocess.SubprocessError) as e:
        error=str(e)
    return editor(request,node,raw,error=error,status=422)

@app.post('/nodes')
async def create_node(request: Request):
    return await save_node(request)

@app.post('/nodes/{identity}/edit')
async def update_node(request: Request,identity: str):
    return await save_node(request,identity)

@app.post('/users')
def create_user(request: Request, token: str = Form(...), name: str = Form(...),
                quota_gib: float = Form(0), expiry: str = Form(''), node_ids: list[str] = Form([])):
    authenticated(request)
    csrf(request,token)
    quota,expires=validate_limits(quota_gib,expiry)
    with runtime.lock, connect(DB) as db:
        existing={r[0] for r in db.execute('SELECT id FROM nodes')}
        if not set(node_ids)<=existing:
            raise HTTPException(422,'节点不存在')
        uid=uuid.uuid4().hex
        db.execute('INSERT INTO users(id,name,secret,uuid,token,quota,expires) VALUES(?,?,?,?,?,?,?)',
                   (uid,valid_name(name),secrets.token_urlsafe(24),str(uuid.uuid4()),secrets.token_urlsafe(32),quota,expires))
        set_memberships(db,uid,node_ids,(STATS_PORT,STATS_PORT+1,18889))
    return RedirectResponse('/',status_code=303)

@app.post('/{kind}/{identity}/action')
def action(request: Request, kind: str, identity: str, token: str = Form(...), action: str = Form(...),
           quota_gib: float = Form(0), expiry: str = Form(''), node_ids: list[str] = Form([])):
    authenticated(request)
    csrf(request,token)
    if kind not in ('nodes','users'):
        raise HTTPException(404)
    with runtime.lock:
        if kind=='users' and action=='reset':
            try:
                runtime.sample()
            except Exception:
                raise HTTPException(503,'统计暂不可用，请恢复后再重置')
        with connect(DB) as db:
            db.execute('BEGIN IMMEDIATE')
            if not db.execute(f'SELECT 1 FROM {kind} WHERE id=?',(identity,)).fetchone():
                raise HTTPException(404)
            if kind=='nodes' and action=='randomize':
                try:
                    rotate_ports(db,identity,(STATS_PORT,STATS_PORT+1,18889))
                except ValueError as e:
                    raise HTTPException(422,str(e))
            elif action=='toggle':
                db.execute(f'UPDATE {kind} SET enabled=1-enabled WHERE id=?',(identity,))
            elif action=='delete':
                db.execute(f'DELETE FROM {kind} WHERE id=?',(identity,))
            elif kind=='users' and action=='reset':
                db.execute('UPDATE users SET upload=0,download=0 WHERE id=?',(identity,))
                db.execute('INSERT OR REPLACE INTO user_accounting_windows VALUES(?,?)',(identity,int(time.time())))
            elif kind=='users' and action=='rotate':
                db.execute('UPDATE users SET token=? WHERE id=?',(secrets.token_urlsafe(32),identity))
            elif kind=='users' and action=='limits':
                quota,expires=validate_limits(quota_gib,expiry)
                if not set(node_ids)<={r[0] for r in db.execute('SELECT id FROM nodes')}:
                    raise HTTPException(422,'节点不存在')
                db.execute('UPDATE users SET quota=?,expires=? WHERE id=?',(quota,expires,identity))
                set_memberships(db,identity,node_ids,(STATS_PORT,STATS_PORT+1,18889))
            else:
                raise HTTPException(422)
    return RedirectResponse('/',status_code=303)

def subscription_user(token):
    with connect(DB) as db:
        row=db.execute('SELECT * FROM users WHERE token=?',(token,)).fetchone()
    if not row:
        raise HTTPException(404)
    return dict(row)

@app.get('/settings', response_class=HTMLResponse)
def settings_page(request: Request):
    authenticated(request)
    return render(request,'settings.html',settings=read_settings(DB))

@app.post('/settings')
async def settings_save(request: Request):
    authenticated(request)
    raw=dict(await request.form())
    csrf(request,str(raw.get('token','')))
    return await run_in_threadpool(settings_save_sync,request,raw)

def settings_save_sync(request,raw):
    authenticated(request)
    csrf(request,str(raw.get('token','')))
    try:
        with runtime.lock:
            authenticated(request)
            csrf(request,str(raw.get('token','')))
            save_settings(DB,raw)
    except ValueError as e:
        return render(request,'settings.html',settings=raw,error=str(e))
    return RedirectResponse('/settings',status_code=303)

@app.get('/s/{token}', response_class=HTMLResponse)
def customer(request: Request, token: str, changed: bool=False, period: str="7d"):
    from .client_profiles import detect_client
    requested = request.query_params.get('format')
    detected = detect_client(request.headers.get('user-agent', ''))
    if requested or detected:
        return subscription(request, token, requested or detected)
    user=user_authenticated(request,token,DB)
    context=share_context(DB,user,PUBLIC_HOST,read_settings(DB)['public_url'] or str(request.base_url).rstrip('/'))
    from .traffic import traffic_view
    context['traffic']=traffic_view(DB,user['id'],context['nodes'],period)
    from .client_profiles import client_imports
    context['client_imports']=client_imports(context['share_url'],user['name'])
    response = render(request,'customer.html',**context,status=reason(user),subtoken=token,changed=changed,customer_authenticated=True)
    response.headers['Vary'] = 'User-Agent'
    return response

@app.get('/s/{token}/traffic', response_class=HTMLResponse)
def customer_traffic(request: Request, token: str, period: str='7d'):
    user=user_authenticated(request,token,DB)
    from .traffic import traffic_view
    with connect(DB) as db:
        nodes=[dict(r) for r in db.execute('SELECT n.id,n.name FROM nodes n JOIN memberships m ON m.node_id=n.id WHERE m.user_id=?',(user['id'],))]
        today=datetime.now(timezone.utc).strftime('%Y-%m-%d')
        usage=db.execute('SELECT upload,download,upload+download total FROM daily WHERE user_id=? AND day=?',(user['id'],today)).fetchone()
    return render(request,'customer_traffic.html',traffic=traffic_view(DB,user['id'],nodes,period),
                  today_usage=dict(usage) if usage else {'upload':0,'download':0,'total':0},subtoken=token)

@app.get('/s/{token}/qr/{kind}')
def customer_qr(request: Request, token: str, kind: str):
    user=user_authenticated(request,token,DB)
    settings=read_settings(DB)
    base=settings['public_url'] or str(request.base_url).rstrip('/')
    if kind in ('page','subscription'):
        text=base+settings['share_path']+'/'+token
    else:
        context=share_context(DB,user,PUBLIC_HOST,base)
        node=next((n for n in context['nodes'] if n['id']==kind),None)
        if not node or not node['uri']:raise HTTPException(404)
        text=node['uri']
    return Response(qr_image(text),media_type='image/svg+xml')

@app.post('/s/{token}/psk')
def customer_psk(request: Request, token: str, csrf_token: str=Form(...), psk: str=Form('')):
    user=user_authenticated(request,token,DB)
    csrf(request,csrf_token)
    if reason(user):raise HTTPException(403,'当前订阅已停用，无法修改密码')
    psk=psk.strip() or secrets.token_urlsafe(24)
    if not re.fullmatch(r'[A-Za-z0-9._~-]{12,255}',psk):
        raise HTTPException(422,'密码须为 12–255 个字母、数字或 . _ ~ - 字符')
    with runtime.lock, connect(DB) as db:
        # Token rotation, account changes and traffic accounting share this
        # lock. Revalidate after waiting so an already revoked link cannot
        # leave a new credential behind.
        user=user_authenticated(request,token,DB)
        if reason(user):raise HTTPException(403,'当前订阅已停用，无法修改密码')
        db.execute('BEGIN IMMEDIATE')
        key='psk_changed:'+user['id']
        last=db.execute('SELECT value FROM settings WHERE key=?',(key,)).fetchone()
        if last and time.time()-float(last[0])<20:raise HTTPException(429,'请 20 秒后再修改密码')
        db.execute('UPDATE users SET secret=? WHERE id=?',(psk,user['id']))
        db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',(key,str(time.time())))
    return RedirectResponse('/s/'+token+'?changed=true',status_code=303)

# Customer subpages must precede the legacy one-segment subscription format.
import sys
from .routing_publish import Publisher
from .customer_routing import install as install_customer_routing
routing_publisher = Publisher(sys.modules[__name__])
install_customer_routing(app, sys.modules[__name__])
from .customer_auth import install as install_customer_auth
install_customer_auth(app, sys.modules[__name__])

@app.get('/s/{token}/{format}')
def subscription(request: Request, token: str, format: str):
    from .diagnostics import record
    user=subscription_user(token)
    started=time.monotonic()
    try:
        response=subscription_response(request,token,format)
    except HTTPException as error:
        record(DB,user['id'],request.headers.get('user-agent',''),format,error.status_code,0,started)
        raise
    except Exception:
        record(DB,user['id'],request.headers.get('user-agent',''),format,500,0,started)
        raise
    record(DB,user['id'],request.headers.get('user-agent',''),response.headers.get('X-Subscription-Format',''),response.status_code,int(response.headers.get('X-Subscription-Node-Count',0)),started)
    return response

def subscription_response(request: Request, token: str, format: str):
    from .client_profiles import resolve_format, singbox_profile, mihomo_profile, ini_profile
    from .subscriptions import native_subscription
    import base64
    user=subscription_user(token)
    try:
        fmt=resolve_format(request.query_params.get('format') or format, request.headers.get('user-agent',''))
    except ValueError as error:
        raise HTTPException(400, str(error))
    if not PUBLIC_HOST:
        raise HTTPException(503,'尚未设置 PANEL_PUBLIC_HOST')
    outs=outbounds(user,records(DB,'nodes'),records(DB,'memberships'),PUBLIC_HOST)
    settings=read_settings(DB)
    base=settings['public_url'] or str(request.base_url).rstrip('/')
    page_url=base+settings['share_path']+'/'+token
    url=page_url
    info=f"upload={user['upload']}; download={user['download']}; total={user['quota']}; expire={user['expires']}"
    headers={'Subscription-Userinfo':info, 'Vary':'User-Agent',
             'Profile-Update-Interval':'6', 'Profile-Web-Page-Url':page_url,
             'Profile-Title':'base64:'+base64.b64encode((settings['brand']+' · '+user['name']).encode()).decode(),
             'Content-Disposition':f'attachment; filename="{fmt}"',
             'X-Subscription-Format':fmt}
    media='text/plain'
    try:
        if fmt=='sing-box.json':
            body,count=singbox_profile(outs,url,request.headers.get('user-agent',''))
            media='application/json'
        elif fmt=='clash.yaml':
            body,count=mihomo_profile(outs,url)
            media='application/yaml'
        elif fmt in ('surge.conf','surfboard.conf'):
            body,count=ini_profile(outs,fmt,url,user)
        else:
            body=native_subscription(outs,fmt)
            count=sum(bool(line.strip()) for line in base64.b64decode(body).decode().splitlines())
            if not reason(user) and user.get('external_cache'):
                body=base64.b64encode((base64.b64decode(body).decode()+user['external_cache']+'\n').encode()).decode()
        headers['X-Subscription-Node-Count']=str(count)
    except ValueError as error:
        raise HTTPException(422,str(error))
    return Response(body,media_type=media,headers=headers)

@app.get('/health')
def health():
    running=runtime.process is not None and runtime.process.poll() is None
    return Response(json.dumps({'ok':running and not runtime.error}),media_type='application/json',
                    status_code=200 if running and not runtime.error else 503)

from .admin import install
import sys
install(app,sys.modules[__name__])

from .routing_admin import install as install_routing
install_routing(app,sys.modules[__name__])

from .fleet_api import install as install_fleet
from .fleet_config import configuration as fleet_configuration
install_fleet(app,sys.modules[__name__])
from .agent_downloads import install as install_agent_downloads
install_agent_downloads(app,sys.modules[__name__])
from .backups import install as install_backups
install_backups(app,sys.modules[__name__])

from .diagnostics import install as install_diagnostics
install_diagnostics(app,sys.modules[__name__])
