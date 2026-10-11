import hmac
import json
import os
import re
import secrets
import sqlite3
import subprocess
import time
import tempfile
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, quote

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from .core import init_db, connect, records, reason, PROTOCOLS, set_memberships, random_port, port_available, rotate_ports
from .runtime import Runtime
from .subscriptions import outbounds
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
ph = PasswordHasher()
templates = Jinja2Templates(directory=str(Path(__file__).parent / 'templates'))
templates.env.filters['bytes'] = lambda n: f'{n / 1024**3:.2f} GiB'
attempts = {}

@asynccontextmanager
async def lifespan(app):
    if not AUTH.exists():
        raise RuntimeError('Run python -m panel.setup to create administrator credentials first')
    runtime.start()
    yield
    runtime.stop()

# Startup fails without setup; no default credentials.
auth = json.loads(AUTH.read_text()) if AUTH.exists() else {}
app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(SessionMiddleware, secret_key=auth.get('session_key', secrets.token_hex(32)),
                   max_age=3600*8, same_site='strict',
                   https_only=os.environ.get('PANEL_SECURE_COOKIE', '0') == '1')

@app.middleware('http')
async def headers(request, call_next):
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    return response

def authenticated(request):
    if not request.session.get('admin'):
        raise HTTPException(401, '请先登录')

def csrf(request, token):
    expected = request.session.get('csrf', '')
    if not expected or not hmac.compare_digest(expected, token):
        raise HTTPException(403, '页面已过期，请刷新后重试')

def render(request, name, **context):
    request.session.setdefault('csrf', secrets.token_urlsafe(32))
    return templates.TemplateResponse(request=request, name=name,
        context={'csrf': request.session['csrf'], **context})

@app.get('/login', response_class=HTMLResponse)
def login_page(request: Request):
    return render(request, 'login.html')

@app.post('/login')
def login(request: Request, password: str = Form(...), token: str = Form(...)):
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
    try:
        ph.verify(auth['password_hash'], password)
    except (VerificationError, KeyError):
        return render(request, 'login.html', error='密码不正确')
    attempts.pop(ip, None)
    request.session.clear()
    request.session.update(admin=True, csrf=secrets.token_urlsafe(32))
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
    users = records(DB, 'users')
    nodes = records(DB, 'nodes')
    memberships = records(DB, 'memberships')
    for u in users:
        u['state'] = reason(u)
        u['node_ids'] = [m['node_id'] for m in memberships if m['user_id']==u['id']]
        u['expires_text'] = datetime.fromtimestamp(u['expires'], timezone.utc).strftime('%Y-%m-%d') if u['expires'] else ''
    with connect(DB) as db:
        daily = [dict(r) for r in db.execute('SELECT day,SUM(upload+download) total FROM daily GROUP BY day ORDER BY day DESC LIMIT 14')]
    return render(request, 'dashboard.html', users=users, nodes=nodes, daily=daily,
                  error=runtime.error, total=sum(u['upload']+u['download'] for u in users),
                  active=sum(not u['state'] for u in users), host=PUBLIC_HOST)

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

def editor(request, node=None, values=None, error='', notice='', status=200):
    context={'name':'','protocol':'snell6','port':'','mode':'compat','server_name':'',
             **NodeOptions().model_dump()}
    if node:
        context.update(node)
        context.update(options(node))
    if values:
        context.update(values)
    # Never echo imported keys or PSKs into responses.
    context.pop('private_key',None)
    context.pop('psk',None)
    response=render(request,'node_editor.html',node=node,values=context,error=error,notice=notice,
                    presets=PRESETS,fingerprints=FINGERPRINTS)
    response.status_code=status
    return response

@app.get('/nodes/new',response_class=HTMLResponse)
def new_node(request: Request, protocol: str='snell6'):
    authenticated(request)
    if protocol not in PROTOCOLS:
        raise HTTPException(422,'协议无效')
    return editor(request,values={'protocol':protocol,'server_name':'www.cloudflare.com' if protocol=='reality' else ''})

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
    csrf(request,str(raw.get('token','')))
    node=next((n for n in records(DB,'nodes') if n['id']==identity),None) if identity else None
    if identity and not node:raise HTTPException(404)
    try:
        protocol=node['protocol'] if node else str(raw.get('protocol','snell6'))
        if protocol not in PROTOCOLS:raise ValueError('协议无效')
        settings=NodeOptions.model_validate(raw)
        mode='shared' if protocol=='reality' else str(raw.get('mode','compat'))
        if mode not in ('shared','compat'):raise ValueError('用户模式无效')
        sni=domain(str(raw.get('server_name',''))) if protocol=='reality' else ''
        if raw.get('intent')=='probe':
            if protocol!='reality':raise ValueError('只有 Reality 节点需要 TLS 握手检测')
            result=probe_tls(settings.handshake_host or sni,settings.handshake_port,sni)
            return editor(request,node,raw,notice=result)
        name=valid_name(str(raw.get('name','')))
        with connect(DB) as db:
            port=int(raw['port']) if str(raw.get('port','')).strip() else (node['port'] if node else random_port(db,(STATS_PORT,18889)))
        if not 1024<=port<=65535 or port in (STATS_PORT,18889):
            raise ValueError('节点端口须为 1024–65535，且不能占用面板或统计 API 端口')
        if protocol=='snell6' and settings.snell_mode=='unsafe-raw' and raw.get('acknowledge_raw')!='1':
            raise ValueError('unsafe-raw 不加密；请明确勾选风险确认，或使用 default / unshaped')
        candidate=dict(node) if node else {'id':uuid.uuid4().hex,'enabled':1,'private_key':'',
            'public_key':'','short_id':secrets.token_hex(8),'secret':secrets.token_urlsafe(24)}
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
        candidate.update(name=name,protocol=protocol,port=port,mode=mode,server_name=sni,
                         options=json.dumps(settings.model_dump()))
        # Check a populated inbound, including nodes that currently have no users.
        from .core import config
        test_user={'id':'validation','enabled':1,'quota':0,'expires':0,'upload':0,'download':0,
                   'secret':'validation-user-key-012345','uuid':'11111111-1111-4111-8111-111111111111'}
        document=config([candidate],[test_user],[{'node_id':candidate['id'],'user_id':'validation','port':port}],STATS_PORT)
        check_document(document)
        with runtime.lock, connect(DB) as db:
            db.execute('BEGIN IMMEDIATE')
            if (not node or port != node['port']) and not port_available(port):
                raise ValueError('该端口已被系统中的服务占用')
            grants=db.execute('SELECT count(*) FROM memberships WHERE node_id=?',(candidate['id'],)).fetchone()[0]
            if node and grants and (mode!=node['mode'] or (node['mode']=='compat' and port!=node['port'])):
                raise ValueError('节点已有用户：请先撤销授权，再更改用户模式或独立端口')
            if db.execute('SELECT 1 FROM nodes WHERE port=? AND id<>?',(port,candidate['id'])).fetchone():
                raise ValueError('该端口已用于其他节点')
            if db.execute('SELECT 1 FROM memberships WHERE port=? AND node_id<>?',(port,candidate['id'])).fetchone():
                raise ValueError('该端口已分配给其他节点的用户')
            fields=('name','protocol','port','secret','private_key','public_key','short_id','server_name','mode','options')
            if node:
                db.execute('UPDATE nodes SET '+','.join(k+'=?' for k in fields)+' WHERE id=?',
                           tuple(candidate[k] for k in fields)+(candidate['id'],))
            else:
                db.execute('INSERT INTO nodes(id,'+','.join(fields)+') VALUES('+','.join('?' for _ in range(len(fields)+1))+')',
                           (candidate['id'],)+tuple(candidate[k] for k in fields))
        return RedirectResponse('/',status_code=303)
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
        set_memberships(db,uid,node_ids,(STATS_PORT,18889))
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
                    rotate_ports(db,identity,(STATS_PORT,18889))
                except ValueError as e:
                    raise HTTPException(422,str(e))
            elif action=='toggle':
                db.execute(f'UPDATE {kind} SET enabled=1-enabled WHERE id=?',(identity,))
            elif action=='delete':
                db.execute(f'DELETE FROM {kind} WHERE id=?',(identity,))
            elif kind=='users' and action=='reset':
                db.execute('UPDATE users SET upload=0,download=0 WHERE id=?',(identity,))
            elif kind=='users' and action=='rotate':
                db.execute('UPDATE users SET token=? WHERE id=?',(secrets.token_urlsafe(32),identity))
            elif kind=='users' and action=='limits':
                quota,expires=validate_limits(quota_gib,expiry)
                if not set(node_ids)<={r[0] for r in db.execute('SELECT id FROM nodes')}:
                    raise HTTPException(422,'节点不存在')
                db.execute('UPDATE users SET quota=?,expires=? WHERE id=?',(quota,expires,identity))
                set_memberships(db,identity,node_ids,(STATS_PORT,18889))
            else:
                raise HTTPException(422)
    return RedirectResponse('/',status_code=303)

def subscription_user(token):
    with connect(DB) as db:
        row=db.execute('SELECT * FROM users WHERE token=?',(token,)).fetchone()
    if not row:
        raise HTTPException(404)
    return dict(row)

@app.get('/s/{token}', response_class=HTMLResponse)
def customer(request: Request, token: str):
    user=subscription_user(token)
    nodes=[n for n in records(DB,'nodes') if any(m['user_id']==user['id'] and m['node_id']==n['id'] for m in records(DB,'memberships'))]
    return render(request,'customer.html',user=user,nodes=nodes,status=reason(user),subtoken=token)

@app.get('/s/{token}/{format}')
def subscription(token: str, format: str):
    user=subscription_user(token)
    if not PUBLIC_HOST:
        raise HTTPException(503,'尚未设置 PANEL_PUBLIC_HOST')
    outs=outbounds(user,records(DB,'nodes'),records(DB,'memberships'),PUBLIC_HOST)
    info=f"upload={user['upload']}; download={user['download']}; total={user['quota']}; expire={user['expires']}"
    headers={'Subscription-Userinfo':info}
    if format=='sing-box.json':
        headers['Content-Disposition']='attachment; filename="sing-box.json"'
        return Response(json.dumps({'outbounds':outs},indent=2),media_type='application/json',headers=headers)
    from .subscriptions import native_subscription
    if format not in ('surge.conf','shadowrocket.txt'):
        raise HTTPException(404)
    return Response(native_subscription(outs,format),media_type='text/plain',headers=headers)

@app.get('/health')
def health():
    running=runtime.process is not None and runtime.process.poll() is None
    return Response(json.dumps({'ok':running and not runtime.error}),media_type='application/json',
                    status_code=200 if running and not runtime.error else 503)
