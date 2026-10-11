import hmac
import json
import os
import re
import secrets
import sqlite3
import subprocess
import time
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
from .core import init_db, connect, records, reason, PROTOCOLS, set_memberships
from .runtime import Runtime
from .subscriptions import outbounds

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

@app.post('/nodes')
def create_node(request: Request, token: str = Form(...), name: str = Form(...),
                protocol: str = Form(...), port: int = Form(...), server_name: str = Form(''), mode: str = Form('compat')):
    authenticated(request)
    csrf(request, token)
    if protocol not in PROTOCOLS or not 1024<=port<=65535 or port==STATS_PORT:
        raise HTTPException(422,'协议或端口无效')
    name=valid_name(name)
    if mode not in ('shared','compat'):
        raise HTTPException(422,'用户模式无效')
    if protocol=='reality':
        mode='shared'
    private=public=short=''
    if protocol=='reality':
        if not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}',server_name):
            raise HTTPException(422,'Reality 需要有效的握手域名')
        keys=subprocess.run([BINARY,'generate','reality-keypair'],check=True,capture_output=True,text=True,timeout=10).stdout
        private=re.search(r'PrivateKey:\s*(\S+)',keys)[1]
        public=re.search(r'PublicKey:\s*(\S+)',keys)[1]
        short=secrets.token_hex(8)
    with runtime.lock:
        try:
            with connect(DB) as db:
                if db.execute('SELECT 1 FROM memberships WHERE port=?',(port,)).fetchone():
                    raise HTTPException(409,'端口已分配给用户')
                db.execute('INSERT INTO nodes(id,name,protocol,port,secret,private_key,public_key,short_id,server_name,mode) VALUES(?,?,?,?,?,?,?,?,?,?)',
                           (uuid.uuid4().hex,name,protocol,port,secrets.token_urlsafe(24),private,public,short,server_name,mode))
        except sqlite3.IntegrityError:
            raise HTTPException(409,'端口已存在')
    return RedirectResponse('/',status_code=303)

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
        set_memberships(db,uid,node_ids,(STATS_PORT,))
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
            if not db.execute(f'SELECT 1 FROM {kind} WHERE id=?',(identity,)).fetchone():
                raise HTTPException(404)
            if action=='toggle':
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
                set_memberships(db,identity,node_ids,(STATS_PORT,))
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
