"""User portal passwords, separate from proxy credentials and subscriptions."""
import hashlib
import hmac
import secrets
import threading
import time
from collections import OrderedDict, deque
from contextlib import contextmanager

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool
from starlette.formparsers import MultiPartException
from starlette.responses import JSONResponse, RedirectResponse

from .core import connect
from .sharing import read_settings

SESSION_KEY = 'customer_auth'
SESSION_SECONDS = 8 * 3600
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
_crypto_slots = threading.BoundedSemaphore(2)


def migrate(db):
    db.execute('''CREATE TABLE IF NOT EXISTS user_auth (
        user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        password_hash TEXT NOT NULL DEFAULT '', auth_revision INTEGER NOT NULL DEFAULT 0,
        session_epoch TEXT NOT NULL, updated_at INTEGER NOT NULL DEFAULT 0)''')


def status(path, user_id):
    with connect(path) as db:
        row = db.execute('SELECT password_hash,updated_at FROM user_auth WHERE user_id=?', (user_id,)).fetchone()
    return {'password_set': bool(row and row['password_hash']), 'updated_at': row['updated_at'] if row else 0}


def validate_password(password):
    try:
        valid = isinstance(password, str) and 10 <= len(password) <= 128 and len(password.encode('utf-8')) <= 512
    except UnicodeError:
        valid = False
    if not valid or not password.strip() or '\x00' in password:
        raise HTTPException(422, '密码须为 10–128 个字符')
    return password


@contextmanager
def _crypto():
    if not _crypto_slots.acquire(blocking=False):
        raise HTTPException(429, '正在处理其他登录请求，请稍后重试', headers={'Retry-After':'2'})
    try:
        yield
    finally:
        _crypto_slots.release()


def _hash(password):
    validate_password(password)
    with _crypto():
        return _hasher.hash(password)


def _verify(encoded, password):
    validate_password(password)
    with _crypto():
        try:
            return _hasher.verify(encoded, password)
        except (VerificationError, InvalidHashError):
            return False


def _read(db, token):
    if not isinstance(token, str) or not 1 <= len(token) <= 256:
        raise HTTPException(404, '订阅不存在')
    user = db.execute('SELECT * FROM users WHERE token=?', (token,)).fetchone()
    if not user:
        raise HTTPException(404, '订阅不存在')
    auth = db.execute('SELECT * FROM user_auth WHERE user_id=?', (user['id'],)).fetchone()
    return dict(user), dict(auth) if auth else None


def _token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _session(user, auth):
    return {'user_id':user['id'], 'token_hash':_token_hash(user['token']),
            'revision':auth['auth_revision'], 'epoch':auth['session_epoch'],
            'expires_at':int(time.time()) + SESSION_SECONDS}


def _valid(session, user, auth):
    if not isinstance(session, dict) or not auth or not auth['password_hash']:
        return False
    return (session.get('user_id') == user['id']
            and session.get('revision') == auth['auth_revision']
            and session.get('epoch') == auth['session_epoch']
            and session.get('token_hash') == _token_hash(user['token'])
            and type(session.get('expires_at')) is int and session['expires_at'] > time.time())


def require_customer(request, token, path):
    with connect(path) as db:
        user, auth = _read(db, token)
    if not _valid(request.session.get(SESSION_KEY), user, auth):
        request.session.pop(SESSION_KEY, None)
        destination = '/s/' + token + ('/login' if auth and auth['password_hash'] else '/setup')
        raise HTTPException(401, '用户面板需要登录', headers={'X-Customer-Login':destination})
    return user


def authenticated(request, token, path):
    try:
        require_customer(request, token, path)
        return True
    except HTTPException as error:
        if error.status_code in (401, 404):
            return False
        raise


def setup_password(path, token, password):
    encoded = _hash(password)
    with connect(path) as db:
        db.execute('BEGIN IMMEDIATE')
        user, auth = _read(db, token)
        if auth and auth['password_hash']:
            raise HTTPException(409, '密码已设置，请使用密码登录')
        if auth is None:
            db.execute('INSERT INTO user_auth(user_id,session_epoch) VALUES(?,?)', (user['id'], secrets.token_hex(32)))
        changed = db.execute('''UPDATE user_auth SET password_hash=?,auth_revision=auth_revision+1,updated_at=?
                                WHERE user_id=? AND password_hash='' ''', (encoded, int(time.time()), user['id']))
        if changed.rowcount != 1:
            raise HTTPException(409, '密码已设置，请使用密码登录')
        auth = dict(db.execute('SELECT * FROM user_auth WHERE user_id=?', (user['id'],)).fetchone())
        return _session(user, auth)


def login_password(path, token, password):
    with connect(path) as db:
        user, auth = _read(db, token)
    if not auth or not auth['password_hash']:
        raise HTTPException(409, '请先设置登录密码')
    if not _verify(auth['password_hash'], password):
        raise HTTPException(401, '密码不正确')
    with connect(path) as db:
        db.execute('BEGIN IMMEDIATE')
        fresh_user, fresh = _read(db, token)
        if fresh_user['id'] != user['id'] or fresh != auth:
            raise HTTPException(409, '密码已更新，请重新登录')
        return _session(fresh_user, fresh)


def change_password(path, token, session, current_password, password):
    with connect(path) as db:
        user, auth = _read(db, token)
    if not _valid(session, user, auth):
        raise HTTPException(401, '用户面板需要登录', headers={'X-Customer-Login':'/s/' + token + '/login'})
    if not _verify(auth['password_hash'], current_password):
        raise HTTPException(401, '当前密码不正确')
    encoded = _hash(password)
    with connect(path) as db:
        db.execute('BEGIN IMMEDIATE')
        fresh_user, fresh = _read(db, token)
        if not _valid(session, fresh_user, fresh) or fresh != auth:
            raise HTTPException(409, '登录状态已变化，请重新登录')
        db.execute('UPDATE user_auth SET password_hash=?,auth_revision=auth_revision+1,updated_at=? WHERE user_id=?',
                   (encoded, int(time.time()), user['id']))
        fresh = dict(db.execute('SELECT * FROM user_auth WHERE user_id=?', (user['id'],)).fetchone())
        return _session(fresh_user, fresh)


def reset_password(path, user_id, authorize=None):
    """Trusted administrator action. Plaintext exists only in this return value."""
    password = secrets.token_urlsafe(24)
    encoded = _hash(password)
    with connect(path) as db:
        db.execute('BEGIN IMMEDIATE')
        if authorize:
            authorize()
        user = db.execute('SELECT name FROM users WHERE id=?', (user_id,)).fetchone()
        if not user:
            raise HTTPException(404, '用户不存在')
        db.execute('INSERT OR IGNORE INTO user_auth(user_id,session_epoch) VALUES(?,?)', (user_id, secrets.token_hex(32)))
        db.execute('UPDATE user_auth SET password_hash=?,auth_revision=auth_revision+1,updated_at=? WHERE user_id=?',
                   (encoded, int(time.time()), user_id))
        from .management import audit
        audit(db, '重置用户面板密码', user['name'])
    return password


def logout_customer(path, token, session):
    with connect(path) as db:
        db.execute('BEGIN IMMEDIATE')
        user, auth = _read(db, token)
        if not _valid(session, user, auth):
            raise HTTPException(401, '用户面板需要登录', headers={'X-Customer-Login':'/s/' + token + '/login'})
        # Signed-cookie deletion alone cannot revoke a copied cookie.
        db.execute('UPDATE user_auth SET auth_revision=auth_revision+1 WHERE user_id=?', (user['id'],))


class RateLimiter:
    """Bounded process-local abuse protection; never trust raw proxy headers."""
    def __init__(self, maximum=4096, clock=time.monotonic):
        self.maximum, self.clock = maximum, clock
        self.events = OrderedDict()
        self.lock = threading.Lock()

    def check(self, ip, user_id):
        now = self.clock()
        limits = (('global', 180), ('ip:' + str(ip)[:200], 30), ('user:' + str(user_id)[:128], 10))
        with self.lock:
            for key in list(self.events):
                values = self.events[key]
                while values and now-values[0] >= 300:
                    values.popleft()
                if not values:
                    del self.events[key]
            for key, maximum in limits:
                if len(self.events.get(key, ())) >= maximum:
                    raise HTTPException(429, '尝试次数过多，请五分钟后重试', headers={'Retry-After':'300'})
            needed = sum(key not in self.events for key, _ in limits)
            if len(self.events) + needed > self.maximum:
                raise HTTPException(429, '登录请求过多，请稍后重试', headers={'Retry-After':'300'})
            for key, _ in limits:
                self.events.setdefault(key, deque()).append(now)


def _csrf(request, supplied):
    expected = request.session.get('csrf', '')
    if (not isinstance(supplied, str) or len(supplied) > 256 or not isinstance(expected, str) or not expected
            or not hmac.compare_digest(expected.encode('utf-8'), supplied.encode('utf-8'))):
        raise HTTPException(403, '页面已过期，请刷新后重试')


async def _form(request):
    contents = bytearray()
    async for chunk in request.stream():
        contents.extend(chunk)
        if len(contents) > 8192:
            raise HTTPException(413, '提交内容过大')
    async def receive():
        return {'type':'http.request', 'body':bytes(contents), 'more_body':False}
    try:
        parsed = await Request(request.scope, receive).form(max_files=0, max_fields=8, max_part_size=2048)
    except MultiPartException:
        # Starlette only converts parser failures to HTTP errors when the
        # request scope contains an app; isolated callers need the same guard.
        raise HTTPException(400, '表单格式无效') from None
    if len(parsed) > 8 or len(parsed.multi_items()) != len(parsed) or any(not isinstance(value, str) for value in parsed.values()):
        raise HTTPException(400, '表单格式无效')
    return parsed


def install(app, m):
    limiter = RateLimiter()

    def view(request, token, mode, error='', status_code=200, notice=''):
        with connect(m.DB) as db:
            user, _ = _read(db, token)
        request.session.setdefault('csrf', secrets.token_urlsafe(32))
        root = read_settings(m.DB)['share_path'] + '/' + token
        response = m.render(request, 'customer_auth.html', mode=mode, action=root + '/' + mode,
                            csrf_token=request.session['csrf'], user={'name':user['name']}, subtoken=token,
                            share_url=root, error=error, notice=notice, auth_enabled=True,
                            customer_authenticated=mode == 'password')
        response.status_code = status_code
        return response

    def grant(request, session):
        # Administrator access in another tab is independent of this identity.
        request.session[SESSION_KEY] = session
        request.session['csrf'] = secrets.token_urlsafe(32)

    def limit(request, user_id):
        limiter.check(request.client.host if request.client else '', user_id)

    def locked(function, *args):
        # Serialize session revocation with PSK/routing writes, which recheck
        # authorization while holding the same runtime lock.
        with m.runtime.lock:
            return function(*args)

    @app.get('/s/{token}/login')
    def login_page(request:Request, token:str):
        with connect(m.DB) as db:
            _, auth = _read(db, token)
        if not auth or not auth['password_hash']:
            return RedirectResponse('/s/' + token + '/setup', 303)
        if authenticated(request, token, m.DB):
            return RedirectResponse('/s/' + token, 303)
        return view(request, token, 'login')

    @app.get('/s/{token}/setup')
    def setup_page(request:Request, token:str):
        with connect(m.DB) as db:
            _, auth = _read(db, token)
        if auth and auth['password_hash']:
            return RedirectResponse('/s/' + token + '/login', 303)
        return view(request, token, 'setup')

    async def submit(request, token, mode):
        raw = await _form(request)
        _csrf(request, raw.get('csrf_token', ''))
        with connect(m.DB) as db:
            user, _ = _read(db, token)
        if mode == 'password':
            require_customer(request, token, m.DB)
        try:
            limit(request, user['id'])
            if mode != 'login' and raw.get('password') != raw.get('password_confirm'):
                raise HTTPException(422, '两次输入的密码不一致')
            if mode == 'setup':
                session = await run_in_threadpool(setup_password, m.DB, token, raw.get('password', ''))
            elif mode == 'login':
                session = await run_in_threadpool(login_password, m.DB, token, raw.get('password', ''))
            else:
                session = await run_in_threadpool(locked, change_password, m.DB, token, request.session.get(SESSION_KEY),
                                                  raw.get('current_password', ''), raw.get('password', ''))
        except HTTPException as error:
            if error.status_code not in (401, 409, 422, 429) or error.detail == '用户面板需要登录':
                raise
            response = view(request, token, mode, str(error.detail), error.status_code)
            if error.headers:
                response.headers.update(error.headers)
            return response
        grant(request, session)
        return RedirectResponse('/s/' + token, 303)

    @app.post('/s/{token}/login')
    async def login_submit(request:Request, token:str):
        return await submit(request, token, 'login')

    @app.post('/s/{token}/setup')
    async def setup_submit(request:Request, token:str):
        return await submit(request, token, 'setup')

    @app.get('/s/{token}/security')
    def security_page(request:Request, token:str):
        require_customer(request, token, m.DB)
        return view(request, token, 'password')

    @app.post('/s/{token}/password')
    async def password_submit(request:Request, token:str):
        return await submit(request, token, 'password')

    @app.post('/s/{token}/logout')
    async def logout_submit(request:Request, token:str):
        raw = await _form(request)
        _csrf(request, raw.get('csrf_token', ''))
        require_customer(request, token, m.DB)
        await run_in_threadpool(locked, logout_customer, m.DB, token, request.session.get(SESSION_KEY))
        request.session.pop(SESSION_KEY, None)
        request.session['csrf'] = secrets.token_urlsafe(32)
        return RedirectResponse('/s/' + token + '/login', 303)

    @app.post('/users/{identity}/portal-password')
    async def admin_reset(request:Request, identity:str):
        m.authenticated(request)
        raw = await _form(request)
        m.csrf(request, str(raw.get('token', '')))
        limit(request, 'admin-reset:' + identity)
        password = await run_in_threadpool(locked, reset_password, m.DB, identity, lambda:m.authenticated(request))
        return JSONResponse({'ok':True, 'password':password, 'password_set':True, 'message':'登录密码已重置'},
                            headers={'Cache-Control':'no-store','Pragma':'no-cache'})
