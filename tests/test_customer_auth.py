"""Password ownership, atomic first setup and durable session revocation."""
import copy
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.formparsers import MultiPartException

from panel import customer_auth as auth
from panel.core import connect, init_db


PASSWORD = 'correct-portal-password'


@pytest.fixture
def database(tmp_path):
    path = tmp_path/'panel.db'
    init_db(path)
    with connect(path) as db:
        auth.migrate(db)
        db.execute("INSERT INTO users(id,name,secret,uuid,token) VALUES('u','Alice','proxy-secret','proxy-uuid','share-token')")
    return path


def request(session):
    return SimpleNamespace(session={auth.SESSION_KEY:copy.deepcopy(session)})


def test_setup_stores_only_argon2_and_preserves_proxy_credentials(database):
    with connect(database) as db:
        before = dict(db.execute("SELECT * FROM users WHERE id='u'").fetchone())
    session = auth.setup_password(database, 'share-token', PASSWORD)
    assert auth.require_customer(request(session), 'share-token', database)['id'] == 'u'
    assert auth.status(database, 'u')['password_set']
    with connect(database) as db:
        row = dict(db.execute("SELECT * FROM user_auth WHERE user_id='u'").fetchone())
        assert row['password_hash'].startswith('$argon2id$')
        assert auth._hasher.verify(row['password_hash'], PASSWORD)
        assert dict(db.execute("SELECT * FROM users WHERE id='u'").fetchone()) == before
        assert PASSWORD not in '\n'.join(db.iterdump())
    assert PASSWORD not in str(session) and 'password_hash' not in session


@pytest.mark.parametrize('password', ['short', 'x'*129, ' '*10, 'bad\0password', '\ud800'*10, None, 42])
def test_password_bounds(database, password):
    with pytest.raises(HTTPException) as error:
        auth.setup_password(database, 'share-token', password)
    assert error.value.status_code == 422
    assert not auth.status(database, 'u')['password_set']


def test_unicode_password_limits_are_explicit():
    assert auth.validate_password('🐾'*128) == '🐾'*128
    with pytest.raises(HTTPException):
        auth.validate_password('🐾'*129)


def test_concurrent_first_setup_has_one_winner(database, monkeypatch):
    barrier = threading.Barrier(2)
    original = auth._hash
    def hashing(password):
        encoded = original(password)
        barrier.wait(timeout=10)
        return encoded
    monkeypatch.setattr(auth, '_hash', hashing)
    def setup(password):
        try:return password, auth.setup_password(database, 'share-token', password)
        except HTTPException as error:return password, error.status_code
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(setup, ('first-password-123', 'second-password-456')))
    assert sorted(isinstance(value, dict) for _,value in results) == [False, True]
    assert next(value for _,value in results if not isinstance(value, dict)) == 409
    winning = next(password for password,value in results if isinstance(value, dict))
    with connect(database) as db:
        row = db.execute("SELECT * FROM user_auth WHERE user_id='u'").fetchone()
        assert row['auth_revision'] == 1
        assert auth._hasher.verify(row['password_hash'], winning)


def test_admin_reset_invalidates_old_cookie_and_setup_cannot_overwrite(database):
    old = auth.setup_password(database, 'share-token', PASSWORD)
    password = auth.reset_password(database, 'u')
    assert password != PASSWORD and len(password) >= 24
    with pytest.raises(HTTPException):auth.require_customer(request(old), 'share-token', database)
    with pytest.raises(HTTPException) as error:auth.setup_password(database, 'share-token', 'attacker-password')
    assert error.value.status_code == 409
    assert auth.login_password(database, 'share-token', password)['revision'] > old['revision']
    with connect(database) as db:
        assert password not in '\n'.join(db.iterdump())
        assert db.execute("SELECT secret FROM users WHERE id='u'").fetchone()[0] == 'proxy-secret'


def test_login_cannot_grant_session_after_concurrent_reset(database, monkeypatch):
    auth.setup_password(database, 'share-token', PASSWORD)
    original = auth._verify
    def verify(encoded, supplied):
        verified = original(encoded, supplied)
        auth.reset_password(database, 'u')
        return verified
    monkeypatch.setattr(auth, '_verify', verify)
    with pytest.raises(HTTPException) as error:auth.login_password(database, 'share-token', PASSWORD)
    assert error.value.status_code == 409


def test_password_change_does_not_overwrite_concurrent_reset(database, monkeypatch):
    session = auth.setup_password(database, 'share-token', PASSWORD)
    original = auth._hash
    reset = []
    def hashing(password):
        encoded = original(password)
        if password == 'replacement-password':reset.append(auth.reset_password(database, 'u'))
        return encoded
    monkeypatch.setattr(auth, '_hash', hashing)
    with pytest.raises(HTTPException) as error:
        auth.change_password(database, 'share-token', session, PASSWORD, 'replacement-password')
    assert error.value.status_code == 409
    assert auth.login_password(database, 'share-token', reset[0])


def test_change_and_logout_revoke_copied_cookies(database):
    old = auth.setup_password(database, 'share-token', PASSWORD)
    current = auth.change_password(database, 'share-token', old, PASSWORD, 'replacement-password')
    assert auth.authenticated(request(current), 'share-token', database)
    assert not auth.authenticated(request(old), 'share-token', database)
    auth.logout_customer(database, 'share-token', current)
    assert not auth.authenticated(request(current), 'share-token', database)
    assert auth.login_password(database, 'share-token', 'replacement-password')


def test_token_rotation_and_identity_recreation_do_not_revive_cookie(database):
    old = auth.setup_password(database, 'share-token', PASSWORD)
    with connect(database) as db:db.execute("UPDATE users SET token='new-token' WHERE id='u'")
    assert not auth.authenticated(request(old), 'new-token', database)
    with connect(database) as db:
        db.execute("DELETE FROM users WHERE id='u'")
        assert not db.execute('SELECT 1 FROM user_auth').fetchone()
        db.execute("INSERT INTO users(id,name,secret,uuid,token) VALUES('u','Alice','new-proxy','new-uuid','share-token')")
    recreated = auth.setup_password(database, 'share-token', PASSWORD)
    assert recreated['epoch'] != old['epoch']
    assert not auth.authenticated(request(old), 'share-token', database)
    assert auth.authenticated(request(recreated), 'share-token', database)


def test_expired_sessions_and_cross_user_are_rejected(database):
    session = auth.setup_password(database, 'share-token', PASSWORD)
    with connect(database) as db:
        db.execute("INSERT INTO users(id,name,secret,uuid,token) VALUES('v','Bob','other-proxy','other-uuid','other-token')")
    assert not auth.authenticated(request(session), 'other-token', database)
    session['expires_at'] = 1
    assert not auth.authenticated(request(session), 'share-token', database)


def test_reset_rechecks_admin_authorization_before_committing(database):
    auth.setup_password(database, 'share-token', PASSWORD)
    with connect(database) as db:before = dict(db.execute('SELECT * FROM user_auth').fetchone())
    def revoked():raise HTTPException(401, 'Admin revoked')
    with pytest.raises(HTTPException):auth.reset_password(database, 'u', revoked)
    with connect(database) as db:assert dict(db.execute('SELECT * FROM user_auth').fetchone()) == before


def test_rate_limit_per_user_ip_global_and_expiration():
    now = [0]
    limiter = auth.RateLimiter(clock=lambda:now[0])
    for _ in range(10):limiter.check('1', 'u')
    with pytest.raises(HTTPException) as error:limiter.check('2', 'u')
    assert error.value.status_code == 429
    now[0] = 301
    for index in range(30):limiter.check('1', str(index))
    with pytest.raises(HTTPException):limiter.check('1', 'other')
    limiter = auth.RateLimiter(clock=lambda:0)
    for index in range(180):limiter.check(str(index), str(index))
    with pytest.raises(HTTPException):limiter.check('overflow', 'overflow')
    assert len(limiter.events) == 361
    limiter = auth.RateLimiter(maximum=5, clock=lambda:0)
    limiter.check('1', '1');limiter.check('2', '2')
    with pytest.raises(HTTPException):limiter.check('3', '3')
    assert len(limiter.events) == 5


def test_csrf_constant_time_bytes_and_missing_token():
    req = SimpleNamespace(session={'csrf':'expected'})
    for bad in ('', 'wrong', '中文', 'x'*257):
        with pytest.raises(HTTPException) as error:auth._csrf(req, bad)
        assert error.value.status_code == 403
    auth._csrf(req, 'expected')


@pytest.mark.parametrize('contents,status', [
    ('&'.join('field'+str(index)+'=value' for index in range(9)), 400),
    ('password=first&password=second', 400),
    ('password='+'x'*8192, 413),
])
def test_form_field_count_duplicates_and_total_body_are_bounded(contents, status):
    async def receive():
        return {'type':'http.request','body':contents.encode(),'more_body':False}
    req = Request({'type':'http','method':'POST','headers':[(b'content-type',b'application/x-www-form-urlencoded')]}, receive)
    with pytest.raises(HTTPException) as error:asyncio.run(auth._form(req))
    assert error.value.status_code == status


def test_parser_exception_is_normalized_without_diagnostic_disclosure(monkeypatch):
    async def receive():
        return {'type':'http.request','body':b'field=value','more_body':False}
    async def rejected(*args, **kwargs):
        raise MultiPartException('internal parser diagnostic')
    monkeypatch.setattr(Request, 'form', rejected)
    req = Request({'type':'http','method':'POST','headers':[(b'content-type',b'application/x-www-form-urlencoded')]}, receive)
    with pytest.raises(HTTPException) as error:asyncio.run(auth._form(req))
    assert error.value.status_code == 400
    assert error.value.detail == '表单格式无效'
