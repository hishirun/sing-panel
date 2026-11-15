"""Administrator account/password checks must not weaken existing sessions."""
import html
from html.parser import HTMLParser
import json
import re

from fastapi.testclient import TestClient
import pytest

from test_app import client, csrf

PASSWORD = 'test-password-only'
GENERIC_ERROR = '账号或密码不正确'


class Markup(HTMLParser):
    def __init__(self, body):
        super().__init__()
        self.elements = []
        self.feed(body)
    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, dict(attrs)))


def login_token(browser):
    response = browser.get('/login')
    assert response.status_code == 200
    return html.unescape(re.search(r'name="token"[^>]*value="([^"]+)"', response.text)[1])


def sign_in(browser, username='admin', password=PASSWORD, supplied=True):
    fields = {'token': login_token(browser), 'password': password}
    if supplied:
        fields['username'] = username
    return browser.post('/login', data=fields, follow_redirects=False)


def configure_username(app, username):
    app.auth['username'] = username
    app.AUTH.write_text(json.dumps(app.auth))


def test_legacy_auth_without_username_requires_default_admin(client):
    browser, app = client
    assert 'username' not in app.auth
    browser.cookies.clear()
    assert sign_in(browser, 'not-admin').status_code != 303
    assert browser.get('/users').status_code == 401
    response = sign_in(browser)
    assert response.status_code == 303 and response.headers['location'] == '/'
    assert browser.get('/users').status_code == 200


@pytest.mark.parametrize('username', ['operator', '管理员', '管理者🐾'])
def test_configured_username_works_and_legacy_default_is_not_an_alias(client, username):
    browser, app = client
    configure_username(app, username)
    browser.cookies.clear()
    denied = sign_in(browser, 'admin')
    assert GENERIC_ERROR in denied.text and denied.status_code != 303
    assert sign_in(browser, username).status_code == 303
    assert browser.get('/users').status_code == 200


@pytest.mark.parametrize('username,password,supplied', [
    ('wrong-account', PASSWORD, True), ('', PASSWORD, True), ('unused', PASSWORD, False),
    ('   ', PASSWORD, True), ('admin', 'wrong-password-only', True),
    ('wrong-account', 'wrong-password-only', True), ('x' * 65, PASSWORD, True),
    ('admin\0', PASSWORD, True), ('ad\nmin', PASSWORD, True),
])
def test_failed_credentials_are_generic_and_do_not_grant_admin(client, username, password, supplied):
    browser, app = client
    browser.cookies.clear()
    response = sign_in(browser, username, password, supplied)
    assert response.status_code != 303 and response.status_code < 500
    assert GENERIC_ERROR in response.text
    assert password not in response.text
    assert browser.get('/users').status_code == 401


@pytest.mark.parametrize('username', ['"><img src=x onerror=alert(1)>', '<script>alert(1)</script>', '未知管理员'])
def test_rejected_username_redisplay_is_escaped(client, username):
    browser, app = client
    browser.cookies.clear()
    response = sign_in(browser, username)
    assert response.status_code < 500 and GENERIC_ERROR in response.text
    elements = Markup(response.text).elements
    inputs = [attrs for tag, attrs in elements if tag == 'input' and attrs.get('name') == 'username']
    assert len(inputs) == 1 and inputs[0].get('value') == username
    assert not any('onerror' in attrs or 'onload' in attrs for _, attrs in elements)
    assert not any(tag == 'img' and attrs.get('src') == 'x' for tag, attrs in elements)
    if '<' in username:
        assert username not in response.text


def test_admin_login_csrf_is_checked_before_credentials_and_attempt_count(client):
    browser, app = client
    browser.cookies.clear()
    token = login_token(browser)
    response = browser.post('/login', data={'username': 'admin', 'password': PASSWORD, 'token': 'invalid'})
    assert response.status_code == 403 and not app.attempts
    response = browser.post('/login', data={'username': 'admin', 'password': PASSWORD, 'token': token}, follow_redirects=False)
    assert response.status_code == 303 and not app.attempts


def test_wrong_username_consumes_existing_rate_limit_even_with_correct_password(client):
    browser, app = client
    browser.cookies.clear()
    token = login_token(browser)
    for _ in range(10):
        response = browser.post('/login', data={'username': 'wrong-account', 'password': PASSWORD, 'token': token})
        assert GENERIC_ERROR in response.text and response.status_code != 303
    response = browser.post('/login', data={'username': 'admin', 'password': PASSWORD, 'token': token}, follow_redirects=False)
    assert response.status_code == 429
    assert browser.get('/users').status_code == 401


@pytest.mark.parametrize('explicit_username', [None, 'operator'])
def test_admin_password_change_preserves_account_and_revokes_old_revision(client, explicit_username):
    browser, app = client
    if explicit_username:
        configure_username(app, explicit_username)
    username = explicit_username or 'admin'
    browser.cookies.clear()
    assert sign_in(browser, username).status_code == 303
    previous_revision = app.auth.get('revision', 0)
    previous_session = browser.cookies.get('session')
    new_password = 'replacement-admin-password-only'
    changed = browser.post('/system/password', data={'token': csrf(browser),
                           'current_password': PASSWORD, 'new_password': new_password})
    assert changed.status_code == 200
    stored = json.loads(app.AUTH.read_text())
    assert stored.get('username', 'admin') == username
    assert stored['revision'] == previous_revision + 1
    assert app.ph.verify(stored['password_hash'], new_password)
    assert new_password not in app.AUTH.read_text()
    assert browser.get('/users').status_code == 200
    stale = TestClient(app.app)
    stale.cookies.set('session', previous_session)
    assert stale.get('/users').status_code == 401
    stale.close()
    browser.cookies.clear()
    denied = sign_in(browser, username, PASSWORD)
    assert GENERIC_ERROR in denied.text and denied.status_code != 303
    assert sign_in(browser, username, new_password).status_code == 303


@pytest.mark.parametrize('previous,entered,expected', [
    (None, '', 'admin'), ({'session_key': 'legacy-session'}, '', 'admin'),
    ({'username': 'existing-operator', 'session_key': 'prior-session'}, '', 'existing-operator'),
    (None, ' new.operator@example ', 'new.operator@example'),
])
def test_setup_default_and_existing_account_preservation(tmp_path, monkeypatch, previous, entered, expected):
    from panel import setup
    monkeypatch.setenv('PANEL_DATA', str(tmp_path))
    path = tmp_path / 'auth.json'
    if previous is not None:
        path.write_text(json.dumps(previous))
    monkeypatch.setattr('builtins.input', lambda prompt: entered)
    monkeypatch.setattr(setup.getpass, 'getpass', lambda prompt: 'new-local-admin-password')
    setup.main()
    stored = json.loads(path.read_text())
    assert stored['username'] == expected
    assert setup.PasswordHasher().verify(stored['password_hash'], 'new-local-admin-password')
    assert 'new-local-admin-password' not in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600
    if previous and 'session_key' in previous:
        assert stored['session_key'] != previous['session_key']


@pytest.mark.parametrize('username', ['a' * 65, 'operator/path', '管理员', 'operator\nname'])
def test_setup_invalid_account_preserves_existing_credentials(tmp_path, monkeypatch, username):
    from panel import setup
    monkeypatch.setenv('PANEL_DATA', str(tmp_path))
    path = tmp_path / 'auth.json'
    before = json.dumps({'username': 'existing', 'session_key': 'existing-session', 'password_hash': 'existing-hash'})
    path.write_text(before)
    monkeypatch.setattr('builtins.input', lambda prompt: username)
    monkeypatch.setattr(setup.getpass, 'getpass', lambda prompt: pytest.fail('Invalid account reached password entry'))
    with pytest.raises(SystemExit):
        setup.main()
    assert path.read_text() == before
