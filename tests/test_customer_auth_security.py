"""Customer password gate boundaries through the complete routed ASGI app."""
import base64
import json

from fastapi.testclient import TestClient
import pytest

from customer_helpers import PASSWORD, customer_csrf, customer_login
from panel.core import connect
from panel import user_routing as ur
from panel import customer_auth
from panel.sharing import read_settings, save_settings
from test_app import client, csrf as admin_csrf


@pytest.fixture
def portal(client, monkeypatch):
    admin, app = client
    app.routing_publisher.stop()
    monkeypatch.setattr(app.runtime, 'apply', lambda: None)
    with connect(app.DB) as db:
        for identity in ('a', 'b'):
            db.execute('INSERT INTO users(id,name,secret,uuid,token) VALUES(?,?,?,?,?)',
                       (identity, 'Customer ' + identity, 'node-credential-' + identity,
                        'node-uuid-' + identity, 'capability-' + identity))
        db.execute("INSERT INTO nodes(id,name,protocol,port,secret,mode) VALUES('node','Private node','snell6',31991,'shared-node-key','shared')")
        db.execute("INSERT INTO memberships(user_id,node_id) VALUES('a','node')")
    ur.configure_user(app.DB, 'a', True, 6)
    customer = TestClient(app.app)
    yield admin, customer, app, '/s/capability-a'
    customer.close()


def decoded_session(client):
    value = client.cookies.get('session')
    if not value:
        return {}
    segment = value.split('.')[0]
    return json.loads(base64.b64decode(segment + '=' * (-len(segment) % 4)))


def test_first_setup_requires_csrf_and_never_echoes_password_or_accepts_oversized_form(portal):
    _, customer, app, root = portal
    page = customer.get(root + '/setup')
    token = customer_csrf(page)
    fields = {'password': PASSWORD, 'password_confirm': PASSWORD, 'csrf_token': 'bad'}
    assert customer.post(root + '/setup', data=fields).status_code == 403
    assert not customer_auth.status(app.DB, 'a')['password_set']
    fields.update(csrf_token=token, password_confirm='different-test-password')
    mismatch = customer.post(root + '/setup', data=fields)
    assert mismatch.status_code == 422 and PASSWORD not in mismatch.text
    assert 'different-test-password' not in mismatch.text
    oversized = customer.post(root + '/setup', content='password=' + 'x' * 9000,
                              headers={'Content-Type': 'application/x-www-form-urlencoded'})
    assert oversized.status_code == 413
    too_many_fields = customer.post(root + '/setup', data={
        'csrf_token': token, 'password': PASSWORD, 'password_confirm': PASSWORD,
        **{'unused' + str(index): 'x' for index in range(6)},
    })
    assert too_many_fields.status_code == 400
    assert not customer_auth.status(app.DB, 'a')['password_set']


@pytest.mark.parametrize('action', ['password', 'logout'])
def test_customer_security_mutations_require_the_authenticated_session_csrf(portal, action):
    _, customer, app, root = portal
    customer_login(customer, root)
    fields = {'csrf_token': 'bad', 'current_password': PASSWORD,
              'password': 'new-test-customer-password', 'password_confirm': 'new-test-customer-password'}
    response = customer.post(root + '/' + action, data=fields)
    assert response.status_code == 403
    assert customer.get(root + '/routing/api').status_code == 200
    assert app.records(app.DB, 'users')[0]['secret'] == 'node-credential-a'


@pytest.mark.parametrize('suffix', [
    '', '/routing', '/routing/api', '/routing/catalog', '/qr/page',
    '/qr/subscription', '/qr/node', '/security',
])
def test_all_interactive_get_routes_require_login_even_with_client_ua_or_format(portal, suffix):
    _, customer, app, root = portal
    response = customer.get(root + suffix, params={'format': 'sing-box.json'} if suffix else {},
                            headers={'User-Agent': 'Surge/4000' if suffix else 'Mozilla/5.0',
                                     'Accept': 'application/json'}, follow_redirects=False)
    assert response.status_code == 401, (suffix, response.text)
    assert 'node-credential-a' not in response.text and 'shared-node-key' not in response.text
    assert not decoded_session(customer).get('customer_auth')


@pytest.mark.parametrize('suffix', ['/routing/draft', '/routing/discard', '/routing/apply',
                                    '/routing/preview', '/routing/latency/unknown', '/psk'])
def test_public_login_csrf_does_not_authorize_customer_writes(portal, suffix):
    _, customer, app, root = portal
    page = customer.get(root + '/login')
    token = customer_csrf(page)
    if suffix == '/psk':
        response = customer.post(root + suffix, data={'csrf_token': token, 'psk': 'attacker-known-credential'})
    else:
        response = customer.post(root + suffix, json={'csrf': token, 'revision': 0,
                                 'document': {'enabled': True, 'rules': []},
                                 'destination': 'example.com', 'node_id': 'node'},
                                 headers={'User-Agent': 'sing-box/1.14.3'})
    assert response.status_code == 401
    assert app.records(app.DB, 'users')[0]['secret'] == 'node-credential-a'
    assert ur.get_policy(app.DB, 'a')['revision'] == 0


def test_raw_exports_remain_subscription_bearers_without_creating_page_session(portal):
    _, customer, app, root = portal
    for suffix, ua in [('/sing-box.json', 'Mozilla/5.0'), ('?format=sing-box.json', 'Mozilla/5.0'),
                       ('', 'sing-box/1.14.3'), ('/subscription', 'sing-box/1.14.3')]:
        response = customer.get(root + suffix, headers={'User-Agent': ua})
        assert response.status_code == 200 and response.headers['X-Subscription-Format'] == 'sing-box.json'
        assert 'node-credential-a' in response.text
        assert not decoded_session(customer).get('customer_auth')
    assert customer.get(root + '/routing/api').status_code == 401
    assert customer.get(root + '/qr/node').status_code == 401


def test_customer_session_is_bound_to_one_user_and_cannot_authorize_admin(portal):
    _, customer, app, root = portal
    customer_login(customer, root)
    assert customer.get(root + '/routing/api').status_code == 200
    assert customer.get('/s/capability-b/routing/api').status_code == 401
    assert customer.get('/users', headers={'Accept': 'application/json'}).status_code == 401
    assert PASSWORD not in json.dumps(decoded_session(customer))


def test_login_password_change_does_not_change_node_psk_uuid_or_subscription_token(portal):
    _, customer, app, root = portal
    token = customer_login(customer, root)
    before = app.records(app.DB, 'users')[0]
    old_session = customer.cookies.get('session')
    changed = customer.post(root + '/password', data={'csrf_token': token, 'current_password': PASSWORD,
                            'password': 'new-customer-password-only', 'password_confirm': 'new-customer-password-only'})
    assert changed.status_code == 200, changed.text
    after = app.records(app.DB, 'users')[0]
    assert {key: before[key] for key in ('secret', 'uuid', 'token')} == {key: after[key] for key in ('secret', 'uuid', 'token')}
    old = TestClient(app.app)
    old.cookies.set('session', old_session)
    assert old.get(root + '/routing/api').status_code == 401
    old.close()
    assert customer.get(root + '/sing-box.json').status_code == 200


def test_admin_reset_is_one_response_only_and_revokes_copied_sessions(portal):
    admin, customer, app, root = portal
    customer_login(customer, root)
    old_session = customer.cookies.get('session')
    endpoint = '/users/a/portal-password'
    assert admin.post(endpoint, data={'token': 'bad'}).status_code == 403
    result = admin.post(endpoint, data={'token': admin_csrf(admin)})
    assert result.status_code == 200
    generated = result.json()['password']
    assert len(generated) >= 24 and result.headers['Cache-Control'] == 'no-store'
    assert generated not in json.dumps(decoded_session(admin))
    assert generated not in json.dumps(dict(result.headers))
    assert admin.get(endpoint).status_code == 405
    assert generated not in admin.get('/users/a/edit').text
    with connect(app.DB) as db:
        assert generated not in json.dumps([tuple(row) for row in db.execute('SELECT * FROM user_auth')])
        assert generated not in json.dumps([tuple(row) for row in db.execute('SELECT * FROM audit_log')])
    stale = TestClient(app.app)
    stale.cookies.set('session', old_session)
    assert stale.get(root + '/routing/api').status_code == 401
    stale.close()
    customer_login(customer, root, generated)
    assert customer.get(root + '/routing/api').status_code == 200
    assert app.records(app.DB, 'users')[0]['secret'] == 'node-credential-a'


def test_customer_logout_revokes_replayed_cookie_and_raw_subscription_survives(portal):
    _, customer, app, root = portal
    token = customer_login(customer, root)
    old_session = customer.cookies.get('session')
    response = customer.post(root + '/logout', data={'csrf_token': token}, follow_redirects=False)
    assert response.status_code == 303
    stale = TestClient(app.app)
    stale.cookies.set('session', old_session)
    assert stale.get(root + '/routing/api').status_code == 401
    assert stale.get(root + '/sing-box.json').status_code == 200
    stale.close()


def test_configured_entry_paths_map_customer_login_without_exposing_legacy_routes(portal):
    _, customer, app, _ = portal
    settings = read_settings(app.DB)
    settings.update(admin_path='/manage-hidden', share_path='/customer-hidden')
    save_settings(app.DB, settings)
    root = '/customer-hidden/capability-a'
    response = customer.get(root, headers={'Accept': 'text/html'}, follow_redirects=False)
    assert response.status_code == 303
    assert response.headers['location'].startswith(root + '/')
    api = customer.get(root + '/routing/api')
    assert api.status_code == 401
    assert api.headers['X-Customer-Login'].startswith(root + '/')
    assert '/manage-hidden' not in api.headers['X-Customer-Login']
    assert customer.get('/s/capability-a/login').status_code == 404
    assert customer.get('/manage-hidden/s/capability-a/login').status_code == 404
    customer_login(customer, root)
    assert customer.get(root + '/routing/api').status_code == 200


@pytest.mark.parametrize('action', ['psk', 'draft', 'discard', 'apply'])
def test_password_reset_while_waiting_for_runtime_lock_revokes_pending_write(portal, monkeypatch, action):
    _, customer, app, root = portal
    token = customer_login(customer, root)
    before = ur.save_draft(app.DB, 'a', {'enabled': True, 'rules': []}, 0)
    original_lock = app.runtime.lock
    class ResetBeforeWrite:
        changed = False
        def __enter__(self):
            original_lock.acquire()
            if not self.changed:
                self.changed = True
                with connect(app.DB) as db:
                    db.execute("UPDATE user_auth SET auth_revision=auth_revision+1 WHERE user_id='a'")
            return self
        def __exit__(self, *args):
            original_lock.release()
    monkeypatch.setattr(app.runtime, 'lock', ResetBeforeWrite())
    if action == 'psk':
        response = customer.post(root + '/psk', data={'csrf_token': token, 'psk': 'attacker-known-credential'})
    else:
        response = customer.post(root + '/routing/' + action, json={'csrf': token, 'revision': 1,
                                 'document': {'enabled': False, 'rules': []}})
    assert response.status_code == 401, response.text
    assert app.records(app.DB, 'users')[0]['secret'] == 'node-credential-a'
    assert ur.get_policy(app.DB, 'a')['revision'] == before['revision']
