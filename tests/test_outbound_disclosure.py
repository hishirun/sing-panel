"""Customer projections never inherit private exit metadata or active markup."""
import base64
import copy
import json
import re
from html.parser import HTMLParser
from urllib.parse import unquote

import pytest

from panel import routing
from panel.client_profiles import client_imports
from panel.core import connect
from panel.sharing import read_settings, save_settings
from test_app import client
from test_customer_routing_api import customer, document


class Markup(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.tags = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def assert_inert(html, payload):
    assert payload not in html
    assert not any('onerror' in attrs or 'onload' in attrs
                   for _, attrs in Markup(html).tags)


@pytest.mark.parametrize('payload', [
    '</script><img src=x onerror=alert(1)>',
    '\"><svg/onload=alert(1)>',
])
def test_stored_names_and_rule_json_cannot_inject_markup_or_templates(customer, payload):
    c, m, root, token = customer
    with connect(m.DB) as db:
        db.execute('UPDATE users SET name=? WHERE id=?', (payload + '{{7*7}}', 'u'))
        db.execute('UPDATE nodes SET name=?,comment=? WHERE id=?', (payload, payload, 'n'))
    settings = routing.load(m.DB)
    settings['outbounds'][0]['public'].update(name=payload, description=payload)
    routing.write(m.DB, settings)
    branding = read_settings(m.DB)
    branding.update(brand=payload, support=payload)
    save_settings(m.DB, branding)

    saved = c.post(root + '/draft', json={
        'csrf': token, 'revision': 0, 'document': document(name=payload),
    })
    assert saved.status_code == 200, saved.text
    assert saved.json()['policy']['draft']['rules'][0]['name'] == payload
    page = c.get(root)
    assert page.status_code == 200
    assert_inert(page.text, payload)
    initial = re.search(r'<script type="application/json" id="routing-initial-state">(.*?)</script>',
                        page.text, re.S)[1]
    assert json.loads(initial)['policy']['draft']['rules'][0]['name'] == payload
    assert '<' not in initial
    share = c.get('/s/token-u', headers={'Accept': 'text/html', 'User-Agent': 'Mozilla/5.0'})
    assert share.status_code == 200
    assert_inert(share.text, payload)
    assert '{{7*7}}' in share.text

    login = c.get('/login')
    csrf = re.search('name="token" value="([^"]+)"', login.text)[1]
    assert c.post('/login', data={'username': 'admin', 'password': 'test-password-only', 'token': csrf}, follow_redirects=False).status_code == 303
    for path in ['/users', '/nodes', '/routing', '/users/u/routing']:
        response = c.get(path)
        assert response.status_code == 200, path
        assert_inert(response.text, payload)


def test_ten_public_exits_do_not_disclose_upstream_settings(customer, monkeypatch):
    c, m, root, token = customer
    # A compatible entry makes every supported subscription contain a real node,
    # so an empty client profile cannot accidentally make this check pass.
    with connect(m.DB) as db:
        db.execute("UPDATE nodes SET protocol='snell5',mode='compat' WHERE id='n'")
        db.execute("UPDATE memberships SET port=31080 WHERE user_id='u' AND node_id='n'")
    settings = copy.deepcopy(routing.DEFAULT)
    markers = []
    for index in range(10):
        host = f'198.51.100.{index + 20}'
        password = f'UPSTREAM_PASSWORD_{index}'
        private = f'PRIVATE_ALIAS_{index}'
        username = f'UPSTREAM_USER_{index}'
        markers.extend([host, password, private, username])
        settings['outbounds'].append({
            'id': f'out{index}', 'name': private, 'enabled': True,
            'settings': {'type': 'socks', 'server': host, 'server_port': 32000 + index,
                         'username': username, 'password': password},
            'public': {'visible': True, 'allow_use': True, 'name': f'Public Exit {index}',
                       'region': 'JP', 'description': 'Public description',
                       'audience': 'all', 'groups': [], 'user_ids': []},
        })
    routing.write(m.DB, settings)
    state = c.get(root + '/api').json()
    assert len(state['outbounds']) == 10
    assert set(state['outbounds'][0]) == {
        'id', 'name', 'region', 'description', 'type', 'enabled', 'selectable', 'latency', 'usable',
    }
    saved = c.post(root + '/draft', json={
        'csrf': token, 'revision': 0, 'document': document(target='out0'),
    })
    assert saved.status_code == 200
    monkeypatch.setattr(m.runtime, 'control', lambda path: {'delay': 12})
    responses = [
        c.get(root), c.get(root + '/api'),
        c.get('/s/token-u', headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html'}),
        c.post(root + '/latency/out0', json={'csrf': token}),
        c.post(root + '/preview', json={
            'csrf': token, 'destination': 'example.com', 'node_id': 'n',
        }),
    ]
    assert set(responses[-2].json()) == {'delay', 'checked_at'}
    assert responses[-1].json()['outbound_name'] == 'Public Exit 0'
    for fmt, ua in [
        ('sing-box.json', 'sing-box/1.14.3'), ('clash.yaml', 'Clash/1.0'),
        ('surge.conf', 'Surge/5'), ('surfboard.conf', 'Surfboard/1.0'),
        ('shadowrocket.txt', 'Shadowrocket/2.2'),
    ]:
        direct = c.get('/s/token-u/' + fmt)
        detected = c.get('/s/token-u', headers={'User-Agent': ua})
        for response in (direct, detected):
            assert response.status_code == 200, (fmt, response.text)
            assert response.headers['X-Subscription-Format'] == fmt
            assert int(response.headers['X-Subscription-Node-Count']) > 0
            responses.append(response)
            if fmt == 'shadowrocket.txt':
                decoded = base64.b64decode(response.content).decode()
                for marker in markers:
                    assert marker not in decoded
    for response in responses:
        assert response.status_code == 200, response.text
        for marker in markers:
            assert marker not in response.text


@pytest.mark.parametrize('alias', [None, '', 'Public name'])
def test_missing_public_alias_never_falls_back_to_internal_name(customer, alias):
    c, m, root, token = customer
    settings = routing.load(m.DB)
    out = settings['outbounds'][0]
    out['name'] = 'PRIVATE 198.51.100.27'
    if alias is None:
        out['public'].pop('name')
    else:
        out['public']['name'] = alias
    routing.write(m.DB, settings)
    expected = alias or '出口 mine'
    response = c.get(root + '/api')
    assert response.status_code == 200
    assert response.json()['outbounds'][0]['name'] == expected
    assert out['name'] not in response.text
    assert out['name'] not in c.get(root).text
    c.post(root + '/draft', json={'csrf': token, 'revision': 0, 'document': document()})
    preview = c.post(root + '/preview', json={
        'csrf': token, 'destination': 'example.com', 'node_id': 'n',
    })
    assert preview.status_code == 200
    assert preview.json()['outbound_name'] == expected
    out['name'] = 'RENAMED PRIVATE 198.51.100.99'
    routing.write(m.DB, settings)
    assert c.get(root + '/api').json()['outbounds'][0]['name'] == expected


def test_import_protocols_are_fixed_and_url_arguments_are_encoded(customer):
    _, m, _, _ = customer
    payload = '</script><img src=x onerror=alert(1)>'
    malicious = 'https://example.com/share/test?x=" onclick="alert(1)\n&other=1#frag'
    links = client_imports(malicious, payload)
    assert [link['href'].split(':')[0] for link in links] == [
        'sing-box', 'clash', 'surge', 'surfboard', 'shadowrocket',
    ]
    for link in links:
        assert not any(char in link['href'] for char in ('"', '<', '\n'))
        assert malicious in unquote(link['href'])
    for value in ['javascript:alert(1)', 'data:text/html,hello', '//evil.test',
                  'https://u:p@example.com', 'https://example.com/#foo']:
        settings = read_settings(m.DB)
        settings['public_url'] = value
        with pytest.raises(ValueError):
            save_settings(m.DB, settings)
