"""Customer projections and previews must describe the selected policy honestly."""
import json
import time

from panel import routing, user_routing as ur, fleet
from panel.core import connect
from test_customer_routing_api import customer, document
from test_app import client


def test_machine_projection_and_preview_respect_disabled_server(customer):
    c, m, root, token = customer
    server = fleet.save_server(m.DB, 'Tokyo', 'private-host.example')
    with connect(m.DB) as db:
        db.execute('UPDATE nodes SET server_id=? WHERE id=?', (server['id'], 'n'))
    state = c.get(root + '/api').json()
    assert state['nodes'][0]['server_name'] == 'Tokyo'
    assert state['nodes'][0]['server_id'] == server['id']
    assert state['nodes'][0]['available'] and not state['nodes'][0]['online']
    assert 'private-host.example' not in json.dumps(state)
    raw = {'csrf': token, 'destination': 'example.com', 'node_id': 'n'}
    preview = c.post(root + '/preview', json=raw).json()
    assert preview['server_name'] == 'Tokyo' and '离线' in preview['warning']
    with connect(m.DB) as db:
        db.execute('UPDATE servers SET enabled=0 WHERE id=?', (server['id'],))
    assert not c.get(root + '/api').json()['nodes'][0]['available']
    assert c.post(root + '/preview', json=raw).status_code == 422


def test_preview_distinguishes_draft_from_published_and_discard_keeps_receipts(customer):
    c, m, root, token = customer
    original = document(name='Published route')
    ur.save_draft(m.DB, 'u', original, 0)
    m.routing_publisher.enqueue('u', 1)
    m.routing_publisher.publish_pending()
    new = document(name='Draft route', target='reject')
    ur.save_draft(m.DB, 'u', new, 1)
    query = {'csrf': token, 'destination': 'api.example.com', 'node_id': 'n'}
    draft = c.post(root + '/preview', json={**query, 'mode': 'draft'}).json()
    applied = c.post(root + '/preview', json={**query, 'mode': 'applied'}).json()
    assert (draft['outbound_name'], draft['revision'], draft['rule_id']) == ('拦截', 2, 'rule-one')
    assert (applied['outbound_name'], applied['revision'], applied['rule_id']) == ('Public mine', 1, 'rule-one')
    assert c.post(root + '/preview', json={**query, 'mode': 'unknown'}).status_code == 422
    state = c.post(root + '/discard', json={'csrf': token, 'revision': 2}).json()
    assert state['policy']['revision'] == 3 and state['policy']['applied_revision'] == 1
    assert state['policy']['draft'] == state['policy']['applied']
    assert state['policy']['rollout']['confirmed'] == 1


def test_presets_are_valid_and_shadowing_warning_is_scope_aware(customer):
    c, m, root, token = customer
    presets = c.get(root + '/api').json()['presets']
    assert presets and any(item['id'] == 'ai' for item in presets)
    assert all(set(item['values']) <= set(routing.GEO_CATALOG[item['kind']]) for item in presets)
    rules = document()
    rules['rules'].append({**rules['rules'][0], 'id': 'second', 'name': 'Shadowed', 'target': 'reject'})
    saved = c.post(root + '/draft', json={'csrf': token, 'revision': 0, 'document': rules}).json()
    assert saved['policy']['warnings'][0]['rule_id'] == 'second'
    assert '覆盖' in saved['policy']['warnings'][0]['message']
    with connect(m.DB) as db:
        db.execute("UPDATE user_routing SET allowed=0 WHERE user_id='u'")
    state = c.get(root + '/api').json()
    assert not state['policy']['applied']['rules'] and not state['policy']['rollout']['targets']
    assert not state['presets'] and not state['nodes']
