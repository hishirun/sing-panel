"""Exercise enrollment and authenticated WebSocket reconciliation end to end."""
import json
import secrets
import uuid

import pytest
from starlette.websockets import WebSocketDisconnect

from panel import fleet
from panel.core import connect
from test_app import client, csrf
from test_fleet import configured, registered, report, uploaded


def public_origin(module, admin_path=None):
    with connect(module.DB) as db:
        db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('public_url','https://panel.example.com')")
        if admin_path is not None:
            db.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('admin_path',?)", (admin_path,))


def bearer(identity, credential):
    return {'authorization': 'Bearer ' + identity + '.' + credential}


def test_server_management_authentication_csrf_and_safe_status(client):
    c, m = client
    public_origin(m)
    token = csrf(c)
    data = {'token': token, 'name': 'Tokyo', 'host': '192.0.2.1',
            'monthly_quota_gib': '1.5', 'traffic_direction': 'tx', 'reset_day': '8'}
    assert c.post('/servers/save', data={**data, 'token': 'wrong'}).status_code == 403
    response = c.post('/servers/save', data=data)
    assert response.status_code == 200
    assert 'https://panel.example.com/agent/install.sh' in response.text
    assert '--token ' in response.text
    row = fleet.list_servers(m.DB)[0]
    assert row['monthly_quota'] == 3 * 1024**3 // 2
    assert row['traffic_direction'] == 'tx' and row['reset_day'] == 8
    assert row['enrollment_pending']
    status = c.get('/servers/status')
    assert status.status_code == 200
    assert len(status.json()['servers']) == 2
    for hidden in ('credential_hash', 'enroll_hash', 'credential_generation', 'connection_generation'):
        assert hidden not in status.text
    assert c.post('/servers/save', data={**data, 'id': 'local', 'monthly_quota_gib': '2'}).status_code == 200
    assert fleet.local_policy(m.DB)['monthly_quota'] == 2 * 1024**3
    assert c.post('/servers/save', data={**data, 'id': row['id'], 'reset_day': '29'}).status_code == 422
    assert fleet.get_server(m.DB, row['id'])['reset_day'] == 8
    c.cookies.clear()
    denied = c.get('/servers/status', follow_redirects=False)
    assert denied.status_code in (401, 303)
    assert '192.0.2.1' not in denied.text
    assert c.post('/servers/save', data=data).status_code == 401


def test_enrollment_is_public_but_bound_and_fixed_outside_admin_prefix(client):
    c, m = client
    public_origin(m, '/private-admin')
    row = fleet.save_server(m.DB, 'Tokyo', '192.0.2.1')
    token, _ = fleet.issue_enrollment(m.DB, row['id'])
    credential = secrets.token_urlsafe(32)
    c.cookies.clear()
    body = {'token': token, 'credential': credential, 'expected_server_id': uuid.uuid4().hex}
    assert c.post('/agent/v1/enroll', json=body).status_code == 403
    assert fleet.get_server(m.DB, row['id'])['enrollment_pending']
    body['expected_server_id'] = row['id']
    result = c.post('/agent/v1/enroll', json=body)
    assert result.status_code == 200
    assert result.json() == {'server_id': row['id'], 'ws_url': 'wss://panel.example.com/agent/v1/ws', 'protocol': 1}
    assert c.post('/agent/v1/enroll', json=body).status_code == 200
    assert c.post('/agent/v1/enroll', json={**body, 'credential': secrets.token_urlsafe(32)}).status_code == 403
    assert c.post('/agent/v1/enroll', content='x' * 8193).status_code == 413
    with c.websocket_connect('/agent/v1/ws', headers=bearer(row['id'], credential)) as ws:
        ws.send_json(report())
        desired = ws.receive_json()
        assert desired['lease_seconds'] == 90 and desired['config']


def test_websocket_requires_agent_identity_and_rejects_foreign_counters(client):
    c, m = client
    a, credential = registered(m.DB)
    b, _ = registered(m.DB, 'Berlin', '192.0.2.2')
    uid, nid, _, counter = configured(m.DB, a)
    other_uid, _, _, other_counter = configured(m.DB, b, port=32002)
    with pytest.raises(WebSocketDisconnect) as rejection:
        with c.websocket_connect('/agent/v1/ws'):
            pass
    assert rejection.value.code == 4403
    with c.websocket_connect('/agent/v1/ws', headers=bearer(a, credential)) as ws:
        ws.send_json(report())
        initial = ws.receive_json()
        assert initial['config'] and initial['lease_seconds'] == 90
        assert nid in json.dumps(initial['config'])
        assert other_uid not in json.dumps(initial['config'])
        sample = report({counter: 100}, applied_revision=initial['revision'])
        ws.send_json(sample)
        reply = ws.receive_json()
        assert reply['ack_report_id'] == sample['report_id'] and 'config' not in reply
        ws.send_json(sample)
        assert ws.receive_json()['ack_report_id'] == sample['report_id']
        assert uploaded(m.DB, uid) == 100
        ws.send_json(report({other_counter: 1000}))
        with pytest.raises(WebSocketDisconnect) as forbidden:
            ws.receive_json()
        assert forbidden.value.code == 1008
    assert uploaded(m.DB, other_uid) == 0
    assert not fleet.get_server(m.DB, a)['online']


def test_revoke_immediately_stops_connected_agent(client):
    c, m = client
    identity, credential = registered(m.DB)
    token = csrf(c)
    with c.websocket_connect('/agent/v1/ws', headers=bearer(identity, credential)) as ws:
        ws.send_json(report())
        assert ws.receive_json()['state'] == 'running'
        assert fleet.get_server(m.DB, identity)['online']
        result = c.post('/servers/' + identity + '/action', data={'token': token, 'action': 'revoke'})
        assert result.status_code == 200
        stopped = ws.receive_json()
        assert stopped['state'] == 'stopped' and stopped['lease_seconds'] == 0 and stopped['revoked']
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
        assert closed.value.code == 4403
    with pytest.raises(WebSocketDisconnect):
        with c.websocket_connect('/agent/v1/ws', headers=bearer(identity, credential)):
            pass


def test_replaced_connection_does_not_clear_new_session(client):
    c, m = client
    identity, credential = registered(m.DB)
    with c.websocket_connect('/agent/v1/ws', headers=bearer(identity, credential)) as old:
        old.send_json(report())
        old.receive_json()
        with c.websocket_connect('/agent/v1/ws', headers=bearer(identity, credential)) as current:
            with pytest.raises(WebSocketDisconnect) as replaced:
                old.receive_json()
            assert replaced.value.code == 4403
            current.send_json(report())
            assert current.receive_json()['state'] == 'running'
            assert fleet.get_server(m.DB, identity)['online']
    assert not fleet.get_server(m.DB, identity)['online']


def test_controller_shutdown_closes_live_websockets_without_revoking_identity(client):
    c, m = client
    identity, credential = registered(m.DB)
    with c.websocket_connect('/agent/v1/ws', headers=bearer(identity, credential)) as ws:
        ws.send_json(report())
        ws.receive_json()
        c.portal.call(m.fleet_shutdown)
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_json()
        assert closed.value.code == 1012
        assert not fleet.get_server(m.DB, identity)['online']
        assert not m.fleet_connections
    assert fleet.authenticate(m.DB, bearer(identity, credential)['authorization'])[0] == identity
    with pytest.raises(WebSocketDisconnect) as rejecting:
        with c.websocket_connect('/agent/v1/ws', headers=bearer(identity, credential)):
            pass
    assert rejecting.value.code == 1012


def test_status_deduplicates_physical_traffic_but_keeps_management_instances(client, monkeypatch):
    c, m = client
    from panel import machine, server_traffic
    monkeypatch.setattr(machine, 'snapshot', lambda _: {'boot_id': 'same-machine', 'rx': 10, 'tx': 20,
                                                       'rx_total': 100, 'tx_total': 200, 'cpu': 20})
    monkeypatch.setattr(server_traffic, 'summary', lambda *args: {'used': 5, 'rx': 50, 'tx': 60})

    def remote(identity, boot, online, metrics, used, count):
        return {'id': identity, 'name': identity, 'online': online, 'is_local': False,
                'last_seen': 100, 'nodes_count': count, 'metrics': {'boot_id': boot, **metrics},
                'traffic': {'used': used, 'rx': used * 10, 'tx': used * 10 + 10}}

    rows = [remote('isolated-agent', 'same-machine', True, {'rx': 999, 'tx': 999, 'rx_total': 9999, 'tx_total': 9999, 'cpu': 99}, 999, 2),
            remote('Berlin', 'remote-machine', True, {'rx': 30, 'tx': 40, 'rx_total': 300, 'tx_total': 400, 'cpu': 60}, 7, 3),
            remote('Offline', 'offline-machine', False, {'rx': 900, 'tx': 900, 'rx_total': 500, 'tx_total': 600, 'cpu': 100}, 9, 4),
            remote('Unknown-1', '', True, {'rx': 5, 'tx': 6, 'rx_total': 50, 'tx_total': 60, 'cpu': None}, 11, 5),
            remote('Unknown-2', '', True, {'rx': 7, 'tx': 8, 'rx_total': 70, 'tx_total': 80, 'cpu': True}, 13, 6)]
    monkeypatch.setattr(fleet, 'list_servers', lambda _: rows)
    payload = c.get('/servers/status').json()
    assert len(payload['servers']) == 6
    assert payload['summary'] == {'total': 6, 'online': 5, 'offline': 1, 'nodes': 20,
                                  'rx': 52, 'tx': 74, 'rates_available': True,
                                  'rx_total': 1020, 'tx_total': 1340,
                                  'monthly_used': 45, 'monthly_rx': 450, 'monthly_tx': 500,
                                  'busy_name': 'Berlin', 'busy_cpu': 60}


def test_status_distinguishes_missing_rates_from_idle_zero(client, monkeypatch):
    c, _ = client
    from panel import machine
    snapshot = {'cpu': None, 'rx': None, 'tx': None, 'rx_total': None, 'tx_total': None}
    monkeypatch.setattr(machine, 'snapshot', lambda _: dict(snapshot))
    first = c.get('/servers/status').json()['summary']
    assert first['rx'] is None and first['tx'] is None and not first['rates_available']
    assert first['busy_name'] == '' and first['busy_cpu'] is None
    snapshot.update(rx=0, cpu=0)
    idle = c.get('/servers/status').json()['summary']
    assert idle['rx'] == 0 and idle['tx'] is None and idle['rates_available']
    assert idle['busy_name'] == '主面板本机' and idle['busy_cpu'] == 0
