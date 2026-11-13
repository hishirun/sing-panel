"""Agent credentials, report replay and machine ownership boundaries."""
import copy
import json
import secrets
import uuid

import pytest

from panel import fleet
from panel.core import account, connect, init_db


@pytest.fixture
def fleet_db(tmp_path):
    path = tmp_path / 'panel.db'
    init_db(path)
    return path


def registered(path, name='Tokyo', host='192.0.2.10'):
    row = fleet.save_server(path, name, host)
    token, _ = fleet.issue_enrollment(path, row['id'])
    credential = secrets.token_urlsafe(32)
    fleet.enroll(path, token, credential)
    return row['id'], credential


def configured(path, identity, port=32001):
    uid, nid = uuid.uuid4().hex, uuid.uuid4().hex
    with connect(path) as db:
        db.execute('INSERT INTO users(id,name,secret,uuid,token) VALUES(?,?,?,?,?)',
                   (uid, 'A', 'user-secret', str(uuid.uuid4()), secrets.token_urlsafe(32)))
        db.execute("INSERT INTO nodes(id,name,protocol,port,secret,server_id) VALUES(?,?,'snell6',?,'node-secret',?)", (nid, 'N', port, identity))
        db.execute('INSERT INTO memberships(user_id,node_id) VALUES(?,?)', (uid, nid))
    name = nid + ':' + uid
    document = {'inbounds': [], 'outbounds': [{'type': 'direct', 'tag': 'direct'}],
                'experimental': {'v2ray_api': {'stats': {'users': [name], 'inbounds': []}}}}
    return uid, nid, document, 'user>>>' + name + '>>>traffic>>>uplink'


def report(counters=None, **changes):
    return {'type': 'report', 'protocol': 1, 'report_id': uuid.uuid4().hex,
            'epoch': 'core-one', 'counters': counters or {}, 'metrics': {},
            'applied_revision': '', 'error': '', **changes}


def reconcile(path, identity, message, document, **extra):
    return fleet.process_report(path, identity, message, lambda *args: copy.deepcopy(document), account,
                                traffic_fn=lambda *args: {'blocked': False}, **extra)


def uploaded(path, uid):
    with connect(path) as db:
        return db.execute('SELECT upload FROM users WHERE id=?', (uid,)).fetchone()[0]


def test_enrollment_is_single_use_expiring_and_hashed(fleet_db):
    row = fleet.save_server(fleet_db, 'Tokyo', '192.0.2.10')
    token, expires = fleet.issue_enrollment(fleet_db, row['id'], now=100)
    credential = secrets.token_urlsafe(32)
    assert expires == 1000
    assert fleet.enroll(fleet_db, token, credential, now=101) == row['id']
    assert fleet.enroll(fleet_db, token, credential, now=102) == row['id']
    with pytest.raises(fleet.AuthenticationError):
        fleet.enroll(fleet_db, token, secrets.token_urlsafe(32), now=103)
    with pytest.raises(fleet.AuthenticationError):
        fleet.enroll(fleet_db, token, credential, now=1000)
    stored = fleet.get_server(fleet_db, row['id'], safe=False)
    assert credential not in json.dumps(stored) and token not in json.dumps(stored)
    safe = fleet.get_server(fleet_db, row['id'])
    assert safe['enrollment_consumed'] and not safe['enrollment_pending']
    assert 'credential_hash' not in safe and 'enroll_hash' not in safe
    assert fleet.authenticate(fleet_db, 'Bearer ' + row['id'] + '.' + credential)[0] == row['id']
    for bearer in ['', 'Bearer nope', 'Bearer ' + row['id'] + '.' + secrets.token_urlsafe(32)]:
        with pytest.raises(fleet.AuthenticationError):
            fleet.authenticate(fleet_db, bearer)


def test_new_token_does_not_claim_success_from_old_online_agent(fleet_db):
    sid, credential = registered(fleet_db)
    generation = fleet.authenticate(fleet_db, 'Bearer ' + sid + '.' + credential)[1]
    connection = fleet.open_connection(fleet_db, sid, generation)
    with connect(fleet_db) as db:
        db.execute('UPDATE servers SET last_seen=100 WHERE id=?', (sid,))
    fleet.issue_enrollment(fleet_db, sid, now=101)
    row = fleet.list_servers(fleet_db, now=102)[0]
    assert row['online'] and row['enrollment_pending'] and not row['enrollment_consumed']
    expired = fleet.list_servers(fleet_db, now=1001)[0]
    assert not expired['enrollment_pending'] and not expired['enrollment_consumed']


def test_enrollment_cannot_rebind_an_existing_installation(fleet_db):
    row = fleet.save_server(fleet_db, 'Correct server', '192.0.2.1')
    token, _ = fleet.issue_enrollment(fleet_db, row['id'])
    credential = secrets.token_urlsafe(32)
    with pytest.raises(fleet.AuthenticationError, match='绑定'):
        fleet.enroll(fleet_db, token, credential, expected_server_id=uuid.uuid4().hex)
    assert fleet.get_server(fleet_db, row['id'])['enrollment_pending']
    assert fleet.enroll(fleet_db, token, credential, expected_server_id=row['id']) == row['id']


def test_counter_replays_do_not_double_bill_or_accept_foreign_identity(fleet_db):
    sid, _ = registered(fleet_db)
    uid, nid, doc, counter = configured(fleet_db, sid)
    first = reconcile(fleet_db, sid, report(), doc)
    assert first['config'] == doc
    message = report({counter: 100})
    reply = reconcile(fleet_db, sid, message, doc)
    assert reply['ack_report_id'] == message['report_id'] and uploaded(fleet_db, uid) == 100
    reconcile(fleet_db, sid, message, doc)
    assert uploaded(fleet_db, uid) == 100
    reconcile(fleet_db, sid, report({counter: 30}), doc)
    assert uploaded(fleet_db, uid) == 100
    reconcile(fleet_db, sid, report({counter: 150}), doc)
    assert uploaded(fleet_db, uid) == 150
    with pytest.raises(ValueError, match='重复报告'):
        reconcile(fleet_db, sid, {**message, 'counters': {counter: 151}}, doc)
    with pytest.raises(ValueError, match='其他服务器'):
        reconcile(fleet_db, sid, report({counter.replace(nid, uuid.uuid4().hex): 1000}), doc)
    assert uploaded(fleet_db, uid) == 150
    for value in [-1, 1.5, True, 2**63]:
        with pytest.raises(ValueError, match='计数器'):
            reconcile(fleet_db, sid, report({counter: value}), doc)


def test_two_machines_share_user_quota_but_not_counter_authority(fleet_db):
    a, _ = registered(fleet_db, 'A')
    b, _ = registered(fleet_db, 'B', '192.0.2.11')
    uid, nid, doc, counter = configured(fleet_db, a)
    reconcile(fleet_db, a, report(), doc)
    other_doc = {'inbounds': [], 'outbounds': [], 'experimental': {'v2ray_api': {'stats': {'users': [], 'inbounds': []}}}}
    reconcile(fleet_db, b, report(), other_doc)
    with pytest.raises(ValueError, match='其他服务器'):
        reconcile(fleet_db, b, report({counter: 999}), other_doc)
    assert uploaded(fleet_db, uid) == 0


def test_displaced_and_revoked_sessions_cannot_report(fleet_db):
    sid, credential = registered(fleet_db)
    _, generation = fleet.authenticate(fleet_db, 'Bearer ' + sid + '.' + credential)
    old = fleet.open_connection(fleet_db, sid, generation)
    current = fleet.open_connection(fleet_db, sid, generation)
    _, _, doc, _ = configured(fleet_db, sid)
    with pytest.raises(fleet.AuthenticationError, match='其他连接'):
        reconcile(fleet_db, sid, report(), doc, credential_generation=generation, connection_generation=old)
    fleet.close_connection(fleet_db, sid, old)
    assert fleet.get_server(fleet_db, sid, safe=False)['connected']
    reconcile(fleet_db, sid, report(), doc, credential_generation=generation, connection_generation=current)
    fleet.set_action(fleet_db, sid, 'revoke')
    with pytest.raises(fleet.AuthenticationError):
        fleet.authenticate(fleet_db, 'Bearer ' + sid + '.' + credential)
    with pytest.raises(fleet.AuthenticationError):
        reconcile(fleet_db, sid, report(), doc, credential_generation=generation, connection_generation=current)


def test_credential_rotation_does_not_rebill_old_spool(fleet_db):
    sid, _ = registered(fleet_db)
    uid, _, doc, counter = configured(fleet_db, sid)
    reconcile(fleet_db, sid, report(), doc)
    reconcile(fleet_db, sid, report({counter: 500}), doc)
    token, _ = fleet.issue_enrollment(fleet_db, sid)
    fleet.enroll(fleet_db, token, secrets.token_urlsafe(32))
    reconcile(fleet_db, sid, report({counter: 500}), doc)
    assert uploaded(fleet_db, uid) == 500


def test_deleted_membership_final_counters_remain_scoped(fleet_db):
    sid, _ = registered(fleet_db)
    uid, nid, doc, counter = configured(fleet_db, sid)
    reconcile(fleet_db, sid, report(), doc)
    with connect(fleet_db) as db:
        db.execute('DELETE FROM memberships WHERE user_id=?', (uid,))
    empty = copy.deepcopy(doc)
    empty['experimental']['v2ray_api']['stats']['users'] = []
    reconcile(fleet_db, sid, report({counter: 42}), empty)
    assert uploaded(fleet_db, uid) == 42


def test_commands_are_scoped_and_failed_updates_can_retry(fleet_db):
    a, _ = registered(fleet_db, 'A')
    b, _ = registered(fleet_db, 'B', '192.0.2.11')
    _, _, doc, _ = configured(fleet_db, a)
    cid = fleet.enqueue_command(fleet_db, a, 'update_agent')
    other = fleet.enqueue_command(fleet_db, b, 'restart')
    assert fleet.enqueue_command(fleet_db, a, 'update_agent') == cid
    first = reconcile(fleet_db, a, report(), doc)
    assert first['commands'] == [{'id': cid, 'action': 'update_agent'}]
    reconcile(fleet_db, a, report(command_acks=[cid, other], command_results=[{'id': cid, 'ok': False, 'error': 'checksum failed'}]), doc)
    assert fleet.last_command(fleet_db, a)['status'] == 'failed'
    assert fleet.last_command(fleet_db, b)['status'] == 'pending'
    assert fleet.enqueue_command(fleet_db, a, 'update_agent') != cid
    for invalid in ('shell', 'curl example.com | sh', 'reboot'):
        with pytest.raises(ValueError):
            fleet.enqueue_command(fleet_db, a, invalid)


def test_user_disconnect_safely_ignores_unenrolled_or_revoked_servers(fleet_db):
    a, _ = registered(fleet_db)
    uid = uuid.uuid4().hex
    assert fleet.enqueue_command(fleet_db, a, 'disconnect_user', uid)
    fleet.set_action(fleet_db, a, 'revoke')
    assert fleet.enqueue_command(fleet_db, a, 'disconnect_user', uid) is None
    b = fleet.save_server(fleet_db, 'Not installed', '192.0.2.11')
    assert fleet.enqueue_command(fleet_db, b['id'], 'disconnect_user', uid) is None
    fleet.set_action(fleet_db, b['id'], 'delete')
    assert fleet.enqueue_command(fleet_db, b['id'], 'disconnect_user', uid) is None
    with pytest.raises(ValueError, match='接入'):
        fleet.enqueue_command(fleet_db, a, 'update_agent')


def test_quota_blocks_only_proxy_and_bad_config_does_not_renew_lease(fleet_db):
    sid, _ = registered(fleet_db)
    uid, _, doc, counter = configured(fleet_db, sid)
    reply = fleet.process_report(fleet_db, sid, report(), lambda *args: doc, account,
                                 traffic_fn=lambda *args: {'blocked': True})
    assert reply['state'] == 'stopped' and reply['lease_seconds'] == 90
    assert fleet.get_server(fleet_db, sid)['desired_state'] == 'running'
    def fail(*args):
        raise ValueError('broken cert')
    payload = report({counter: 2})
    reply = fleet.process_report(fleet_db, sid, payload, fail, account, traffic_fn=lambda *args: {'blocked': False})
    assert reply['ack_report_id'] == payload['report_id'] and uploaded(fleet_db, uid) == 2
    assert reply['state'] == 'stopped' and reply['lease_seconds'] == 0 and 'config' not in reply


def test_machine_policy_and_delete_guard(fleet_db):
    row = fleet.save_server(fleet_db, 'Quota', '192.0.2.10', monthly_quota=1024**3, traffic_direction='tx', reset_day=15)
    assert row['monthly_quota'] == 1024**3 and row['traffic']['quota'] == 1024**3
    fleet.save_server(fleet_db, '', '', 'local', monthly_quota=2*1024**3, traffic_direction='rx', reset_day=28)
    assert fleet.local_policy(fleet_db)['reset_day'] == 28
    configured(fleet_db, row['id'])
    with pytest.raises(ValueError, match='仍有节点'):
        fleet.set_action(fleet_db, row['id'], 'delete')
    for kwargs in ({'monthly_quota': -1}, {'traffic_direction': 'evil'}, {'reset_day': 29}):
        with pytest.raises(ValueError):
            fleet.save_server(fleet_db, 'Invalid', '192.0.2.1', **kwargs)


def test_metrics_are_bounded_and_do_not_store_unknown_fields():
    metrics = fleet.sanitize_metrics({'cpu': 12, 'hostname': 'host\nname', 'password': 'not-stored',
                                     'memory': {'used': 1, 'total': 2, 'percent': 50, 'bad': 'hidden'},
                                     'interfaces': [{'name': 'eth0', 'rx_total': 100, 'tx_total': 200, 'billable': True, 'command': 'evil'}],
                                     'load': [1, 2, 3], 'running': True, 'rx': float('inf')})
    encoded = json.dumps(metrics)
    assert 'not-stored' not in encoded and 'hidden' not in encoded and 'evil' not in encoded
    assert 'rx' not in metrics and metrics['hostname'] == 'hostname'
    assert metrics['interfaces'][0]['rx_total'] == 100


def test_presence_and_ip_policy_are_scoped_and_expire(fleet_db):
    sid, _ = registered(fleet_db)
    uid, nid, doc, counter = configured(fleet_db, sid)
    other, _ = registered(fleet_db, 'Other', '192.0.2.2')
    other_uid, other_nid, _, _ = configured(fleet_db, other, port=32002)
    with connect(fleet_db) as db:
        db.execute('UPDATE users SET max_ips=2 WHERE id=?', (uid,))
    first = reconcile(fleet_db, sid, report(), doc, now=100)
    assert first['policy'] == {'max_ips': {uid: 2}}
    connection = {'id': 'conn-1', 'user_id': uid, 'node_id': nid, 'source_ip': '2001:db8::1', 'start': '2026-01-01T00:00:00Z'}
    reply = reconcile(fleet_db, sid, report({counter: 50}, connections=[connection]), doc, now=101)
    assert reply['policy']['max_ips'] == {uid: 2}
    online = fleet.presence_connections(fleet_db, now=102)
    assert online == [{'id': 'agent:' + sid + ':conn-1', 'server_id': sid, 'agent_connection_id': 'conn-1',
                       'start': connection['start'], 'metadata': {'inboundTag': nid, 'inboundUser': nid + ':' + uid, 'sourceIP': '2001:db8::1'}}]
    assert fleet.presence_connections(fleet_db, now=137) == []
    with pytest.raises(ValueError, match='其他服务器'):
        reconcile(fleet_db, sid, report(connections=[{**connection, 'user_id': other_uid, 'node_id': other_nid}]), doc, now=103)
    assert uploaded(fleet_db, uid) == 50
    with connect(fleet_db) as db:
        db.execute('DELETE FROM memberships WHERE user_id=?', (uid,))
    assert fleet.presence_connections(fleet_db, now=104) == []
    final = reconcile(fleet_db, sid, report({counter: 60}, connections=[connection]), doc, now=104)
    assert final['policy'] == {'max_ips': {}} and uploaded(fleet_db, uid) == 60
    assert fleet.presence_connections(fleet_db, now=104) == []


def test_disconnect_ip_commands_are_validated_deduplicated_and_scoped(fleet_db):
    sid, _ = registered(fleet_db)
    uid, _, doc, _ = configured(fleet_db, sid)
    identity = fleet.enqueue_command(fleet_db, sid, 'disconnect_ip', user_id=uid, source_ip='192.0.2.1')
    assert fleet.enqueue_command(fleet_db, sid, 'disconnect_ip', user_id=uid, source_ip='192.0.2.1') == identity
    reply = reconcile(fleet_db, sid, report(), doc)
    assert reply['commands'] == [{'id': identity, 'action': 'disconnect_ip', 'user_id': uid, 'source_ip': '192.0.2.1'}]
    for source_ip in ('example.com', '192.0.2.1; reboot', True):
        with pytest.raises(ValueError):
            fleet.enqueue_command(fleet_db, sid, 'disconnect_ip', user_id=uid, source_ip=source_ip)
    fleet.set_action(fleet_db, sid, 'revoke')
    assert fleet.enqueue_command(fleet_db, sid, 'disconnect_ip', user_id=uid, source_ip='192.0.2.1') is None
