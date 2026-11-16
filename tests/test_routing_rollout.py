"""Publication is not successful until each affected core confirms delivery."""
import json
import hashlib
import sqlite3

from panel import fleet, routing_rollout as rollout, user_routing
from panel.core import account, connect
from panel.fleet_config import configuration
from test_fleet import report
from test_routing_publish import publisher
from test_user_routing import draft, policy_db


def remote(publisher):
    row = fleet.save_server(publisher.m.DB, 'Tokyo', '192.0.2.1')
    token, _ = fleet.issue_enrollment(publisher.m.DB, row['id'])
    fleet.enroll(publisher.m.DB, token, 'a' * 43)
    with connect(publisher.m.DB) as db:
        db.execute("UPDATE nodes SET server_id=? WHERE id='shared'", (row['id'],))
    return row['id']


def publish(publisher, uid='alice', target='exit1'):
    policy = user_routing.get_policy(publisher.m.DB, uid)
    saved = user_routing.save_draft(publisher.m.DB, uid, draft(target=target, node_ids=['shared']), policy['revision'])
    publisher.last_request.clear()
    publisher.enqueue(uid, saved['revision'])
    publisher.publish_pending()
    return user_routing.get_policy(publisher.m.DB, uid)


def exchange(publisher, sid, **changes):
    return fleet.process_report(publisher.m.DB, sid, report(**changes), configuration, account,
                                traffic_fn=lambda *args: {'blocked': False})


def test_remote_publication_waits_for_real_running_ack_and_checks_own_nodes(publisher):
    sid = remote(publisher)
    policy = publish(publisher)
    assert policy['status'] == 'syncing'
    publisher.m.runtime.apply.assert_not_called()
    # Remote validation is deferred to that server's independent coordinator.
    publisher.m.check_document.assert_not_called()
    assert [node['tag'] for node in configuration(publisher.m.DB,sid)['inbounds']]==['shared']
    before = rollout.public_status(publisher.m.DB, 'alice')
    assert before['confirmed'] == 0 and before['targets'][0]['status'] == 'offline'
    desired = exchange(publisher, sid, metrics={'running': True})
    exchange(publisher, sid, applied_revision=desired['revision'], metrics={'running': False})
    assert rollout.public_status(publisher.m.DB, 'alice')['confirmed'] == 0
    exchange(publisher, sid, applied_revision=desired['revision'], metrics={'running': True})
    assert rollout.public_status(publisher.m.DB, 'alice')['state'] == 'applied'
    assert user_routing.get_policy(publisher.m.DB, 'alice')['status'] == 'applied'


def test_only_issued_hash_failure_is_reported_without_exposing_diagnostics(publisher):
    sid = remote(publisher)
    publish(publisher)
    desired = exchange(publisher, sid)
    exchange(publisher, sid, error='SECRET password: hidden', apply_result={'revision': '0' * 64, 'ok': False})
    assert rollout.public_status(publisher.m.DB, 'alice')['state'] == 'syncing'
    exchange(publisher, sid, apply_result={'revision': desired['revision'], 'ok': False, 'error': 'SECRET password: hidden'})
    failed = rollout.public_status(publisher.m.DB, 'alice')
    assert failed['state'] == 'failed' and 'SECRET' not in json.dumps(failed)
    assert user_routing.get_policy(publisher.m.DB, 'alice')['applied']['enabled']
    exchange(publisher, sid, applied_revision=desired['revision'], metrics={'running': True},
             apply_result={'revision': desired['revision'], 'ok': False})
    assert rollout.public_status(publisher.m.DB, 'alice')['state'] == 'applied'


def test_new_revision_supersedes_pending_but_old_hash_cannot_confirm_it(publisher):
    sid = remote(publisher)
    publish(publisher)
    old = exchange(publisher, sid)
    policy = publish(publisher, target='exit2')
    assert policy['revision'] == 2 and policy['status'] == 'syncing'
    exchange(publisher, sid, applied_revision=old['revision'], metrics={'running': True})
    assert rollout.public_status(publisher.m.DB, 'alice')['confirmed'] == 0
    latest = exchange(publisher, sid)
    exchange(publisher, sid, applied_revision=latest['revision'], metrics={'running': True})
    assert rollout.public_status(publisher.m.DB, 'alice')['revision'] == 2
    assert rollout.public_status(publisher.m.DB, 'alice')['state'] == 'applied'


def test_later_other_user_config_can_confirm_both_policy_revisions(publisher):
    sid = remote(publisher)
    publish(publisher)
    exchange(publisher, sid)
    publish(publisher, uid='bob')
    latest = exchange(publisher, sid)
    exchange(publisher, sid, applied_revision=latest['revision'], metrics={'running': True})
    assert all(rollout.public_status(publisher.m.DB, uid)['state'] == 'applied' for uid in ('alice', 'bob'))


def test_reset_user_waits_for_remote_cleanup_and_paused_is_not_confirmed(publisher):
    sid = remote(publisher)
    publish(publisher)
    desired = exchange(publisher, sid)
    exchange(publisher, sid, applied_revision=desired['revision'], metrics={'running': True})
    policy = publisher.reset_user('alice')
    assert policy['status'] == 'syncing' and policy['applied']['rules'] == []
    fleet.set_action(publisher.m.DB, sid, 'stop')
    assert rollout.public_status(publisher.m.DB, 'alice')['targets'][0]['status'] == 'paused'
    publisher.m.runtime.apply.assert_not_called()
    fleet.set_action(publisher.m.DB, sid, 'start')
    latest = exchange(publisher, sid)
    exchange(publisher, sid, applied_revision=latest['revision'], metrics={'running': True})
    assert rollout.public_status(publisher.m.DB, 'alice')['state'] == 'applied'


def test_first_report_cannot_ack_a_hash_not_previously_sent(publisher):
    sid = remote(publisher)
    publish(publisher)
    document = configuration(publisher.m.DB, sid, 19190)
    digest = hashlib.sha256(json.dumps(document, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    initial = exchange(publisher, sid, applied_revision=digest, metrics={'running': True})
    assert initial['config'] == document
    assert rollout.public_status(publisher.m.DB, 'alice')['confirmed'] == 0
    exchange(publisher, sid, applied_revision=digest, metrics={'running': True})
    assert rollout.public_status(publisher.m.DB, 'alice')['confirmed'] == 1


def test_new_machine_is_projected_without_get_writes_and_joins_delivery(publisher, monkeypatch):
    user_routing.save_draft(publisher.m.DB, 'alice', draft(), 0)
    publisher.enqueue('alice', 1)
    publisher.publish_pending()
    sid = remote(publisher)
    # Moving this fixture node simulates a new server assignment; the public
    # projection must already show pending even before its first report.
    original_connect = rollout.connect
    def readonly(path):
        db = original_connect(path)
        db.set_authorizer(lambda action, *args: sqlite3.SQLITE_DENY if action in
                          (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE) else sqlite3.SQLITE_OK)
        return db
    with monkeypatch.context() as patch:
        patch.setattr(rollout, 'connect', readonly)
        state = rollout.public_status(publisher.m.DB, 'alice')
    assert state['total'] == 2 and state['confirmed'] == 1 and state['state'] == 'syncing'
    initial = exchange(publisher, sid)
    exchange(publisher, sid, applied_revision=initial['revision'], metrics={'running': True})
    assert rollout.public_status(publisher.m.DB, 'alice')['state'] == 'applied'


def test_revoked_machine_names_are_hidden_and_deleted_targets_do_not_block_reset(publisher):
    sid = remote(publisher)
    publish(publisher)
    with connect(publisher.m.DB) as db:
        db.execute("DELETE FROM memberships WHERE user_id='alice' AND node_id='shared'")
    status = rollout.public_status(publisher.m.DB, 'alice')
    assert status['targets'][0]['server_id'] == '' and status['targets'][0]['name'] == '原节点配置清理'
    assert sid not in json.dumps(status) and 'Tokyo' not in json.dumps(status)
    with connect(publisher.m.DB) as db:
        db.execute("DELETE FROM nodes WHERE id='shared'")
    fleet.set_action(publisher.m.DB, sid, 'delete')
    publisher.reset_user('alice')
    status = rollout.public_status(publisher.m.DB, 'alice')
    assert status['state'] == 'applied' and status['total'] == 0


def test_per_machine_checks_do_not_hold_runtime_lock(publisher):
    remote(publisher)
    publisher.m.check_document.side_effect = lambda document: (
        (_ for _ in ()).throw(AssertionError('core check held runtime.lock'))
        if publisher.m.runtime.lock._is_owned() else None)
    assert publish(publisher)['status'] == 'syncing'
    assert publisher.reset_user('alice')['status'] == 'syncing'


def test_local_quota_pause_cannot_confirm_publish_or_reset(publisher, monkeypatch):
    from panel import server_traffic
    blocked = [True]
    monkeypatch.setattr(server_traffic, 'summary', lambda path, sid: {'blocked': blocked[0] and sid == 'local'})
    user_routing.save_draft(publisher.m.DB, 'alice', draft(), 0)
    publisher.enqueue('alice', 1)
    publisher.publish_pending()
    status = rollout.public_status(publisher.m.DB, 'alice')
    assert status['confirmed'] == 0 and status['targets'][0]['status'] == 'paused'
    rollout.confirm_local(publisher.m.DB)
    assert rollout.public_status(publisher.m.DB, 'alice')['confirmed'] == 0
    blocked[0] = False
    rollout.confirm_local(publisher.m.DB)
    assert rollout.public_status(publisher.m.DB, 'alice')['state'] == 'applied'
    blocked[0] = True
    assert publisher.reset_user('alice')['status'] == 'syncing'
    assert rollout.public_status(publisher.m.DB, 'alice')['targets'][0]['status'] == 'paused'


def test_paused_machine_does_not_replay_a_stale_failure_as_new_publication_failure(publisher):
    sid = remote(publisher)
    publish(publisher)
    desired = exchange(publisher, sid)
    fleet.set_action(publisher.m.DB, sid, 'stop')
    exchange(publisher, sid, apply_result={'revision': desired['revision'], 'ok': False})
    state = rollout.public_status(publisher.m.DB, 'alice')
    assert state['state'] == 'syncing' and state['targets'][0]['status'] == 'paused'


def test_completed_cleanup_does_not_keep_an_unrelated_machine_in_future_rollouts(publisher):
    sid = remote(publisher)
    publish(publisher)
    desired = exchange(publisher, sid)
    exchange(publisher, sid, applied_revision=desired['revision'], metrics={'running': True})
    publisher.reset_user('alice')
    cleared = exchange(publisher, sid)
    exchange(publisher, sid, applied_revision=cleared['revision'], metrics={'running': True})
    assert rollout.target_servers(publisher.m.DB, 'alice', {'enabled': True, 'rules': []}) == set()


def test_deleting_empty_server_clears_pending_delivery_and_refreshes_policy(publisher):
    sid = remote(publisher)
    publish(publisher)
    exchange(publisher, sid)
    assert user_routing.get_policy(publisher.m.DB, 'alice')['status'] == 'syncing'
    with connect(publisher.m.DB) as db:
        db.execute("DELETE FROM nodes WHERE server_id=?", (sid,))
    fleet.set_action(publisher.m.DB, sid, 'delete')
    assert rollout.public_status(publisher.m.DB, 'alice') == {'revision': 1, 'total': 0, 'confirmed': 0, 'state': 'applied', 'targets': []}
    assert user_routing.get_policy(publisher.m.DB, 'alice')['status'] == 'applied'
    with connect(publisher.m.DB) as db:
        assert not db.execute('SELECT 1 FROM routing_config_deliveries WHERE server_id=?', (sid,)).fetchone()
