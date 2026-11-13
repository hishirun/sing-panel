"""Publication transaction tests; no production core or credentials involved."""
import copy
import json
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from panel import routing, routing_publish, user_routing
from panel.core import connect, current_config
from test_user_routing import policy_db, draft, publish_for_test, terminal_rules


@pytest.fixture
def publisher(policy_db, monkeypatch):
    module = SimpleNamespace(DB=policy_db, DIRECTORY=policy_db.parent, BINARY='unused-in-unit-tests', STATS_PORT=19090,
                             runtime=SimpleNamespace(lock=threading.RLock(), apply=Mock()), check_document=Mock())
    monkeypatch.setattr(routing, 'prepare_rule_sets', lambda *args: None)
    return routing_publish.Publisher(module)


def save(publisher, uid='alice', target='exit1'):
    old = user_routing.get_policy(publisher.m.DB, uid)
    return user_routing.save_draft(publisher.m.DB, uid, draft(target), old['revision'])


def journal(publisher):
    with connect(publisher.m.DB) as db:
        return db.execute('SELECT * FROM routing_publish_journal').fetchall()


def test_enqueued_users_are_coalesced_into_one_core_apply(publisher):
    for uid in ('alice', 'bob'):
        save(publisher, uid)
        assert publisher.enqueue(uid, 1)['status'] == 'queued'
    snapshots = []
    publisher.m.runtime.apply.side_effect = lambda: snapshots.append(current_config(publisher.m.DB))
    publisher.publish_pending()
    assert publisher.m.runtime.apply.call_count == 1
    assert len(terminal_rules(snapshots[0])) == 2
    for uid in ('alice', 'bob'):
        policy = user_routing.get_policy(publisher.m.DB, uid)
        assert policy['status'] == 'applied'
        assert policy['applied_revision'] == policy['revision'] == 1
        assert policy['applied'] == policy['draft']
        assert policy['applied_at'] > 0
    assert not journal(publisher)
    with connect(publisher.m.DB) as db:
        assert db.execute("SELECT COUNT(*) FROM audit_log WHERE action='用户应用分流'").fetchone()[0] == 2


def test_queue_revision_idempotency_and_rate_limit(publisher):
    save(publisher)
    with pytest.raises(user_routing.RevisionConflict):publisher.enqueue('alice', 0)
    publisher.enqueue('alice', 1)
    assert publisher.enqueue('alice', 1)['status'] == 'queued'
    with pytest.raises(user_routing.RevisionConflict):save(publisher)
    publisher.publish_pending()
    save(publisher)
    with pytest.raises(ValueError, match='频繁'):publisher.enqueue('alice', 2)


def test_failed_runtime_restores_applied_document_and_revision(publisher):
    publish_for_test(publisher.m.DB, 'alice', draft('exit2'))
    old = user_routing.get_policy(publisher.m.DB, 'alice')
    save(publisher)
    publisher.enqueue('alice', 2)
    publisher.m.runtime.apply.side_effect = [RuntimeError('private startup diagnostic'), None]
    publisher.publish_pending()
    actual = user_routing.get_policy(publisher.m.DB, 'alice')
    assert actual['status'] == 'failed'
    assert actual['applied'] == old['applied']
    assert actual['applied_revision'] == old['applied_revision']
    assert actual['draft'] != old['applied']
    assert 'private startup diagnostic' not in actual['error']
    assert publisher.m.runtime.apply.call_count == 2
    assert publisher.last_batch > 0  # Failed restarts must also be throttled.
    assert not journal(publisher)


def test_validation_and_download_failure_do_not_promote_or_leak(publisher, monkeypatch):
    save(publisher)
    publisher.enqueue('alice', 1)
    monkeypatch.setattr(routing, 'prepare_rule_sets', Mock(side_effect=RuntimeError('password=secret-diagnostic')))
    publisher.publish_pending()
    policy = user_routing.get_policy(publisher.m.DB, 'alice')
    assert policy['status'] == 'failed'
    assert policy['applied_revision'] == 0
    assert policy['applied']['rules'] == []
    assert 'secret-diagnostic' not in policy['error']
    publisher.m.runtime.apply.assert_not_called()
    assert not journal(publisher)


def test_check_failure_preserves_original_runtime(publisher):
    save(publisher)
    publisher.enqueue('alice', 1)
    publisher.m.check_document.side_effect = RuntimeError('private core configuration')
    publisher.publish_pending()
    policy = user_routing.get_policy(publisher.m.DB, 'alice')
    assert policy['status'] == 'failed' and policy['applied_revision'] == 0
    assert 'private' not in policy['error']
    publisher.m.runtime.apply.assert_not_called()


def test_exit_revocation_during_download_prevents_promotion(publisher, monkeypatch):
    save(publisher, target='exit2')
    publisher.enqueue('alice', 1)
    def revoke(*args):
        settings = routing.load(publisher.m.DB)
        settings['outbounds'][1]['public']['groups'] = []
        routing.write(publisher.m.DB, settings)
    monkeypatch.setattr(routing, 'prepare_rule_sets', revoke)
    publisher.publish_pending()
    policy = user_routing.get_policy(publisher.m.DB, 'alice')
    assert policy['status'] == 'failed'
    assert policy['applied_revision'] == 0
    publisher.m.runtime.apply.assert_not_called()


def test_user_revocation_during_download_prevents_promotion(publisher, monkeypatch):
    save(publisher)
    publisher.enqueue('alice', 1)
    monkeypatch.setattr(routing, 'prepare_rule_sets', lambda *args: user_routing.configure_user(publisher.m.DB, 'alice', False))
    publisher.publish_pending()
    policy = user_routing.get_policy(publisher.m.DB, 'alice')
    assert policy['status'] == 'failed' and not policy['allowed']
    assert policy['applied_revision'] == 0
    publisher.m.runtime.apply.assert_not_called()


def test_jobs_queued_during_preparation_remain_for_next_batch(publisher, monkeypatch):
    save(publisher, 'alice');save(publisher, 'bob')
    publisher.enqueue('alice', 1)
    monkeypatch.setattr(routing, 'prepare_rule_sets', lambda *args: publisher.enqueue('bob', 1))
    publisher.publish_pending()
    assert user_routing.get_policy(publisher.m.DB, 'alice')['status'] == 'applied'
    assert user_routing.get_policy(publisher.m.DB, 'bob')['status'] == 'queued'
    monkeypatch.setattr(routing, 'prepare_rule_sets', lambda *args: None)
    publisher.publish_pending()
    assert user_routing.get_policy(publisher.m.DB, 'bob')['status'] == 'applied'
    assert publisher.m.runtime.apply.call_count == 2


def test_startup_recovery_restores_journaled_policy(publisher):
    publish_for_test(publisher.m.DB, 'alice', draft('exit2'))
    old = user_routing.get_policy(publisher.m.DB, 'alice')
    save(publisher);publisher.enqueue('alice', 2)
    save(publisher, 'bob');publisher.enqueue('bob', 1)
    publisher.m.runtime.apply.side_effect = KeyboardInterrupt()
    with pytest.raises(KeyboardInterrupt):publisher.publish_pending()
    assert journal(publisher)
    assert user_routing.get_policy(publisher.m.DB, 'alice')['applied_revision'] == 2
    with pytest.raises(ValueError, match='恢复'):
        publisher.enqueue('bob', 1)
    restored = routing_publish.Publisher(publisher.m)
    restored.recover()
    policy = user_routing.get_policy(publisher.m.DB, 'alice')
    assert policy['applied'] == old['applied']
    assert policy['applied_revision'] == 1
    assert policy['status'] == 'failed'
    assert user_routing.get_policy(publisher.m.DB, 'bob')['status'] == 'failed'
    assert not journal(publisher)


def test_post_launch_database_failure_rolls_back_and_retains_draft(publisher, monkeypatch):
    publish_for_test(publisher.m.DB, 'alice', draft('exit2'))
    old = user_routing.get_policy(publisher.m.DB, 'alice')
    save(publisher);publisher.enqueue('alice', 2)
    monkeypatch.setattr(routing_publish, 'audit', Mock(side_effect=RuntimeError('disk write failure')))
    publisher.publish_pending()
    policy = user_routing.get_policy(publisher.m.DB, 'alice')
    assert policy['status'] == 'failed'
    assert policy['applied'] == old['applied']
    assert policy['applied_revision'] == old['applied_revision']
    assert policy['draft'] != old['applied']
    assert publisher.m.runtime.apply.call_count == 2
    assert not journal(publisher)


def test_reset_default_and_failed_reset_restore_policy(publisher):
    publish_for_test(publisher.m.DB, 'alice', draft())
    old = user_routing.get_policy(publisher.m.DB, 'alice')
    publisher.m.runtime.apply.side_effect = [RuntimeError('launch'), None]
    with pytest.raises(ValueError, match='原策略'):publisher.reset_user('alice')
    assert user_routing.get_policy(publisher.m.DB, 'alice') == old
    publisher.m.runtime.apply.side_effect = None
    new = publisher.reset_user('alice')
    assert new['draft'] == new['applied'] == {'enabled': True, 'rules': []}
    assert new['revision'] == new['applied_revision'] == old['revision']+1


def test_failed_rollback_keeps_journal_and_blocks_later_batch(publisher, monkeypatch):
    publish_for_test(publisher.m.DB, 'alice', draft('exit2'))
    save(publisher);save(publisher, 'bob')
    publisher.enqueue('alice', 2)
    monkeypatch.setattr(routing, 'prepare_rule_sets', lambda *args: publisher.enqueue('bob', 1))
    publisher.m.runtime.apply.side_effect = RuntimeError('core remains unavailable')
    publisher.publish_pending()
    before = [dict(row) for row in journal(publisher)]
    assert before
    assert user_routing.get_policy(publisher.m.DB, 'alice')['status'] == 'failed'
    assert user_routing.get_policy(publisher.m.DB, 'bob')['status'] == 'queued'
    assert '恢复记录' in publisher.m.runtime.error
    with pytest.raises(ValueError, match='恢复'):publisher.enqueue('bob', 1)
    with pytest.raises(ValueError, match='恢复'):publisher.reset_user('alice')
    publisher.publish_pending()
    assert [dict(row) for row in journal(publisher)] == before
    assert publisher.m.runtime.apply.call_count == 2
    assert user_routing.get_policy(publisher.m.DB, 'bob')['status'] != 'applied'


def test_shutdown_during_download_does_not_launch_core_after_stop(publisher, monkeypatch):
    save(publisher)
    publisher.enqueue('alice', 1)
    monkeypatch.setattr(routing, 'prepare_rule_sets', lambda *args: publisher.stopped.set())
    publisher.publish_pending()
    policy = user_routing.get_policy(publisher.m.DB, 'alice')
    assert policy['status'] == 'failed' and policy['applied_revision'] == 0
    assert '停止' in policy['error']
    publisher.m.runtime.apply.assert_not_called()
    assert not journal(publisher)
