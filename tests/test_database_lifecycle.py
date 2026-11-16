import gc
import sqlite3

import pytest

from panel.core import connect


def test_frequent_status_queries_close_connections_without_waiting_for_gc(tmp_path):
    path = tmp_path / 'panel.db'
    with connect(path) as db:
        db.execute('CREATE TABLE values_test(value INTEGER)')
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(100):
            with connect(path) as db:
                assert db.execute('SELECT COUNT(*) FROM values_test').fetchone()[0] == 0
            with pytest.raises(sqlite3.ProgrammingError, match='closed'):
                db.execute('SELECT 1')
    finally:
        if was_enabled:
            gc.enable()


def test_connection_scope_still_commits_and_rolls_back_before_closing(tmp_path):
    path = tmp_path / 'panel.db'
    with connect(path) as db:
        db.execute('CREATE TABLE values_test(value INTEGER)')
        db.execute('INSERT INTO values_test VALUES(1)')
    with pytest.raises(ValueError, match='abort'):
        with connect(path) as db:
            db.execute('INSERT INTO values_test VALUES(2)')
            raise ValueError('abort')
    with connect(path) as db:
        assert [row[0] for row in db.execute('SELECT value FROM values_test')] == [1]


def test_agent_spool_queries_close_their_connection(tmp_path):
    from agent.storage import Spool
    spool = Spool(tmp_path)
    report_id = spool.store('epoch', {'traffic': 12})
    with spool.connect() as db:
        assert db.execute('SELECT report_id FROM timed_reports').fetchone()[0] == report_id
    with pytest.raises(sqlite3.ProgrammingError, match='closed'):
        db.execute('SELECT 1')
    assert spool.oldest()['counters'] == {'traffic': 12}
    spool.acknowledge(report_id)
    assert spool.count() == 0
