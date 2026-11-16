import sqlite3
import time
from datetime import datetime,timezone
import pytest
from agent.storage import Spool
from panel import fleet
from panel.core import account,connect,init_db
from test_fleet import registered,configured,report,reconcile,uploaded
from test_app import client


def test_hourly_spool_preserves_days_fifo_and_inflight_snapshots(tmp_path):
    queue=Spool(tmp_path)
    key='user>>>n:u>>>traffic>>>uplink'
    queue.store('epoch',{key:100},observed_at=100000)
    first=queue.oldest()
    queue.store('epoch',{key:150},observed_at=100010)
    assert queue.oldest()==first # A sent batch is frozen even before its ACK.
    queue.store('epoch',{key:200},observed_at=104000)
    restored=Spool(tmp_path);values=[];times=[];sequences=[]
    while row:=restored.oldest():
        values.append(row['counters'][key]);times.append(row['observed_at']);sequences.append(row['sequence'])
        restored.acknowledge(row['report_id'])
    assert values==[100,150,200] and times==[100000,100010,104000] and sequences==[1,2,3]
    assert restored.summary()['pending_reports']==0
    with pytest.raises(ValueError):restored.store('epoch',{key:199},observed_at=104010)


def test_legacy_spool_is_drained_before_timestamped_samples(tmp_path):
    queue=Spool(tmp_path)
    with queue.connect() as db:db.execute('INSERT INTO reports VALUES(?,?,?,?)',('old-epoch','legacy-id','{"key":10}',10))
    queue.store('old-epoch',{'key':20},observed_at=100)
    assert queue.oldest()['report_id']=='legacy-id'
    queue.acknowledge('legacy-id')
    assert queue.oldest()['counters']=={'key':20} and queue.oldest()['sequence']==1


def system(tmp_path):
    path=tmp_path/'panel.db';init_db(path)
    sid,_=registered(path);uid,nid,doc,key=configured(path,sid)
    reconcile(path,sid,report(),doc)
    return path,sid,uid,nid,doc,key


def test_late_cross_day_samples_and_replay_keep_original_buckets(tmp_path):
    path,sid,uid,nid,doc,key=system(tmp_path)
    stamps=[int(datetime(2026,10,31,23,59,tzinfo=timezone.utc).timestamp()),int(datetime(2026,11,1,0,1,tzinfo=timezone.utc).timestamp())]
    frames=[]
    for sequence,(stamp,value) in enumerate(zip(stamps,[100,160]),1):
        frame=report({key:value},accounting_version=2,sequence=sequence,observed_at=stamp)
        frames.append(frame);reconcile(path,sid,frame,doc);reconcile(path,sid,frame,doc)
    # Lost ACK replay of an old batch cannot add bytes or reassign history.
    reconcile(path,sid,frames[0],doc)
    with connect(path) as db:
        assert [tuple(r) for r in db.execute('SELECT day,upload FROM daily ORDER BY day')]==[('2026-10-31',100),('2026-11-01',60)]
        assert [r[0] for r in db.execute('SELECT hour FROM node_hourly ORDER BY hour')]==['2026-10-31T23:00','2026-11-01T00:00']
    assert uploaded(path,uid)==160


def test_counter_and_receipt_rollback_together(tmp_path):
    path,sid,uid,nid,doc,key=system(tmp_path)
    frame=report({key:100},accounting_version=2,sequence=1,observed_at=int(time.time())-10)
    def fail(*args,**kwargs):
        account(*args,**kwargs)
        raise RuntimeError('simulated commit failure')
    with pytest.raises(RuntimeError):fleet.process_report(path,sid,frame,lambda *args:doc,fail)
    assert uploaded(path,uid)==0
    with connect(path) as db:
        assert not db.execute('SELECT 1 FROM server_reports WHERE report_id=?',(frame['report_id'],)).fetchone()
        assert not db.execute('SELECT 1 FROM server_report_sequences').fetchone()
    reconcile(path,sid,frame,doc);assert uploaded(path,uid)==100


def test_out_of_order_and_mutated_batches_are_rejected(tmp_path):
    path,sid,uid,nid,doc,key=system(tmp_path);stamp=int(time.time())-10
    with pytest.raises(ValueError):reconcile(path,sid,report({key:100},accounting_version=2,sequence=2,observed_at=stamp),doc)
    reconcile(path,sid,report({key:100},accounting_version=2,sequence=1,observed_at=stamp),doc)
    with pytest.raises(ValueError):reconcile(path,sid,report({key:101},accounting_version=2,sequence=1,observed_at=stamp),doc)
    with pytest.raises(ValueError):reconcile(path,sid,report({key:110},accounting_version=2,sequence=2,observed_at=stamp-1),doc)
    assert uploaded(path,uid)==100


def test_old_cycle_backfill_does_not_consume_new_quota(tmp_path):
    path,sid,uid,nid,doc,key=system(tmp_path);stamp=int(time.time())-3600
    with connect(path) as db:db.execute('INSERT INTO user_accounting_windows VALUES(?,?)',(uid,stamp+60))
    reconcile(path,sid,report({key:100},accounting_version=2,sequence=1,observed_at=stamp),doc)
    assert uploaded(path,uid)==0
    with connect(path) as db:assert db.execute('SELECT SUM(upload) FROM daily').fetchone()[0]==100
    reconcile(path,sid,report({key:140},accounting_version=2,sequence=2,observed_at=stamp+120),doc)
    assert uploaded(path,uid)==40


def test_automatic_daily_reset_precedes_late_and_current_samples(tmp_path):
    import json
    path,sid,uid,nid,doc,key=system(tmp_path)
    now=int(time.time());today=now//86400*86400
    with connect(path) as db:
        db.execute('UPDATE users SET upload=500,policy=? WHERE id=?',(json.dumps({'reset_mode':'daily','reset_days':1,'reset_day':1,'reset_weekday':1,'next_reset':today}),uid))
    reconcile(path,sid,report({key:100},accounting_version=2,sequence=1,observed_at=today-30),doc,now=now)
    assert uploaded(path,uid)==0
    reconcile(path,sid,report({key:160},accounting_version=2,sequence=2,observed_at=today+30),doc,now=now)
    assert uploaded(path,uid)==60


def test_timestamped_spool_roundtrip_through_authenticated_websocket(client,tmp_path):
    from test_fleet_api import bearer
    c,m=client;sid,credential=registered(m.DB);uid,nid,doc,key=configured(m.DB,sid)
    stamp=int(time.time())-86400
    queue=Spool(tmp_path/'agent')
    queue.store('offline-core',{key:100},observed_at=stamp)
    queue.store('offline-core',{key:170},observed_at=stamp+86400)
    with c.websocket_connect('/agent/v1/ws',headers=bearer(sid,credential)) as ws:
        ws.send_json(report());assert ws.receive_json()['state']=='running'
        while batch:=queue.oldest():
            ws.send_json({'type':'report','protocol':1,'metrics':{},'applied_revision':'','error':'',**batch})
            ack=ws.receive_json()
            assert ack['accounting_version']==2 and ack['ack_report_id']==batch['report_id']
            queue.acknowledge(ack['ack_report_id'])
    with connect(m.DB) as db:
        totals=[r[0] for r in db.execute('SELECT upload FROM daily WHERE user_id=? ORDER BY day',(uid,))]
    assert totals==[100,70] and queue.count()==0


def test_agent_keeps_batch_when_old_controller_cannot_confirm_timestamped_accounting(tmp_path):
    import json
    from agent.client import Agent
    from agent.storage import atomic_json
    config=tmp_path/'config.json'
    atomic_json(config,{'panel':'https://panel.example','server_id':'server-a','credential':'a'*64,'data_dir':str(tmp_path),'binary':'/missing-test-core'})
    instance=Agent(config);instance.core.spool.store('epoch',{'counter':1})
    before=instance.core.spool.oldest()
    class OldController:
        def send(self,payload):self.message=json.loads(payload)
        def recv(self,timeout):return json.dumps({'type':'desired','protocol':1,'ack_report_id':self.message['report_id']})
    with pytest.raises(ValueError,match='timestamped accounting'):instance.exchange(OldController())
    assert instance.core.spool.oldest()==before
