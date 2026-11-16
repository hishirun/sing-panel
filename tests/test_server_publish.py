"""A slow or invalid machine must not block another machine's delivery."""
import threading
from concurrent.futures import ThreadPoolExecutor
from panel import fleet,fleet_config
from panel.core import connect
from panel.server_publish import input_signature,status
from test_app import client
from test_routing_publish import publisher
from test_user_routing import policy_db
from test_fleet import registered,configured,report


def test_slow_machine_validates_outside_shared_lock_and_caches(client,monkeypatch):
    c,m=client
    a,_=registered(m.DB);ua,na,_,_=configured(m.DB,a)
    b,_=registered(m.DB,'Other');ub,nb,_,_=configured(m.DB,b,32002)
    entered=threading.Event();release=threading.Event();calls=[]
    original=fleet_config.configuration
    def build(path,sid,*args):
        calls.append(sid)
        if sid==a:entered.set();assert release.wait(5)
        return original(path,sid,*args)
    monkeypatch.setattr(fleet_config,'configuration',build)
    with ThreadPoolExecutor(max_workers=2) as pool:
        waiting=pool.submit(m.server_publisher.reconcile,a,report(),None,None)
        try:
            assert entered.wait(2)
            assert m.runtime.lock.acquire(timeout=.5);m.runtime.lock.release()
            busy=pool.submit(m.server_publisher.reconcile,a,report(),None,None).result(timeout=1)
            assert busy['lease_seconds']==0
            fast=pool.submit(m.server_publisher.reconcile,b,report(),None,None).result(timeout=2)
            assert fast['state']=='running' and fast['config']['inbounds'][0]['tag']==nb
        finally:release.set()
        assert waiting.result(timeout=5)['config']['inbounds'][0]['tag']==na
    # Routine byte-count changes and another machine's users do not recompile A.
    with connect(m.DB) as db:db.execute('UPDATE users SET upload=upload+1 WHERE id=?',(ua,))
    m.server_publisher.reconcile(a,report(),None,None)
    assert calls.count(a)==1 and calls.count(b)==1
    before=input_signature(m.DB,a)
    with connect(m.DB) as db:db.execute('UPDATE users SET secret=? WHERE id=?',('changed-credential',ub))
    assert input_signature(m.DB,a)==before


def test_invalid_machine_does_not_poison_another_publication(client,monkeypatch):
    c,m=client;a,_=registered(m.DB);_,na,_,_=configured(m.DB,a)
    b,_=registered(m.DB,'Other');_,nb,_,_=configured(m.DB,b,32002)
    def check(document):
        if document['inbounds'][0]['tag']==na:raise ValueError('password=private-diagnostic')
    monkeypatch.setattr(m,'check_document',check)
    failed=m.server_publisher.reconcile(a,report(),None,None)
    good=m.server_publisher.reconcile(b,report(),None,None)
    assert failed['lease_seconds']==0 and good['state']=='running'
    assert status(m.DB,a)['status']=='failed' and 'private-diagnostic' not in str(status(m.DB,a))
    assert status(m.DB,b)['status']=='ready'


def test_edit_during_validation_never_delivers_stale_credentials(client,monkeypatch):
    c,m=client;sid,_=registered(m.DB);uid,nid,_,_=configured(m.DB,sid)
    original=m.check_document
    def edit(document):
        with m.runtime.lock,connect(m.DB) as db:db.execute('UPDATE users SET secret=? WHERE id=?',('new-user-credential',uid))
    monkeypatch.setattr(m,'check_document',edit)
    result=m.server_publisher.reconcile(sid,report(),None,None)
    assert result['lease_seconds']==0 and 'config' not in result
    assert status(m.DB,sid)['status']=='queued'
    monkeypatch.setattr(m,'check_document',original)
    result=m.server_publisher.reconcile(sid,report(),None,None)
    assert result['config']['inbounds'][0]['users'][0]['userkey']=='new-user-credential'


def test_revocation_during_validation_cannot_renew_lease(client,monkeypatch):
    c,m=client;sid,_=registered(m.DB);configured(m.DB,sid)
    generation=fleet._raw(m.DB,sid)['credential_generation']
    def revoke(document):
        with m.runtime.lock,connect(m.DB) as db:db.execute('UPDATE servers SET credential_generation=credential_generation+1 WHERE id=?',(sid,))
    monkeypatch.setattr(m,'check_document',revoke)
    import pytest
    with pytest.raises(fleet.AuthenticationError):m.server_publisher.reconcile(sid,report(),generation,None)


def test_unrelated_user_policy_publishes_while_local_validation_waits(publisher,monkeypatch):
    import time
    from panel import user_routing
    from test_user_routing import draft
    from test_routing_publish import save
    sid,_=registered(publisher.m.DB,'Remote')
    with connect(publisher.m.DB) as db:db.execute("UPDATE nodes SET server_id=? WHERE id='compat'",(sid,))
    for uid,nid in [('alice','shared'),('bob','compat')]:
        p=user_routing.save_draft(publisher.m.DB,uid,draft(node_ids=[nid]),0)
        publisher.enqueue(uid,p['revision'])
    entered=threading.Event();release=threading.Event()
    def slow(document):entered.set();assert release.wait(5)
    monkeypatch.setattr(publisher.m,'check_document',slow)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future=pool.submit(publisher.publish_pending)
        try:
            assert entered.wait(2)
            deadline=time.monotonic()+2
            while user_routing.get_policy(publisher.m.DB,'bob')['status']=='applying' and time.monotonic()<deadline:time.sleep(.02)
            assert user_routing.get_policy(publisher.m.DB,'bob')['status']=='syncing'
            assert user_routing.get_policy(publisher.m.DB,'alice')['status']=='applying'
        finally:release.set()
        future.result(timeout=5)
