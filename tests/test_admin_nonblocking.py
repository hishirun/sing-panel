"""Slow administration must not block ASGI or overwrite concurrent changes."""
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from panel import admin as admin_module
from panel import routing
from panel.core import connect
from test_app import client, csrf


@pytest.fixture
def admin(client, monkeypatch):
    c, m = client
    m.routing_publisher.stop()
    monkeypatch.setattr(m.runtime, 'apply', lambda:None)
    monkeypatch.setattr(m, 'check_document', lambda document:None)
    with connect(m.DB) as db:
        db.execute("INSERT INTO users(id,name,secret,uuid,token,external_links) VALUES('u','User','proxy-secret','uuid','token-u','https://example.test/sub')")
        db.execute("INSERT INTO nodes(id,name,protocol,port,secret,mode) VALUES('n','Node','snell6',31001,'node-secret','shared')")
        db.execute("INSERT INTO memberships(user_id,node_id) VALUES('u','n')")
    return c, m, csrf(c)


def blocked_request(c, path, data, entered, release, inspect):
    """A watchdog also releases old blocking implementations on assertion failure."""
    watchdog = threading.Timer(4, release.set)
    watchdog.start()
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(c.post, path, data=data, follow_redirects=False)
            assert entered.wait(2), 'The operation never reached the blocking fixture'
            try:inspect()
            finally:release.set()
            return pending.result(timeout=5)
    finally:
        release.set();watchdog.cancel()


def test_rule_download_and_validation_release_runtime_lock(admin, monkeypatch):
    c,m,token=admin
    entered,release=threading.Event(),threading.Event()
    def prepare(*args):
        entered.set();assert release.wait(5)
    monkeypatch.setattr(routing, 'prepare_rule_sets', prepare)
    def inspect():
        acquired=m.runtime.lock.acquire(timeout=.5)
        assert acquired, 'Download held the core/accounting lock'
        m.runtime.lock.release()
        assert c.get('/users').status_code==200
    response=blocked_request(c,'/routing/settings',{'token':token,'final':'direct','sniff':'1'},entered,release,inspect)
    assert response.status_code==303
    assert routing.load(m.DB)['sniff'] is True


def test_slow_routing_edit_rejects_a_later_committed_edit(admin, monkeypatch):
    c,m,token=admin
    entered,release=threading.Event(),threading.Event()
    calls=[]
    def prepare(*args):
        calls.append(1)
        if len(calls)==1:
            entered.set();assert release.wait(5)
    monkeypatch.setattr(routing, 'prepare_rule_sets', prepare)
    def inspect():
        response=c.post('/routing/settings',data={'token':token,'final':'direct','sniff':'1'},follow_redirects=False)
        assert response.status_code==303
    response=blocked_request(c,'/routing/outbounds/save',{
        'token':token,'name':'First edit','type':'socks','server':'example.test','server_port':'1080',
    },entered,release,inspect)
    assert response.status_code==409
    actual=routing.load(m.DB)
    assert actual['sniff'] is True and actual['outbounds']==[]


@pytest.mark.parametrize('revocation', ['admin','user'])
def test_routing_rechecks_authorization_and_semantic_config_after_download(admin, monkeypatch, revocation):
    c,m,token=admin
    before=routing.load(m.DB)
    def prepare(*args):
        if revocation=='admin':m.auth['revision']=m.auth.get('revision',0)+1
        else:
            with m.runtime.lock,connect(m.DB) as db:db.execute("UPDATE users SET enabled=0 WHERE id='u'")
    monkeypatch.setattr(routing,'prepare_rule_sets',prepare)
    response=c.post('/routing/settings',data={'token':token,'final':'direct','sniff':'1'},follow_redirects=False)
    assert response.status_code==(401 if revocation=='admin' else 409)
    assert routing.load(m.DB)==before


@pytest.mark.parametrize('operation', ['user-save','user-external','node-bulk','restart','password'])
def test_blocking_admin_work_does_not_stop_other_requests(admin, monkeypatch, operation):
    c,m,token=admin
    entered,release=threading.Event(),threading.Event()
    def wait():
        entered.set();assert release.wait(5)
    if operation=='user-save':
        original=admin_module.set_memberships
        def blocked(*args):wait();return original(*args)
        monkeypatch.setattr(admin_module,'set_memberships',blocked)
        path='/users/save/u';data={'token':token,'name':'Updated','quota_gib':0,'node_ids':'n'}
    elif operation=='user-external':
        def refresh(*args):wait();return 'snell://fixture'
        monkeypatch.setattr(admin_module,'refresh_external',refresh)
        path='/users/bulk';data={'token':token,'ids':'u','action':'refresh_external'}
    elif operation=='node-bulk':
        monkeypatch.setattr(m,'rotate_ports',lambda *args:wait())
        path='/nodes/bulk';data={'token':token,'ids':'n','action':'randomize'}
    elif operation=='restart':
        monkeypatch.setattr(m.runtime,'apply',wait)
        path='/system/restart';data={'token':token}
    else:
        original=m.ph
        def verify(*args):wait();return original.verify(*args)
        monkeypatch.setattr(m,'ph',SimpleNamespace(verify=verify,hash=original.hash))
        path='/system/password';data={'token':token,'current_password':'test-password-only','new_password':'replacement-password'}
    def inspect():
        started=time.monotonic()
        # /health needs no runtime lock; it must remain serviceable while a
        # write is waiting on DB/core/network work in another worker.
        response=c.get('/health')
        assert response.status_code in (200,503)
        assert time.monotonic()-started<1, 'Blocking work ran on the ASGI event loop'
    assert blocked_request(c,path,data,entered,release,inspect).status_code==303


@pytest.mark.parametrize('path,data', [
    ('/users/save/u', {'name':'Unauthorized edit','quota_gib':0}),
    ('/users/bulk', {'ids':'u','action':'disable'}),
    ('/nodes/bulk', {'ids':'n','action':'disable'}),
    ('/system/restart', {}),
])
def test_admin_mutations_recheck_session_after_waiting_for_lock(admin, monkeypatch, path, data):
    c,m,token=admin
    original=m.runtime.lock
    class Revoke:
        def __enter__(self):
            original.acquire();m.auth['revision']=m.auth.get('revision',0)+1
        def __exit__(self,*args):original.release()
    monkeypatch.setattr(m.runtime,'lock',Revoke())
    response=c.post(path,data={'token':token,**data},follow_redirects=False)
    assert response.status_code==401
    with connect(m.DB) as db:
        assert dict(db.execute("SELECT name,enabled FROM users WHERE id='u'").fetchone())=={'name':'User','enabled':1}
        assert db.execute("SELECT enabled FROM nodes WHERE id='n'").fetchone()[0]==1


def test_admin_password_hashing_cannot_overwrite_newer_credentials(admin, monkeypatch):
    c,m,token=admin
    original=m.ph
    def hashed(value):
        encoded=original.hash(value)
        m.auth['revision']=m.auth.get('revision',0)+1
        m.auth['username']='new-administrator'
        m.AUTH.write_text(json.dumps(m.auth))
        return encoded
    monkeypatch.setattr(m,'ph',SimpleNamespace(verify=original.verify,hash=hashed))
    response=c.post('/system/password',data={'token':token,'current_password':'test-password-only',
        'new_password':'replacement-password'},follow_redirects=False)
    assert response.status_code==401
    actual=json.loads(m.AUTH.read_text())
    assert actual['username']=='new-administrator'
    assert original.verify(actual['password_hash'],'test-password-only')


def test_external_download_rechecks_admin_before_writing_cache(admin, monkeypatch):
    c,m,token=admin
    def refresh(*args):
        m.auth['revision']=m.auth.get('revision',0)+1
        return 'unapproved-cache'
    monkeypatch.setattr(admin_module,'refresh_external',refresh)
    response=c.post('/users/bulk',data={'token':token,'ids':'u','action':'refresh_external'},follow_redirects=False)
    assert response.status_code==401
    with connect(m.DB) as db:assert db.execute("SELECT external_cache FROM users WHERE id='u'").fetchone()[0]==''


def test_restore_defaults_rechecks_admin_after_configuration_check(admin, monkeypatch):
    from panel import user_routing
    c,m,token=admin
    user_routing.configure_user(m.DB,'u',True)
    policy=user_routing.get_policy(m.DB,'u')
    policy.update(revision=1,applied_revision=1,
        draft={'enabled':True,'rules':[{'id':'r','name':'Keep','enabled':True,'kind':'domain_suffix',
             'values':['example.test'],'target':'reject','node_ids':[]}]})
    policy['applied']=policy['draft']
    user_routing.restore_policy(m.DB,'u',policy)
    before=user_routing.get_policy(m.DB,'u')
    def validation(*args):m.auth['revision']=m.auth.get('revision',0)+1
    monkeypatch.setattr(m.routing_publisher,'validate_documents',validation)
    response=c.post('/users/u/routing',data={'token':token,'intent':'reset'},follow_redirects=False)
    assert response.status_code==401
    assert user_routing.get_policy(m.DB,'u')==before
