"""Performance regressions with accounting and authentication invariants."""
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from panel.core import connect, init_db, account, records
from panel.management import presence
from test_app import client, csrf
from customer_helpers import customer_login


def test_unchanged_counters_do_not_write_or_create_idle_days(tmp_path, monkeypatch):
    path=tmp_path/'panel.db';init_db(path)
    with connect(path) as db:
        db.execute("INSERT INTO users(id,name,secret,uuid,token) VALUES('u','User','secret','uuid','token')")
    key='user>>>u>>>traffic>>>uplink'
    account(path,'epoch',{key:0},day='2026-01-01')
    account(path,'epoch',{key:10},day='2026-01-01')
    import panel.core as core
    opened=[]
    def tracked(path):
        db=connect(path);opened.append(db)
        return db
    # sqlite total_changes can only be queried before closing.
    changes=[]
    from contextlib import contextmanager
    @contextmanager
    def measured(path):
        with tracked(path) as db:
            yield db
            changes.append(db.total_changes)
    monkeypatch.setattr(core,'connect',measured)
    account(path,'epoch',{key:10},day='2026-01-02')
    assert changes==[0]
    with connect(path) as db:
        assert db.execute('SELECT count(*) FROM daily').fetchone()[0]==1
        assert db.execute('SELECT value FROM samples').fetchone()[0]==10
    with pytest.raises(ValueError):account(path,'epoch',{key:9})
    account(path,'new-epoch',{key:3},day='2026-01-02')
    assert records(path,'users')[0]['upload']==13


def test_presence_coalesces_connections_preserving_ip_limit(tmp_path,monkeypatch):
    path=tmp_path/'panel.db';init_db(path)
    with connect(path) as db:
        db.execute("INSERT INTO users(id,name,secret,uuid,token,max_ips) VALUES('u','User','secret','uuid','token',1)")
    import panel.management as management
    from contextlib import contextmanager
    changes=[]
    @contextmanager
    def measured(path):
        with connect(path) as db:
            yield db
            changes.append(db.total_changes)
    monkeypatch.setattr(management,'connect',measured)
    conns=[{'id':str(i),'start':str(i).zfill(4),'metadata':{'inboundUser':'n:u','sourceIP':'192.0.2.1'}} for i in range(100)]
    conns.append({'id':'blocked','start':'9999','metadata':{'inboundUser':'n:u','sourceIP':'192.0.2.2'}})
    closed=[]
    result=presence(path,conns,closed.append,now=100)
    assert result['u']=={'ips':['192.0.2.1'],'connections':100}
    assert closed==['blocked'] and changes==[2]
    presence(path,conns,closed.append,now=200)
    with connect(path) as db:
        row=db.execute('SELECT * FROM client_ips').fetchone()
        assert (row['first_seen'],row['last_seen'])==(100,200)


def test_private_responses_not_cached_and_versioned_assets_are_cookie_free(client):
    c,m=client
    from panel.assets import asset_url
    url=asset_url('select.js')
    response=c.get(url)
    assert response.status_code==200 and 'immutable' in response.headers['cache-control']
    assert 'set-cookie' not in response.headers
    etag=response.headers['etag']
    conditional=c.get(url,headers={'If-None-Match':etag})
    assert conditional.status_code==304 and 'set-cookie' not in conditional.headers
    assert 'immutable' in conditional.headers['cache-control']
    for path in ('/users','/system/metrics','/static/select.js','/static/select.js?v=old','/static/missing.js?v=anything'):
        assert c.get(path).headers['cache-control']=='no-store'


def test_fixed_paths_do_not_read_entry_settings(client,monkeypatch):
    c,m=client
    import panel.paths as paths
    def unexpected(*args):raise AssertionError('Fixed path accessed entry settings')
    monkeypatch.setattr(paths,'read_settings',unexpected)
    assert c.get('/static/select.js').status_code==200
    assert c.get('/health').status_code in (200,503)


def test_traffic_fragment_requires_customer_and_skips_profile_generation(client,monkeypatch):
    c,m=client
    with connect(m.DB) as db:
        db.execute("INSERT INTO users(id,name,secret,uuid,token) VALUES('u','User','secret','uuid','token')")
    assert c.get('/s/token/traffic').status_code==401
    customer_login(c,'/s/token')
    def unexpected(*args):raise AssertionError('Full share context generated')
    monkeypatch.setattr(m,'share_context',unexpected)
    for period,count in [('24h',24),('7d',7),('30d',30)]:
        response=c.get('/s/token/traffic',params={'period':period})
        assert response.status_code==200 and response.text.count('data-traffic-tip')==count
        assert '<html' not in response.text and response.headers['cache-control']=='no-store'
    assert c.get('/s/token/qr/page').status_code==200


def test_node_check_does_not_block_event_loop_and_rechecks_revocation(client,monkeypatch):
    c,m=client;t=csrf(c)
    entered=threading.Event();release=threading.Event()
    def slow_check(document):
        entered.set();assert release.wait(10)
    monkeypatch.setattr(m,'check_document',slow_check)
    with ThreadPoolExecutor(max_workers=2) as pool:
        future=pool.submit(c.post,'/nodes',data={'token':t,'name':'Test','protocol':'snell6','mode':'shared'})
        try:
            assert entered.wait(5)
            health=pool.submit(c.get,'/health')
            assert health.result(timeout=2).status_code in (200,503)
            m.auth['revision']=m.auth.get('revision',0)+1
        finally:release.set()
        assert future.result(timeout=5).status_code==401
    assert records(m.DB,'nodes')==[]


def test_queued_settings_save_rechecks_revocation(client):
    c,m=client;t=csrf(c)
    before=m.read_settings(m.DB)
    entered=threading.Event()
    original=m.runtime.lock
    class QueuedLock:
        def __enter__(self):
            entered.set();original.acquire()
        def __exit__(self,*args):original.release()
    m.runtime.lock=QueuedLock()
    with ThreadPoolExecutor(max_workers=1) as pool:
        with original:
            future=pool.submit(c.post,'/settings',data={**before,'token':t,'brand':'Unauthorized change'})
            assert entered.wait(5)
            m.auth['revision']=m.auth.get('revision',0)+1
        assert future.result(timeout=5).status_code==401
    assert m.read_settings(m.DB)==before
