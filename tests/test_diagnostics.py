import asyncio
import json
import time
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from test_app import client,csrf
from panel.core import connect
from panel.diagnostics import clean_log,record,stream,tail


def test_subscription_records_client_format_errors_without_secrets(client):
    c,m=client;t=csrf(c)
    c.post('/users',data={'token':t,'name':'<Xiang>'})
    user=m.records(m.DB,'users')[0]
    link='/s/'+user['token']
    assert c.get(link+'/clash.yaml',headers={'User-Agent':'Clash/1.0 SECRET-UA'}).status_code==200
    assert c.get(link+'/invalid-secret-format').status_code==400
    assert c.get('/s/missing/clash.yaml').status_code==404
    with connect(m.DB) as db:
        rows=[dict(r) for r in db.execute('SELECT * FROM subscription_fetches ORDER BY id')]
    assert len(rows)==2 and rows[0]['client']=='Clash' and rows[0]['format']=='clash.yaml'
    assert rows[1]['status']==400 and rows[1]['format']=='未知格式'
    assert all(user['token'] not in str(r) and 'SECRET-UA' not in str(r) for r in rows)
    page=c.get('/system/subscriptions');assert page.status_code==200 and '&lt;Xiang&gt;' in page.text
    assert c.get('/system/subscriptions?result=failed').text.count('未知格式')==1
    c.cookies.clear()
    assert c.get('/system/subscriptions').status_code==401
    assert c.get('/system/live').status_code==401
    assert c.get('/servers/live').status_code==401
    assert c.get('/system/diagnostics').status_code==401


def test_history_cursor_frozen_window_and_retention(client):
    c,m=client
    for i in range(55):record(m.DB,'u','Surge','surge.conf',200,5,time.monotonic())
    with connect(m.DB) as db:window=db.execute('SELECT MAX(id) FROM subscription_fetches').fetchone()[0]
    record(m.DB,'u','Clash','clash.yaml',200,2,time.monotonic())
    page=c.get('/system/subscriptions',params={'window':window,'before':window-49})
    assert 'Clash' not in page.text and page.text.count('surge.conf')==5
    with connect(m.DB) as db:db.execute("UPDATE subscription_fetches SET timestamp=0 WHERE id=1")
    record(m.DB,'u','Surge','surge.conf',200,5,time.monotonic())
    with connect(m.DB) as db:assert db.execute('SELECT 1 FROM subscription_fetches WHERE id=1').fetchone() is None


def test_log_tail_is_bounded_redacted_and_escaped(client,tmp_path):
    c,m=client
    path=m.DIRECTORY/'core.log'
    path.write_text('x'*20000+'\nERROR <script>alert(1)</script> password=secret-value https://host/share/private-token\n')
    text=tail(path)
    assert len(text)<=12000 and 'secret-value' not in text and 'private-token' not in text
    assert '<script>' in text # Browser renders via textContent, never HTML.
    assert clean_log('\x1b[31mERROR\x1b[0m psk:abc')=='ERROR psk:[隐藏]'
    assert c.get('/system/diagnostics').status_code==200
    assert c.get('/system/diagnostics?server=missing').status_code==404


def test_stream_rechecks_authorization_on_every_event():
    async def run():
        calls=[]
        request=SimpleNamespace(is_disconnected=lambda:asyncio.sleep(0,result=False))
        def producer():
            calls.append(1)
            raise HTTPException(401)
        response=stream(request,producer,None)
        frames=[frame async for frame in response.body_iterator]
        assert len(calls)==1 and len(frames)==1 and 'event: expired' in frames[0]
        assert response.headers['cache-control']=='no-store'
    asyncio.run(run())


def test_remote_logs_only_from_authenticated_report(client):
    # Existing fleet authorization tests cover report admission; no public log route.
    c,m=client
    with connect(m.DB) as db:
        db.execute("INSERT INTO server_logs VALUES('remote',123,'ERROR remote')")
    c.cookies.clear()
    assert c.get('/system/live?server=remote').status_code==401


def test_agent_log_snapshot_is_bounded_and_server_scoped(tmp_path):
    from test_fleet import registered,configured,report,reconcile
    from panel.core import init_db
    path=tmp_path/'fleet.db';init_db(path)
    sid,_=registered(path);uid,nid,doc,key=configured(path,sid)
    reconcile(path,sid,report(logs='x'*20000+'\nERROR password=hidden-secret'),doc)
    with connect(path) as db:
        row=db.execute('SELECT * FROM server_logs').fetchone()
        assert row['server_id']==sid and len(row['content'])<=12000 and 'hidden-secret' not in row['content']
    # Older agents omit logs; existing snapshot remains available with its timestamp.
    reconcile(path,sid,report(),doc)
    with connect(path) as db:assert db.execute('SELECT COUNT(*) FROM server_logs').fetchone()[0]==1
