import json
from datetime import datetime, timezone
from panel.core import connect, records, account
from panel.management import maintain, next_boundary, presence
from test_app import client, csrf

def test_management_pages_and_bulk_lifecycle(client):
    c,m=client;t=csrf(c)
    assert all(c.get(path).status_code==200 for path in ('/users','/nodes','/settings','/system/status','/users/new'))
    c.post('/nodes',data={'token':t,'name':'N','protocol':'snell6','mode':'compat'})
    node=records(m.DB,'nodes')[0]
    data={'token':t,'name':'Team','quantity':2,'group_name':'Friends','comment':'note','node_ids':node['id'],
          'quota_gib':1,'first_use_days':7,'renew_mode':'days','renew_days':30,'renew_limit':2,
          'reset_mode':'monthly','reset_day':1,'max_ips':1}
    assert c.post('/users/create',data=data).status_code==200
    users=records(m.DB,'users');assert len(users)==2
    assert all(u['expires']==0 and u['group_name']=='Friends' for u in users)
    assert '等待激活' in c.get('/s/'+users[0]['token']).text
    account(m.DB,'epoch',{'user>>>'+users[0]['id']+'>>>traffic>>>uplink':100})
    user=records(m.DB,'users')[0]
    assert user['activated_at'] and user['expires']==user['activated_at']+7*86400
    page=c.get('/users?q=Team&group=Friends');assert 'Team-001' in page.text
    ids=[u['id'] for u in users]
    assert c.post('/users/bulk',data={'token':t,'ids':ids,'action':'adjust','add_days':3,'add_gib':1}).status_code==200
    assert all(u['quota']==2*1024**3 for u in records(m.DB,'users'))
    assert c.post('/users/bulk',data={'token':t,'ids':ids,'action':'disable'}).status_code==200
    assert not any(u['enabled'] for u in records(m.DB,'users'))
    assert c.post('/users/bulk',data={'token':t,'ids':ids,'action':'reset'}).status_code==200
    account(m.DB,'epoch',{'user>>>'+ids[0]+'>>>traffic>>>uplink':110})
    assert records(m.DB,'users')[0]['upload']==10
    assert c.post('/users/bulk',data={'token':'wrong','ids':ids,'action':'delete'}).status_code==403
    assert c.post('/users/bulk',data={'token':t,'ids':[ids[0],'missing'],'action':'delete'}).status_code==422
    assert len(records(m.DB,'users'))==2

def test_calendar_and_renewals_preserve_manual_disable(client):
    c,m=client
    jan31=int(datetime(2026,1,31,tzinfo=timezone.utc).timestamp())
    assert datetime.fromtimestamp(next_boundary(jan31,'monthly',day=31),timezone.utc).day==28
    with connect(m.DB) as db:
        policy=json.dumps({'renew_mode':'days','renew_days':1,'renew_limit':2,'reset_mode':'none'})
        for identity,enabled in [('active',1),('disabled',0)]:
            db.execute('INSERT INTO users(id,name,secret,uuid,token,expires,upload,enabled,policy) VALUES(?,?,?,?,?,?,?,?,?)',
                       (identity,identity,'secret',identity,identity,100,99,enabled,policy))
    maintain(m.DB,now=100+86400)
    active,disabled=records(m.DB,'users')
    assert active['expires']==100+2*86400 and active['upload']==0
    assert disabled['expires']==100 and disabled['upload']==99
    maintain(m.DB,now=100+86400)
    assert json.loads(records(m.DB,'users')[0]['policy'])['renew_count']==2
    maintain(m.DB,now=100+4*86400)
    assert records(m.DB,'users')[0]['expires']==100+2*86400

def test_presence_mapping_and_ip_limit(client):
    c,m=client
    with connect(m.DB) as db:
        db.execute("INSERT INTO users(id,name,secret,uuid,token,max_ips) VALUES('u','U','secret','uuid','token',1)")
    conns=[{'id':'one','start':'1','metadata':{'inboundUser':'u','inboundTag':'node','sourceIP':'1.1.1.1'}},
           {'id':'two','start':'2','metadata':{'inboundTag':'node:u','sourceIP':'2.2.2.2'}},
           {'id':'three','start':'3','metadata':{'inboundUser':'other','sourceIP':'3.3.3.3'}}]
    closed=[];result=presence(m.DB,conns,closed.append,now=500)
    assert closed==['two'] and result['u']['ips']==['1.1.1.1']
    assert records(m.DB,'users')[0]['last_seen']==500
    with connect(m.DB) as db:assert db.execute('SELECT count(*) FROM client_ips').fetchone()[0]==1

def test_node_clone_external_subscription_and_backup(client):
    c,m=client;t=csrf(c)
    c.post('/nodes',data={'token':t,'name':'N','protocol':'snell6','mode':'shared','group_name':'G'})
    n=records(m.DB,'nodes')[0]
    assert c.post('/nodes/bulk',data={'token':t,'ids':[n['id']],'action':'clone'}).status_code==200
    a,b=records(m.DB,'nodes');assert a['port']!=b['port'] and not b['enabled'] and b['group_name']=='G'
    link='vless://11111111-1111-4111-8111-111111111111@example.com:443?security=reality#external'
    assert c.post('/users/create',data={'token':t,'name':'External','external_links':link}).status_code==200
    u=records(m.DB,'users')[0]
    import base64
    assert link in base64.b64decode(c.get('/s/'+u['token']+'/shadowrocket.txt').text).decode()
    assert c.get('/system/backup').content.startswith(b'SQLite format 3')
    c.cookies.clear();assert c.get('/system/backup').status_code==401

def test_periodic_reset_keeps_sampling_baseline_and_phase(client):
    c,m=client
    policy={'reset_mode':'days','reset_days':1,'reset_day':1,'reset_weekday':1,'next_reset':100,'renew_mode':'none'}
    with connect(m.DB) as db:
        db.execute('INSERT INTO users(id,name,secret,uuid,token,policy) VALUES(?,?,?,?,?,?)',('u','U','secret','uuid','token',json.dumps(policy)))
    account(m.DB,'e',{'user>>>u>>>traffic>>>uplink':1000})
    maintain(m.DB,now=100+86400+10)
    u=records(m.DB,'users')[0]
    assert u['upload']==0 and json.loads(u['policy'])['next_reset']==100+2*86400
    account(m.DB,'e',{'user>>>u>>>traffic>>>uplink':1010})
    assert records(m.DB,'users')[0]['upload']==10
    maintain(m.DB,now=100+86400+20)
    assert records(m.DB,'users')[0]['upload']==10
