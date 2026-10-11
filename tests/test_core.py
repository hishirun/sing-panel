import pytest
from panel.core import init_db, connect, records, config, account, reason
from panel.subscriptions import outbounds

@pytest.fixture
def db(tmp_path):
    path=tmp_path/'panel.db'
    init_db(path)
    with connect(path) as c:
        c.execute("INSERT INTO users(id,name,secret,uuid,token) VALUES('alice','Alice','secret','uuid','token')")
    return path

def test_account_idempotent_and_restart(db):
    key='user>>>alice>>>traffic>>>uplink'
    for epoch,value in [('one',100),('one',100),('one',150),('two',20)]:
        account(db,epoch,{key:value})
    assert records(db,'users')[0]['upload']==170

def test_invalid_sample_rolls_back(db):
    key='user>>>alice>>>traffic>>>uplink'
    account(db,'one',{key:100})
    with pytest.raises(ValueError):
        account(db,'one',{'user>>>alice>>>traffic>>>downlink':50,key:99})
    assert records(db,'users')[0]['download']==0

def test_only_user_counts_no_double_billing(db):
    account(db,'one',{'inbound>>>alice>>>traffic>>>uplink':500,'user>>>alice>>>traffic>>>downlink':50})
    assert records(db,'users')[0]['download']==50
    assert records(db,'users')[0]['upload']==0

def test_quota_and_expiry(db):
    u=records(db,'users')[0]
    u.update(quota=100,upload=60,download=40)
    assert reason(u)=='额度耗尽'
    u.update(quota=0,expires=100)
    assert reason(u,now=100)=='已到期'
    u.update(expires=0,enabled=0)
    assert reason(u)=='手动停用'

def test_reset_keeps_sample_baseline(db):
    key='user>>>alice>>>traffic>>>uplink'
    account(db,'one',{key:100})
    with connect(db) as c:c.execute('UPDATE users SET upload=0,download=0')
    account(db,'one',{key:110})
    assert records(db,'users')[0]['upload']==10

def test_grants_and_no_empty_authentication(db):
    u=records(db,'users')[0]
    n=dict(id='node',name='node',protocol='snell6',port=31000,secret='0123456789abcdef',enabled=1)
    assert config([n],[u],[])['inbounds']==[]
    m=[dict(node_id='node',user_id='alice')]
    doc=config([n],[u],m)
    assert doc['inbounds'][0]['users']==[{'name':'node:alice','userkey':'secret'}]
    assert outbounds(u,[n],m,'example.com')[0]['userkey']=='secret'
    u['enabled']=0
    assert config([n],[u],m)['inbounds']==[]
    assert outbounds(u,[n],m,'example.com')==[]

def test_compat_ports_preserved_and_native_exports(db):
    from panel.core import set_memberships, current_config
    from panel.subscriptions import native_subscription
    with connect(db) as c:
        c.execute("INSERT INTO nodes(id,name,protocol,port,secret,mode) VALUES('n','Node','snell6',32000,'server-secret','compat')")
        set_memberships(c,'alice',['n'])
        c.execute("INSERT INTO users(id,name,secret,uuid,token) VALUES('bob','Bob','bob-secret','bob-uuid','bob-token')")
        set_memberships(c,'bob',['n'])
        set_memberships(c,'alice',['n'])
    ports=[m['port'] for m in records(db,'memberships')]
    assert ports[0]==32000 and ports[1]!=32000 and 20000<=ports[1]<=65000
    doc=current_config(db)
    assert doc['inbounds'][0]['psk']=='secret'
    assert 'users' not in doc['inbounds'][0]
    assert doc['experimental']['v2ray_api']['stats']['inbounds']==['n:alice','n:bob']
    account(db,'one',{'inbound>>>n:alice>>>traffic>>>uplink':100,'inbound>>>n:bob>>>traffic>>>uplink':20})
    assert [u['upload'] for u in records(db,'users')]==[100,20]
    outs=outbounds(records(db,'users')[0],records(db,'nodes'),records(db,'memberships'),'test.example.com')
    assert outs[0]['psk']=='secret'
    assert 'userkey' not in outs[0]
    assert 'psk=secret, version=6' in native_subscription(outs,'surge.conf')

def test_node_accounting_shared_and_compat_no_double_count(db):
    with connect(db) as c:
        c.execute("INSERT INTO nodes(id,name,protocol,port,secret) VALUES('n1','Node One','snell6',32001,'secret')")
        c.execute("INSERT INTO nodes(id,name,protocol,port,secret) VALUES('n2','Node Two','snell6',32002,'secret')")
    counters={'user>>>n1:alice>>>traffic>>>uplink':100,'user>>>n1:alice>>>traffic>>>downlink':200,'inbound>>>n2:alice>>>traffic>>>downlink':300}
    account(db,'epoch',counters,day='2026-10-11')
    account(db,'epoch',counters,day='2026-10-11')
    assert records(db,'users')[0]['upload']==100
    assert records(db,'users')[0]['download']==500
    with connect(db) as c:
        assert c.execute('SELECT SUM(upload+download) FROM node_daily').fetchone()[0]==600
        assert c.execute('SELECT SUM(upload+download) FROM node_hourly').fetchone()[0]==600
        assert c.execute('SELECT SUM(upload+download) FROM daily').fetchone()[0]==600
        c.execute('UPDATE users SET upload=0,download=0')
    account(db,'epoch',dict(counters,**{'user>>>n1:alice>>>traffic>>>uplink':150}),day='2026-10-12')
    assert records(db,'users')[0]['upload']==50
    with connect(db) as c:assert c.execute('SELECT SUM(upload+download) FROM node_daily').fetchone()[0]==650
