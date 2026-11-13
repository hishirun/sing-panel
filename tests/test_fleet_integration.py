import json,time,tarfile,sqlite3
from pathlib import Path
import pytest
from panel.core import init_db,connect,account,current_config,records
from panel.fleet import save_server
from panel.fleet_config import configuration,retain_used_outbounds
from panel.subscriptions import outbounds
from panel import server_traffic as traffic
from panel.backups import Manager,listing,save

@pytest.fixture
def fleet_db(tmp_path):
    db=tmp_path/'panel.db';init_db(db)
    server=save_server(db,'Tokyo','203.0.113.25')
    sid=server['id']
    with connect(db) as c:
        c.execute("INSERT INTO users(id,name,secret,uuid,token,quota) VALUES('u','Alice','password123456','11111111-1111-4111-8111-111111111111','token',1000)")
        for nid,owner,port in [('local-node','local',30001),('remote-node',sid,30002)]:
            c.execute("INSERT INTO nodes(id,name,protocol,port,secret,server_id,mode) VALUES(?,?,'snell6',?,'nodepassword123',?,'shared')",(nid,nid,port,owner))
            c.execute("INSERT INTO memberships(user_id,node_id) VALUES('u',?)",(nid,))
    return db,sid


def test_server_scoped_configs_and_subscriptions(fleet_db):
    db,sid=fleet_db
    assert [n['tag'] for n in current_config(db)['inbounds']]==['local-node']
    remote=configuration(db,sid)
    assert [n['tag'] for n in remote['inbounds']]==['remote-node']
    assert remote['experimental']['v2ray_api']['listen']=='127.0.0.1:19190'
    users=records(db,'users');outs=outbounds(users[0],records(db,'nodes'),records(db,'memberships'),'198.51.100.2')
    assert {o['tag']:o['server'] for o in outs}=={'local-node':'198.51.100.2','remote-node':'203.0.113.25'}


def test_unused_upstream_credentials_never_leave_master():
    document={'route':{'final':'direct','rules':[{'outbound':'used'}]},'outbounds':[
        {'tag':'direct','type':'direct'}, {'tag':'used','type':'shadowsocks','detour':'transport'},
        {'tag':'transport','type':'socks'}, {'tag':'other-machine','type':'shadowsocks','password':'unrelated-secret'}]}
    retain_used_outbounds(document)
    assert {item['tag'] for item in document['outbounds']}=={'direct','used','transport'}
    assert 'unrelated-secret' not in json.dumps(document)


def test_shared_quota_and_cross_server_counter_isolation(fleet_db):
    db,sid=fleet_db
    local='user>>>local-node:u>>>traffic>>>uplink';remote='user>>>remote-node:u>>>traffic>>>downlink'
    account(db,'local-epoch',{local:400},server_id='local')
    account(db,'agent:'+sid+':epoch',{remote:600,local:999999},server_id=sid,ignore_stale=True)
    account(db,'agent:'+sid+':epoch',{remote:500},server_id=sid,ignore_stale=True)
    u=records(db,'users')[0]
    assert u['upload']==400 and u['download']==600
    assert not current_config(db)['inbounds'] and not configuration(db,sid)['inbounds']


def test_cross_machine_ip_limit_queues_after_presence_transaction(fleet_db,tmp_path,monkeypatch):
    from panel.runtime import Runtime
    from panel import fleet
    db,sid=fleet_db
    with connect(db) as c:c.execute("UPDATE users SET max_ips=1 WHERE id='u'")
    local={'id':'local-connection','start':'2026-01-01T00:00:00Z','metadata':{'inboundUser':'local-node:u','sourceIP':'192.0.2.1'}}
    remote={'id':'agent:'+sid+':remote','server_id':sid,'start':'2026-01-01T00:00:01Z','metadata':{'inboundUser':'remote-node:u','sourceIP':'192.0.2.2'}}
    monkeypatch.setattr(fleet,'presence_connections',lambda path:[remote])
    queued=[]
    def enqueue(path,server,action,**payload):
        # An independent write would lock if presence() still held its transaction.
        with connect(path) as c:c.execute("INSERT INTO audit_log(timestamp,action,detail) VALUES(1,'test','queued')")
        queued.append((server,action,payload))
    monkeypatch.setattr(fleet,'enqueue_command',enqueue)
    rt=Runtime('unused',tmp_path,19090)
    monkeypatch.setattr(rt,'control',lambda *args,**kwargs:{'connections':[local]})
    rt.track()
    assert rt.online['u']['ips']==['192.0.2.1']
    assert queued==[(sid,'disconnect_ip',{'user_id':'u','source_ip':'192.0.2.2'})]
    monkeypatch.setattr(rt,'control',lambda *args,**kwargs:(_ for _ in ()).throw(OSError('core down')))
    rt.disconnect('u')
    assert queued[-1]==(sid,'disconnect_user',{'user_id':'u'})
    def unavailable_delete(path='/connections',method='GET'):
        if method=='DELETE':raise OSError('local API disappeared')
        return {'connections':[local]}
    monkeypatch.setattr(rt,'control',unavailable_delete)
    with pytest.raises(ValueError,match='部分连接'):rt.disconnect('u')
    assert queued[-1]==(sid,'disconnect_user',{'user_id':'u'})


def test_global_presence_runs_when_local_core_apply_fails(fleet_db,tmp_path,monkeypatch):
    from panel.runtime import Runtime
    rt=Runtime('unused',tmp_path,19090);checked=[]
    monkeypatch.setattr(rt,'sample',lambda:None)
    monkeypatch.setattr(rt,'apply',lambda:(_ for _ in ()).throw(RuntimeError('local certificate unavailable')))
    monkeypatch.setattr(rt,'track',lambda:checked.append('global presence'))
    with pytest.raises(RuntimeError,match='certificate'):rt.tick()
    assert checked==['global presence']


def metric(stamp,rx,tx,boot='boot-one',uptime=100):
    return {'sampled_at':stamp,'uptime':uptime,'boot_id':boot,'interfaces':[{'name':'eth0','billable':True,'rx_total':rx,'tx_total':tx},{'name':'veth0','billable':False,'rx_total':999999,'tx_total':999999}]}


def test_machine_quota_baseline_dedup_reset_and_new_cycle(fleet_db,monkeypatch):
    db,sid=fleet_db;now=time.time();monkeypatch.setattr(traffic.time,'time',lambda:now+10)
    with connect(db) as c:c.execute('UPDATE servers SET monthly_quota=1000 WHERE id=?',(sid,))
    assert traffic.record(db,sid,metric(now,10000,20000))['used']==0
    assert traffic.record(db,sid,metric(now+1,10400,20500))['used']==900
    assert traffic.record(db,sid,metric(now+1,10400,20500))['used']==900
    assert traffic.record(db,sid,metric(now-1,100,200))['used']==900
    assert traffic.record(db,sid,metric(now+2,10,20,boot='boot-two'))['used']==930
    assert traffic.record(db,sid,metric(now+3,80,30,boot='boot-two'))['blocked']
    reset=traffic.summary(db,sid)['next_reset']
    assert traffic.summary(db,sid,now=reset+1)['used']==0
    assert not traffic.summary(db,sid,now=reset+1)['blocked']


def test_local_machine_limit_closes_only_local_inbounds(fleet_db,monkeypatch):
    db,sid=fleet_db;now=time.time();monkeypatch.setattr(traffic.time,'time',lambda:now+5)
    with connect(db) as c:c.execute("INSERT INTO settings VALUES('server_quota:local',?)",(json.dumps({'monthly_quota':100,'traffic_direction':'tx','reset_day':1}),))
    traffic.record(db,'local',metric(now,1000,1000))
    traffic.record(db,'local',metric(now+1,1000,1100))
    assert not current_config(db)['inbounds']
    assert configuration(db,sid)['inbounds']


def test_online_backup_contains_db_auth_tls_and_retains_files(fleet_db,tmp_path):
    db,sid=fleet_db
    (tmp_path/'auth.json').write_text('{"example":"private"}')
    (tmp_path/'tls').mkdir();(tmp_path/'tls'/'cert.pem').write_text('certificate')
    (tmp_path/'core.log').write_text('do not archive logs')
    (tmp_path/'tls'/'outside').symlink_to('/etc/hosts')
    save(db,{'enabled':'true','interval_hours':24,'keep':1})
    manager=Manager(db,tmp_path);first=manager.create();second=manager.create()
    assert [r['name'] for r in listing(tmp_path)]==[second]
    target=tmp_path/'backups'/'automatic'/second
    assert target.stat().st_mode&0o777==0o600
    with tarfile.open(target) as tar:
        assert set(tar.getnames())=={'panel.db','auth.json','tls/cert.pem'}
        saved=tmp_path/'read-only-backup.db';saved.write_bytes(tar.extractfile('panel.db').read())
    with sqlite3.connect(saved) as c:assert c.execute('SELECT count(*) FROM users').fetchone()[0]==1
