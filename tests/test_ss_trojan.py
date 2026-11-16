import base64,json,os,socket,subprocess,threading,time,uuid
from pathlib import Path
import pytest
from panel.core import init_db,connect,records,set_memberships,config,account
from panel.options import NodeOptions
from panel.protocols import new_key,user_key
from panel.subscriptions import outbounds,native_subscription
from panel.client_profiles import ini_profile,mihomo_profile,singbox_profile
from test_app import client,csrf
from test_tls_protocols import certificate
from loopback_fixture import LoopbackFixtureRuntime
from traffic_audit import receive,socks
from test_integration import port

CASES=[('ss','compat',m,'tcp') for m in ('aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305')]+[('ss2022','shared',m,'tcp') for m in ('2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm')]+[('ss2022','compat',m,'tcp') for m in ('2022-blake3-chacha20-poly1305','2022-blake3-aes-128-gcm')]+[('trojan','shared','chacha20-ietf-poly1305',tr) for tr in ('tcp','ws','grpc')]

def seed(path,proto,mode,method,tr,cert,key):
    init_db(path)
    opts=NodeOptions(listen='127.0.0.1',ss_method=method,trojan_transport=tr,ws_path='/test',grpc_service_name='TestService',certificate_path=str(cert),key_path=str(key)).model_dump()
    with connect(path) as db:
        db.execute('INSERT INTO nodes(id,name,protocol,port,secret,mode,server_name,options) VALUES(?,?,?,?,?,?,?,?)',('node','Test node',proto,port(),new_key(method) if proto=='ss2022' else 'node-secret-123456789',mode,'localhost.example.com',json.dumps(opts)))
        for uid in ('alice','bob'):
            db.execute('INSERT INTO users(id,name,secret,uuid,token) VALUES(?,?,?,?,?)',(uid,uid,uid+'-secret-0123456789',str(uuid.uuid4()),uid+'-token'))
            set_memberships(db,uid,['node'])

@pytest.mark.skipif(not os.environ.get('SING_BOX'),reason='SING_BOX required')
@pytest.mark.parametrize('proto,mode,method,tr',CASES)
def test_real_tcp_udp_exact_accounting_and_user_isolation(tmp_path,certificate,proto,mode,method,tr):
    cert,key=certificate;path=tmp_path/'panel.db';seed(path,proto,mode,method,tr,cert,key)
    rt=LoopbackFixtureRuntime(os.environ['SING_BOX'],tmp_path,port());process=None
    try:
        rt.apply()
        for uid in ('alice','bob'):
            user=next(u for u in records(path,'users') if u['id']==uid)
            out=outbounds(user,records(path,'nodes'),records(path,'memberships'),'127.0.0.1')[0]
            if proto=='trojan':out['tls']['certificate_path']=str(cert)
            client_port=port();filename=tmp_path/(uid+'.json');filename.write_text(json.dumps({'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':client_port}],'outbounds':[out]}))
            with (tmp_path/'client.log').open('a') as log:process=subprocess.Popen([os.environ['SING_BOX'],'run','-c',str(filename)],stdout=log,stderr=log)
            for _ in range(100):
                try:
                    with socket.create_connection(('127.0.0.1',client_port),timeout=.1):break
                except OSError:
                    if process.poll() is not None:pytest.fail((tmp_path/'client.log').read_text())
                    time.sleep(.05)
            def count():
                rt.sample();u=next(u for u in records(path,'users') if u['id']==uid)
                return u['upload'],u['download']
            before=count();upload=b'u'*32768;download=b'd'*65536
            listener=socket.socket();listener.bind(('127.0.0.1',0));listener.listen();target=listener.getsockname()[1]
            errors=[]
            def tcp():
                try:
                    with listener.accept()[0] as peer:
                        peer.settimeout(10);assert receive(peer,len(upload))==upload;peer.sendall(download)
                except Exception as exc:errors.append(str(exc))
                finally:listener.close()
            worker=threading.Thread(target=tcp,daemon=True);worker.start()
            with socket.create_connection(('127.0.0.1',client_port),timeout=10) as peer:
                peer.settimeout(10);socks(peer,1,target);peer.sendall(upload);assert receive(peer,len(download))==download
            worker.join(3);assert not errors;time.sleep(.15)
            after=count();assert (after[0]-before[0],after[1]-before[1])==(len(upload),len(download))
            udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0));udp.settimeout(10);target=udp.getsockname()[1]
            def echo():
                try:
                    for _ in range(4):
                        data,address=udp.recvfrom(4096);assert data==b'x'*512;udp.sendto(b'y'*1024,address)
                except Exception as exc:errors.append(str(exc))
                finally:udp.close()
            worker=threading.Thread(target=echo,daemon=True);worker.start();before=count()
            with socket.create_connection(('127.0.0.1',client_port),timeout=10) as control:
                address,relay=socks(control,3)
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as local:
                    local.settimeout(10)
                    for _ in range(4):
                        local.sendto(b'\x00\x00\x00\x01\x7f\x00\x00\x01'+target.to_bytes(2,'big')+b'x'*512,('127.0.0.1',relay))
                        reply,_=local.recvfrom(4096);assert reply.endswith(b'y'*1024)
            worker.join(3);assert not errors;time.sleep(.15);after=count()
            assert (after[0]-before[0],after[1]-before[1])==(2048,4096)
            process.terminate();process.wait(timeout=5);process=None
        users=records(path,'users')
        assert all((u['upload'],u['download'])==(34816,69632) for u in users)
        with connect(path) as db:
            assert [tuple(r) for r in db.execute('SELECT upload,download FROM node_daily ORDER BY user_id')]==[(34816,69632),(34816,69632)]
            db.execute("UPDATE users SET quota=1 WHERE id='alice'")
        assert outbounds(records(path,'users')[0],records(path,'nodes'),records(path,'memberships'),'127.0.0.1')==[]
        from panel.core import current_config
        compiled=json.dumps(current_config(path))
        assert 'node:alice' not in compiled and 'node:bob' in compiled
    finally:
        if process:process.terminate();process.wait(timeout=5)
        rt.stop()


def test_admin_protocol_options_validation_and_private_exports(client,certificate):
    c,m=client;cert,key=certificate;t=csrf(c)
    for proto in ('ss','ss2022','trojan'):
        page=c.get('/nodes/new?protocol='+proto)
        assert page.status_code==200
        assert ('Trojan · 传输方式' in page.text)==(proto=='trojan')
        raw={'token':t,'name':proto,'protocol':proto}
        if proto=='trojan':raw.update(server_name='localhost.example.com',certificate_path=str(cert),key_path=str(key))
        assert c.post('/nodes',data=raw).status_code==200
    nodes=records(m.DB,'nodes');assert [n['mode'] for n in nodes]==['compat','shared','shared']
    for node in nodes:
        assert c.post('/users',data={'token':t,'name':'U-'+node['protocol'],'node_ids':node['id']}).status_code==200
    users=records(m.DB,'users')
    for user in users:
        response=c.get('/s/'+user['token']+'/sing-box.json');assert response.status_code==200
        assert 'private_key' not in response.text and 'certificate_path' not in response.text
        for other in users:
            if user['id']!=other['id']:assert other['secret'] not in response.text
        for fmt in ('clash.yaml','surge.conf','surfboard.conf','shadowrocket.txt'):
            assert c.get('/s/'+user['token']+'/'+fmt).headers['X-Subscription-Node-Count']=='1'
    assert c.post('/nodes',data={'token':t,'name':'bad','protocol':'ss2022','ss_server_key':'bad-key'}).status_code==422
    assert c.post('/nodes',data={'token':t,'name':'bad','protocol':'ss2022','ss_method':'aes-128-gcm'}).status_code==422
    assert c.post('/nodes',data={'token':t,'name':'bad','protocol':'ss2022','ss_method':'2022-blake3-chacha20-poly1305','mode':'shared'}).status_code==422

@pytest.mark.parametrize('proto,mode,method,tr',CASES)
def test_subscription_formats_credentials_and_transport(tmp_path,certificate,proto,mode,method,tr):
    import yaml
    cert,key=certificate;path=tmp_path/'panel.db';seed(path,proto,mode,method,tr,cert,key)
    users=records(path,'users');nodes=records(path,'nodes');members=records(path,'memberships')
    outs=outbounds(users[0],nodes,members,'example.com');out=outs[0]
    assert users[1]['secret'] not in json.dumps(out) and 'key_path' not in json.dumps(out)
    if proto=='ss2022':
        assert user_key(nodes[0],users[1]) not in out['password']
        assert len(base64.b64decode(user_key(nodes[0],users[0])))==(16 if 'aes-128' in method else 32)
    text=base64.b64decode(native_subscription(outs,'shadowrocket.txt')).decode()
    assert text.startswith('trojan://' if proto=='trojan' else 'ss://')
    from urllib.parse import urlsplit,unquote,parse_qs
    link=urlsplit(text.strip())
    if proto=='trojan':
        assert unquote(link.username)==out['password'] and parse_qs(link.query)['type']==[tr]
    elif proto=='ss2022':
        assert link.username==method and unquote(link.password)==out['password']
    else:
        raw=link.netloc.split('@',1)[0]
        assert base64.urlsafe_b64decode(raw+'='*(-len(raw)%4)).decode()==method+':'+out['password']
    body,count=mihomo_profile(outs,'https://example.com/s/test');assert count==1
    proxy=yaml.safe_load(body)['proxies'][0]
    assert proxy['password']==out['password']
    if tr!='tcp':assert proxy['network']==tr
    for fmt in ('surge.conf','surfboard.conf'):
        body,count=ini_profile(outs,fmt,'https://example.com/s/test',users[0])
        assert count==(0 if tr=='grpc' or method.endswith('chacha20-poly1305') and method.startswith('2022-') else 1)
        if count:assert out['password'] in body and 'skip-cert-verify=true' not in body
