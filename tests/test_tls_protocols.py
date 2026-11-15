from test_app import client

import base64,json,os,subprocess,threading,time
from http.server import ThreadingHTTPServer
import pytest
from panel.core import init_db,connect,records,set_memberships,config
from panel.subscriptions import outbounds,native_subscription
from panel.options import NodeOptions
from loopback_fixture import LoopbackFixtureRuntime
from test_integration import Handler,port,exchange
BINARY=os.environ.get('SING_BOX')

@pytest.fixture
def certificate(tmp_path):
    cert=tmp_path/'cert.pem';key=tmp_path/'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,DNS:localhost.example.com,IP:127.0.0.1','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
    return cert,key

@pytest.mark.skipif(not BINARY,reason='SING_BOX required')
@pytest.mark.parametrize('proto,obfs',[('anytls','none'),('hysteria2','none'),('hysteria2','salamander'),('hysteria2','gecko')])
def test_tls_protocol_real_connection_and_user_node_accounting(tmp_path,certificate,proto,obfs):
    cert,key=certificate;db=tmp_path/'panel.db';init_db(db)
    options=NodeOptions(certificate_path=str(cert),key_path=str(key),hy_obfs=obfs,hy_obfs_password='test-obfs-secret',any_padding='stop=8\n0=30-30\n1=100-400').model_dump()
    with connect(db) as c:
        c.execute('INSERT INTO nodes(id,name,protocol,port,secret,mode,server_name,options) VALUES(?,?,?,?,?,?,?,?)',('tls-node','TLS Node',proto,port(),'node-secret','shared','localhost',json.dumps(options)))
        for uid in ['alice','bob']:
            c.execute('INSERT INTO users(id,name,secret,uuid,token) VALUES(?,?,?,?,?)',(uid,uid,uid+'-secret-0123456789',uid,uid))
            set_memberships(c,uid,['tls-node'])
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler);rt=LoopbackFixtureRuntime(BINARY,tmp_path,port())
    threading.Thread(target=server.serve_forever,daemon=True).start();client=None
    try:
        rt.apply()
        u=records(db,'users')[0];outs=outbounds(u,records(db,'nodes'),records(db,'memberships'),'127.0.0.1')
        serialized=json.dumps(outs)
        assert 'key_path' not in serialized and 'certificate_path' not in serialized and 'insecure' not in serialized
        assert 'bob-secret' not in serialized
        native=base64.b64decode(native_subscription(outs,'shadowrocket.txt')).decode()
        assert (not native.strip()) if obfs=='gecko' else native.startswith(proto+'://')
        outs[0]['tls']['certificate_path']=str(cert)
        socks=port();document={'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':socks}],'outbounds':outs}
        path=tmp_path/'client.json';path.write_text(json.dumps(document))
        with (tmp_path/'client.log').open('w') as log:client=subprocess.Popen([BINARY,'run','-c',str(path)],stdout=log,stderr=log)
        import socket
        for _ in range(60):
            try:
                with socket.create_connection(('127.0.0.1',socks),timeout=.2):break
            except OSError:time.sleep(.05)
        exchange(socks,server.server_port)
        rt.sample();before_udp=records(db,'users')[0]
        from traffic_audit import socks as socks_request
        udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(('127.0.0.1',0));udp.settimeout(5)
        target=udp.getsockname()[1];errors=[]
        def udp_echo():
            try:
                for _ in range(2):
                    payload,peer=udp.recvfrom(4096)
                    assert payload==b'probe'*80
                    udp.sendto(b'reply'*160,peer)
            except Exception as error:errors.append(str(error))
            finally:udp.close()
        worker=threading.Thread(target=udp_echo,daemon=True);worker.start()
        with socket.create_connection(('127.0.0.1',socks),timeout=10) as control:
            _,relay=socks_request(control,3)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as packet:
                packet.settimeout(10)
                for _ in range(2):
                    packet.sendto(b'\0\0\0\1\x7f\0\0\1'+target.to_bytes(2,'big')+b'probe'*80,('127.0.0.1',relay))
                    response=packet.recv(4096)
                    offset=22 if response[3]==4 else 10
                    assert response[offset:]==b'reply'*160
        worker.join(timeout=5);assert not errors
        time.sleep(.15);rt.sample();after_udp=records(db,'users')[0]
        assert after_udp['upload']-before_udp['upload']==800
        assert after_udp['download']-before_udp['download']==1600

        client.terminate();client.wait(timeout=10);client=None
        time.sleep(.15);rt.sample();users=records(db,'users')
        assert users[0]['upload']>=32768 and users[0]['download']>=131072
        assert users[1]['upload']==users[1]['download']==0
        with connect(db) as c:
            r=c.execute('SELECT SUM(upload),SUM(download) FROM node_daily WHERE user_id=?',('alice',)).fetchone()
            assert tuple(r)==(users[0]['upload'],users[0]['download'])
            c.execute("UPDATE users SET enabled=0 WHERE id='alice'")
        outs=outbounds(records(db,'users')[0],records(db,'nodes'),records(db,'memberships'),'127.0.0.1')
        assert outs==[]
    finally:
        if client:client.terminate();client.wait(timeout=10)
        rt.stop();server.shutdown()

def test_protocol_option_validation():
    from pydantic import ValidationError
    for raw in [dict(hy_obfs='salamander'),dict(hy_gecko_min=1400,hy_gecko_max=1200),dict(hy_up_mbps=10,hy_ignore_client_bandwidth=True),dict(connect_host='https://bad/path')]:
        with pytest.raises(ValidationError):NodeOptions(**raw)

def test_admin_tls_node_forms_save_and_no_private_data_in_subscription(client,certificate):
    from test_app import csrf
    c,m=client;cert,key=certificate;t=csrf(c)
    for proto in ['anytls','hysteria2']:
        page=c.get('/nodes/new?protocol='+proto)
        assert page.status_code==200
        assert 'TLS 证书' in page.text and 'Reality · SNI' not in page.text
        assert ('TCP 连接设置' in page.text)==(proto=='anytls')
        raw={'token':t,'name':proto,'protocol':proto,'server_name':'wrong.example.com','certificate_path':str(cert),'key_path':str(key)}
        assert c.post('/nodes',data=raw).status_code==422
        raw['server_name']='localhost.example.com'
        assert c.post('/nodes',data=raw).status_code==200
        node=m.records(m.DB,'nodes')[-1]
        assert node['protocol']==proto and node['mode']=='shared'
        assert c.get('/nodes/'+node['id']+'/edit').status_code==200



def test_share_reset_date_display(client):
    from test_app import csrf
    c,m=client;t=csrf(c)
    c.post('/users/create',data={'token':t,'name':'Cycle','quota_gib':10,'reset_mode':'daily'})
    from panel.management import maintain
    maintain(m.DB)
    u=m.records(m.DB,'users')[0]
    page=c.get('/s/'+u['token'])
    assert '下次重置' in page.text and '北京时间' in page.text
    assert '计算中' not in page.text

def test_share_reset_includes_automatic_renewal(client):
    from test_app import csrf
    c,m=client;t=csrf(c)
    c.post('/users/create',data={'token':t,'name':'Renew','quota_gib':10,'expiry':'2027-01-01','renew_mode':'monthly'})
    u=m.records(m.DB,'users')[0]
    from panel.sharing import share_context
    view=share_context(m.DB,u,'test.example.com','https://panel.example.com')
    assert view['reset_at']==u['expires'] and view['reset_local']=='2027-01-01 08:00'
