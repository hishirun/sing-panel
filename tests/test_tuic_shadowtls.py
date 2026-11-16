"""Composite protocols keep one grant, one meter, and private per-user auth."""
import base64,copy,json,os,socket,subprocess
import pytest
from panel.core import account,config,connect,current_config,records
from panel.options import NodeOptions
from panel.protocols import expand_singbox_nodes,shadow_password,user_key
from panel.subscriptions import outbounds,native_subscription
from panel.client_profiles import singbox_profile,ini_profile,mihomo_profile
from test_ss_trojan import seed
from test_tls_protocols import certificate
from test_app import client,csrf
from test_agent import core
from customer_helpers import customer_login


def test_unified_ss_form_and_safe_family_changes(client):
    c,m=client;t=csrf(c);page=c.get('/nodes/new?protocol=ss')
    assert 'protocol=ss2022' not in page.text
    for method in ('aes-128-gcm','2022-blake3-aes-128-gcm','2022-blake3-chacha20-poly1305'):assert method in page.text
    assert c.post('/nodes',data={'token':t,'name':'SS','protocol':'ss','ss_method':'2022-blake3-aes-128-gcm','mode':'compat'}).status_code==200
    node=records(m.DB,'nodes')[0];assert node['protocol']=='ss2022'
    assert c.post('/users',data={'token':t,'name':'Alice','node_ids':node['id']}).status_code==200
    before=records(m.DB,'memberships')
    assert c.post('/nodes/'+node['id']+'/edit',data={'token':t,'name':'SS','ss_method':'aes-256-gcm'}).status_code==200
    assert records(m.DB,'nodes')[0]['protocol']=='ss'
    assert records(m.DB,'memberships')==before
    assert c.post('/nodes/'+node['id']+'/edit',data={'token':t,'name':'SS','ss_method':'2022-blake3-aes-128-gcm','mode':'shared'}).status_code==422
    assert records(m.DB,'memberships')==before


@pytest.mark.parametrize('proto',('tuic','shadowtls'))
def test_new_protocol_forms_credentials_validation_and_customer_page(client,certificate,proto):
    c,m=client;cert,key=certificate;t=csrf(c)
    page=c.get('/nodes/new?protocol='+proto);assert page.status_code==200
    assert ('TUIC v5 · QUIC 设置' in page.text)==(proto=='tuic')
    assert ('一键组合' in page.text)
    raw={'token':t,'name':proto,'protocol':proto,'server_name':'localhost.example.com'}
    if proto=='tuic':raw.update(certificate_path=str(cert),key_path=str(key))
    assert c.post('/nodes',data={**raw,'tuic_congestion':'invalid'}).status_code==422
    if proto=='tuic':
        for invalid in ({'tls_min_version':'1.2'},{'tls_alpn':'h2'},{'certificate_path':''}):
            assert c.post('/nodes',data={**raw,**invalid}).status_code==422
    assert c.post('/nodes',data=raw).status_code==200
    node=records(m.DB,'nodes')[0];assert node['mode']==('shared' if proto=='tuic' else 'compat')
    assert c.post('/users',data={'token':t,'name':'Alice','node_ids':node['id']}).status_code==200
    assert c.post('/users',data={'token':t,'name':'Bob','node_ids':node['id']}).status_code==200
    alice,bob=records(m.DB,'users');customer_login(c,'/s/'+alice['token'])
    page=c.get('/s/'+alice['token']);assert page.status_code==200
    for secret in (node['secret'],bob['secret'],str(key)):
        assert secret not in page.text
    if proto=='shadowtls':assert shadow_password(node,bob) not in page.text
    for fmt in ('sing-box.json','clash.yaml','surge.conf','surfboard.conf','shadowrocket.txt'):
        response=c.get('/s/'+alice['token']+'/'+fmt)
        assert response.status_code==200
        assert response.headers['X-Subscription-Node-Count']==('0' if proto=='shadowtls' and fmt=='surfboard.conf' else '1')
        assert bob['secret'] not in response.text


def test_shadowtls_injected_backend_and_single_accounting(tmp_path,certificate):
    cert,key=certificate;path=tmp_path/'panel.db';seed(path,'shadowtls','compat','2022-blake3-aes-128-gcm','tcp',cert,key)
    nodes,users,members=[records(path,t) for t in ('nodes','users','memberships')]
    document=config(nodes,users,members);ins=document['inbounds']
    assert len(ins)==4
    outer=[i for i in ins if i['type']=='shadowtls'];backends=[i for i in ins if i['type']=='shadowsocks']
    assert all('listen_port' not in i and 'listen' not in i and i['network']=='tcp' for i in backends)
    assert {i['detour'] for i in outer}=={i['tag'] for i in backends}
    assert all(i['version']==3 and i['strict_mode'] for i in outer)
    assert document['experimental']['v2ray_api']['stats']['users']==[]
    assert set(document['experimental']['v2ray_api']['stats']['inbounds'])=={'node:alice','node:bob'}
    counters={'inbound>>>node:alice>>>traffic>>>uplink':100,'inbound>>>node:alice>>>traffic>>>downlink':200,
              'user>>>node:alice>>>traffic>>>uplink':150,'user>>>node:alice>>>traffic>>>downlink':250}
    account(path,'epoch',counters);account(path,'epoch',counters)
    alice,bob=records(path,'users');assert (alice['upload'],alice['download'])==(100,200);assert bob['upload']==bob['download']==0
    with connect(path) as db:db.execute("UPDATE users SET quota=1 WHERE id='alice'")
    assert 'node:alice' not in json.dumps(current_config(path))
    with connect(path) as db:db.execute("DELETE FROM memberships WHERE user_id='bob'")
    assert config(records(path,'nodes'),records(path,'users'),records(path,'memberships'))['inbounds']==[]


def test_shadowtls_export_graph_helpers_and_native_plugin(tmp_path,certificate):
    from urllib.parse import urlsplit,parse_qs
    import yaml
    cert,key=certificate;path=tmp_path/'panel.db';seed(path,'shadowtls','compat','2022-blake3-aes-128-gcm','tcp',cert,key)
    users=records(path,'users');node=records(path,'nodes')[0]
    outs=outbounds(users[0],[node],records(path,'memberships'),'example.com')
    outs[0]['tag']='__shadowtls_1'
    expanded=expand_singbox_nodes(outs)
    assert expanded[0]['type']=='shadowsocks' and expanded[0]['detour']==expanded[1]['tag']
    assert len({i['tag'] for i in expanded})==2 and all('_shadowtls' not in i for i in expanded)
    text,count=singbox_profile(outs,'https://panel.example/s/test');doc=json.loads(text)
    assert count==1
    selectors=[i for i in doc['outbounds'] if i['type'] in ('selector','urltest')]
    helper=next(i['tag'] for i in doc['outbounds'] if i['type']=='shadowtls')
    assert all(helper not in i['outbounds'] for i in selectors)
    native=base64.b64decode(native_subscription(outs,'shadowrocket.txt')).decode().strip()
    plugin=json.loads(base64.b64decode(parse_qs(urlsplit(native).query)['shadow-tls'][0]))
    assert '%3D' not in urlsplit(native).query  # Shadowrocket-compatible parsers decode the Base64 field directly
    assert plugin=={'version':3,'host':node['server_name'],'password':shadow_password(node,users[0])}
    text,count=mihomo_profile(outs,'https://panel.example/s/test');proxy=yaml.safe_load(text)['proxies'][0]
    assert proxy['plugin']=='shadow-tls' and proxy['plugin-opts']==plugin and proxy['udp'] is False
    assert shadow_password(node,users[1]) not in native
    body,count=ini_profile(outs,'surge.conf','https://panel.example/s/test',users[0])
    assert count==1 and 'shadow-tls-version=3' in body and 'udp-relay=false' in body
    assert ini_profile(outs,'surfboard.conf','https://panel.example/s/test',users[0])[1]==0


def test_agent_injected_ports_are_only_allowed_for_strict_combinations(core):
    backend={'type':'shadowsocks','tag':'node:alice','network':'tcp','method':'aes-128-gcm','password':'test'}
    wrapper={'type':'shadowtls','version':3,'strict_mode':True,'tag':'node:alice:st','listen_port':35000,'detour':'node:alice'}
    assert core.prepare({'inbounds':[wrapper,backend]})['inbounds'][1]==backend
    for broken in ([backend],[{**wrapper,'version':2},backend],[{**wrapper,'strict_mode':False},backend],
                   [wrapper,{**backend,'listen':'0.0.0.0'}],[{**wrapper,'listen_port':80},backend],
                   [wrapper,{**backend,'listen_port':80}],[wrapper,{**backend,'type':'socks'}]):
        with pytest.raises(ValueError):core.prepare({'inbounds':broken})


def test_remote_shadowtls_requires_current_agent_and_preserves_server_scope(client):
    from panel.fleet import save_server
    from panel.fleet_config import configuration
    c,m=client;t=csrf(c);server=save_server(m.DB,'Fixture machine','203.0.113.20')
    raw={'token':t,'name':'Remote combo','protocol':'shadowtls','server_id':server['id'],'server_name':'www.cloudflare.com'}
    with connect(m.DB) as db:
        db.execute('UPDATE servers SET credential_hash=?,metrics=? WHERE id=?',('fixture-only',json.dumps({'agent_version':'0.2.0'}),server['id']))
    response=c.post('/nodes',data=raw)
    assert response.status_code==422 and 'Agent 0.2.1' in response.text
    with connect(m.DB) as db:db.execute('UPDATE servers SET metrics=? WHERE id=?',(json.dumps({'agent_version':'0.2.1'}),server['id']))
    assert c.post('/nodes',data=raw).status_code==200
    node=records(m.DB,'nodes')[0]
    assert c.post('/users',data={'token':t,'name':'Alice','node_ids':node['id']}).status_code==200
    doc=configuration(m.DB,server['id']);assert len(doc['inbounds'])==2
    assert current_config(m.DB)['inbounds']==[]
    uid=records(m.DB,'users')[0]['id']
    counter={'inbound>>>'+node['id']+':'+uid+'>>>traffic>>>uplink':100}
    account(m.DB,'epoch',counter,server_id='wrong-server')
    assert records(m.DB,'users')[0]['upload']==0
    account(m.DB,'epoch',counter,server_id=server['id'])
    assert records(m.DB,'users')[0]['upload']==100


@pytest.mark.skipif(not os.environ.get('SING_BOX'),reason='SING_BOX required')
@pytest.mark.parametrize('layer',('shadowtls','shadowsocks'))
def test_real_mixed_layer_credentials_cannot_cross_users(tmp_path,certificate,layer):
    import ssl,threading,time
    from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
    from loopback_fixture import LoopbackFixtureRuntime
    from traffic_audit import receive
    from test_integration import port
    hits=[]
    class Target(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path);self.send_response(200);self.end_headers();self.wfile.write(b'forbidden-cross-user')
        def log_message(self,*args):pass
        def handle(self):
            try:super().handle()
            except OSError:pass
    cert,key=certificate;path=tmp_path/'panel.db';seed(path,'shadowtls','compat','2022-blake3-aes-128-gcm','tcp',cert,key)
    handshake=ThreadingHTTPServer(('127.0.0.1',0),Target);target=ThreadingHTTPServer(('127.0.0.1',0),Target)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.load_cert_chain(cert,key)
    handshake.socket=ctx.wrap_socket(handshake.socket,server_side=True)
    for server in (handshake,target):threading.Thread(target=server.serve_forever,daemon=True).start()
    with connect(path) as db:
        o=json.loads(records(path,'nodes')[0]['options']);o.update(handshake_host='127.0.0.1',handshake_port=handshake.server_port)
        db.execute('UPDATE nodes SET options=?',(json.dumps(o),))
    rt=LoopbackFixtureRuntime(os.environ['SING_BOX'],tmp_path,port());process=None
    try:
        rt.apply();alice,bob=records(path,'users');node=records(path,'nodes')[0]
        out=outbounds(alice,[node],records(path,'memberships'),'127.0.0.1')[0]
        out['_shadowtls']['tls']['certificate_path']=str(cert)
        if layer=='shadowtls':out['_shadowtls']['password']=shadow_password(node,bob)
        else:out['password']=user_key(node,bob)
        local=port();filename=tmp_path/'client.json'
        filename.write_text(json.dumps({'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':local}],'outbounds':expand_singbox_nodes([out])}))
        with (tmp_path/'client.log').open('w') as log:process=subprocess.Popen([os.environ['SING_BOX'],'run','-c',str(filename)],stdout=log,stderr=log)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1',local),timeout=.1):break
            except OSError:
                if process.poll() is not None:pytest.fail((tmp_path/'client.log').read_text())
                time.sleep(.03)
        data=b''
        try:
            with socket.create_connection(('127.0.0.1',local),timeout=3) as peer:
                peer.settimeout(3);peer.sendall(b'\x05\x01\x00');assert receive(peer,2)==b'\x05\x00'
                peer.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+target.server_port.to_bytes(2,'big'))
                header=receive(peer,4);assert header[0]==5
                if header[1]==0:
                    receive(peer,6 if header[3]==1 else 18)
                    peer.sendall(b'GET /cross-user HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n');data=peer.recv(4096)
        except OSError:pass
        assert not data and not hits
        rt.sample();assert all(u['upload']==u['download']==0 for u in records(path,'users'))
    finally:
        if process:process.terminate();process.wait(timeout=5)
        rt.stop()
        for server in (handshake,target):server.shutdown();server.server_close()
