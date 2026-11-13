import base64,json,os,socket,subprocess,threading,time,uuid
from pathlib import Path
from http.server import ThreadingHTTPServer
import pytest
from panel import routing as r
from panel.core import connect,init_db,records,set_memberships,config,current_config
from panel.runtime import Runtime
from test_app import client,csrf
from test_integration import Handler,port
BINARY=os.environ.get('SING_BOX')

@pytest.fixture
def routing_client(client,monkeypatch):
    c,m=client;monkeypatch.setattr(m.runtime,'apply',lambda:None)
    return c,m

def test_admin_crud_import_secrets_rules_and_reference_guards(routing_client):
    c,m=routing_client;t=csrf(c)
    assert c.get('/routing').status_code==200
    uri='socks5://alice:secret-123@127.0.0.1:1080#My%20Proxy'
    page=c.post('/routing/outbounds/save',data={'token':t,'intent':'import','uri':uri})
    assert 'My Proxy' in page.text and 'secret-123' in page.text
    assert not r.load(m.DB)['outbounds']
    raw={'token':t,'name':'Proxy','type':'socks','server':'127.0.0.1','server_port':1080,'username':'alice','password':'secret-123','tls_mode':'none'}
    assert c.post('/routing/outbounds/save',data=raw).status_code==200
    o=r.load(m.DB)['outbounds'][0]
    listing=c.get('/routing').text
    assert 'secret-123' not in listing and 'secret-123' not in c.get('/routing/preview').text
    raw.update(id=o['id'],password='',name='Renamed')
    c.post('/routing/outbounds/save',data=raw)
    assert r.load(m.DB)['outbounds'][0]['settings']['password']=='secret-123'
    c.post('/routing/rules/save',data={'token':t,'name':'Example','target':o['id'],'domain_suffix':'example.com','port':'443,8000-9000'})
    data=r.load(m.DB);assert len(data['rules'])==1
    compiled=current_config(m.DB,m.STATS_PORT)
    assert compiled['route']['rules'][0]['outbound']=='up-'+o['id']
    c.post('/routing/outbounds/'+o['id']+'/delete',data={'token':t})
    assert len(r.load(m.DB)['outbounds'])==1
    c.post('/routing/outbounds/'+o['id']+'/toggle',data={'token':t})
    assert r.load(m.DB)['outbounds'][0]['enabled']
    rule=data['rules'][0]
    c.post('/routing/rules/'+rule['id']+'/toggle',data={'token':t})
    assert not current_config(m.DB,m.STATS_PORT)['route']['rules']
    c.post('/routing/rules/'+rule['id']+'/delete',data={'token':t})
    c.post('/routing/outbounds/'+o['id']+'/delete',data={'token':t})
    assert not r.load(m.DB)['outbounds']
    assert c.post('/routing/settings',data={'token':'bad','final':'direct'}).status_code==403
    c.cookies.clear();assert c.get('/routing').status_code==401

def test_failed_apply_restores_persistent_settings(routing_client,monkeypatch):
    c,m=routing_client;t=csrf(c);old=r.load(m.DB)
    monkeypatch.setattr(m.runtime,'apply',lambda:(_ for _ in ()).throw(RuntimeError('simulated startup failure')))
    response=c.post('/routing/outbounds/save',data={'token':t,'name':'Test','type':'socks','server':'127.0.0.1','server_port':1080})
    assert '已恢复原分流设置' in response.text
    assert r.load(m.DB)==old

def test_match_validation_and_missing_source_never_becomes_global():
    with pytest.raises(ValueError):r.rule_input({'target':'direct','name':'empty'},[],[])
    with pytest.raises(ValueError):r.rule_input({'target':'direct','name':'bad','port':'99999'},[],[])
    with pytest.raises(ValueError):r.rule_input({'target':'missing','name':'bad','domain':'example.com'},[],[])
    data={'outbounds':[],'rules':[{'id':'r','name':'source','enabled':True,'node_ids':['gone'],'match':{},'target':'reject'}],'final':'direct','sniff':False}
    assert r.compile_into(config([],[],[]),data)['route']['rules']==[]
    data['rules'][0].update(node_ids=['n'])
    document=config([],[],[]);document['inbounds']=[{'tag':'n:user1'},{'tag':'other'}]
    assert r.compile_into(document,data)['route']['rules']==[{'inbound':['n:user1'],'action':'reject'}]

def test_uri_import_and_protocol_builders():
    encoded=base64.urlsafe_b64encode(b'aes-128-gcm:test-secret').decode().rstrip('=')
    value=r.parse_uri('ss://'+encoded+'@example.com:8388#SS')
    assert r.build_outbound(value)['password']=='test-secret'
    v=r.parse_uri('vless://11111111-1111-4111-8111-111111111111@example.com:443?security=tls&type=ws&path=%2Fproxy#VLESS')
    assert r.build_outbound(v)['transport']['path']=='/proxy'
    socks_uri='socks://'+base64.urlsafe_b64encode(b'alice:password').decode()+'@example.com:1080'
    assert r.parse_uri(socks_uri)['password']=='password'
    from panel.subscriptions import native_subscription
    snell={'type':'snell','version':6,'psk':'test-psk','server':'example.com','server_port':12345,'tag':'Snell','reuse':True,'mode':'default'}
    link=base64.b64decode(native_subscription([snell],'shadowrocket.txt')).decode().strip()
    assert r.build_outbound(r.parse_uri(link))['psk']=='test-psk'
    for kind in r.TYPES:
        raw=dict(r.edit_values(),type=kind,server='127.0.0.1',server_port=1080,password='test-password-123',uuid='11111111-1111-4111-8111-111111111111',tls_mode='tls' if kind in ('trojan','anytls','hysteria2','tuic') else 'none')
        out=r.build_outbound(raw)
        assert out['type']==kind
        if BINARY:
            import tempfile
            with tempfile.NamedTemporaryFile('w',suffix='.json') as f:
                json.dump({'outbounds':[dict(out,tag='test')]},f);f.flush()
                checked=subprocess.run([BINARY,'check','-c',f.name],capture_output=True,text=True)
                assert checked.returncode==0,(kind,checked.stderr)

def test_protocol_sniff_requires_explicit_enable():
    data={'outbounds':[],'rules':[{'enabled':True,'match':{'protocol':['tls']},'node_ids':[],'target':'direct'}],'final':'direct','sniff':False}
    with pytest.raises(ValueError):r.compile_into(config([],[],[]),data)
    data['sniff']=True
    assert r.compile_into(config([],[],[]),data)['route']['rules'][0]['action']=='sniff'

@pytest.mark.skipif(not BINARY,reason='SING_BOX required')
@pytest.mark.parametrize('kind',['socks','shadowsocks','ss2022'])
def test_real_routing_through_upstream_default_and_reject(tmp_path,kind):
    from traffic_audit import socks,receive
    from panel.subscriptions import outbounds
    class ProbeHandler(Handler):
        def do_GET(self):self.send_response(204);self.end_headers()
    http=ThreadingHTTPServer(('127.0.0.1',0),ProbeHandler);threading.Thread(target=http.serve_forever,daemon=True).start()
    method='2022-blake3-aes-128-gcm' if kind=='ss2022' else 'aes-128-gcm'
    password=base64.b64encode(b'0123456789abcdef').decode() if kind=='ss2022' else 'upstream-pass'
    if kind=='ss2022':kind='shadowsocks'
    upstream_port=port()
    inbound={'type':kind,'listen':'127.0.0.1','listen_port':upstream_port}
    if kind=='socks':inbound['users']=[{'username':'test','password':'upstream-pass'}]
    else:inbound.update(method=method,password=password)
    upstream_doc={'log':{'level':'error'},'inbounds':[inbound],'outbounds':[{'type':'direct','tag':'direct'}],'route':{'rules':[{'domain':['routed.invalid'],'action':'route','outbound':'direct','override_address':'127.0.0.1','override_port':http.server_port}]}}
    upfile=tmp_path/'upstream.json';upfile.write_text(json.dumps(upstream_doc));uplog=(tmp_path/'upstream.log').open('w')
    upstream=subprocess.Popen([BINARY,'run','-c',str(upfile)],stdout=uplog,stderr=uplog)
    db=tmp_path/'panel.db';init_db(db)
    with connect(db) as c:
        c.execute("INSERT INTO nodes(id,name,protocol,port,secret,mode) VALUES('n','N','snell6',?,'node-secret-123','compat')",(port(),))
        c.execute("INSERT INTO users(id,name,secret,uuid,token) VALUES('u','U','test-user-secret','uuid','token')")
        set_memberships(c,'u',['n'])
    upstream_options=r.build_outbound({'type':kind,'server':'127.0.0.1','server_port':upstream_port,'username':'test','password':password,'method':method})
    rules={'outbounds':[{'id':'exit','name':'Exit','enabled':True,'settings':upstream_options}],'rules':[{'id':'one','name':'Test','enabled':True,'match':{'domain':['routed.invalid']},'target':'exit','node_ids':['n']}],'final':'direct','sniff':False}
    r.write(db,rules);rt=Runtime(BINARY,tmp_path,port());client=None;clog=None
    try:
        rt.apply();user=records(db,'users')[0];outs=outbounds(user,records(db,'nodes'),records(db,'memberships'),'127.0.0.1')
        local=port();client_file=tmp_path/'client.json';client_file.write_text(json.dumps({'log':{'level':'error'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':local}],'outbounds':outs}))
        clog=(tmp_path/'client.log').open('w');client=subprocess.Popen([BINARY,'run','-c',str(client_file)],stdout=clog,stderr=clog)
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1',local),timeout=.1):break
            except OSError:time.sleep(.03)
        def request(domain,target_port):
            with socket.create_connection(('127.0.0.1',local),timeout=5) as s:
                s.settimeout(8);s.sendall(b'\x05\x01\x00');assert receive(s,2)==b'\x05\x00'
                encoded=domain.encode();s.sendall(bytes([5,1,0,3,len(encoded)])+encoded+target_port.to_bytes(2,'big'))
                head=receive(s,4);assert head[1]==0
                receive(s,18 if head[3]==4 else 6)
                s.sendall(b'POST / HTTP/1.1\r\nHost: routed.invalid\r\nConnection: close\r\nContent-Length: 0\r\n\r\n')
                result=b''
                while data:=s.recv(65535):result+=data
                return result
        assert request('routed.invalid',80).endswith(b'z'*131072)
        assert request('127.0.0.1',http.server_port).endswith(b'z'*131072)
        rt.sample();assert records(db,'users')[0]['download']>=2*131072
        probe=rt.control('/proxies/up-exit/delay?url=http%3A%2F%2Frouted.invalid%2F&timeout=3000')
        assert probe['delay']>=0
        rules['rules'][0]['target']='reject';r.write(db,rules);rt.apply()
        try:blocked=request('routed.invalid',80)
        except (AssertionError,OSError,RuntimeError):blocked=b''
        assert blocked==b''
        rules['rules']=[];rules['final']='exit';r.write(db,rules);rt.apply()
        assert request('routed.invalid',80).endswith(b'z'*131072)
    finally:
        if client:client.terminate();client.wait(timeout=10)
        rt.stop();upstream.terminate();upstream.wait(timeout=10);http.shutdown();uplog.close()
        if clog:clog.close()

def test_rule_order_default_exit_and_invalid_final_rollback(routing_client):
    c,m=routing_client;t=csrf(c)
    c.post('/routing/outbounds/save',data={'token':t,'name':'Exit','type':'socks','server':'127.0.0.1','server_port':1080})
    identity=r.load(m.DB)['outbounds'][0]['id']
    for name in ['First','Second']:
        c.post('/routing/rules/save',data={'token':t,'name':name,'target':'direct','domain_suffix':name.lower()+'.example.com'})
    rules=r.load(m.DB)['rules']
    c.post('/routing/rules/'+rules[1]['id']+'/up',data={'token':t})
    assert [x['name'] for x in r.load(m.DB)['rules']]==['Second','First']
    c.post('/routing/settings',data={'token':t,'final':identity})
    assert current_config(m.DB,m.STATS_PORT)['route']['final']=='up-'+identity
    old=r.load(m.DB)
    c.post('/routing/settings',data={'token':t,'final':'missing'})
    assert r.load(m.DB)==old
    c.post('/routing/outbounds/'+identity+'/toggle',data={'token':t})
    assert r.load(m.DB)==old

def test_geo_catalog_multiselect_logic_and_core(tmp_path):
    import copy
    raw={'name':'Geo','target':'direct','geoip':['cn','us'],'geosite':['google','github'],'port':'443'}
    rule=r.rule_input(raw,[],[])
    settings=copy.deepcopy(r.DEFAULT);settings['rules']=[dict(id='geo',enabled=True,**rule)]
    document=r.compile_into({'inbounds':[],'outbounds':[{'type':'direct','tag':'direct'}]},settings)
    assert [item['action'] for item in document['route']['rules']]==['resolve','route']
    resolver=document['route']['rules'][0]
    assert resolver['rules']==[{'port':[443]},{'rule_set':['geosite-google','geosite-github']}]
    compiled=next(item for item in document['route']['rules'] if item['action']=='route')
    assert compiled['type']=='logical' and compiled['mode']=='and'
    assert compiled['rules']==[{'port':[443]},{'rule_set':['geosite-google','geosite-github']},{'rule_set':['geoip-cn','geoip-us']}]
    assert len(document['route']['rule_set'])==4
    assert all(x['http_client']=={'version':1} for x in document['route']['rule_set'])
    with pytest.raises(ValueError):r.rule_input({**raw,'geoip':['../../secret']},[],[])
    if BINARY:
        # Real core schema check uses deterministic local seed files, no network.
        source=tmp_path/'source.json';source.write_text('{"version":3,"rules":[{"domain_suffix":["example.com"]}]}')
        binary=tmp_path/'test.srs'
        subprocess.run([BINARY,'rule-set','compile',str(source),'-o',str(binary)],check=True,capture_output=True)
        for entry in document['route']['rule_set']:entry['initial_path']=str(binary)
        configfile=tmp_path/'geo.json';configfile.write_text(json.dumps(document))
        result=subprocess.run([BINARY,'check','-c',str(configfile)],capture_output=True,text=True)
        assert result.returncode==0,result.stderr

def test_geo_form_choices_and_failed_download_keeps_settings(routing_client,monkeypatch):
    c,m=routing_client;t=csrf(c)
    page=c.get('/routing/rules/new').text
    assert 'name="geosite" multiple' in page and 'value="google"' in page and 'value="cn"' in page
    old=r.load(m.DB)
    monkeypatch.setattr(r,'prepare_rule_sets',lambda *args:(_ for _ in ()).throw(ValueError('download failed')))
    response=c.post('/routing/rules/save',data={'token':t,'name':'Geo','target':'direct','geoip':'cn'})
    assert 'download failed' in response.text and r.load(m.DB)==old

def test_geo_http_client_downloads_without_direct_detour(tmp_path):
    if not BINARY:pytest.skip('requires core')
    from http.server import BaseHTTPRequestHandler
    import copy
    source=tmp_path/'source.json';source.write_text('{"version":3,"rules":[{"domain_suffix":["openai.com"]}]}')
    binary=tmp_path/'rules.srs'
    subprocess.run([BINARY,'rule-set','compile',str(source),'-o',str(binary)],check=True,capture_output=True)
    class RulesHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            body=binary.read_bytes();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),RulesHandler)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    settings=copy.deepcopy(r.DEFAULT);settings['rules']=[{'enabled':True,'target':'direct','match':{'geosite':['category-ai-!cn']},'node_ids':[]}]
    document=r.compile_into({'inbounds':[],'outbounds':[{'type':'direct','tag':'direct'}]},settings)
    document['route']['rule_set'][0]['url']=f'http://127.0.0.1:{server.server_port}/rules.srs'
    document['experimental']['cache_file']['path']=str(tmp_path/'cache.db')
    path=tmp_path/'config.json';path.write_text(json.dumps(document))
    with (tmp_path/'core.log').open('w+') as output:
        process=subprocess.Popen([BINARY,'run','-c',str(path)],stdout=output,stderr=output)
        try:
            deadline=time.monotonic()+5
            while time.monotonic()<deadline:
                output.seek(0);logs=output.read()
                if 'sing-box started' in logs:break
                if process.poll() is not None:break
                time.sleep(.05)
            assert 'sing-box started' in logs,logs
            assert 'empty direct' not in logs
        finally:
            process.terminate();process.wait(timeout=5);server.shutdown();server.server_close()

def test_action_links_redirect_without_mutation(routing_client):
    c,m=routing_client;t=csrf(c)
    c.post('/routing/outbounds/save',data={'token':t,'name':'Read-only link','type':'socks','server':'127.0.0.1','server_port':1080})
    before=r.load(m.DB);identity=before['outbounds'][0]['id']
    for action in ('toggle','delete','test'):
        response=c.get('/routing/outbounds/'+identity+'/'+action,follow_redirects=False)
        assert response.status_code==303
        assert response.headers['location'].endswith('/routing')
        assert r.load(m.DB)==before
    c.cookies.clear()
    assert c.get('/routing/outbounds/'+identity+'/toggle').status_code==401
