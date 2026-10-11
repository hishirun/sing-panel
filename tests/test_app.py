import importlib
import json
import os
import re
from argon2 import PasswordHasher
from fastapi.testclient import TestClient
import pytest

@pytest.fixture
def client(tmp_path,monkeypatch):
    monkeypatch.setenv('PANEL_DATA',str(tmp_path))
    monkeypatch.setenv('PANEL_PUBLIC_HOST','test.example.com')
    (tmp_path/'auth.json').write_text(json.dumps({'password_hash':PasswordHasher().hash('test-password-only'),'session_key':'test-secret-only'}))
    import panel.app as module
    module=importlib.reload(module)
    monkeypatch.setattr(module.monitor,'start',lambda:None)
    monkeypatch.setattr(module.monitor,'stop',lambda:None)
    monkeypatch.setattr(module.runtime,'start',lambda:None)
    monkeypatch.setattr(module.runtime,'stop',lambda:None)
    monkeypatch.setattr(module.runtime,'sample',lambda:None)
    if not os.environ.get('SING_BOX'):
        monkeypatch.setattr(module,'check_document',lambda doc:None)
    with TestClient(module.app) as c:
        page=c.get('/login')
        token=re.search('name="token" value="([^"]+)"',page.text)[1]
        assert c.post('/login',data={'password':'test-password-only','token':token}).status_code==200
        yield c,module

def csrf(c):
    return re.search('name="token" value="([^"]+)"',c.get('/').text)[1]

def test_csrf_required(client):
    c,_=client
    assert c.post('/nodes',data={'token':'bad','name':'x','protocol':'snell6','port':31000,'mode':'shared'}).status_code==403

def test_nodes_users_subscription_rotation(client):
    c,m=client
    token=csrf(c)
    r=c.post('/nodes',data={'token':token,'name':'<script>x</script>','protocol':'snell6','port':31000,'mode':'shared'})
    assert r.status_code==200
    assert '&lt;script&gt;x&lt;/script&gt;' in r.text
    node=m.records(m.DB,'nodes')[0]
    assert c.post('/users',data={'token':token,'name':'Alice','node_ids':node['id'],'quota_gib':1}).status_code==200
    user=m.records(m.DB,'users')[0]
    url=f"/s/{user['token']}/sing-box.json"
    r=c.get(url)
    assert r.status_code==200
    assert r.json()['outbounds'][0]['userkey']==user['secret']
    assert 'private_key' not in r.text
    assert 'Subscription-Userinfo' in r.headers
    c.post(f"/users/{user['id']}/action",data={'token':token,'action':'toggle'})
    assert c.get(url).json()['outbounds']==[]
    c.post(f"/users/{user['id']}/action",data={'token':token,'action':'rotate'})
    assert c.get(url).status_code==404
    c.post(f"/nodes/{node['id']}/action",data={'token':token,'action':'delete'})
    assert m.records(m.DB,'memberships')==[]

def test_unauthenticated_admin_hidden(client):
    c,_=client
    c.cookies.clear()
    assert c.post('/users',data={'name':'intruder','token':'x'}).status_code==401
    assert c.get('/s/invalid/sing-box.json').status_code==404

def test_edit_node_and_unsafe_mode_requires_acknowledgement(client):
    c,m=client
    token=csrf(c)
    data={'token':token,'name':'v6','protocol':'snell6','port':32001,'mode':'shared',
          'snell_mode':'unshaped','reuse':'true','tcp_fast_open':'true'}
    assert c.post('/nodes',data=data).status_code==200
    node=m.records(m.DB,'nodes')[0]
    assert json.loads(node['options'])['snell_mode']=='unshaped'
    url=f"/nodes/{node['id']}/edit"
    assert 'Snell v6 特征与加密' in c.get(url).text
    data.update(snell_mode='unsafe-raw')
    assert c.post(url,data=data).status_code==422
    assert json.loads(m.records(m.DB,'nodes')[0]['options'])['snell_mode']=='unshaped'
    data.update(acknowledge_raw='1')
    assert c.post(url,data=data).status_code==200
    assert json.loads(m.records(m.DB,'nodes')[0]['options'])['snell_mode']=='unsafe-raw'

def test_reality_key_import_short_ids_and_edit_preserves_keys(client):
    c,m=client
    data={'token':csrf(c),'name':'Reality','protocol':'reality','port':32002,
          'server_name':'www.cloudflare.com','private_key':'A'*43,
          'short_ids':'aabb,11223344','fingerprint':'firefox','handshake_host':'www.cloudflare.com'}
    assert c.post('/nodes',data=data).status_code==200
    before=m.records(m.DB,'nodes')[0]
    assert before['public_key'] and before['private_key']=='A'*43
    data.update(name='Updated Reality',private_key='')
    assert c.post(f"/nodes/{before['id']}/edit",data=data).status_code==200
    after=m.records(m.DB,'nodes')[0]
    assert after['private_key']==before['private_key']
    assert after['public_key']==before['public_key']
    assert json.loads(after['options'])['short_ids']=='aabb,11223344'

def test_probe_does_not_require_node_name_or_listen_port(client,monkeypatch):
    c,m=client
    monkeypatch.setattr(m,'probe_tls',lambda host,port,sni:'TLSv1.3 · h2 · verified')
    r=c.post('/nodes',data={'token':csrf(c),'protocol':'reality',
                         'server_name':'www.cloudflare.com','intent':'probe'})
    assert r.status_code==200
    assert 'TLSv1.3' in r.text
    assert m.records(m.DB,'nodes')==[]

def test_random_node_ports_and_rotation(client):
    c,m=client
    token=csrf(c)
    for name in ('one','two'):
        assert c.post('/nodes',data={'token':token,'name':name,'protocol':'snell6','mode':'compat'}).status_code==200
    nodes=m.records(m.DB,'nodes')
    assert len({n['port'] for n in nodes})==2
    assert all(20000<=n['port']<=65000 for n in nodes)
    node=nodes[0]
    for name in ('alice','bob'):
        assert c.post('/users',data={'token':token,'name':name,'node_ids':node['id']}).status_code==200
    old={row['port'] for row in m.records(m.DB,'memberships')}
    assert node['port'] in old and len(old)==2
    assert c.post(f"/nodes/{node['id']}/action",data={'token':token,'action':'randomize'}).status_code==200
    new={row['port'] for row in m.records(m.DB,'memberships')}
    assert len(new)==2 and not old & new
    changed=m.records(m.DB,'nodes')[0]
    assert changed['port'] in new
    assert nodes[1]==m.records(m.DB,'nodes')[1]
    assert c.get('/').status_code==200
    assert new=={row['port'] for row in m.records(m.DB,'memberships')}

def test_manual_port_in_use_rejected(client):
    import socket
    c,m=client
    with socket.socket() as sock:
        sock.bind(('0.0.0.0',0))
        response=c.post('/nodes',data={'token':csrf(c),'name':'occupied','protocol':'snell6',
                                     'mode':'shared','port':sock.getsockname()[1]})
    assert response.status_code==422
    assert m.records(m.DB,'nodes')==[]

def test_share_page_scoped_configs_qr_and_password(client):
    c,m=client
    token=csrf(c)
    for name in ('first','second'):
        c.post('/nodes',data={'token':token,'name':name,'protocol':'snell6','mode':'compat'})
    nodes=m.records(m.DB,'nodes')
    c.post('/users',data={'token':token,'name':'Alice','node_ids':[n['id'] for n in nodes]})
    c.post('/users',data={'token':token,'name':'Bob','node_ids':[nodes[0]['id']]})
    alice,bob=m.records(m.DB,'users')
    url='/s/'+alice['token']
    page=c.get(url)
    assert page.status_code==200
    assert alice['secret'] in page.text and bob['secret'] not in page.text
    assert 'first' in page.text and 'second' in page.text
    assert '复制节点链接' in page.text and '节点延迟监控' in page.text
    assert c.get(url+'/qr/'+nodes[0]['id']).headers['content-type'].startswith('image/svg+xml')
    assert c.get(url+'/qr/page').status_code==200
    assert c.post(url+'/psk',data={'csrf_token':'bad','psk':'new-secret-012345'}).status_code==403
    page_token=re.search('name="csrf_token" value="([^"]+)"',page.text)[1]
    response=c.post(url+'/psk',data={'csrf_token':page_token,'psk':'new-secret-012345'})
    assert response.status_code==200
    assert 'new-secret-012345' in response.text
    assert m.records(m.DB,'users')[1]['secret']==bob['secret']
    outs=c.get(url+'/sing-box.json').json()['outbounds']
    assert len(outs)==2 and all(o['psk']=='new-secret-012345' for o in outs)
    assert c.post(url+'/psk',data={'csrf_token':page_token}).status_code==429
    c.post('/users/'+alice['id']+'/action',data={'token':csrf(c),'action':'toggle'})
    assert 'new-secret-012345' not in c.get(url).text
    assert c.get(url+'/qr/'+nodes[0]['id']).status_code==404

def test_share_settings_validation_and_branding(client):
    c,m=client
    token=csrf(c)
    settings={'token':token,'brand':'My Panel','public_url':'https://example.com','support':'Contact admin',
              'monitor_targets':'Test,example.com,443'}
    assert c.post('/settings',data=settings).status_code==200
    assert 'My Panel' in c.get('/').text
    c.post('/users',data={'token':token,'name':'Alice'})
    user=m.records(m.DB,'users')[0]
    page=c.get('/s/'+user['token'])
    assert 'https://example.com/s/'+user['token'] in page.text
    assert 'Contact admin' in page.text
    settings['public_url']='javascript:alert(1)'
    assert '公开地址' in c.post('/settings',data=settings).text
    from panel.sharing import read_settings
    assert read_settings(m.DB)['public_url']=='https://example.com'

def test_monitor_records_success_and_failure(client,monkeypatch):
    c,m=client
    from panel.sharing import Monitor
    class Connected:
        def __enter__(self):return self
        def __exit__(self,*args):pass
    monkeypatch.setattr('panel.sharing.socket.create_connection',lambda *a,**k:Connected())
    monitor=Monitor(m.DB)
    monitor.collect()
    with m.connect(m.DB) as db:
        assert db.execute('SELECT count(*) FROM monitor_samples WHERE ms IS NOT NULL').fetchone()[0]==3
    def fail(*a,**k):raise OSError('offline')
    monkeypatch.setattr('panel.sharing.socket.create_connection',fail)
    monitor.collect()
    with m.connect(m.DB) as db:
        assert db.execute('SELECT count(*) FROM monitor_samples WHERE ms IS NULL').fetchone()[0]==3
