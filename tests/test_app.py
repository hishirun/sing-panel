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
