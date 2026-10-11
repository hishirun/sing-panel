import importlib
import json
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
