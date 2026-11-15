import re
import pytest
from test_app import client,csrf
from panel.paths import validate_paths
from customer_helpers import customer_login

def test_paths_validation():
    assert validate_paths('/manage-123/','/share-456/')==('/manage-123','/share-456')
    for a,s in [('/static','/share'),('/admin','/admin'),('/a/b','/share'),('/admin','/../s'),('//host','/share')]:
        with pytest.raises(ValueError):validate_paths(a,s)

def test_changed_paths_redirects_and_old_entry_rejected(client):
    c,m=client
    token=csrf(c)
    raw=dict(m.read_settings(m.DB),token=token,admin_path='/manage-test',share_path='/share-test')
    r=c.post('/settings',data=raw,follow_redirects=False)
    assert r.headers['location']=='/manage-test/settings'
    assert c.get('/settings').status_code==404
    assert c.get('/login').status_code==404
    assert c.get('/').status_code==404
    assert c.get('/s/invalid').status_code==404
    assert c.get('/manage-test/s/invalid').status_code==404
    assert c.get('/manage-test/settings').status_code==200
    assert c.get('/manage-test/users/',follow_redirects=False).headers['location']=='http://testserver/manage-test/users'
    html=c.get('/manage-test/users').text
    assert 'href="/manage-test/users/new"' in html
    assert c.get('/static/panel.css').status_code==200
    assert c.get('/health').status_code in (200,503)
    c.cookies.clear()
    assert c.get('/manage-test',follow_redirects=False).headers['location']=='/manage-test/login'
    login=c.get('/manage-test/login')
    token=re.search('name="token" value="([^"]+)"',login.text)[1]
    assert c.post('/manage-test/login',data={'username':'admin','password':'test-password-only','token':token},follow_redirects=False).headers['location']=='/manage-test/'
    token=re.search('name="token" value="([^"]+)"',c.get('/manage-test/').text)[1]
    c.post('/manage-test/nodes',data={'token':token,'name':'v6','protocol':'snell6','port':32123,'mode':'shared'})
    node=m.records(m.DB,'nodes')[0]
    assert 'action="/manage-test/nodes/'+node['id']+'/edit"' in c.get('/manage-test/nodes/'+node['id']+'/edit').text
    assert 'action="/manage-test/users/create"' in c.get('/manage-test/users/new').text
    c.post('/manage-test/users',data={'token':token,'name':'tester','node_ids':node['id'],'quota_gib':1})
    user=m.records(m.DB,'users')[0]
    prefix='/share-test/'+user['token']
    customer_login(c,prefix)
    assert c.get(prefix).status_code==200
    assert prefix in c.get(prefix).text
    assert c.get(prefix+'/sing-box.json').status_code==200
    assert c.get(prefix+'/qr/subscription').status_code==200
    assert c.get('/s/'+user['token']).status_code==404
