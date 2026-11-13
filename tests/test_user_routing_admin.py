"""Administrator grants and application rollback, separate from customer APIs."""
import json

import pytest

from panel import routing as r
from panel import user_routing as ur
from panel.core import connect
from test_app import client, csrf


@pytest.fixture
def admin(client,monkeypatch):
    c,m=client
    monkeypatch.setattr(m.runtime,'apply',lambda:None)
    with connect(m.DB) as db:
        db.execute("INSERT INTO users(id,name,secret,uuid,token,group_name) VALUES('u','User','secret','uuid','user-token','Friends')")
        db.execute("INSERT INTO users(id,name,secret,uuid,token,group_name) VALUES('v','Other','secret','uuid2','other-token','Team')")
    return c,m,csrf(c)


def outbound(c,token,**extra):
    return c.post('/routing/outbounds/save',data={
        'token':token,'name':'Private label','type':'socks','server':'127.0.0.1',
        'server_port':1080,'username':'upstream','password':'private-upstream-password',
        **extra,
    })


def test_outbound_grant_form_persistence_validation_and_public_projection(admin):
    c,m,t=admin
    response=outbound(c,t,public_present='1',public_visible='1',public_allow_use='1',
                      public_name='Seattle',public_region='US',public_description='Streaming',
                      public_audience='selected',public_user_ids='u',public_groups='Friends')
    assert response.status_code==200
    row=r.load(m.DB)['outbounds'][0]
    assert row['public']==dict(visible=True,allow_use=True,name='Seattle',region='US',
                              description='Streaming',audience='selected',user_ids=['u'],groups=['Friends'],order=0)
    listing=c.get('/routing').text
    assert '用户可见' in listing and 'private-upstream-password' not in listing
    edit=c.get('/routing/outbounds/'+row['id']+'/edit').text
    assert 'name="public_user_ids"' in edit and 'Seattle' in edit
    assert 'private-upstream-password' not in edit
    # Older clients that do not submit publication fields must preserve grants.
    outbound(c,t,id=row['id'],password='')
    assert r.load(m.DB)['outbounds'][0]['public']==row['public']
    before=r.load(m.DB)
    rejected=outbound(c,t,id=row['id'],public_present='1',public_visible='1',
                      public_audience='selected',public_user_ids='missing')
    assert '已不存在' in rejected.text and r.load(m.DB)==before
    ur.configure_user(m.DB,'u',True)
    with connect(m.DB) as db:
        user=dict(db.execute("SELECT * FROM users WHERE id='u'").fetchone())
        other=dict(db.execute("SELECT * FROM users WHERE id='v'").fetchone())
    assert ur.public_outbounds(m.DB,other)==[]
    public=ur.public_outbounds(m.DB,user)
    assert public[0]['name']=='Seattle' and public[0]['selectable']
    assert 'private-upstream-password' not in json.dumps(public) and '127.0.0.1' not in json.dumps(public)


def test_user_permissions_defaults_and_rollback_without_password(admin,monkeypatch):
    c,m,t=admin
    path='/users/u/routing'
    assert '分流设置' in c.get('/users').text
    page=c.get(path)
    assert page.status_code==200 and 'name="password"' not in page.text
    assert 'name="max_rules"' in page.text and 'value="6"' in page.text
    assert c.post(path,data={'token':t,'allowed':'1'}).status_code==200
    original=ur.get_policy(m.DB,'u')
    assert original['allowed'] and original['max_rules']==6 and not original['password_hash']
    c.post(path,data={'token':t,'allowed':'1','max_rules':'12'})
    retained=ur.get_policy(m.DB,'u')
    assert retained['max_rules']==12 and retained['auth_revision']==original['auth_revision']
    monkeypatch.setattr(m.runtime,'apply',lambda:(_ for _ in ()).throw(RuntimeError('test')))
    rejected=c.post(path,data={'token':t,'max_rules':'12'})
    assert '已恢复原用户分流权限' in rejected.text
    assert ur.get_policy(m.DB,'u')==retained
    assert c.post(path,data={'token':'bad','allowed':'1'}).status_code==403
    c.cookies.clear()
    assert c.get(path).status_code==401


def test_priority_validation_reordering_and_user_reference_guard(admin):
    c,m,t=admin
    outbound(c,t)
    out=r.load(m.DB)['outbounds'][0]
    for name,priority in [('F1','forced'),('D1','default'),('F2','forced')]:
        c.post('/routing/rules/save',data={'token':t,'name':name,'target':'direct',
                                         'domain_suffix':name.lower()+'.example.com','priority':priority})
    rules=r.load(m.DB)['rules']
    c.post('/routing/rules/'+rules[2]['id']+'/up',data={'token':t})
    assert [row['name'] for row in r.load(m.DB)['rules'] if row['priority']=='forced']==['F2','F1']
    assert '默认规则 · 可被用户覆盖' in c.get('/routing').text
    before=r.load(m.DB)
    rejected=c.post('/routing/rules/save',data={'token':t,'name':'Bad','target':'direct',
                                             'domain_suffix':'example.com','priority':'unknown'})
    assert '有效的规则优先级' in rejected.text and r.load(m.DB)==before
    ur.configure_user(m.DB,'u',True)
    policy=ur.get_policy(m.DB,'u')
    policy['applied']={'enabled':True,'rules':[{'id':'r','name':'AI','enabled':True,
                         'kind':'domain_suffix','values':['example.com'],'target':out['id'],'node_ids':[]}]}
    ur.restore_policy(m.DB,'u',policy)
    rejected=c.post('/routing/outbounds/'+out['id']+'/delete',data={'token':t})
    assert '用户已应用的规则引用' in rejected.text
    assert r.load(m.DB)['outbounds']


def test_admin_edit_waits_for_inflight_application(admin):
    c,m,t=admin
    ur.configure_user(m.DB,'u',True)
    with connect(m.DB) as db:
        db.execute("UPDATE user_routing SET status='queued' WHERE user_id='u'")
    response=c.post('/users/u/routing',data={'token':t,'max_rules':'20'})
    assert '正在应用' in response.text
    assert ur.get_policy(m.DB,'u')['allowed']


def test_admin_restore_defaults_clears_rules_but_preserves_user_access(admin):
    c,m,t=admin
    ur.configure_user(m.DB,'u',True)
    policy=ur.get_policy(m.DB,'u')
    policy.update(revision=3,applied_revision=2,status='draft',
                  draft={'enabled':True,'rules':[{'id':'draft','name':'Draft','enabled':True,'kind':'domain_suffix','values':['example.com'],'target':'reject','node_ids':[]}]},
                  applied={'enabled':True,'rules':[{'id':'applied','name':'Applied','enabled':True,'kind':'domain_suffix','values':['example.net'],'target':'reject','node_ids':[]}]})
    ur.restore_policy(m.DB,'u',policy)
    response=c.post('/users/u/routing',data={'token':t,'intent':'reset'})
    assert response.status_code==200 and '默认策略已发布' in response.text
    after=ur.get_policy(m.DB,'u')
    assert after['draft']['rules']==[] and after['applied']['rules']==[]
    assert after['allowed'] and after['password_hash']==policy['password_hash']
    assert after['revision']==after['applied_revision']==4 and after['status']=='applied'
