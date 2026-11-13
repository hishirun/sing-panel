"""Customer sessions, grants and mutation boundaries through the real ASGI app."""
import copy
import json
import os
import subprocess
import time

import pytest

from panel import routing, user_routing as ur
from panel.core import connect
from test_app import client


@pytest.fixture
def customer(client,monkeypatch):
    c,m=client
    # Exercise queue endpoints deterministically; publication itself has a
    # dedicated suite. Never launch a real core or fetch rule sets here.
    m.routing_publisher.stop()
    m.routing_publisher.stopped.clear()
    monkeypatch.setattr(m.runtime,'apply',lambda:None)
    monkeypatch.setattr(m,'check_document',lambda document:None)
    with connect(m.DB) as db:
        for uid,name in [('u','Alice'),('v','Bob')]:
            db.execute('INSERT INTO users(id,name,secret,uuid,token) VALUES(?,?,?,?,?)',
                       (uid,name,'user-secret-'+uid,'uuid-'+uid,'token-'+uid))
        for nid in ['n','other']:
            db.execute("INSERT INTO nodes(id,name,protocol,port,secret,mode) VALUES(?,?,'snell6',?,'node-secret','shared')",(nid,nid,30001 if nid=='n' else 30002))
        db.execute("INSERT INTO memberships(user_id,node_id) VALUES('u','n')")
        db.execute("INSERT INTO memberships(user_id,node_id) VALUES('v','other')")
    for uid in ['u','v']:
        ur.configure_user(m.DB,uid,True,password='password-for-'+uid)
    settings=copy.deepcopy(routing.DEFAULT)
    settings['outbounds']=[{
        'id':oid,'name':'private-name-'+oid,'enabled':True,
        'settings':{'type':'socks','server':'private-upstream.example.com','server_port':1080,'username':'hidden-user','password':'hidden-secret'},
        'public':{'visible':True,'allow_use':True,'name':'Public '+oid,'region':'JP','description':'AI',
                  'audience':'selected','user_ids':[uid],'groups':[]},
    } for oid,uid in [('mine','u'),('theirs','v')]]
    routing.write(m.DB,settings)
    c.cookies.clear()
    root='/s/token-u/routing'
    initial=c.get(root+'/api').json()
    return c,m,root,initial['csrf']


def unlock(c,root,csrf,password='password-for-u'):
    response=c.post(root+'/unlock',json={'csrf':csrf,'password':password})
    assert response.status_code==200,response.text
    return response.json()


def document(**changes):
    row={'id':'rule-one','name':'Example','enabled':True,'kind':'domain_suffix',
         'values':['example.com'],'target':'mine','node_ids':[]}
    row.update(changes)
    return {'enabled':True,'rules':[row]}


def test_link_is_read_only_until_independent_unlock_and_api_projection(customer):
    c,m,root,t=customer
    state=c.get(root+'/api').json()
    assert state['locked'] and not state['editable'] and state['can_unlock']
    assert state['policy']['draft']['rules']==[] and not state['outbounds'] and not state['nodes']
    assert c.get(root+'/catalog').status_code==401
    assert c.post(root+'/draft',json={'csrf':t,'revision':0,'document':document()}).status_code==401
    assert c.post(root+'/unlock',json={'csrf':t,'password':'wrong'}).status_code==422
    state=unlock(c,root,t)
    assert state['editable'] and not state['locked']
    assert [out['id'] for out in state['outbounds']]==['mine']
    assert [node['id'] for node in state['nodes']]==['n']
    encoded=json.dumps(state)
    for secret in ['hidden-secret','hidden-user','private-upstream.example.com','password_hash','private-name-theirs']:
        assert secret not in encoded
    assert c.get(root+'/catalog?kind=geosite&q=AI').json()['items']
    assert c.get(root+'/catalog?kind=unknown').status_code==422
    assert c.get(root+'/catalog?offset=-1').status_code==422
    assert c.post(root+'/lock',json={'csrf':t}).json()['locked']
    assert c.get(root+'/catalog').status_code==401


def test_draft_grants_are_checked_on_server_and_cannot_target_other_user(customer):
    c,m,root,t=customer
    unlock(c,root,t)
    endpoint=root+'/draft'
    for attempted in [document(target='theirs'),document(node_ids=['other']),document(target='direct')]:
        result=c.post(endpoint,json={'csrf':t,'revision':0,'document':attempted})
        assert result.status_code==422,result.text
    assert c.post(endpoint,json={'csrf':'bad','revision':0,'document':document()}).status_code==403
    sent=document()
    sent['user_id']='v'
    sent['rules'][0]['auth_user']=['other:v']
    result=c.post(endpoint,json={'csrf':t,'revision':0,'user_id':'v','document':sent})
    assert result.status_code==200,result.text
    saved=ur.get_policy(m.DB,'u')
    assert saved['revision']==1 and saved['status']=='draft'
    assert 'auth_user' not in saved['draft']['rules'][0]
    assert ur.get_policy(m.DB,'v')['revision']==0
    assert c.post(endpoint,json={'csrf':t,'revision':0,'document':document()}).status_code==409
    assert c.post(endpoint,json={'csrf':t,'revision':True,'document':document()}).status_code==409
    assert c.post('/s/token-v/routing/draft',json={'csrf':t,'revision':0,'document':document()}).status_code==401


def test_apply_queue_discard_and_busy_are_explicit(customer):
    c,m,root,t=customer
    unlock(c,root,t)
    saved=c.post(root+'/draft',json={'csrf':t,'revision':0,'document':document()}).json()
    revision=saved['policy']['revision']
    assert c.post(root+'/apply',json={'csrf':t,'revision':revision-1}).status_code==409
    queued=c.post(root+'/apply',json={'csrf':t,'revision':revision})
    assert queued.status_code==200,queued.text
    assert queued.json()['policy']['status']=='queued'
    assert c.post(root+'/draft',json={'csrf':t,'revision':revision,'document':document()}).status_code==409
    assert c.post(root+'/discard',json={'csrf':t,'revision':revision}).status_code==409
    m.routing_publisher.publish_pending()
    applied=c.get(root+'/api').json()['policy']
    assert applied['status']=='applied' and applied['applied_revision']==revision
    changed=c.post(root+'/draft',json={'csrf':t,'revision':revision,'document':document(name='Changed')}).json()['policy']
    discarded=c.post(root+'/discard',json={'csrf':t,'revision':changed['revision']})
    assert discarded.status_code==200,discarded.text
    assert discarded.json()['policy']['draft']['rules'][0]['name']=='Example'


def test_password_token_rotation_and_account_restrictions_invalidate_writes(customer):
    c,m,root,t=customer
    unlock(c,root,t)
    ur.configure_user(m.DB,'u',True,password='replacement-password')
    assert c.get(root+'/api').json()['locked']
    assert c.post(root+'/draft',json={'csrf':t,'revision':0,'document':document()}).status_code==401
    unlock(c,root,t,'replacement-password')
    with connect(m.DB) as db:
        db.execute("UPDATE users SET token='new-token' WHERE id='u'")
    assert c.get(root+'/api').status_code==404
    root='/s/new-token/routing'
    assert c.get(root+'/api').json()['locked']
    unlock(c,root,t,'replacement-password')
    with connect(m.DB) as db:
        db.execute("UPDATE users SET enabled=0 WHERE id='u'")
    state=c.get(root+'/api').json()
    assert not state['editable'] and state['reason']=='手动停用'
    assert c.post(root+'/draft',json={'csrf':t,'revision':0,'document':document()}).status_code==403
    assert c.post(root+'/apply',json={'csrf':t,'revision':0}).status_code==403
    ur.configure_user(m.DB,'u',False)
    assert c.get(root+'/api').json()['locked']


def test_rate_limits_size_limit_and_authorized_latency(customer,monkeypatch):
    c,m,root,t=customer
    oversized=json.dumps({'csrf':t,'password':'x'*(257*1024)})
    assert c.post(root+'/unlock',content=oversized,headers={'Content-Type':'application/json'}).status_code==413
    assert c.post(root+'/unlock',content='[]').status_code==400
    unlock(c,root,t)
    calls=[]
    monkeypatch.setattr(m.runtime,'control',lambda path:(calls.append(path) or {'delay':12}))
    assert c.post(root+'/latency/theirs',json={'csrf':t}).status_code==404
    response=c.post(root+'/latency/mine',json={'csrf':t})
    assert response.status_code==200 and response.json()['delay']==12
    assert set(response.json())=={'delay','checked_at'}
    assert 'up-mine' in calls[0]
    assert c.post(root+'/latency/mine',json={'csrf':t}).json()['delay']==12
    assert len(calls)==1
    c.post(root+'/lock',json={'csrf':t})
    for _ in range(7):
        assert c.post(root+'/unlock',json={'csrf':t,'password':'wrong'}).status_code==422
    assert c.post(root+'/unlock',json={'csrf':t,'password':'password-for-u'}).status_code==429


def test_routing_subpage_precedes_subscription_catchall_and_prefixes(customer):
    c,m,root,t=customer
    assert c.get(root).status_code==200
    from panel.sharing import read_settings,save_settings
    settings=read_settings(m.DB)
    settings.update(admin_path='/manage-test',share_path='/share-test')
    save_settings(m.DB,settings)
    root='/share-test/token-u/routing'
    state=c.get(root+'/api')
    assert state.status_code==200 and '/share-test/token-u' in state.json()['share_url']
    assert c.get('/s/token-u/routing/api').status_code==404
    page=c.get(root)
    assert page.status_code==200 and '我的分流' in page.text


def test_setting_session_expires_and_legacy_subscription_remains_ua_driven(customer,monkeypatch):
    c,m,root,t=customer
    unlock(c,root,t)
    subscription=c.get('/s/token-u',headers={'User-Agent':'sing-box/1.14.3'})
    assert subscription.status_code==200 and subscription.headers['content-type'].startswith('application/json')
    assert subscription.headers['X-Subscription-Format']=='sing-box.json'
    browser=c.get('/s/token-u',headers={'User-Agent':'Mozilla/5.0','Accept':'text/html'})
    assert browser.status_code==200 and '我的分流' in browser.text
    # The dedicated route must not be swallowed by /s/{token}/{format}.
    assert c.get(root,headers={'User-Agent':'sing-box/1.14.3'}).headers['content-type'].startswith('text/html')
    future=time.time()+7201
    monkeypatch.setattr('panel.customer_routing.time.time',lambda:future)
    assert c.get(root+'/api').json()['locked']
    assert c.post(root+'/draft',json={'csrf':t,'revision':0,'document':document()}).status_code==401


@pytest.mark.parametrize('action',['draft','discard','apply'])
def test_password_rotation_while_request_waits_for_core_lock_prevents_mutation(customer,monkeypatch,action):
    c,m,root,t=customer
    unlock(c,root,t)
    original=ur.save_draft(m.DB,'u',document(),0)
    lock=m.runtime.lock

    class PasswordChangedBeforeLock:
        changed=False

        def __enter__(self):
            lock.acquire()
            if not self.changed:
                self.changed=True
                ur.configure_user(m.DB,'u',True,password='new-password-during-request')
            return self

        def __exit__(self,*args):
            lock.release()

    monkeypatch.setattr(m.runtime,'lock',PasswordChangedBeforeLock())
    response=c.post(root+'/'+action,json={'csrf':t,'revision':original['revision'],'document':document(name='Unauthorized change')})
    assert response.status_code==401,response.text
    current=ur.get_policy(m.DB,'u')
    assert current['draft']==original['draft'] and current['revision']==original['revision']
    assert current['status']=='draft'


@pytest.mark.skipif(not os.environ.get('SING_BOX'),reason='requires real core SRS matcher')
def test_preview_matches_real_srs_but_never_exposes_private_admin_exit(customer,monkeypatch):
    c,m,root,t=customer
    unlock(c,root,t)
    directory=m.DIRECTORY/'rule-sets'
    directory.mkdir(exist_ok=True)
    source=directory/'source.json'
    source.write_text(json.dumps({'version':3,'rules':[{'domain_suffix':['openai.com']}]}))
    target=directory/'geosite-category-ai-!cn.srs'
    subprocess.run([m.BINARY,'rule-set','compile',str(source),'-o',str(target)],check=True,capture_output=True)
    saved=c.post(root+'/draft',json={'csrf':t,'revision':0,
                 'document':document(kind='geosite',values=['category-ai-!cn'])})
    assert saved.status_code==200,saved.text
    matched=c.post(root+'/preview',json={'csrf':t,'destination':'api.openai.com','node_id':'n'})
    assert matched.status_code==200,matched.text
    assert matched.json()['source']=='user' and matched.json()['outbound_name']=='Public mine'
    unmatched=c.post(root+'/preview',json={'csrf':t,'destination':'example.org','node_id':'n'}).json()
    assert unmatched['source']=='default' and unmatched['outbound_name']=='服务器直连'
    assert c.post(root+'/preview',json={'csrf':t,'destination':'api.openai.com','node_id':'other'}).status_code==422
    assert c.post(root+'/preview',json={'csrf':t,'destination':'https://api.openai.com/path','node_id':'n'}).status_code==422
    settings=routing.load(m.DB)
    settings['rules']=[{'id':'forced','name':'Private admin rule','enabled':True,'priority':'forced',
                       'match':{},'target':'theirs','node_ids':['n']}]
    routing.write(m.DB,settings)
    forced=c.post(root+'/preview',json={'csrf':t,'destination':'api.openai.com','node_id':'n'})
    assert forced.json()['source']=='admin' and forced.json()['outbound_name']=='管理员指定出口'
    assert 'Private admin rule' not in forced.text and 'theirs' not in forced.text
    settings['rules']=[]
    routing.write(m.DB,settings)
    target.unlink()
    monkeypatch.setattr(routing,'prepare_rule_sets',lambda *args:pytest.fail('preview must not download rules'))
    unknown=c.post(root+'/preview',json={'csrf':t,'destination':'api.openai.com','node_id':'n'}).json()
    assert unknown['outbound_name']=='待确定'
