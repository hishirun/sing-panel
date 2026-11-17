"""Personal egress ownership, secret handling, pinning and rollback boundaries."""
import copy,json,re,socket
from unittest.mock import Mock
import pytest
from panel import personal_outbounds as p,routing,user_routing as ur
from panel.core import connect,current_config,records
from panel.fleet import save_server
from panel.fleet_config import configuration
from panel.server_publish import input_signature
from test_app import client,csrf
from test_customer_routing_api import customer,document
from customer_helpers import customer_login


def raw(kind='socks',**changes):
    return {'name':'My exit','type':kind,'server':'1.1.1.1','server_port':1080,'username':'owner-user','password':'owner-only-secret',
            'method':'chacha20-ietf-poly1305',**changes}


def create(customer,kind='socks',**changes):
    c,m,root,token=customer
    response=c.post(root+'/personal',json={'csrf':token,**raw(kind,**changes)})
    assert response.status_code==200,response.text
    return response.json()['personal_outbounds'][-1]


@pytest.mark.parametrize('kind,tls',[('http','none'),('http','tls'),('socks','none'),('shadowsocks','none')])
def test_customer_crud_credentials_redacted_and_admin_can_inspect(customer,kind,tls):
    c,m,root,token=customer;entry=create(customer,kind,tls_mode=tls)
    assert entry['type']==kind and entry['has_password'] and entry['password']==''
    row=p.rows(m.DB,'u')[0]
    assert row['settings']['password']=='owner-only-secret'
    assert row['settings']['server']=='1.1.1.1'
    page=c.get(root);assert '管理员可查看配置' in page.text and '个人出口' in page.text
    for url in (root,root+'/api','/s/token-u/sing-box.json'):
        text=c.get(url).text
        for secret in ('owner-only-secret','hidden-secret','hidden-user','private-upstream.example.com'):
            assert secret not in text
    update=c.post(root+'/personal/'+entry['id'],json={'csrf':token,**raw(kind,password='',name='Changed'), 'tls_mode':tls,'revision':entry['revision']})
    assert update.status_code==200 and p.rows(m.DB,'u')[0]['settings']['password']=='owner-only-secret'
    assert c.post(root+'/personal/'+entry['id'],json={'csrf':token,**raw(kind),'revision':entry['revision']}).status_code==422
    customer_login(c,'/s/token-v');other=c.get('/s/token-v/routing/api').json()
    assert entry['id'] not in json.dumps(other) and 'owner-user' not in json.dumps(other)
    for suffix in ('','/delete','/toggle'):
        assert c.post('/s/token-v/routing/personal/'+entry['id']+suffix,json={'csrf':other['csrf'],'revision':2,**raw(kind)}).status_code==404
    assert c.post('/s/token-v/routing/latency/'+entry['id'],json={'csrf':other['csrf']}).status_code==404
    with pytest.raises(ValueError,match='未授权'):ur.validate_draft(m.DB,'v',document(target=entry['id']))
    c.cookies.clear();page=c.get('/login');t=re.search('name="token" value="([^"]+)"',page.text)[1]
    c.post('/login',data={'token':t,'username':'admin','password':'test-password-only'})
    page=c.get('/routing');assert '用户个人出口' in page.text and 'Alice' in page.text
    page=c.get('/routing/personal/'+entry['id'])
    assert page.status_code==200 and 'owner-only-secret' in page.text and '管理员调试' in page.text and page.headers['cache-control']=='no-store'
    t=csrf(c)
    m.runtime.control=Mock(return_value={'delay':23})
    assert c.post('/routing/personal/'+entry['id']+'/latency',data={'token':t}).json()['delay']==23
    payload={**raw(kind,password='admin-changed'),'token':t,'revision':2,'tls_mode':tls,'intent':'save'}
    assert c.post('/routing/personal/'+entry['id'],data=payload).status_code==200
    assert p.rows(m.DB,'u')[0]['settings']['password']=='admin-changed'
    assert routing.load(m.DB)['final']=='direct'


@pytest.mark.parametrize('address',['127.0.0.1','10.0.0.1','169.254.169.254','192.168.1.1','100.100.100.200','0.0.0.0','::1','fc00::1','fe80::1','::ffff:127.0.0.1','224.0.0.1','ff02::1','192.0.2.1'])
def test_non_public_personal_addresses_rejected(address):
    with pytest.raises(ValueError,match='公网|内网|保留'):p.build(raw(server=address))


def test_dns_mixed_answers_rebinding_and_tls_original_hostname(monkeypatch):
    answers=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('1.1.1.1',0))]
    query=Mock(return_value=answers);monkeypatch.setattr(socket,'getaddrinfo',query)
    built=p.build(raw('http',server='proxy.example.com',tls_mode='tls'))
    assert built['settings']['server']=='1.1.1.1' and built['settings']['tls']['server_name']=='proxy.example.com'
    answers.append((socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',0)))
    with pytest.raises(ValueError,match='公网'):p.build(raw(server='rebind.example.com'))
    assert query.call_count==2


def test_protocol_whitelist_and_raw_config_injection_cannot_reach_core():
    with pytest.raises(ValueError):p.build(raw('vless'))
    for bad in ({'server_port':19090},{'tls_mode':'reality'},{'password':'abc\r\nCookie: secret'}, {'name':'x\nforged'}):
        with pytest.raises(ValueError):p.build(raw(**bad))
    built=p.build(raw(detour='direct',tls={'insecure':True},insecure=True,transport='ws',owner_id='other',tag='direct',dialer={'bind_interface':'lo'}))
    assert set(built['settings'])=={'type','server','server_port','version','username','password'}
    from panel.protocols import new_key
    for method in ('2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm'):
        assert p.build(raw('shadowsocks',method=method,password=new_key(method)))['settings']['method']==method
        with pytest.raises(ValueError):p.build(raw('shadowsocks',method=method,password='bad'))


def test_compiler_identity_scope_disable_refs_deletion_and_cascade(customer):
    c,m,root,t=customer;entry=create(customer)
    policy=ur.save_draft(m.DB,'u',document(target=entry['id']),0)
    with connect(m.DB) as db:db.execute('UPDATE user_routing SET applied=draft,applied_revision=revision WHERE user_id=?',('u',))
    compiled=current_config(m.DB)
    private=[row for row in compiled['route']['rules'] if row.get('outbound')=='up-'+entry['id']]
    assert len(private)==1 and 'n:u' in json.dumps(private) and 'other:v' not in json.dumps(private)
    assert c.post(root+'/personal/'+entry['id']+'/delete',json={'csrf':t,'revision':1}).status_code==422
    assert c.post(root+'/personal/'+entry['id']+'/toggle',json={'csrf':t,'revision':1}).status_code==200
    compiled=current_config(m.DB)
    assert 'up-'+entry['id'] not in json.dumps(compiled)
    assert any(row.get('action')=='reject' and 'n:u' in json.dumps(row) for row in compiled['route']['rules'])
    with connect(m.DB) as db:db.execute("UPDATE user_routing SET draft=?,applied=? WHERE user_id='u'",(json.dumps({'enabled':True,'rules':[]}),json.dumps({'enabled':True,'rules':[]})))
    assert c.post(root+'/personal/'+entry['id']+'/delete',json={'csrf':t,'revision':2}).status_code==200
    assert p.rows(m.DB,'u')==[]
    create(customer)
    with connect(m.DB) as db:db.execute("DELETE FROM users WHERE id='u'")
    assert p.rows(m.DB)==[]


def test_failed_check_or_runtime_retains_original_and_does_not_leak(customer,monkeypatch):
    c,m,root,t=customer;entry=create(customer);before=p.rows(m.DB)
    monkeypatch.setattr(m,'check_document',Mock(side_effect=ValueError('password=ADMIN-SECRET')))
    response=c.post(root+'/personal/'+entry['id'],json={'csrf':t,**raw(password='new-secret'),'revision':1})
    assert response.status_code==422 and 'ADMIN-SECRET' not in response.text and p.rows(m.DB)==before
    monkeypatch.setattr(m,'check_document',lambda document:None)
    monkeypatch.setattr(m.runtime,'apply',Mock(side_effect=[RuntimeError('ADMIN-SECRET'),None]))
    response=c.post(root+'/personal/'+entry['id'],json={'csrf':t,**raw(password='new-secret'),'revision':1})
    assert response.status_code==422 and 'ADMIN-SECRET' not in response.text and p.rows(m.DB)==before


def test_auth_csrf_caps_and_field_ownership(customer):
    c,m,root,t=customer
    assert c.post(root+'/personal',json=raw()).status_code==403
    entry=create(customer,owner_id='v',public={'visible':True,'audience':'all'})
    assert p.rows(m.DB)[0]['user_id']=='u'
    for i in range(9):
        row=copy.deepcopy(p.rows(m.DB)[0]);row.update(id='personal-fixture-'+str(i));p._put(m.DB,row)
    assert c.post(root+'/personal',json={'csrf':t,**raw()}).status_code==422
    with connect(m.DB) as db:db.execute("UPDATE user_routing SET allowed=0 WHERE user_id='u'")
    assert c.post(root+'/personal/'+entry['id']+'/toggle',json={'csrf':t,'revision':1}).status_code==403
    assert c.get(root+'/api').json()['personal_outbounds']==[]
    c.cookies.clear();assert c.post(root+'/personal',json={'csrf':t,**raw()}).status_code in (401,403)


def test_remote_signature_and_delivery_strip_other_owners(customer):
    c,m,root,t=customer;entry=create(customer)
    first=save_server(m.DB,'First','8.8.8.8');second=save_server(m.DB,'Second','9.9.9.9')
    with connect(m.DB) as db:
        db.execute('UPDATE nodes SET server_id=? WHERE id=?',(first['id'],'n'))
        db.execute('UPDATE nodes SET server_id=? WHERE id=?',(second['id'],'other'))
        policy=document(target=entry['id']);db.execute("UPDATE user_routing SET applied=? WHERE user_id='u'",(json.dumps(policy),))
    before=[input_signature(m.DB,s['id']) for s in (first,second)]
    assert entry['id'] in json.dumps(configuration(m.DB,first['id']))
    assert 'owner-only-secret' not in json.dumps(configuration(m.DB,second['id']))
    row=p.rows(m.DB)[0];row['settings']['password']='changed-password';row['revision']+=1;p._put(m.DB,row)
    after=[input_signature(m.DB,s['id']) for s in (first,second)]
    assert before[0]!=after[0] and before[1]==after[1]


def test_permissions_rechecked_after_slow_validation_and_work_is_bounded(customer,monkeypatch):
    c,m,root,t=customer
    def revoked(document):
        with connect(m.DB) as db:db.execute("UPDATE user_routing SET allowed=0 WHERE user_id='u'")
    monkeypatch.setattr(m,'check_document',revoked)
    assert c.post(root+'/personal',json={'csrf':t,**raw()}).status_code==403
    assert p.rows(m.DB)==[]
    with connect(m.DB) as db:db.execute("UPDATE user_routing SET allowed=1 WHERE user_id='u'")
    assert p._mutations.acquire(blocking=False) and p._mutations.acquire(blocking=False)
    try:
        response=c.post(root+'/personal',json={'csrf':t,**raw()})
        assert response.status_code==422 and '请稍后重试' in response.text
        assert p.rows(m.DB)==[]
    finally:p._mutations.release();p._mutations.release()


@pytest.mark.parametrize('kind',[None,[],{},True])
def test_invalid_protocol_types_return_validation_errors(kind):
    with pytest.raises(ValueError):p.build(raw(kind))


def test_personal_cannot_loop_back_to_a_managed_listener(customer,monkeypatch):
    c,m,root,t=customer
    monkeypatch.setattr(m,'PUBLIC_HOST','1.1.1.1')
    response=c.post(root+'/personal',json={'csrf':t,**raw(server_port=30001)})
    assert response.status_code==422 and '循环连接' in response.text
    assert p.rows(m.DB)==[]
