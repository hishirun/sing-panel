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


def test_batch_roundtrip_json_and_uri_special_chars_ipv6_ss2022_and_admin_debug(customer,monkeypatch):
    import base64
    from urllib.parse import quote
    from panel.protocols import new_key
    c,m,root,t=customer
    answers=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('1.1.1.1',0))]
    monkeypatch.setattr(socket,'getaddrinfo',lambda *args,**kwargs:answers)
    apply_calls=[]
    monkeypatch.setattr(m.runtime,'apply',lambda:apply_calls.append(1))
    k128=new_key('2022-blake3-aes-128-gcm')
    k256_pair=new_key('2022-blake3-aes-256-gcm')+':'+new_key('2022-blake3-aes-256-gcm')
    sr_socks=base64.urlsafe_b64encode(b'sr-user:sr-p@ss:1').decode().rstrip('=')
    legacy_ss=base64.b64encode('aes-128-gcm:leg@cy%40pass@1.1.1.1:8381'.encode()).decode()
    lines=[
        f"http://{quote('u:@/#?%+',safe='')}:{quote('p@ss:w/rd?#%&+ 中文',safe='')}@[2001:4860:4860::8888]:8080#{quote('香港 HTTP #1 <img src=x onerror=1>',safe='')}",
        f"https://tls-user:{quote('tls/p?a=1#b',safe='')}@proxy.example.com:8443?sni=cdn.example.com#{quote('东京 HTTPS 节点',safe='')}",
        f"socks5://only-user:@[2606:4700:4700::1111]:1080#{quote('IPv6 仅用户名',safe='')}",
        f"socks5://{sr_socks}@8.8.8.8:1081#ShadowrocketSocks",
        'ss://'+base64.urlsafe_b64encode('chacha20-ietf-poly1305:cl@ssic:p/w%40#中文'.encode()).decode().rstrip('=')+f'@[2606:4700:4700::1111]:8388#{quote("经典 SS IPv6",safe="")}',
        f"ss://2022-blake3-aes-128-gcm:{quote(k128,safe='')}@1.1.1.1:8389#{quote('SS2022 单密钥',safe='')}",
        f"ss://2022-blake3-aes-256-gcm:{quote(k256_pair,safe='')}@[2001:4860:4860::8844]:8390#{quote('SS2022 双密钥',safe='')}",
        f"ss://{legacy_ss}#LegacyBase64",
    ]
    batch_text='\n\n# 注释行忽略\n'+'\n'.join(lines)+'\n'
    prev=c.post(root+'/personal/import/preview',json={'csrf':t,'text':batch_text})
    assert prev.status_code==200,prev.text
    pdata=prev.json()
    assert pdata['parsed_count']==8 and pdata['importable_count']==8 and pdata['duplicate_count']==0 and pdata['error_count']==0
    assert pdata['remaining_quota']==10 and pdata['after_remaining_quota']==2 and pdata['can_import'] is True
    for secret in ('p@ss:w/rd','tls/p?a=1','sr-p@ss','cl@ssic:p/w',k128,k256_pair.split(':')[0]):
        assert secret not in prev.text
    res=c.post(root+'/personal/import',json={'csrf':t,'text':batch_text})
    assert res.status_code==200,res.text
    assert res.json()['import_result']['imported_count']==8 and len(apply_calls)==1
    # Toggle one item to disabled so JSON round-trip also verifies enabled=False fidelity.
    saved_rows=p.rows(m.DB,'u')
    assert len(saved_rows)==8
    assert c.post(root+'/personal/'+saved_rows[1]['id']+'/toggle',json={'csrf':t,'revision':1}).status_code==200
    original_snapshot=[(r['name'],r['enabled'],r['address'],r['settings']) for r in p.rows(m.DB,'u')]
    # Selective export of 2 items
    sel=c.post(root+'/personal/export',json={'csrf':t,'scope':'selected','ids':[saved_rows[0]['id'],saved_rows[6]['id']],'format':'json'})
    assert sel.status_code==200
    assert 'private' in sel.headers['cache-control'] and 'no-store' in sel.headers['cache-control']
    assert re.fullmatch(r'attachment; filename="personal-outbounds-\d{8}-\d{6}\.json"',sel.headers['content-disposition'])
    sel_doc=sel.json()
    assert sel_doc['format']=='sing-panel-personal-outbounds' and sel_doc['version']==1 and len(sel_doc['items'])==2
    # Full JSON export — verify no internal IDs, tokens, rules or public secrets leak, nor enter audit logs
    full_json=c.post(root+'/personal/export',json={'csrf':t,'scope':'all','format':'json'})
    assert full_json.status_code==200
    for forbidden in ('token-u','hidden-secret','private-upstream.example.com','owner_id','user_id',saved_rows[0]['id']):
        assert forbidden not in full_json.text
    with connect(m.DB) as db:
        logs=json.dumps([dict(r) for r in db.execute('SELECT * FROM audit_log')])
    assert 'p@ss:w/rd' not in logs and k128 not in logs
    # Full URI export
    full_uri=c.post(root+'/personal/export',json={'csrf':t,'scope':'all','format':'uri'})
    assert full_uri.status_code==200
    assert re.fullmatch(r'attachment; filename="personal-outbounds-\d{8}-\d{6}\.txt"',full_uri.headers['content-disposition'])
    assert len(full_uri.text.strip().splitlines())==8
    # Wipe DB rows and re-import from JSON export -> exact bit-for-bit restoration in a single apply!
    with connect(m.DB) as db:db.execute("DELETE FROM personal_outbounds WHERE user_id='u'")
    apply_calls.clear()
    reimp_json=c.post(root+'/personal/import',json={'csrf':t,'text':full_json.text})
    assert reimp_json.status_code==200 and len(apply_calls)==1
    assert [(r['name'],r['enabled'],r['address'],r['settings']) for r in p.rows(m.DB,'u')]==original_snapshot
    # Wipe DB rows and re-import from URI export -> exact connection/name restoration in a single apply!
    with connect(m.DB) as db:db.execute("DELETE FROM personal_outbounds WHERE user_id='u'")
    apply_calls.clear()
    reimp_uri=c.post(root+'/personal/import',json={'csrf':t,'text':full_uri.text})
    assert reimp_uri.status_code==200 and len(apply_calls)==1
    assert [(r['name'],r['address'],r['settings']) for r in p.rows(m.DB,'u')]==[(n,a,s) for n,_,a,s in original_snapshot]
    # Administrator inspection & debugging remains functional on batch-imported exits
    target_id=p.rows(m.DB,'u')[0]['id']
    c.cookies.clear();login_page=c.get('/login');adm_csrf=re.search('name="token" value="([^"]+)"',login_page.text)[1]
    c.post('/login',data={'token':adm_csrf,'username':'admin','password':'test-password-only'})
    detail=c.get('/routing/personal/'+target_id)
    assert detail.status_code==200 and 'p@ss:w/rd' in detail.text and detail.headers['cache-control']=='no-store'


def test_cross_user_export_and_auth_csrf_revocation_boundaries(customer,monkeypatch):
    c,m,root,t=customer
    alice_exit=create(customer,password='alice-top-secret')
    # Cross-user export attempts by Bob ('v')
    c.cookies.clear();customer_login(c,'/s/token-v')
    v_root='/s/token-v/routing'
    v_csrf=c.get(v_root+'/api').json()['csrf']
    assert c.post(v_root+'/personal/export',json={'csrf':v_csrf,'ids':[alice_exit['id']]}).status_code==404
    bob_exit=c.post(v_root+'/personal',json={'csrf':v_csrf,**raw(server='8.8.8.8',password='bob-own-secret')}).json()['personal_outbounds'][0]
    mixed=c.post(v_root+'/personal/export',json={'csrf':v_csrf,'ids':[bob_exit['id'],alice_exit['id']]})
    assert mixed.status_code==404 and 'alice-top-secret' not in mixed.text
    assert c.post(v_root+'/personal/export',json={'csrf':v_csrf,'ids':['mine']}).status_code==404
    bob_all=c.post(v_root+'/personal/export',json={'csrf':v_csrf,'scope':'all','format':'json'})
    assert bob_all.status_code==200 and 'bob-own-secret' in bob_all.text and 'alice-top-secret' not in bob_all.text
    # CSRF rejection on all 3 batch endpoints
    for endpoint,payload in [('/personal/import/preview',{'text':'socks5://1.1.1.1:1080#A'}),
                             ('/personal/import',{'text':'socks5://1.1.1.1:1080#A'}),
                             ('/personal/export',{'scope':'all'})]:
        assert c.post(v_root+endpoint,json=payload).status_code==403
        assert c.post(v_root+endpoint,json={'csrf':'forged',**payload}).status_code==403
    # Permission revocation (allowed=0) blocks preview, import and export
    with connect(m.DB) as db:db.execute("UPDATE user_routing SET allowed=0 WHERE user_id='v'")
    for endpoint,payload in [('/personal/import/preview',{'csrf':v_csrf,'text':'socks5://1.1.1.1:1080#A'}),
                             ('/personal/import',{'csrf':v_csrf,'text':'socks5://1.1.1.1:1080#A'}),
                             ('/personal/export',{'csrf':v_csrf,'scope':'all'})]:
        assert c.post(v_root+endpoint,json=payload).status_code==403
    # Disabled account (reason(user) truthy) blocks preview, import and export even when allowed=1
    with connect(m.DB) as db:
        db.execute("UPDATE user_routing SET allowed=1 WHERE user_id='v'")
        db.execute("UPDATE users SET enabled=0 WHERE id='v'")
    for endpoint,payload in [('/personal/import/preview',{'csrf':v_csrf,'text':'socks5://1.1.1.1:1080#A'}),
                             ('/personal/import',{'csrf':v_csrf,'text':'socks5://1.1.1.1:1080#A'}),
                             ('/personal/export',{'csrf':v_csrf,'scope':'all'})]:
        assert c.post(v_root+endpoint,json=payload).status_code==403
    with connect(m.DB) as db:db.execute("UPDATE users SET enabled=1 WHERE id='v'")
    # Mid-flight permission revocation during batch import check_document
    calls=0
    def revoke_on_full_check(doc):
        nonlocal calls;calls+=1
        if 'route' in doc:
            with connect(m.DB) as db:db.execute("UPDATE user_routing SET allowed=0 WHERE user_id='v'")
    monkeypatch.setattr(m,'check_document',revoke_on_full_check)
    assert c.post(v_root+'/personal/import',json={'csrf':v_csrf,'text':'socks5://9.9.9.9:1080#LateRevoke'}).status_code==403
    assert len(p.rows(m.DB,'v'))==1
    # Unauthenticated client rejected on all 3 endpoints
    c.cookies.clear()
    for endpoint in ('/personal/import/preview','/personal/import','/personal/export'):
        assert c.post(v_root+endpoint,json={'csrf':v_csrf,'text':'socks5://1.1.1.1:1080#A'}).status_code in (401,403)


def test_malicious_fields_private_ips_loopback_and_secret_redaction_in_errors(customer,monkeypatch):
    c,m,root,t=customer
    monkeypatch.setattr(m,'PUBLIC_HOST','1.1.1.1')
    def fake_dns(host,*args,**kwargs):
        if host=='rebind.example.com':
            return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('1.1.1.1',0)),
                    (socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',0))]
        raise OSError('dns failed')
    monkeypatch.setattr(socket,'getaddrinfo',fake_dns)
    # 1. Arbitrary sing-box JSON rejected
    for raw_doc in (
        {'outbounds':[{'type':'socks','server':'1.1.1.1','server_port':1080}]},
        [{'name':'x','type':'socks','server':'1.1.1.1','server_port':1080}],
        {'format':'sing-panel-personal-outbounds','version':2,'items':[]},
        {'format':'sing-panel-personal-outbounds','version':1,'extra':1,'items':[{'name':'x','type':'socks','server':'1.1.1.1','server_port':1080}]},
    ):
        r1=c.post(root+'/personal/import/preview',json={'csrf':t,'text':json.dumps(raw_doc)})
        assert r1.status_code==422
        r2=c.post(root+'/personal/import',json={'csrf':t,'text':json.dumps(raw_doc)})
        assert r2.status_code==422
    # 2. Versioned JSON with malicious / unsupported item keys rejected and secret redacted
    evil_items=[
        {'name':'detour','type':'socks','server':'1.1.1.1','server_port':1080,'password':'SECRET_JSON_1','detour':'direct'},
        {'name':'iface','type':'socks','server':'1.1.1.1','server_port':1080,'password':'SECRET_JSON_2','bind_interface':'lo0'},
        {'name':'dialer','type':'socks','server':'1.1.1.1','server_port':1080,'password':'SECRET_JSON_3','dialer':{'bind_interface':'eth0'}},
        {'name':'insec','type':'http','server':'1.1.1.1','server_port':8443,'tls_mode':'tls','insecure':True,'password':'SECRET_JSON_4'},
        {'name':'tlsdict','type':'http','server':'1.1.1.1','server_port':8443,'tls':{'enabled':True,'insecure':True},'password':'SECRET_JSON_5'},
        {'name':'hijack','type':'socks','server':'1.1.1.1','server_port':1080,'owner_id':'v','password':'SECRET_JSON_6'},
        {'name':'boolport','type':'socks','server':'1.1.1.1','server_port':True,'password':'SECRET_JSON_7'},
    ]
    evil_json=json.dumps({'format':'sing-panel-personal-outbounds','version':1,'items':evil_items})
    pj=c.post(root+'/personal/import/preview',json={'csrf':t,'text':evil_json})
    assert pj.status_code==200 and pj.json()['error_count']==len(evil_items) and not pj.json()['can_import']
    for i in range(1,8):assert f'SECRET_JSON_{i}' not in pj.text
    cj=c.post(root+'/personal/import',json={'csrf':t,'text':evil_json})
    assert cj.status_code==422 and all(f'SECRET_JSON_{i}' not in cj.text for i in range(1,8))
    # 3. Malicious / private / loopback / bad-port / plugin / skip-verify URIs rejected without echoing secrets or URIs
    bad_uris=[
        'vless://SECRET_URI_1@1.1.1.1:443?security=tls#Unsupported',
        'https://user:SECRET_URI_2@8.8.8.8:8443?insecure=1#SkipVerify1',
        'https://user:SECRET_URI_3@8.8.8.8:8443?allowInsecure=true#SkipVerify2',
        'socks5://user:SECRET_URI_4@8.8.8.8:1080?detour=direct#Detour',
        'socks5://user:SECRET_URI_5@8.8.8.8:1080?bind_interface=eth0#Bind',
        'ss://aes-128-gcm:SECRET_URI_6@8.8.8.8:8388/?plugin=obfs-local#Plugin',
        'socks5://user:SECRET_URI_7@127.0.0.1:1080#Loopback',
        'http://user:SECRET_URI_8@169.254.169.254:80#Metadata',
        'socks5://user:SECRET_URI_9@[::ffff:127.0.0.1]:1080#MappedLoopback',
        'socks5://user:SECRET_URI_10@[fe80::1%25lo0]:1080#ZoneBind',
        'socks5://user:SECRET_URI_11@rebind.example.com:1080#DNSRebind',
        'socks5://user:SECRET_URI_12@8.8.8.8:19090#StatsPort',
        'socks5://user:SECRET_URI_13@1.1.1.1:30001#ManagedNodeLoop',
        'socks5://myuser:SECRET_URI_14#MissingHostPort',
        'ss://2022-blake3-aes-128-gcm:SECRET_URI_15@8.8.8.8:8388#BadSS2022Key',
    ]
    uri_blob='\n'.join(bad_uris)
    pu=c.post(root+'/personal/import/preview',json={'csrf':t,'text':uri_blob})
    assert pu.status_code==200 and pu.json()['error_count']==len(bad_uris) and pu.json()['parsed_count']==0
    for idx in range(1,16):
        assert f'SECRET_URI_{idx}' not in pu.text
    assert 'socks5://' not in pu.text and 'https://' not in pu.text
    cu=c.post(root+'/personal/import',json={'csrf':t,'text':uri_blob})
    assert cu.status_code==422
    for idx in range(1,16):
        assert f'SECRET_URI_{idx}' not in cu.text
    assert p.rows(m.DB)==[]


def test_duplicates_skip_without_overwriting_and_quota_cap_enforced(customer):
    c,m,root,t=customer
    first=create(customer,name='My exit',server='1.1.1.1',server_port=1080,username='owner-user',password='owner-only-secret')
    batch='\n'.join([
        'socks5://owner-user:owner-only-secret@1.1.1.1:1080#My exit',
        'socks5://owner-user:owner-only-secret@1.1.1.1:1080',
        'socks5://u2:p2@8.8.8.8:1080#Fresh',
        'socks5://u2:p2@8.8.8.8:1080#Fresh',
        'socks5://owner-user:different-secret@1.1.1.1:1081#My exit',
    ])
    prev=c.post(root+'/personal/import/preview',json={'csrf':t,'text':batch}).json()
    assert prev['parsed_count']==5 and prev['importable_count']==2 and prev['duplicate_count']==3 and prev['can_import'] is True
    res=c.post(root+'/personal/import',json={'csrf':t,'text':batch})
    assert res.status_code==200
    assert res.json()['import_result']=={'imported_count':2,'duplicate_count':3,'ids':res.json()['import_result']['ids']}
    current=p.rows(m.DB,'u')
    assert len(current)==3
    # Original 'My exit' was NOT overwritten
    orig=next(r for r in current if r['id']==first['id'])
    assert orig['settings']['password']=='owner-only-secret' and orig['settings']['server_port']==1080
    # Re-importing an all-duplicate export succeeds cleanly with 0 imported and 0 mutations
    exported=c.post(root+'/personal/export',json={'csrf':t,'scope':'all','format':'json'}).text
    again=c.post(root+'/personal/import',json={'csrf':t,'text':exported})
    assert again.status_code==200 and again.json()['import_result']['imported_count']==0 and again.json()['import_result']['duplicate_count']==3
    assert len(p.rows(m.DB,'u'))==3
    # Quota enforcement: currently 3/10 (remaining 7). Importing 8 new items must fail atomically with 0 added.
    eight='\n'.join(f'socks5://u:p@9.9.9.9:{2000+i}#Cap{i}' for i in range(8))
    cap_prev=c.post(root+'/personal/import/preview',json={'csrf':t,'text':eight}).json()
    assert cap_prev['remaining_quota']==7 and cap_prev['importable_count']==8 and cap_prev['exceeds_quota'] is True and not cap_prev['can_import']
    assert c.post(root+'/personal/import',json={'csrf':t,'text':eight}).status_code==422
    assert len(p.rows(m.DB,'u'))==3
    # Importing 7 new + 1 duplicate reaches exact cap 10/10
    seven_plus_dup='\n'.join([*(f'socks5://u:p@9.9.9.9:{2000+i}#Cap{i}' for i in range(7)),'socks5://u2:p2@8.8.8.8:1080#Fresh'])
    ok=c.post(root+'/personal/import',json={'csrf':t,'text':seven_plus_dup})
    assert ok.status_code==200 and ok.json()['import_result']['imported_count']==7 and ok.json()['import_result']['duplicate_count']==1
    assert len(p.rows(m.DB,'u'))==10
    # At 10/10, 1 more new outbound is rejected
    over=c.post(root+'/personal/import/preview',json={'csrf':t,'text':'socks5://u:p@9.9.9.9:2999#Eleven'}).json()
    assert over['remaining_quota']==0 and over['exceeds_quota'] is True and not over['can_import']
    assert c.post(root+'/personal/import',json={'csrf':t,'text':'socks5://u:p@9.9.9.9:2999#Eleven'}).status_code==422
    assert len(p.rows(m.DB,'u'))==10


def test_mixed_error_batch_atomic_rollback_and_concurrent_modifications(customer,monkeypatch):
    c,m,root,t=customer
    create(customer,name='Baseline',server='1.1.1.1',server_port=1080)
    baseline=p.rows(m.DB)
    apply_calls=[]
    monkeypatch.setattr(m.runtime,'apply',lambda:apply_calls.append(1))
    # 1. Mixed valid + invalid lines must NOT persist any line
    mixed='\n'.join([
        'socks5://u:p@8.8.8.8:1081#Good1',
        'socks5://u:SECRET_BAD@127.0.0.1:1082#BadPrivate',
        'socks5://u:p@8.8.4.4:1083#Good2',
    ])
    mp=c.post(root+'/personal/import/preview',json={'csrf':t,'text':mixed}).json()
    assert mp['parsed_count']==2 and mp['importable_count']==2 and mp['error_count']==1 and mp['errors'][0]['line']==2 and not mp['can_import']
    mc=c.post(root+'/personal/import',json={'csrf':t,'text':mixed})
    assert mc.status_code==422 and 'SECRET_BAD' not in mc.text and p.rows(m.DB)==baseline and apply_calls==[]
    # 2. Verify runtime.lock is NOT held during DNS resolution or check_document
    lock_states=[]
    monkeypatch.setattr(socket,'getaddrinfo',lambda *a,**k:(lock_states.append(m.runtime.lock.locked()),[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',0))])[1])
    monkeypatch.setattr(m,'check_document',lambda doc:lock_states.append(m.runtime.lock.locked()))
    clean_batch='socks5://u:p@valid.example.com:1081#One\nsocks5://u:p@valid.example.com:1082#Two'
    # 3. Runtime apply failure rolls back ALL inserted rows in the batch and restores runtime
    monkeypatch.setattr(m.runtime,'apply',Mock(side_effect=[RuntimeError('CORE-INTERNAL-SECRET'),None]))
    failed_apply=c.post(root+'/personal/import',json={'csrf':t,'text':clean_batch})
    assert failed_apply.status_code==422 and 'CORE-INTERNAL-SECRET' not in failed_apply.text
    assert p.rows(m.DB)==baseline
    assert lock_states and not any(lock_states)
    assert m.runtime.apply.call_count==2
    # 4. Concurrent modification of user's personal outbounds during validation aborts commit
    monkeypatch.setattr(m.runtime,'apply',lambda:apply_calls.append(1))
    def concurrent_personal_edit(doc):
        if 'route' in doc:
            extra=copy.deepcopy(baseline[0]);extra.update(id='personal-concurrent',name='Concurrent')
            p._put(m.DB,extra)
    monkeypatch.setattr(m,'check_document',concurrent_personal_edit)
    conflict1=c.post(root+'/personal/import',json={'csrf':t,'text':clean_batch})
    assert conflict1.status_code==422 and '已被修改' in conflict1.text and apply_calls==[]
    assert {r['id'] for r in p.rows(m.DB,'u')}=={baseline[0]['id'],'personal-concurrent'}
    # 5. Concurrent modification of global running config during validation aborts commit
    def concurrent_global_edit(doc):
        if 'route' in doc:
            s=routing.load(m.DB);s['sniff']=not s.get('sniff',False);routing.write(m.DB,s)
    monkeypatch.setattr(m,'check_document',concurrent_global_edit)
    before_conflict2=p.rows(m.DB,'u')
    conflict2=c.post(root+'/personal/import',json={'csrf':t,'text':clean_batch})
    assert conflict2.status_code==422 and '已变化' in conflict2.text and apply_calls==[]
    assert p.rows(m.DB,'u')==before_conflict2


def test_customer_routing_html_and_frontend_xss_and_batch_workflow(customer):
    import shutil,subprocess
    from pathlib import Path
    c,m,root,t=customer
    xss='"><img src=x onerror=alert(1)>测试出口'
    create(customer,name=xss)
    page=c.get(root)
    assert page.status_code==200
    for marker in ('personal-egress-import','personal-egress-export','personal-select-all',
                   'personal-egress-importer','personal-egress-exporter','导出文件包含连接密码'):
        assert marker in page.text
    assert '<img src=x' not in page.text
    repo=Path(__file__).resolve().parent.parent
    js=(repo/'panel/static/customer-routing.js').read_text()
    for unsafe in ('innerHTML','outerHTML','insertAdjacentHTML'):
        assert unsafe not in js
    node=shutil.which('node') or ('/opt/homebrew/bin/node' if Path('/opt/homebrew/bin/node').is_file() else None)
    if not node:
        pytest.skip('Node.js is required for frontend UI verification')
    result=subprocess.run([node,str(repo/'tests/frontend/personal_outbounds_ui.cjs')],
                          cwd=repo,text=True,capture_output=True,timeout=15)
    assert result.returncode==0,result.stdout+result.stderr


def test_bulk_export_requires_explicit_selection_and_never_expands_scope(customer):
    c,m,root,t=customer;entry=create(customer)
    for payload in ({'scope':'selected'},{'scope':'selected','ids':None},{'scope':'selected','ids':[]},
                    {'scope':'all','ids':[entry['id']]}):
        response=c.post(root+'/personal/export',json={'csrf':t,**payload})
        assert response.status_code==422 and 'owner-only-secret' not in response.text
    response=c.post(root+'/personal/export',json={'csrf':t,'scope':'selected','ids':[entry['id']]})
    assert response.status_code==200 and len(response.json()['items'])==1


@pytest.mark.parametrize('revoke',('permission','session'))
def test_export_reauthorizes_after_waiting_for_worker(customer,monkeypatch,revoke):
    import panel.customer_routing as cr
    c,m,root,t=customer;create(customer,password='NEVER-RETURN-AFTER-REVOCATION')
    original=cr.run_in_threadpool
    async def delayed(function,*args,**kwargs):
        if function.__name__=='download':
            with connect(m.DB) as db:
                if revoke=='permission':db.execute("UPDATE user_routing SET allowed=0 WHERE user_id='u'")
                else:db.execute("UPDATE user_auth SET auth_revision=auth_revision+1 WHERE user_id='u'")
        return await original(function,*args,**kwargs)
    monkeypatch.setattr(cr,'run_in_threadpool',delayed)
    response=c.post(root+'/personal/export',json={'csrf':t,'scope':'all'})
    assert response.status_code==(403 if revoke=='permission' else 401)
    assert 'NEVER-RETURN-AFTER-REVOCATION' not in response.text


def test_preview_permission_revocation_and_batch_deadline(customer,monkeypatch):
    c,m,root,t=customer;original=p.preview_import
    def revoked(*args):
        result=original(*args)
        with connect(m.DB) as db:db.execute("UPDATE user_routing SET allowed=0 WHERE user_id='u'")
        return result
    monkeypatch.setattr(p,'preview_import',revoked)
    response=c.post(root+'/personal/import/preview',json={'csrf':t,'text':'socks5://u:p@1.1.1.1:1080#One'})
    assert response.status_code==403
    with monkeypatch.context() as clock:
        clock.setattr(p.time,'monotonic',Mock(side_effect=[0,0,31]))
        with pytest.raises(ValueError,match='校验超时'):
            original(m,'u','socks5://1.1.1.1:1080#One\nsocks5://8.8.8.8:1080#Two')
    assert p.rows(m.DB)==[]
