import base64
import json
import os
import re
import subprocess
from pathlib import Path
import pytest
import yaml
from test_app import client, csrf
from panel.client_profiles import detect_client, ini_profile, mihomo_profile, singbox_profile

URL='https://panel.example.com/share-abc/user-token'

def nodes():
    tls={'enabled':True,'server_name':'example.com'}
    return [
        dict(type='snell',tag='Proxy',server='127.0.0.1',server_port=31001,version=6,psk='example-password-123',mode='unshaped'),
        dict(type='snell',tag='Proxy',server='127.0.0.1',server_port=31002,version=4,psk='example-password-123'),
        dict(type='snell',tag='Shared',server='127.0.0.1',server_port=31003,version=6,psk='example-password-123',userkey='my-user-key-123'),
        dict(type='hysteria2',tag='HY2',server='127.0.0.1',server_port=31004,password='my-password',tls=tls,obfs={'type':'salamander','password':'obfs-password'}),
        dict(type='anytls',tag='AnyTLS',server='127.0.0.1',server_port=31005,password='my-password',tls=tls),
        dict(type='vless',tag='Reality',server='127.0.0.1',server_port=31006,uuid='b49661a4-7fab-40fe-a045-71ed212a6c3d',flow='xtls-rprx-vision',tls={**tls,'utls':{'enabled':True,'fingerprint':'chrome'},'reality':{'enabled':True,'public_key':'v4Dh93ZoHXLUPMSYZyyEIufio9XPLhpJMGt_dAPDezk','short_id':'12345678'}}),
    ]

@pytest.mark.parametrize('ua,expected',[
    ('Mozilla/5.0 Safari/605.1',None), ('Surge iOS/4000','surge.conf'),
    ('Surfboard/2.0 (Surge-compatible)','surfboard.conf'), ('Shadowrocket/2400','shadowrocket.txt'),
    ('Clash.Meta/1.19','clash.yaml'), ('mihomo/1.19.0','clash.yaml'),
    ('sing-box/1.14.3','sing-box.json'), ('Hiddify/4.0','sing-box.json')])
def test_detection(ua,expected):
    assert detect_client(ua)==expected

def test_profiles_filter_protocols_and_fill_templates():
    items=nodes()
    surge,count=ini_profile(items,'surge.conf',URL+'/surge.conf',{})
    assert count==4 and 'version=6' in surge and 'mode=unshaped' in surge
    assert 'hysteria2,' in surge and 'anytls,' in surge
    assert 'Shared =' not in surge and 'Reality =' not in surge
    assert surge.startswith('#!MANAGED-CONFIG '+URL+'/surge.conf')
    assert '$' not in surge and '[Rule]' in surge and '[Proxy Group]' in surge
    surf,count=ini_profile(items,'surfboard.conf',URL+'/surfboard.conf',{})
    assert count==3 and 'version=6' not in surf and 'version=4' in surf
    assert '$' not in surf and 'DOMAIN,panel.example.com,DIRECT' in surf
    clash,count=mihomo_profile(items,URL+'/clash.yaml')
    doc=yaml.safe_load(clash)
    assert count==4 and len(doc['proxies'])==4
    assert not any(p.get('version')==6 for p in doc['proxies'])
    names=[p['name'] for p in doc['proxies']]
    assert len(names)==len(set(names)) and 'Proxy' not in names
    assert doc['dns']['listen']=='127.0.0.1:1053'
    all_names=set(names)|{g['name'] for g in doc['proxy-groups']}|{'DIRECT','REJECT'}
    assert all(p in all_names for g in doc['proxy-groups'] for p in g['proxies'])
    assert all(r.split(',')[-1] in all_names for r in doc['rules'])
    assert items[0]['tag']=='Proxy'  # No mutation of account data.

def test_singbox_current_schema_and_empty_profiles(tmp_path):
    text,count=singbox_profile(nodes(),URL+'/sing-box.json','sing-box/1.14.3')
    doc=json.loads(text)
    assert count==6 and len({o['tag'] for o in doc['outbounds']})==len(doc['outbounds'])
    assert not any('sniff' in i or 'domain_strategy' in i for i in doc['inbounds'])
    assert all('type' in d and 'address' not in d for d in doc['dns']['servers'])
    assert not any(o['type'] in ('block','dns') for o in doc['outbounds'])
    assert json.loads(singbox_profile(nodes(),URL,'sing-box/1.12.0')[0])['outbounds'][0]['type']=='hysteria2'
    with pytest.raises(ValueError):singbox_profile(nodes(),URL,'sing-box/1.11.0')
    empty=json.loads(singbox_profile([],URL)[0])
    assert empty['outbounds']==[] and empty['route']['rules']==[{'action':'reject'}]
    assert yaml.safe_load(mihomo_profile([],URL)[0])['rules']==['MATCH,REJECT']
    assert 'Proxy = select, REJECT' in ini_profile([],'surge.conf',URL,{})[0]
    if os.environ.get('SING_BOX'):
        for name,body in [('full',text),('empty',json.dumps(empty))]:
            path=tmp_path/(name+'.json');path.write_text(body)
            result=subprocess.run([os.environ['SING_BOX'],'check','-c',str(path)],capture_output=True,text=True)
            assert result.returncode==0,result.stderr

def test_ua_routes_scope_headers_and_overrides(client):
    c,m=client;t=csrf(c)
    c.post('/nodes',data={'token':t,'name':'test','protocol':'snell6','mode':'compat'})
    node=m.records(m.DB,'nodes')[0]
    for name in ('Alice','Bob'):
        c.post('/users',data={'token':t,'name':name,'node_ids':[node['id']]})
    alice,bob=m.records(m.DB,'users')
    path='/s/'+alice['token']
    browser=c.get(path,headers={'user-agent':'Mozilla/5.0','accept':'text/html'})
    assert 'text/html' in browser.headers['content-type']
    assert '设置登录密码' in browser.text and alice['secret'] not in browser.text
    for agent,fmt in [('Surge/4000','surge.conf'),('Surfboard/2','surfboard.conf'),('mihomo/1.19','clash.yaml'),('sing-box/1.14','sing-box.json'),('Shadowrocket/2400','shadowrocket.txt')]:
        for entry in (path,path+'/subscription'):
            res=c.get(entry,headers={'user-agent':agent})
            assert res.status_code==200
            assert res.headers['x-subscription-format']==fmt
            assert 'User-Agent' in res.headers['vary']
            assert res.headers['profile-web-page-url'].endswith(path)
            assert bob['secret'] not in res.text and bob['uuid'] not in res.text
            assert 'no-store' in res.headers['cache-control']
            assert 'subscription-userinfo' in res.headers
    explicit=c.get(path+'?format=surge',headers={'user-agent':'mihomo/1.19'})
    assert explicit.headers['x-subscription-format']=='surge.conf'
    assert alice['secret'] in explicit.text
    assert path+' interval=' in explicit.text
    assert c.get(path+'?format=nope').status_code==400
    c.post('/users/'+alice['id']+'/action',data={'token':csrf(c),'action':'toggle'})
    for fmt in ('sing-box.json','clash.yaml','surge.conf','surfboard.conf','shadowrocket.txt'):
        res=c.get(path+'/'+fmt)
        content=base64.b64decode(res.text).decode() if fmt=='shadowrocket.txt' else res.text
        assert alice['secret'] not in content
        assert res.headers['x-subscription-node-count']=='0'


def test_client_import_links():
    from urllib.parse import urlsplit, parse_qs, unquote
    from panel.client_profiles import client_imports
    result=client_imports(URL, '用户 & 测试')
    assert len(result)==5
    for client in result:
        if client['key']=='shadowrocket':
            target=unquote(client['href'].removeprefix('shadowrocket://add/'))
        else:
            target=parse_qs(urlsplit(client['href']).query)['url'][0]
        assert target==URL
        assert (Path('panel/static/clients')/client['icon']).is_file()
    assert unquote(urlsplit(result[0]['href']).fragment)=='用户 & 测试'
