import json
import pytest
from pydantic import ValidationError
from panel.options import NodeOptions,import_key,reality_tls,listen_options
from panel.core import config
from panel.subscriptions import outbounds,native_subscription

@pytest.mark.parametrize('field,value',[
    ('snell_mode','invisible'),('listen','example.com'),('handshake_port',0),
    ('short_ids','abc'),('short_ids','gg'),('alpn','h3'),('fingerprint','unknown'),
    ('handshake_timeout',0),('max_time_difference',-1),('handshake_host','https://example.com')])
def test_reject_unsupported_options(field,value):
    with pytest.raises(ValidationError):NodeOptions.model_validate({field:value})

def test_reality_config_and_client_match():
    private,public=import_key('A'*43)
    n=dict(id='n',name='Reality',protocol='reality',port=32100,enabled=1,mode='shared',
           private_key=private,public_key=public,short_id='ab',server_name='www.microsoft.com',
           options=json.dumps(dict(handshake_host='1.2.3.4',handshake_port=8443,
             short_ids='aabb,11223344',max_time_difference=60,handshake_timeout=9,
             fingerprint='firefox',flow='',alpn='h2,http/1.1')))
    u=dict(id='u',uuid='11111111-1111-4111-8111-111111111111',secret='secret',enabled=1,quota=0,expires=0)
    m=[dict(node_id='n',user_id='u')]
    server=config([n],[u],m)['inbounds'][0]
    client=outbounds(u,[n],m,'test.example.com')[0]
    assert server['tls']['reality']['handshake']==dict(server='1.2.3.4',server_port=8443)
    assert server['tls']['reality']['short_id']==['aabb','11223344']
    assert server['tls']['reality']['max_time_difference']=='60s'
    assert client['tls']['reality']['short_id']=='aabb'
    assert client['tls']['utls']['fingerprint']=='firefox'
    assert client['flow']==server['users'][0]['flow']==''
    assert private not in json.dumps(client)
    import base64
    uri=base64.b64decode(native_subscription([client],'shadowrocket.txt')).decode()
    assert 'fp=firefox' in uri and 'sid=aabb' in uri

def test_no_keepalive_fields_when_disabled():
    result=listen_options({'options':{'disable_tcp_keep_alive':True}})
    assert result['disable_tcp_keep_alive']
    assert 'tcp_keep_alive' not in result
