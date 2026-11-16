"""Protocol-specific credentials and transport options shared by both sides."""
import base64
import hashlib
import hmac
import secrets

SS_CLASSIC=('aes-128-gcm','aes-256-gcm','chacha20-ietf-poly1305')
SS_2022=('2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305')

def key_size(method):return 16 if method=='2022-blake3-aes-128-gcm' else 32

def new_key(method):return base64.b64encode(secrets.token_bytes(key_size(method))).decode()

def validate_key(value,method):
    try:
        raw=base64.b64decode(value,validate=True)
        if len(raw)!=key_size(method) or base64.b64encode(raw).decode()!=value:raise ValueError()
    except Exception:raise ValueError('SS2022 密钥须为正确长度的标准 Base64；留空可自动生成') from None
    return value

def user_key(node,user):
    from .options import options
    method=options(node)['ss_method']
    payload=('sing-panel:ss2022:'+node['id']+':'+method).encode()
    return base64.b64encode(hmac.new(user['secret'].encode(),payload,hashlib.sha256).digest()[:key_size(method)]).decode()

def shadow_password(node,user):
    payload=('sing-panel:shadowtls-v3:'+node['id']).encode()
    return base64.urlsafe_b64encode(hmac.new(user['secret'].encode(),payload,hashlib.sha256).digest()).decode().rstrip('=')

def expand_singbox_nodes(nodes):
    """Materialize private ShadowTLS detours without adding helpers to selectors."""
    import copy
    result=[]
    reserved={n['tag'] for n in nodes}|{'direct','节点选择','自动选择'}
    for node in nodes:
        node=copy.deepcopy(node)
        wrapper=node.pop('_shadowtls',None)
        if wrapper:
            tag='__shadowtls_'+str(len(result)+1)
            while tag in reserved:tag+='_'
            reserved.add(tag)
            node['detour']=tag
        result.append(node)
        if wrapper:result.append({**wrapper,'tag':tag})
    return result

def transport(node):
    from .options import options
    o=options(node)
    if o['trojan_transport']=='ws':
        host=o['ws_host']
        if ':' in host:host='['+host+']'
        return {'type':'ws','path':o['ws_path'],**({'headers':{'Host':host}} if host else {})}
    if o['trojan_transport']=='grpc':return {'type':'grpc','service_name':o['grpc_service_name']}
    return None
