"""User-scoped sing-box subscriptions. Never exposes server private keys."""
from .core import reason

def outbounds(user,nodes,memberships,host):
    if reason(user):
        return []
    allowed={m['node_id']:m for m in memberships if m['user_id']==user['id']}
    result=[]
    for n in nodes:
        if not n['enabled'] or n['id'] not in allowed:
            continue
        out={'tag':n['name'],'server':host,'server_port':n['port']}
        if n['protocol'] in ('snell5','snell6'):
            # sing-box's v4 outbound speaks the v5 TCP wire protocol.
            out.update(type='snell',version=4 if n['protocol']=='snell5' else 6,
                       psk=n['secret'],userkey=user['secret'])
            if n.get('mode')=='compat':
                out['psk']=user['secret']
                out['server_port']=allowed[n['id']]['port']
                del out['userkey']
        else:
            out.update(type='vless',uuid=user['uuid'],flow='xtls-rprx-vision',tls={
                'enabled':True,'server_name':n['server_name'],
                'utls':{'enabled':True,'fingerprint':'chrome'},
                'reality':{'enabled':True,'public_key':n['public_key'],'short_id':n['short_id']}})
        result.append(out)
    return result


def native_subscription(outs,format):
    import base64
    from urllib.parse import quote
    lines=[]
    for o in outs:
        if o['type']=='vless' and format=='shadowrocket.txt':
            from urllib.parse import urlencode
            tls=o['tls']
            host=o['server']
            if ':' in host:host='['+host+']'
            params=urlencode({'encryption':'none','security':'reality','sni':tls['server_name'],
                'fp':'chrome','pbk':tls['reality']['public_key'],'sid':tls['reality']['short_id'],
                'type':'tcp','flow':o['flow']})
            lines.append(f"vless://{o['uuid']}@{host}:{o['server_port']}?{params}#{quote(o['tag'])}")
            continue
        if o['type']!='snell' or 'userkey' in o:
            continue
        version=5 if o['version']==4 else 6
        host=o['server']
        if ':' in host:host='['+host+']'
        name=o['tag'].replace('\n',' ').replace('\r',' ').replace(',',' ').replace('=',' ')
        if format=='surge.conf':
            lines.append(f"{name} = snell, {host}, {o['server_port']}, psk={o['psk']}, version={version}, reuse=true")
        else:
            raw=f"chacha20-ietf-poly1305:{o['psk']}@{host}:{o['server_port']}"
            encoded=base64.b64encode(raw.encode()).decode()
            lines.append(f"snell://{encoded}?version={version}&reuse=1#{quote(name)}")
    if format=='surge.conf':
        return '[Proxy]\n'+'\n'.join(lines)+'\n'
    return base64.b64encode(('\n'.join(lines)+'\n').encode()).decode()
