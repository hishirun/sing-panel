"""User-scoped sing-box subscriptions. Never exposes server private keys."""
from .core import reason
from .options import options, snell_options, reality_tls

def outbounds(user,nodes,memberships,host):
    if reason(user):
        return []
    allowed={m['node_id']:m for m in memberships if m['user_id']==user['id']}
    result=[]
    for n in nodes:
        if not n['enabled'] or n['id'] not in allowed:
            continue
        o=options(n)
        out={'tag':n['name'],'server':host,'server_port':n['port']}
        if n['protocol'] in ('snell5','snell6'):
            # sing-box's v4 outbound speaks the v5 TCP wire protocol.
            out.update(type='snell',version=4 if n['protocol']=='snell5' else 6,
                       psk=n['secret'],userkey=user['secret'],reuse=o['reuse'],**snell_options(n))
            if o['network']!='both':out['network']=o['network']
            if n['protocol']=='snell5' and o['obfs_host']:out['obfs_host']=o['obfs_host']
            if n.get('mode')=='compat':
                out['psk']=user['secret']
                out['server_port']=allowed[n['id']]['port']
                del out['userkey']
        else:
            out.update(type='vless',uuid=user['uuid'],flow=o['flow'],tls=reality_tls(n,client=True))
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
                'fp':tls['utls']['fingerprint'],'pbk':tls['reality']['public_key'],'sid':tls['reality']['short_id'],
                'type':'tcp','flow':o['flow'], **({'alpn':','.join(tls['alpn'])} if tls.get('alpn') else {})})
            lines.append(f"vless://{o['uuid']}@{host}:{o['server_port']}?{params}#{quote(o['tag'])}")
            continue
        if o['type']!='snell' or 'userkey' in o:
            continue
        version=5 if o['version']==4 else 6
        host=o['server']
        if ':' in host:host='['+host+']'
        name=o['tag'].replace('\n',' ').replace('\r',' ').replace(',',' ').replace('=',' ')
        if format=='surge.conf':
            lines.append(f"{name} = snell, {host}, {o['server_port']}, psk={o['psk']}, version={version}, reuse={str(o.get('reuse',False)).lower()}" + (f", mode={o['mode']}" if version==6 else (f", obfs={o['obfs_mode']}" if o.get('obfs_mode')=='http' else '')) + (f", obfs-host={o['obfs_host']}" if o.get('obfs_host') else ''))
        else:
            raw=f"chacha20-ietf-poly1305:{o['psk']}@{host}:{o['server_port']}"
            encoded=base64.b64encode(raw.encode()).decode()
            from urllib.parse import urlencode
            params={'version':version,'reuse':int(o.get('reuse',False))}
            if version==6:params['mode']=o.get('mode','default')
            elif o.get('obfs_mode')=='http':params.update(obfs='http', **({'obfs-host':o['obfs_host']} if o.get('obfs_host') else {}))
            lines.append(f"snell://{encoded}?{urlencode(params)}#{quote(name)}")
    if format=='surge.conf':
        return '[Proxy]\n'+'\n'.join(lines)+'\n'
    return base64.b64encode(('\n'.join(lines)+'\n').encode()).decode()
