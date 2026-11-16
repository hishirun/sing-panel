"""User-scoped sing-box subscriptions. Never exposes server private keys."""
from .core import reason
from .options import options, snell_options, reality_tls, certificate_tls, hysteria_options

def outbounds(user,nodes,memberships,host):
    if reason(user):
        return []
    allowed={m['node_id']:m for m in memberships if m['user_id']==user['id']}
    result=[]
    for n in nodes:
        if not n['enabled'] or not n.get('server_enabled',True) or n['id'] not in allowed:
            continue
        o=options(n)
        out={'tag':n['name'],'server':o['connect_host'] or n.get('server_host') or host,'server_port':n['port']}
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
        elif n['protocol'] in ('ss','ss2022'):
            from .protocols import user_key
            password=user_key(n,user) if n['protocol']=='ss2022' else user['secret']
            if n.get('mode')=='compat':out['server_port']=allowed[n['id']]['port']
            else:password=n['secret']+':'+password
            out.update(type='shadowsocks',method=o['ss_method'],password=password)
            if o['network']!='both':out['network']=o['network']
        elif n['protocol'] in ('anytls','hysteria2','trojan'):
            out.update(type=n['protocol'],password=user['secret'],tls=certificate_tls(n,client=True))
            if n['protocol']=='hysteria2':out.update(hysteria_options(n,client=True))
            elif n['protocol']=='trojan':
                from .protocols import transport
                if transport(n):out['transport']=transport(n)
            else:out.update(idle_session_check_interval=f"{o['any_idle_check']}s",idle_session_timeout=f"{o['any_idle_timeout']}s",min_idle_session=o['any_min_idle'])
        else:
            out.update(type='vless',uuid=user['uuid'],flow=o['flow'],tls=reality_tls(n,client=True))
        result.append(out)
    return result


def native_subscription(outs,format):
    import base64
    from urllib.parse import quote
    lines=[]
    for o in outs:
        if o['type'] in ('shadowsocks','trojan'):
            if format=='surge.conf':
                from .client_profiles import ini_proxy,named_outbounds
                line=ini_proxy(named_outbounds([o])[0])
                if line:lines.append(line)
                continue
            from urllib.parse import urlencode
            host=o['server'];host='['+host+']' if ':' in host else host
            if o['type']=='shadowsocks':
                credential=(o['method']+':'+quote(o['password'],safe='')) if o['method'].startswith('2022-') else base64.urlsafe_b64encode((o['method']+':'+o['password']).encode()).decode().rstrip('=')
                lines.append(f"ss://{credential}@{host}:{o['server_port']}#{quote(o['tag'],safe='')}")
            else:
                params={'security':'tls','sni':o['tls']['server_name'],'type':'tcp'}
                if o['tls'].get('alpn'):params['alpn']=','.join(o['tls']['alpn'])
                transport=o.get('transport',{})
                if transport.get('type')=='ws':params.update(type='ws',path=transport['path'],host=transport.get('headers',{}).get('Host',''))
                elif transport.get('type')=='grpc':params.update(type='grpc',serviceName=transport['service_name'])
                lines.append(f"trojan://{quote(o['password'],safe='')}@{host}:{o['server_port']}?{urlencode(params)}#{quote(o['tag'],safe='')}")
            continue
        if o['type'] in ('anytls','hysteria2') and format=='shadowrocket.txt':
            from urllib.parse import urlencode
            host=o['server'];host='['+host+']' if ':' in host else host
            params={'sni':o['tls']['server_name']}
            if o['tls'].get('alpn'):params['alpn']=','.join(o['tls']['alpn'])
            if o.get('obfs'):
                if o['obfs']['type']=='gecko':continue
                params.update(obfs='salamander',**{'obfs-password':o['obfs']['password']})
            lines.append(f"{o['type']}://{quote(o['password'],safe='')}@{host}:{o['server_port']}?{urlencode(params)}#{quote(o['tag'])}")
            continue
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
