"""Local, user-scoped client profile generation; no third-party converter."""
import copy
import json
import re
from pathlib import Path
from string import Template
from urllib.parse import urlsplit
import yaml

TEMPLATES = Path(__file__).with_name('subscription_templates')
FORMATS = {'sing-box.json', 'surge.conf', 'surfboard.conf', 'clash.yaml', 'shadowrocket.txt'}
ALIASES = {'singbox': 'sing-box.json', 'sing-box': 'sing-box.json', 'surge': 'surge.conf',
           'surfboard': 'surfboard.conf', 'clash': 'clash.yaml', 'mihomo': 'clash.yaml',
           'shadowrocket': 'shadowrocket.txt'}


def detect_client(ua):
    ua = ua.lower()
    for needle, fmt in [('shadowrocket', 'shadowrocket.txt'), ('surfboard', 'surfboard.conf'),
                        ('surge', 'surge.conf'), ('mihomo', 'clash.yaml'), ('clash', 'clash.yaml'),
                        ('sing-box', 'sing-box.json'), ('singbox', 'sing-box.json'),
                        ('hiddify', 'sing-box.json'), ('sfi/', 'sing-box.json'), ('sfa/', 'sing-box.json')]:
        if needle in ua:
            return fmt
    return None


def resolve_format(value, ua=''):
    if value in ('auto', 'subscription'):
        return detect_client(ua) or 'shadowrocket.txt'
    fmt = ALIASES.get(value, value)
    if fmt not in FORMATS:
        raise ValueError('未知订阅格式')
    return fmt


def named_outbounds(outs):
    """Avoid duplicate tags and collisions with built-ins or template group names."""
    reserved = {'DIRECT','REJECT','REJECT-DROP','GLOBAL','direct','block','dns-out','节点选择','自动选择',
                'Proxy','Final','Streaming','AdBlock','auto','fallback'}
    template = yaml.safe_load((TEMPLATES / 'mihomo.yaml').read_text())
    reserved.update(g['name'] for g in template['proxy-groups'])
    result = copy.deepcopy(outs)
    for index, out in enumerate(result, 1):
        name = re.sub(r'[\x00-\x1f\x7f,=\[\]#;$"\\]', ' ', out['tag']).strip() or f'节点 {index}'
        base = name
        counter = 2
        while name in reserved:
            name = f'{base} ({counter})'
            counter += 1
        reserved.add(name)
        out['tag'] = name
    return result


def ini_value(value):
    value = str(value)
    if any(ord(c) < 32 for c in value):
        raise ValueError('节点参数含有不支持的控制字符')
    return json.dumps(value, ensure_ascii=False) if re.search(r'[\s,;#"\\]', value) else value


def ini_proxy(out, surfboard=False):
    kind = out['type']
    host = out['server']
    if ':' in host:
        host = '[' + host + ']'
    prefix = f"{out['tag']} = {kind}, {ini_value(host)}, {out['server_port']}"
    if kind=='shadowsocks':
        if out['method']=='2022-blake3-chacha20-poly1305':return None
        return f"{out['tag']} = ss, {ini_value(host)}, {out['server_port']}, encrypt-method={out['method']}, password={ini_value(out['password'])}, udp-relay=true"
    if kind=='trojan':
        transport=out.get('transport',{})
        if transport.get('type')=='grpc':return None
        line=prefix+', password='+ini_value(out['password'])+', sni='+ini_value(out['tls']['server_name'])+', skip-cert-verify=false'
        if out['tls'].get('alpn') and not surfboard:line+=', alpn='+ini_value(','.join(out['tls']['alpn']))
        if transport.get('type')=='ws':
            line+=', ws=true, ws-path='+ini_value(transport['path'])
            if transport.get('headers',{}).get('Host'):line+=', ws-headers='+ini_value('Host:'+transport['headers']['Host'])
        return line+(', udp-relay=true' if surfboard else '')
    if kind == 'snell':
        if 'userkey' in out or (surfboard and out['version'] == 6):
            return None
        version = (4 if surfboard else 5) if out['version'] == 4 else 6
        line = prefix + f", psk={ini_value(out['psk'])}, version={version}, reuse={str(out.get('reuse', False)).lower()}"
        if version == 6:
            line += ', mode=' + out.get('mode', 'default')
        elif out.get('obfs_mode') == 'http':
            line += ', obfs=http, obfs-host=' + ini_value(out.get('obfs_host', 'bing.com'))
        if surfboard:
            line += ', udp-relay=true'
        return line
    if kind not in ('hysteria2', 'anytls'):
        return None
    obfs = out.get('obfs', {})
    if surfboard and obfs.get('type') == 'gecko':
        return None
    tls = out['tls']
    line = prefix + ', password=' + ini_value(out['password']) + ', sni=' + ini_value(tls['server_name'])
    line += ', skip-cert-verify=' + str(tls.get('insecure', False)).lower()
    if tls.get('alpn') and not surfboard:
        line += ', alpn=' + ini_value(','.join(tls['alpn']))
    if obfs:
        line += ', ' + obfs['type'] + '-password=' + ini_value(obfs['password'])
    if kind == 'hysteria2' and out.get('down_mbps'):
        line += ', download-bandwidth=' + str(out['down_mbps'])
    return line


def ini_profile(outs, fmt, url, user):
    pairs = [(o, ini_proxy(o, fmt == 'surfboard.conf')) for o in named_outbounds(outs)]
    pairs = [(o, line) for o, line in pairs if line]
    text = (TEMPLATES / fmt).read_text()
    # The supplied Surfboard panel uses a template-only macro. Native response
    # headers carry quota/expiry without injecting an unsupported panel value.
    text = re.sub(r'\[Panel\]\s*SubscribeInfo[^\n]*\n', '', text)
    body = Template(text).substitute(subs_link=url, proxies='\n'.join(line for _, line in pairs),
                                    proxy_group=', '.join(o['tag'] for o, _ in pairs) or 'REJECT',
                                    subs_domain=urlsplit(url).hostname)
    return body, len(pairs)


def mihomo_proxy(out):
    kind = out['type']
    p = {'name': out['tag'], 'type': kind, 'server': out['server'], 'port': out['server_port'], 'udp': True}
    if kind=='shadowsocks':
        p.update(type='ss',cipher=out['method'],password=out['password'],udp=out.get('network')!='tcp')
        return p
    if kind=='trojan':
        tls=out['tls'];p.update(password=out['password'],sni=tls['server_name'],**{'skip-cert-verify':False})
        if tls.get('alpn'):p['alpn']=tls['alpn']
        transport=out.get('transport',{})
        if transport.get('type')=='ws':p.update(network='ws',**{'ws-opts':{'path':transport['path'],'headers':transport.get('headers',{})}})
        elif transport.get('type')=='grpc':p.update(network='grpc',**{'grpc-opts':{'grpc-service-name':transport['service_name']}})
        return p
    if kind == 'snell':
        if out['version'] == 6 or 'userkey' in out:
            return None
        # v4 avoids unsupported QUIC-proxy mode; wire compatible with our v5.
        p.update(psk=out['psk'], version=4, reuse=out.get('reuse', False))
        if out.get('obfs_mode') == 'http':
            p['obfs-opts'] = {'mode': 'http', 'host': out.get('obfs_host', 'bing.com')}
        return p
    if kind not in ('vless', 'anytls', 'hysteria2'):
        return None
    tls = out['tls']
    p.update(sni=tls['server_name'], **{'skip-cert-verify': tls.get('insecure', False)})
    if tls.get('alpn'):
        p['alpn'] = tls['alpn']
    if kind == 'vless':
        p.update(uuid=out['uuid'], flow=out.get('flow', ''), tls=True, network='tcp')
        p['servername'] = p.pop('sni')
        p['client-fingerprint'] = tls.get('utls', {}).get('fingerprint', 'chrome')
        p['reality-opts'] = {'public-key': tls['reality']['public_key'], 'short-id': tls['reality']['short_id']}
    else:
        p['password'] = out['password']
    if kind == 'anytls':
        p['client-fingerprint'] = 'chrome'
        for key in ('idle_session_check_interval', 'idle_session_timeout', 'min_idle_session'):
            if key in out:
                p[key.replace('_','-')] = int(str(out[key]).removesuffix('s'))
    if kind == 'hysteria2':
        if out.get('obfs'):
            p.update(obfs=out['obfs']['type'], **{'obfs-password': out['obfs']['password']})
            for key in ('min_packet_size', 'max_packet_size'):
                if key in out['obfs']:
                    p['obfs-' + key.replace('_', '-')] = out['obfs'][key]
        for key, target in [('up_mbps','up'), ('down_mbps','down')]:
            if out.get(key):
                p[target] = f"{out[key]} Mbps"
    return p


def mihomo_profile(outs, url):
    doc = yaml.safe_load((TEMPLATES / 'mihomo.yaml').read_text())
    proxies = [p for o in named_outbounds(outs) if (p := mihomo_proxy(o))]
    doc.pop('global-client-fingerprint', None)
    doc['proxies'] = proxies
    names = [p['name'] for p in proxies]
    for group in doc['proxy-groups']:
        if group['name'] == '自动选择':
            group['proxies'] = names or ['REJECT']
        elif group['name'] == 'Proxy':
            group['proxies'] += names
    # Avoid exposing a recursive resolver on every network interface.
    doc['dns']['listen'] = '127.0.0.1:1053'
    doc['dns']['proxy-server-nameserver'] = ['223.5.5.5','119.29.29.29']
    doc['rules'].insert(0, 'DOMAIN,' + urlsplit(url).hostname + ',DIRECT')
    if not proxies:
        doc['rules'] = ['MATCH,REJECT']
    return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), len(proxies)


def singbox_profile(outs, url, ua=''):
    nodes = named_outbounds(outs)
    version = re.search(r'sing-?box[/\s]+(\d+)\.(\d+)', ua, re.I)
    if version and tuple(map(int, version.groups())) < (1,12):
        raise ValueError('此配置需要 sing-box 1.12 或更新版本；Snell 需要 1.14 或更新版本')
    if version and tuple(map(int, version.groups())) < (1,14):
        nodes = [o for o in nodes if o['type'] != 'snell']
    names = [o['tag'] for o in nodes]
    doc = {
        'log': {'level':'warn'},
        'dns': {
            'servers': [{'type':'https','tag':'remote','server':'1.1.1.1','path':'/dns-query','detour':'节点选择'},
                        {'type':'https','tag':'local','server':'223.5.5.5','path':'/dns-query'}],
            'rules': [{'clash_mode':'global','server':'remote'}, {'clash_mode':'direct','server':'local'},
                      {'rule_set':['geosite-cn'],'server':'local'}],
            'final':'remote', 'strategy':'prefer_ipv4'
        },
        'experimental': {'cache_file': {'enabled':True,'path':'cache.db'}},
        'inbounds': [
            {'type':'tun','tag':'tun-in','address':['172.19.0.1/30','fdfe:dcba:9876::1/126'],
             'mtu':1500,'auto_route':True,'strict_route':True,'stack':'system'},
            {'type':'socks','tag':'socks-in','listen':'127.0.0.1','listen_port':2333},
            {'type':'mixed','tag':'mixed-in','listen':'127.0.0.1','listen_port':2334}],
        'outbounds': nodes + [{'type':'selector','tag':'节点选择','default':'自动选择','outbounds':['自动选择']+names},
                             {'type':'urltest','tag':'自动选择','outbounds':names or ['direct'],
                              'url':'https://www.gstatic.com/generate_204','interval':'3m'},
                             {'type':'direct','tag':'direct'}],
        'route': {
            'auto_detect_interface':True,'default_domain_resolver':{'server':'local','strategy':'prefer_ipv4'},
            'final':'节点选择',
            'rules':[{'action':'sniff'}, {'protocol':'dns','action':'hijack-dns'},
                     {'domain':[urlsplit(url).hostname],'outbound':'direct'},
                     {'clash_mode':'direct','outbound':'direct'}, {'clash_mode':'global','outbound':'节点选择'},
                     {'ip_is_private':True,'outbound':'direct'},
                     {'rule_set':['geosite-cn','geoip-cn'],'outbound':'direct'}],
            'rule_set':[{'tag':tag,'type':'remote','format':'binary',
                         'url':f'https://raw.githubusercontent.com/SagerNet/{repo}/rule-set/{tag}.srs'}
                        for tag,repo in [('geosite-cn','sing-geosite'),('geoip-cn','sing-geoip')]]
        }
    }
    if not nodes:
        doc['route'] = {'rules':[{'action':'reject'}]}
        doc['outbounds'] = []
        doc['dns'] = {'servers':[{'type':'https','tag':'local','server':'223.5.5.5','path':'/dns-query'}], 'final':'local'}
    return json.dumps(doc, ensure_ascii=False, indent=2), len(nodes)


def client_imports(share_url, name):
    """Every client imports the canonical share URL; HTTP UA selects the profile."""
    from urllib.parse import quote
    clients = [
        ('singbox', 'sing-box', 'singbox.png', 'sing-box://import-remote-profile?url='),
        ('clash', 'Clash', 'clash.png', 'clash://install-config?url='),
        ('surge', 'Surge', 'surge.jpg', 'surge:///install-config?url='),
        ('surfboard', 'Surfboard', 'surfboard.png', 'surfboard:///install-config?url='),
        ('shadowrocket', 'Shadowrocket', 'shadowrocket.jpg', 'shadowrocket://add/'),
    ]
    result = []
    for key, label, icon, prefix in clients:
        url = share_url
        href = prefix + quote(url, safe='')
        if key == 'singbox':
            href += '#' + quote(name, safe='')
        result.append(dict(key=key, label=label, icon=icon, href=href))
    return result
