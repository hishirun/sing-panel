"""Explain a route using the saved draft and real local SRS match command.

This does not connect to the supplied destination. Missing DNS/transport facts
produce an explicit uncertain result instead of a misleading successful test.
"""
import ipaddress
import subprocess
import time
from pathlib import Path

from . import routing, user_routing
from .core import reason
from .customer_routing_scope import nodes as scoped_nodes


def preview(m, user, policy, destination, node_id, mode='draft'):
    if mode not in ('draft', 'applied'):
        raise ValueError('请选择草稿或已发布规则')
    if not isinstance(destination,str) or not destination.strip() or len(destination)>253:
        raise ValueError('请输入域名或 IP 地址，不带协议和路径')
    destination=routing.host(destination.strip().lower())
    try:
        address=ipaddress.ip_address(destination)
    except ValueError:
        address=None
    settings=routing.load(m.DB)
    nodes=scoped_nodes(m.DB, user['id'], settings)
    selected=next((node for node in nodes if node['id']==node_id and node['available']),None)
    if selected is None:
        raise ValueError('请选择一个当前可用节点')
    if reason(user):
        raise ValueError('当前账户不可用，不能推演新连接')
    public={out['id']:out for out in user_routing.public_outbounds(m.DB,user,settings)}
    permitted={out['id'] for out in settings['outbounds'] if user_routing.allowed_outbound(out,user,policy)}
    cache={}
    checks=0
    deadline=time.monotonic()+8

    def any_result(values):
        return True if True in values else None if None in values else False

    def all_result(values):
        return False if False in values else None if None in values else True

    def geo(kind, values):
        nonlocal checks
        if (kind=='geoip' and address is None) or (kind=='geosite' and address is not None):
            return None
        results=[]
        for value in values:
            if value not in routing.GEO_CATALOG[kind]:
                return None
            tag=kind+'-'+value
            if tag in cache:
                results.append(cache[tag]);continue
            path=Path(m.DIRECTORY)/'rule-sets'/(tag+'.srs')
            if not path.exists() or checks>=32 or time.monotonic()>=deadline:
                cache[tag]=None;results.append(None);continue
            checks+=1
            try:
                result=subprocess.run([m.BINARY,'rule-set','match','--format','binary',str(path),destination],capture_output=True,text=True,timeout=max(.05,min(2,deadline-time.monotonic())))
                value=bool(result.stderr.strip() or result.stdout.strip()) if result.returncode==0 else None
            except (OSError,subprocess.TimeoutExpired):
                value=None
            cache[tag]=value;results.append(value)
            if value is True:
                return True
        return any_result(results)

    def match(fields):
        groups=[];host=[]
        for key, values in fields.items():
            if key in ('geosite','geoip'):
                groups.append(geo(key,values))
            elif key in ('domain','domain_suffix','domain_keyword'):
                if address is not None:
                    host.append(None)
                elif key=='domain':host.append(destination in values)
                elif key=='domain_suffix':host.append(any(destination==v.lstrip('.') or destination.endswith('.'+v.lstrip('.')) for v in values))
                else:host.append(any(v in destination for v in values))
            elif key=='ip_cidr':
                host.append(any(address in ipaddress.ip_network(v) for v in values) if address else None)
            elif key=='ip_is_private':
                host.append(address.is_private if address else None)
            else:
                # Protocol/network/port require facts not present in a bare
                # destination; never claim a definite later fallback.
                groups.append(None)
        if host:groups.append(any_result(host))
        return all_result(groups)

    def result(source, name, target, uncertain=False, rule_id=None):
        label='拦截' if target=='reject' else '服务器直连' if target=='direct' else public.get(target,{}).get('name','管理员指定出口')
        metadata={'mode':mode, 'matched': None if uncertain else True,
                  'revision':policy['revision'] if mode=='draft' else policy['applied_revision'],
                  'rule_id':rule_id, 'node_name':selected['name'], 'server_name':selected['server_name']}
        note='仅预览规则匹配，不代表连通性。' if selected['online'] else '机器离线；仅预览规则匹配。'
        if uncertain:
            return {**metadata,'summary':'还不能确定匹配结果','rule_name':name,'outbound_name':'待确定','source':source,
                    'warning':'缺少规则集、目标 IP 或连接信息；需实际连接验证。'}
        return {**metadata,'summary':name+' → '+label,'rule_name':name,'outbound_name':label,'source':source,
                'warning':note}

    forced=[row for row in settings['rules'] if row.get('priority','forced')!='default']
    ordinary=[row for row in settings['rules'] if row.get('priority','forced')=='default']

    def administrative(rows):
        for row in rows:
            if not row['enabled'] or (row.get('node_ids') and node_id not in row['node_ids']):
                continue
            matched=match(row['match'])
            if matched is not False:
                name='管理员强制规则' if row.get('priority','forced')!='default' else '管理员默认规则'
                return result('admin',name,row['target'],matched is None)

    hit=administrative(forced)
    if hit:return hit
    document=policy[mode]
    if policy['allowed'] and document.get('enabled'):
        for row in document['rules']:
            if not row['enabled'] or (row.get('node_ids') and node_id not in row['node_ids']):
                continue
            matched=match({row['kind']:row['values']})
            if matched is not False:
                target=row['target'] if row['target']=='reject' or row['target'] in permitted else 'reject'
                value=result('user',row['name'],target,matched is None,row['id'])
                if target!=row['target']:value['warning']='此规则的出口已不可用；当前连接会被拦截，请替换出口。'
                return value
    return administrative(ordinary) or result('default','系统默认',settings['final'])
