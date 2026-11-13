"""Explain a route using the saved draft and real local SRS match command.

This does not connect to the supplied destination. Missing DNS/transport facts
produce an explicit uncertain result instead of a misleading successful test.
"""
import ipaddress
import subprocess
import time
from pathlib import Path

from . import routing, user_routing
from .core import connect, reason


def preview(m, user, policy, destination, node_id):
    if not isinstance(destination,str) or not destination.strip() or len(destination)>253:
        raise ValueError('请输入域名或 IP 地址，不带协议和路径')
    destination=routing.host(destination.strip().lower())
    try:
        address=ipaddress.ip_address(destination)
    except ValueError:
        address=None
    with connect(m.DB) as db:
        nodes=[dict(row) for row in db.execute('SELECT n.* FROM nodes n JOIN memberships g ON g.node_id=n.id WHERE g.user_id=? AND n.enabled=1', (user['id'],))]
    selected=next((node for node in nodes if node['id']==node_id),None)
    if selected is None:
        raise ValueError('请选择一个当前可用节点')
    if reason(user):
        raise ValueError('当前账户不可用，不能推演新连接')
    settings=routing.load(m.DB)
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

    def result(source, name, target, uncertain=False):
        label='拦截' if target=='reject' else '服务器直连' if target=='direct' else public.get(target,{}).get('name','管理员指定出口')
        if uncertain:
            return {'summary':'匹配结果需要更多信息','rule_name':name,'outbound_name':'待确定','source':source,
                    'warning':'域名规则需要域名，GeoIP 需要目标 IP。新规则集请应用后再预览；条件过多或涉及端口、协议时，需真实连接验证。'}
        return {'summary':name+' → '+label,'rule_name':name,'outbound_name':label,'source':source,
                'warning':'依据已保存草稿与规则集快照推演；仅对经过此节点的流量生效，不代表真实连通性测试。'}

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
    if policy['allowed'] and policy['draft'].get('enabled'):
        for row in policy['draft']['rules']:
            if not row['enabled'] or (row.get('node_ids') and node_id not in row['node_ids']):
                continue
            matched=match({row['kind']:row['values']})
            if matched is not False:
                target=row['target'] if row['target']=='reject' or row['target'] in permitted else 'reject'
                value=result('user',row['name'],target,matched is None)
                if target!=row['target']:value['warning']='此规则的出口已不可用；当前连接会被拦截，请替换出口。'
                return value
    return administrative(ordinary) or result('default','系统默认',settings['final'])
