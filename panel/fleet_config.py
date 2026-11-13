"""Build an agent's configuration without sharing another server's inbounds."""
from pathlib import Path
from .core import connect, config
from .user_routing import compose


def retain_used_outbounds(document):
    """Send only credentials needed by this server's compiled routing graph."""
    available={item['tag']:item for item in document.get('outbounds',[])}
    needed=set()
    def references(value):
        if isinstance(value,dict):
            for key,child in value.items():
                if key in ('outbound','detour','download_detour','final','default','outbounds'):
                    values=child if isinstance(child,list) else [child]
                    needed.update(item for item in values if isinstance(item,str) and item in available)
                references(child)
        elif isinstance(value,list):
            for child in value:references(child)
    references({key:value for key,value in document.items() if key!='outbounds'})
    seen=set()
    while needed-seen:
        tag=next(iter(needed-seen));seen.add(tag);references(available[tag])
    document['outbounds']=[item for item in document.get('outbounds',[]) if item['tag'] in needed]


def configuration(path, server_id, stats_port=19190, policy_overrides=None):
    with connect(path) as db:
        server=db.execute('SELECT * FROM servers WHERE id=?',(server_id,)).fetchone()
        if server is None:
            raise ValueError('服务器不存在')
        nodes=[dict(row) for row in db.execute('SELECT * FROM nodes WHERE server_id=? ORDER BY rowid',(server_id,))]
        users=[dict(row) for row in db.execute('SELECT * FROM users')]
        memberships=[dict(row) for row in db.execute('SELECT m.* FROM memberships m JOIN nodes n ON n.id=m.node_id WHERE n.server_id=?',(server_id,))]
    document=compose(config(nodes,users,memberships,stats_port),path,policy_overrides=policy_overrides)
    retain_used_outbounds(document)
    # Master filesystem paths are never meaningful on the remote machine.
    # Only validated TLS material for that machine's inbounds is transferred.
    for inbound in document['inbounds']:
        tls=inbound.get('tls',{})
        for source,target in (('certificate_path','certificate'),('key_path','key')):
            if tls.get(source):
                content=Path(tls.pop(source)).read_text()
                if len(content)>262144:
                    raise ValueError('节点 TLS 文件过大')
                tls[target]=content.splitlines()
    cache=document.get('experimental',{}).get('cache_file')
    if cache:
        cache['path']='routing-cache.db'
    for entry in document.get('route',{}).get('rule_set',[]):
        entry.pop('initial_path',None)
    return document
