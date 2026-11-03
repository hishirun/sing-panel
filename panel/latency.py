"""Persisted outbound latency, invalidated when connection settings change."""
import hashlib,json,time
from urllib.parse import quote
from .core import connect

def fingerprint(out):return hashlib.sha256(json.dumps(out['settings'],sort_keys=True).encode()).hexdigest()
def cached(path,out):
    with connect(path) as db:row=db.execute('SELECT value FROM settings WHERE key=?',('latency:'+out['id'],)).fetchone()
    value=json.loads(row[0]) if row else {}
    return value if value.get('fingerprint')==fingerprint(out) else {}
def probe(path,runtime,out):
    if not out['enabled']:raise ValueError('出口未启用')
    result={'fingerprint':fingerprint(out),'checked_at':int(time.time()),'delay':None}
    try:
        response=runtime.control('/proxies/up-'+quote(out['id'],safe='')+'/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=3000')
        delay=response.get('delay')
        if not isinstance(delay,(int,float)) or delay<0:raise ValueError()
        result['delay']=delay
    except Exception:pass
    with connect(path) as db:db.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',('latency:'+out['id'],json.dumps(result)))
    return {k:v for k,v in result.items() if k!='fingerprint'}
def node_exits(path,node,data):
    targets=[];terminal=False
    for rule in data['rules']:
        if not rule['enabled'] or (rule.get('node_ids') and node['id'] not in rule['node_ids']):continue
        targets.append((rule['target'],bool(rule['match'])))
        if not rule['match']:terminal=True;break
    if not terminal:targets.append((data['final'],False))
    outs={o['id']:o for o in data['outbounds'] if o['enabled']};result=[];seen=set()
    for target,conditional in targets:
        if target in seen:continue
        seen.add(target)
        if target in outs:
            out=outs[target];result.append({'id':target,'name':out['name'],'conditional':conditional,**cached(path,out)})
        elif target in ('direct','reject'):result.append({'id':'','name':'直连' if target=='direct' else '拦截','conditional':conditional})
    return result
