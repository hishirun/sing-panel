"""Node configuration and durable per-user accounting."""
import json
from contextlib import nullcontext
import sqlite3
import secrets
import socket
import time
from pathlib import Path
from .options import listen_options, snell_options, reality_tls, options, certificate_tls, hysteria_options

PROTOCOLS = ('snell5', 'snell6', 'reality', 'hysteria2', 'anytls', 'ss', 'ss2022', 'trojan', 'tuic', 'shadowtls')

class DatabaseConnection(sqlite3.Connection):
    """Commit or roll back, then release the connection at the scope boundary."""
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()


def connect(path):
    db = sqlite3.connect(path, timeout=20, factory=DatabaseConnection)
    db.row_factory = sqlite3.Row
    try:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA foreign_keys=ON')
    except Exception:
        db.close()
        raise
    return db

def init_db(path):
    with connect(path) as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS nodes (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, protocol TEXT NOT NULL,
          port INTEGER UNIQUE NOT NULL, secret TEXT NOT NULL,
          private_key TEXT NOT NULL DEFAULT '', public_key TEXT NOT NULL DEFAULT '',
          short_id TEXT NOT NULL DEFAULT '', server_name TEXT NOT NULL DEFAULT '',
          enabled INTEGER NOT NULL DEFAULT 1, mode TEXT NOT NULL DEFAULT 'shared');
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY, name TEXT NOT NULL, secret TEXT NOT NULL,
          uuid TEXT NOT NULL, token TEXT UNIQUE NOT NULL,
          quota INTEGER NOT NULL DEFAULT 0, expires INTEGER NOT NULL DEFAULT 0,
          enabled INTEGER NOT NULL DEFAULT 1, upload INTEGER NOT NULL DEFAULT 0,
          download INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS memberships (
          user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
          node_id TEXT REFERENCES nodes(id) ON DELETE CASCADE,
          port INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(user_id,node_id));
        CREATE TABLE IF NOT EXISTS samples (
          epoch TEXT NOT NULL, counter TEXT NOT NULL, value INTEGER NOT NULL,
          PRIMARY KEY(epoch,counter));
        CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS monitor_samples (target TEXT NOT NULL, timestamp INTEGER NOT NULL, ms REAL, PRIMARY KEY(target,timestamp));
        CREATE TABLE IF NOT EXISTS node_hourly (
          hour TEXT NOT NULL,user_id TEXT NOT NULL,node_id TEXT NOT NULL,
          upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY(hour,user_id,node_id));
        CREATE TABLE IF NOT EXISTS node_daily (
          day TEXT NOT NULL,user_id TEXT NOT NULL,node_id TEXT NOT NULL,node_name TEXT NOT NULL,
          upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY(day,user_id,node_id));
        CREATE TABLE IF NOT EXISTS daily (
          day TEXT NOT NULL, user_id TEXT NOT NULL, upload INTEGER NOT NULL DEFAULT 0,
          download INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(day,user_id));
        ''')
        if 'mode' not in {r[1] for r in db.execute('PRAGMA table_info(nodes)')}:
            db.execute("ALTER TABLE nodes ADD COLUMN mode TEXT NOT NULL DEFAULT 'shared'")
        if 'port' not in {r[1] for r in db.execute('PRAGMA table_info(memberships)')}:
            db.execute('ALTER TABLE memberships ADD COLUMN port INTEGER NOT NULL DEFAULT 0')
        if 'options' not in {r[1] for r in db.execute('PRAGMA table_info(nodes)')}:
            db.execute("ALTER TABLE nodes ADD COLUMN options TEXT NOT NULL DEFAULT '{}'")
        db.execute('CREATE UNIQUE INDEX IF NOT EXISTS unique_member_port ON memberships(port) WHERE port>0')
        db.execute('CREATE INDEX IF NOT EXISTS daily_user_day ON daily(user_id,day)')
        db.execute('CREATE INDEX IF NOT EXISTS node_daily_user_day ON node_daily(user_id,day,node_id)')
        db.execute('CREATE INDEX IF NOT EXISTS node_hourly_user_hour ON node_hourly(user_id,hour,node_id)')
        from .server_publish import migrate as migrate_publish
        migrate_publish(db)
        from .diagnostics import migrate as migrate_diagnostics
        migrate_diagnostics(db)
        from .management import migrate
        migrate(db)
        from .user_routing import migrate as migrate_user_routing
        migrate_user_routing(db)
        from .customer_auth import migrate as migrate_customer_auth
        migrate_customer_auth(db)
        if 'server_id' not in {r[1] for r in db.execute('PRAGMA table_info(nodes)')}:
            db.execute("ALTER TABLE nodes ADD COLUMN server_id TEXT NOT NULL DEFAULT 'local'")
        from .fleet import migrate as migrate_fleet
        migrate_fleet(db)
        from .server_traffic import migrate as migrate_server_traffic
        migrate_server_traffic(db)

def records(path, table):
    if table not in ('nodes','users','memberships'):
        raise ValueError(table)
    with connect(path) as db:
        result = [dict(r) for r in db.execute(f'SELECT * FROM {table} ORDER BY rowid')]
        if table == 'nodes':
            servers = {r['id']: dict(r) for r in db.execute('SELECT id,name,host,enabled FROM servers')}
            for node in result:
                remote = servers.get(node.get('server_id', 'local'))
                node['server_host'] = remote['host'] if remote else ''
                node['server_name_label'] = remote['name'] if remote else '本机'
                node['server_enabled'] = bool(remote['enabled']) if remote else node.get('server_id','local') == 'local'
        return result

def reason(row, now=None):
    now = time.time() if now is None else now
    if not row['enabled']:
        return '手动停用'
    if row.get('expires',0) and row['expires'] <= now:
        return '已到期'
    if row.get('quota',0) and row['upload'] + row['download'] >= row['quota']:
        return '额度耗尽'
    return ''

def config(nodes, users, memberships, stats_port=19090):
    inbounds = []
    grants = {(m['user_id'],m['node_id']):m for m in memberships}
    granted = set(grants)
    compat_tags = []
    for n in nodes:
        allowed = [u for u in users if not reason(u) and (u['id'],n['id']) in granted]
        # Empty users on some protocols means unauthenticated/default access.
        if not n['enabled'] or not allowed:
            continue
        if n.get('mode')=='compat' and n['protocol'] in ('snell5','snell6','ss','ss2022','shadowtls'):
            for u in allowed:
                tag=n['id']+':'+u['id']
                compat_tags.append(tag)
                inbound={'tag':tag,'listen_port':grants[(u['id'],n['id'])]['port'],**listen_options(n)}
                if n['protocol']=='shadowtls':
                    from .protocols import user_key, shadow_password, SS_2022
                    o=options(n)
                    inbounds.append({**inbound,'type':'shadowtls','tag':tag+':st','version':3,
                        'users':[{'name':tag,'password':shadow_password(n,u)}],
                        'handshake':{'server':o['handshake_host'] or n['server_name'],'server_port':o['handshake_port']},
                        'strict_mode':True,'detour':tag})
                    # Injected only: the backend has no socket that could bypass ShadowTLS.
                    inbound={'type':'shadowsocks','tag':tag,'method':o['ss_method'],'network':'tcp',
                        'password':user_key(n,u) if o['ss_method'] in SS_2022 else u['secret']}
                elif n['protocol'] in ('ss','ss2022'):
                    from .protocols import user_key
                    o=options(n)
                    inbound.update(type='shadowsocks',method=o['ss_method'],password=user_key(n,u) if n['protocol']=='ss2022' else u['secret'])
                    if o['network']!='both':inbound['network']=o['network']
                else:inbound.update(type='snell',version=int(n['protocol'][-1]),psk=u['secret'],**snell_options(n))
                inbounds.append(inbound)
            continue
        i = {'tag': n['id'], 'listen_port': n['port'], **listen_options(n)}
        if n['protocol']=='ss2022':
            from .protocols import user_key
            o=options(n)
            i.update(type='shadowsocks',method=o['ss_method'],password=n['secret'],users=[{'name':n['id']+':'+u['id'],'password':user_key(n,u)} for u in allowed])
            if o['network']!='both':i['network']=o['network']
        elif n['protocol'] in ('hysteria2','anytls','trojan','tuic'):
            i.update(type=n['protocol'],users=[{'name':n['id']+':'+u['id'],'password':u['secret']} for u in allowed],tls=certificate_tls(n))
            if n['protocol']=='tuic':
                from .options import tuic_options
                i={k:v for k,v in i.items() if not k.startswith('tcp_') and k!='disable_tcp_keep_alive'}
                i['users']=[{'name':n['id']+':'+u['id'],'uuid':u['uuid'],'password':u['secret']} for u in allowed]
                i.update(tuic_options(n))
            elif n['protocol']=='hysteria2':
                i={k:v for k,v in i.items() if not k.startswith('tcp_') and k!='disable_tcp_keep_alive'}
                i.update(hysteria_options(n))
            elif n['protocol']=='trojan':
                from .protocols import transport
                if transport(n):i['transport']=transport(n)
            elif options(n)['any_padding'].strip():i['padding_scheme']=options(n)['any_padding'].strip().splitlines()
        elif n['protocol'] in ('snell5', 'snell6'):
            i.update(type='snell', version=int(n['protocol'][-1]), psk=n['secret'],
                     users=[{'name': n['id']+':'+u['id'], 'userkey': u['secret']} for u in allowed], **snell_options(n))
        else:
            i.update(type='vless', users=[{'name':n['id']+':'+u['id'],'uuid':u['uuid'],'flow':options(n)['flow']} for u in allowed],
                     tls=reality_tls(n))
        inbounds.append(i)
    return {'log': {'level': 'warn', 'timestamp': True}, 'inbounds': inbounds,
            'outbounds': [{'type': 'direct', 'tag': 'direct'}],
            'experimental': {'v2ray_api': {'listen': f'127.0.0.1:{stats_port}',
                'stats': {'enabled': True, 'users': [entry['name'] for inbound in inbounds if inbound['type']!='shadowtls' for entry in inbound.get('users',[])], 'inbounds':compat_tags}}}}

def current_config(path, stats_port=19090, server_id='local'):
    with connect(path) as db:
        db.execute('BEGIN')
        rows = [[dict(r) for r in db.execute(f'SELECT * FROM {t} ORDER BY rowid')]
                for t in ('nodes','users','memberships')]
    rows[0] = [node for node in rows[0] if node.get('server_id','local') == server_id]
    selected = {node['id'] for node in rows[0]}
    rows[2] = [member for member in rows[2] if member['node_id'] in selected]
    from .server_traffic import summary
    if summary(path,server_id).get('blocked'):
        rows[0]=[];rows[2]=[]
    from .routing import set_rule_paths
    from .user_routing import compose
    document=compose(config(*rows,stats_port),path)
    return set_rule_paths(document,Path(path).parent)

def account(path, epoch, counters, day=None, *, server_id=None, ignore_stale=False, observed_at=None, _connection=None):
    """Atomic and idempotent; never reset the remote counter."""
    stamp=time.time() if observed_at is None else min(time.time(),float(observed_at))
    hour=time.strftime('%Y-%m-%dT%H:00',time.gmtime(stamp))
    day = day or time.strftime('%Y-%m-%d', time.gmtime(stamp))
    with (connect(path) if _connection is None else nullcontext(_connection)) as db:
        if _connection is None:db.execute('BEGIN IMMEDIATE')
        node_meta={}
        for counter, value in counters.items():
            parts = counter.split('>>>')
            if len(parts)!=4 or parts[0] not in ('user','inbound') or parts[2]!='traffic':
                continue
            if parts[3] not in ('uplink','downlink') or isinstance(value,bool) or not isinstance(value,int) or not 0 <= value <= 2**63-1:
                continue
            if parts[0]=='inbound' and ':' not in parts[1]:
                continue
            user = parts[1].split(':')[-1]
            node_id=parts[1].rsplit(':',1)[0] if ':' in parts[1] else None
            # Only the decrypted backend counts for a composed ShadowTLS node.
            if node_id not in node_meta:
                node_meta[node_id]=db.execute('SELECT protocol,server_id FROM nodes WHERE id=?',(node_id,)).fetchone()
            owner=node_meta[node_id]
            if parts[0]=='user' and owner and owner['protocol']=='shadowtls':
                continue
            if server_id is not None:
                if not owner or owner['server_id'] != server_id:
                    continue
            if not db.execute('SELECT 1 FROM users WHERE id=?',(user,)).fetchone():
                continue
            previous = db.execute('SELECT value FROM samples WHERE epoch=? AND counter=?',(epoch,counter)).fetchone()
            if previous and value<previous[0]:
                if ignore_stale:
                    continue
                raise ValueError('counter regressed inside one core epoch')
            delta = value-(previous[0] if previous else 0)
            # Keep initial baselines, but an unchanged counter has no new usage.
            if previous and not delta:
                continue
            if delta>0:
                db.execute('UPDATE users SET last_seen=MAX(last_seen,?) WHERE id=?',(int(stamp),user))
                row=db.execute('SELECT policy,activated_at FROM users WHERE id=?',(user,)).fetchone()
                policy=json.loads(row['policy'])
                if policy.get('first_use_days') and not row['activated_at']:
                    activated=int(stamp)
                    db.execute('UPDATE users SET activated_at=?,expires=? WHERE id=?',(activated,activated+policy['first_use_days']*86400,user))
                elif not row['activated_at']:
                    db.execute('UPDATE users SET activated_at=? WHERE id=?',(int(stamp),user))
            col = 'upload' if parts[3]=='uplink' else 'download'
            window=db.execute('SELECT since FROM user_accounting_windows WHERE user_id=?',(user,)).fetchone()
            cutoff=window['since'] if window else 0
            if delta>0 and not window and policy.get('reset_mode','none')!='none' and policy.get('next_reset'):
                from .management import cycle_start
                cutoff=cycle_start(policy['next_reset'],policy['reset_mode'],policy.get('reset_days',30),policy.get('reset_day',1))
            if stamp>=cutoff:
                db.execute(f'UPDATE users SET {col}={col}+? WHERE id=?',(delta,user))
            db.execute(f'''INSERT INTO daily(day,user_id,{col}) VALUES(?,?,?)
                ON CONFLICT(day,user_id) DO UPDATE SET {col}={col}+excluded.{col}''',(day,user,delta))
            if delta:
                db.execute(f'''INSERT INTO node_hourly(hour,user_id,node_id,{col}) VALUES(?,?,?,?)
                    ON CONFLICT(hour,user_id,node_id) DO UPDATE SET {col}={col}+excluded.{col}''',(hour,user,node_id or '',delta))
            if node_id and delta:
                node=db.execute('SELECT name FROM nodes WHERE id=?',(node_id,)).fetchone()
                if node:
                    db.execute(f'''INSERT INTO node_daily(day,user_id,node_id,node_name,{col}) VALUES(?,?,?,?,?)
                        ON CONFLICT(day,user_id,node_id) DO UPDATE SET {col}={col}+excluded.{col},node_name=excluded.node_name''',(day,user,node_id,node['name'],delta))
            db.execute('INSERT OR REPLACE INTO samples VALUES(?,?,?)',(epoch,counter,value))


def port_available(port):
    """Probe TCP and UDP on both address families without reusing live sockets."""
    from contextlib import ExitStack
    try:
        with ExitStack() as stack:
            for family, address in ((socket.AF_INET, '0.0.0.0'), (socket.AF_INET6, '::')):
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    try:
                        sock = socket.socket(family, kind)
                    except OSError:
                        if family == socket.AF_INET6:
                            continue
                        raise
                    stack.enter_context(sock)
                    if family == socket.AF_INET6:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    sock.bind((address, port))
        return True
    except OSError:
        return False

def random_port(db, reserved_ports=()):
    used = {r[0] for r in db.execute('SELECT port FROM nodes UNION SELECT port FROM memberships')}
    used.update((18889, 19090, 19091, 19190, 19191, *reserved_ports))
    candidates = list(set(range(20000, 65001)) - used)
    secrets.SystemRandom().shuffle(candidates)
    for port in candidates:
        if port_available(port):
            return port
    raise ValueError('没有可用的随机端口')

def rotate_ports(db, node_id, reserved_ports=()):
    """Caller holds the runtime lock and a write transaction."""
    node = db.execute('SELECT * FROM nodes WHERE id=?', (node_id,)).fetchone()
    reserved_ports = (*reserved_ports, node['port'], *(r[0] for r in db.execute('SELECT port FROM memberships WHERE node_id=?', (node_id,))))
    port = random_port(db, reserved_ports)
    db.execute('UPDATE nodes SET port=? WHERE id=?', (port, node_id))
    if node['mode'] == 'compat':
        members = list(db.execute('SELECT user_id FROM memberships WHERE node_id=? ORDER BY rowid', (node_id,)))
        for index, member in enumerate(members):
            dedicated = port if index == 0 else random_port(db, reserved_ports)
            db.execute('UPDATE memberships SET port=? WHERE node_id=? AND user_id=?',
                       (dedicated, node_id, member['user_id']))
    return port


def set_memberships(db, user_id, node_ids, reserved_ports=()):
    """Preserve existing dedicated ports; assign collision-free ports to new grants."""
    node_ids=set(node_ids)
    nodes={r['id']:dict(r) for r in db.execute('SELECT * FROM nodes')}
    if not node_ids <= nodes.keys():
        raise ValueError('节点不存在')
    existing={r['node_id']:r['port'] for r in db.execute('SELECT * FROM memberships WHERE user_id=?',(user_id,))}
    for nid in existing.keys()-node_ids:
        db.execute('DELETE FROM memberships WHERE user_id=? AND node_id=?',(user_id,nid))
    for nid in node_ids-existing.keys():
        node=nodes[nid]
        dedicated=0
        if node['mode']=='compat':
            used={r[0] for r in db.execute('SELECT port FROM memberships WHERE port>0')}
            # The first user inherits the node's saved port; subsequent users get random ports.
            dedicated = node['port'] if node['port'] not in used and port_available(node['port']) else random_port(db, reserved_ports)
        db.execute('INSERT INTO memberships(user_id,node_id,port) VALUES(?,?,?)',(user_id,nid,dedicated))
