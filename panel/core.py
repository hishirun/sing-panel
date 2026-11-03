"""Node configuration and durable per-user accounting."""
import json
import sqlite3
import secrets
import socket
import time
from pathlib import Path
from .options import listen_options, snell_options, reality_tls, options, certificate_tls, hysteria_options

PROTOCOLS = ('snell5', 'snell6', 'reality', 'hysteria2', 'anytls')

def connect(path):
    db = sqlite3.connect(path, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA foreign_keys=ON')
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
        from .management import migrate
        migrate(db)

def records(path, table):
    if table not in ('nodes','users','memberships'):
        raise ValueError(table)
    with connect(path) as db:
        return [dict(r) for r in db.execute(f'SELECT * FROM {table} ORDER BY rowid')]

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
        if n.get('mode')=='compat' and n['protocol'] in ('snell5','snell6'):
            for u in allowed:
                tag=n['id']+':'+u['id']
                compat_tags.append(tag)
                inbounds.append({'tag':tag,'listen_port':grants[(u['id'],n['id'])]['port'],
                    'type':'snell','version':int(n['protocol'][-1]),'psk':u['secret'],
                    **listen_options(n),**snell_options(n)})
            continue
        i = {'tag': n['id'], 'listen_port': n['port'], **listen_options(n)}
        if n['protocol'] in ('hysteria2','anytls'):
            i.update(type=n['protocol'],users=[{'name':n['id']+':'+u['id'],'password':u['secret']} for u in allowed],tls=certificate_tls(n))
            if n['protocol']=='hysteria2':
                i={k:v for k,v in i.items() if not k.startswith('tcp_') and k!='disable_tcp_keep_alive'}
                i.update(hysteria_options(n))
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
                'stats': {'enabled': True, 'users': [entry['name'] for inbound in inbounds for entry in inbound.get('users',[])], 'inbounds':compat_tags}}}}

def current_config(path, stats_port=19090):
    with connect(path) as db:
        db.execute('BEGIN')
        rows = [[dict(r) for r in db.execute(f'SELECT * FROM {t} ORDER BY rowid')]
                for t in ('nodes','users','memberships')]
    from .routing import load, compile_into
    return compile_into(config(*rows,stats_port),load(path))

def account(path, epoch, counters, day=None):
    """Atomic and idempotent; never reset the remote counter."""
    hour=time.strftime('%Y-%m-%dT%H:00',time.gmtime())
    day = day or time.strftime('%Y-%m-%d', time.gmtime())
    with connect(path) as db:
        db.execute('BEGIN IMMEDIATE')
        for counter, value in counters.items():
            parts = counter.split('>>>')
            if len(parts)!=4 or parts[0] not in ('user','inbound') or parts[2]!='traffic':
                continue
            if parts[3] not in ('uplink','downlink') or value<0:
                continue
            if parts[0]=='inbound' and ':' not in parts[1]:
                continue
            user = parts[1].split(':')[-1]
            node_id=parts[1].rsplit(':',1)[0] if ':' in parts[1] else None
            if not db.execute('SELECT 1 FROM users WHERE id=?',(user,)).fetchone():
                continue
            previous = db.execute('SELECT value FROM samples WHERE epoch=? AND counter=?',(epoch,counter)).fetchone()
            if previous and value<previous[0]:
                raise ValueError('counter regressed inside one core epoch')
            delta = value-(previous[0] if previous else 0)
            if delta>0:
                row=db.execute('SELECT policy,activated_at FROM users WHERE id=?',(user,)).fetchone()
                policy=json.loads(row['policy'])
                if policy.get('first_use_days') and not row['activated_at']:
                    activated=int(time.time())
                    db.execute('UPDATE users SET activated_at=?,expires=? WHERE id=?',(activated,activated+policy['first_use_days']*86400,user))
                elif not row['activated_at']:
                    db.execute('UPDATE users SET activated_at=? WHERE id=?',(int(time.time()),user))
            col = 'upload' if parts[3]=='uplink' else 'download'
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
    used.update((18889, 19090, 19091, *reserved_ports))
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
