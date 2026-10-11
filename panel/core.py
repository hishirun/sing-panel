"""Node configuration and durable per-user accounting."""
import json
import sqlite3
import time
from pathlib import Path
from .options import listen_options, snell_options, reality_tls, options

PROTOCOLS = ('snell5', 'snell6', 'reality')

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
        if n['protocol'] in ('snell5', 'snell6'):
            i.update(type='snell', version=int(n['protocol'][-1]), psk=n['secret'],
                     users=[{'name': u['id'], 'userkey': u['secret']} for u in allowed], **snell_options(n))
        else:
            i.update(type='vless', users=[{'name':u['id'],'uuid':u['uuid'],'flow':options(n)['flow']} for u in allowed],
                     tls=reality_tls(n))
        inbounds.append(i)
    return {'log': {'level': 'warn', 'timestamp': True}, 'inbounds': inbounds,
            'outbounds': [{'type': 'direct', 'tag': 'direct'}],
            'experimental': {'v2ray_api': {'listen': f'127.0.0.1:{stats_port}',
                'stats': {'enabled': True, 'users': [u['id'] for u in users], 'inbounds':compat_tags}}}}

def current_config(path, stats_port=19090):
    with connect(path) as db:
        db.execute('BEGIN')
        rows = [[dict(r) for r in db.execute(f'SELECT * FROM {t} ORDER BY rowid')]
                for t in ('nodes','users','memberships')]
    return config(*rows,stats_port)

def account(path, epoch, counters, day=None):
    """Atomic and idempotent; never reset the remote counter."""
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
            if not db.execute('SELECT 1 FROM users WHERE id=?',(user,)).fetchone():
                continue
            previous = db.execute('SELECT value FROM samples WHERE epoch=? AND counter=?',(epoch,counter)).fetchone()
            if previous and value<previous[0]:
                raise ValueError('counter regressed inside one core epoch')
            delta = value-(previous[0] if previous else 0)
            col = 'upload' if parts[3]=='uplink' else 'download'
            db.execute(f'UPDATE users SET {col}={col}+? WHERE id=?',(delta,user))
            db.execute(f'''INSERT INTO daily(day,user_id,{col}) VALUES(?,?,?)
                ON CONFLICT(day,user_id) DO UPDATE SET {col}={col}+excluded.{col}''',(day,user,delta))
            db.execute('INSERT OR REPLACE INTO samples VALUES(?,?,?)',(epoch,counter,value))


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
            used.update(n['port'] for n in nodes.values() if n['id']!=nid)
            used.update(reserved_ports)
            dedicated=next((p for p in range(node['port'],65536) if p not in used),None)
            if dedicated is None:
                raise ValueError('没有可用的独立端口')
        db.execute('INSERT INTO memberships(user_id,node_id,port) VALUES(?,?,?)',(user_id,nid,dedicated))
