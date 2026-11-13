"""Durable per-user publication delivery, separate from desired policy storage."""
import json
import time

from .core import connect


def migrate(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS routing_rollout_targets (
      user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      revision INTEGER NOT NULL, server_id TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending', message TEXT NOT NULL DEFAULT '',
      updated_at INTEGER NOT NULL, PRIMARY KEY(user_id,revision,server_id));
    CREATE TABLE IF NOT EXISTS routing_config_deliveries (
      server_id TEXT NOT NULL, config_hash TEXT NOT NULL, user_revisions TEXT NOT NULL,
      created_at INTEGER NOT NULL, PRIMARY KEY(server_id,config_hash));
    ''')


def target_servers(path, uid, *documents):
    """The union of old/new active scopes includes machines needing cleanup."""
    with connect(path) as db:
        nodes = db.execute('''SELECT n.id,n.server_id FROM nodes n JOIN memberships m ON m.node_id=n.id
                              WHERE m.user_id=?''', (uid,)).fetchall()
    selected = set()
    for document in documents:
        if not document.get('enabled'):
            continue
        for rule in document.get('rules', []):
            if rule.get('enabled'):
                scope = set(rule.get('node_ids', []))
                selected.update(row['server_id'] for row in nodes if not scope or row['id'] in scope)
    # A replacement publication also supersedes an unfinished previous rollout.
    with connect(path) as db:
        selected.update(row[0] for row in db.execute("SELECT server_id FROM routing_rollout_targets WHERE user_id=? AND status!='applied'", (uid,)))
        existing = {row[0] for row in db.execute('SELECT id FROM servers')}
        selected.intersection_update(existing | {'local'})
    return selected


def publish(db, uid, revision, servers, local_confirmed=False):
    now = int(time.time())
    db.execute('DELETE FROM routing_rollout_targets WHERE user_id=?', (uid,))
    db.executemany('INSERT INTO routing_rollout_targets VALUES(?,?,?,?,?,?)',
                   ((uid, revision, sid, 'applied' if sid == 'local' and local_confirmed else 'pending', '', now)
                    for sid in sorted(servers)))
    pending = any(sid != 'local' or not local_confirmed for sid in servers)
    db.execute('UPDATE user_routing SET status=?,error=? WHERE user_id=?', ('syncing' if pending else 'applied', '', uid))


def _required_servers(db, uid):
    policy = db.execute('SELECT allowed,applied,applied_revision FROM user_routing WHERE user_id=?', (uid,)).fetchone()
    if not policy or not policy['allowed']:
        return 0, set()
    document = json.loads(policy['applied'])
    if not document.get('enabled'):
        return policy['applied_revision'], set()
    nodes = db.execute('''SELECT n.id,n.server_id FROM nodes n JOIN memberships m ON m.node_id=n.id
                          WHERE m.user_id=?''', (uid,)).fetchall()
    servers = set()
    for rule in document.get('rules', []):
        if rule.get('enabled'):
            scope = set(rule.get('node_ids', []))
            servers.update(row['server_id'] for row in nodes if not scope or row['id'] in scope)
    return policy['applied_revision'], servers


def _ensure_targets(db, uid):
    revision, servers = _required_servers(db, uid)
    existing = {row[0] for row in db.execute('SELECT server_id FROM routing_rollout_targets WHERE user_id=? AND revision=?',
                                            (uid, revision))}
    missing = servers - existing
    if missing:
        db.executemany('INSERT OR IGNORE INTO routing_rollout_targets VALUES(?,?,?,?,?,?)',
                       ((uid, revision, sid, 'pending', '', int(time.time())) for sid in missing))


def remember_delivery(path, server_id, config_hash):
    """Called under runtime.lock for a configuration actually sent to Agent."""
    with connect(path) as db:
        users = [row[0] for row in db.execute('''SELECT DISTINCT m.user_id FROM memberships m
            JOIN nodes n ON n.id=m.node_id WHERE n.server_id=?''', (server_id,))]
        for uid in users:
            _ensure_targets(db, uid)
        revisions = {row['user_id']: row['applied_revision'] for row in db.execute('''
            SELECT DISTINCT u.user_id,u.applied_revision FROM user_routing u JOIN routing_rollout_targets t
            ON t.user_id=u.user_id AND t.revision=u.applied_revision WHERE t.server_id=?''', (server_id,))}
        previous = db.execute('SELECT user_revisions FROM routing_config_deliveries WHERE server_id=? AND config_hash=?',
                              (server_id, config_hash)).fetchone()
        if previous and json.loads(previous[0]) == revisions:
            return False
        db.execute('INSERT OR REPLACE INTO routing_config_deliveries VALUES(?,?,?,?)',
                   (server_id, config_hash, json.dumps(revisions), int(time.time())))
        db.execute('''DELETE FROM routing_config_deliveries WHERE server_id=? AND rowid NOT IN
                      (SELECT rowid FROM routing_config_deliveries WHERE server_id=? ORDER BY rowid DESC LIMIT 128)''',
                   (server_id, server_id))
    return True


def confirm_local(path):
    """The caller has successfully applied current_config under runtime.lock."""
    from .server_traffic import summary
    if summary(path, 'local')['blocked']:
        return
    with connect(path) as db:
        users = {row[0] for row in db.execute('''SELECT DISTINCT m.user_id FROM memberships m
            JOIN nodes n ON n.id=m.node_id WHERE n.server_id='local' ''')}
        users.update(row[0] for row in db.execute("SELECT user_id FROM routing_rollout_targets WHERE server_id='local'"))
        for uid in users:
            _ensure_targets(db, uid)
            db.execute('''UPDATE routing_rollout_targets SET status='applied',message='',updated_at=?
                          WHERE server_id='local' AND user_id=? AND revision=(SELECT applied_revision FROM user_routing WHERE user_id=?)''',
                       (int(time.time()), uid, uid))
            _refresh(db, uid)


def _refresh(db, uid):
    row = db.execute('SELECT * FROM user_routing WHERE user_id=?', (uid,)).fetchone()
    if not row or row['status'] in ('queued', 'applying', 'failed'):
        return
    if json.loads(row['draft']) != json.loads(row['applied']):
        return
    pending = db.execute("SELECT 1 FROM routing_rollout_targets WHERE user_id=? AND revision=? AND status!='applied'",
                         (uid, row['applied_revision'])).fetchone()
    status = 'syncing' if pending else 'applied'
    if row['status'] != status:
        db.execute('UPDATE user_routing SET status=? WHERE user_id=?', (status, uid))


def retire_server(db, server_id):
    """Deleting an empty server ends its outstanding delivery obligations."""
    users = {row[0] for row in db.execute('SELECT user_id FROM routing_rollout_targets WHERE server_id=?', (server_id,))}
    db.execute('DELETE FROM routing_rollout_targets WHERE server_id=?', (server_id,))
    db.execute('DELETE FROM routing_config_deliveries WHERE server_id=?', (server_id,))
    for uid in users:
        _refresh(db, uid)


def observe(path, server_id, applied_hash, running, apply_result=None):
    """Only hashes issued to this server can confirm/reject their user revisions."""
    evidence = []
    if running and applied_hash:
        evidence.append((applied_hash, 'applied', ''))
    if apply_result and apply_result.get('ok') is False:
        evidence.append((apply_result['revision'], 'failed', '远端核心未能应用配置，请联系管理员或重试'))
    with connect(path) as db:
        users = set()
        for digest, status, message in evidence:
            delivery = db.execute('SELECT user_revisions FROM routing_config_deliveries WHERE server_id=? AND config_hash=?',
                                  (server_id, digest)).fetchone()
            if not delivery:
                continue
            for uid, revision in json.loads(delivery[0]).items():
                # A stale failed attempt cannot undo a later successful ACK.
                extra = " AND status!='applied'" if status == 'failed' else ''
                db.execute('UPDATE routing_rollout_targets SET status=?,message=?,updated_at=? WHERE user_id=? AND revision=? AND server_id=?' + extra,
                           (status, message, int(time.time()), uid, revision, server_id))
                users.add(uid)
        for uid in users:
            _refresh(db, uid)


def public_status(path, uid):
    now = int(time.time())
    with connect(path) as db:
        policy = db.execute('SELECT applied_revision FROM user_routing WHERE user_id=?', (uid,)).fetchone()
        revision = policy[0] if policy else 0
        rows = [dict(row) for row in db.execute('SELECT * FROM routing_rollout_targets WHERE user_id=? AND revision=? ORDER BY server_id', (uid, revision))]
        _, required = _required_servers(db, uid)
        existing = {row['server_id'] for row in rows}
        rows.extend({'server_id': sid, 'status': 'pending', 'message': ''} for sid in sorted(required - existing))
        targets = []
        authorized = {row[0] for row in db.execute('''SELECT DISTINCT n.server_id FROM nodes n JOIN memberships m
            ON m.node_id=n.id WHERE m.user_id=?''', (uid,))}
        for row in rows:
            sid, status, message = row['server_id'], row['status'], row['message']
            server = db.execute('SELECT * FROM servers WHERE id=?', (sid,)).fetchone() if sid != 'local' else None
            name = '主面板本机' if sid == 'local' else server['name'] if server else '已移除服务器'
            if status not in ('applied', 'failed') and sid == 'local':
                from .server_traffic import summary
                if summary(path, 'local')['blocked']:
                    status, message = 'paused', '服务器流量额度已用尽，恢复后继续同步'
                else:
                    message = '等待本机核心确认'
            if status not in ('applied', 'failed') and sid != 'local':
                if not server or not server['enabled'] or server['desired_state'] == 'stopped':
                    status, message = 'paused', '服务器已暂停，恢复后继续同步'
                elif not server['connected'] or server['last_seen'] < now - 35:
                    status, message = 'offline', '等待服务器恢复连接'
                else:
                    from .server_traffic import summary
                    if summary(path, sid)['blocked']:
                        status, message = 'paused', '服务器流量额度已用尽，恢复后继续同步'
                    else:
                        message = '等待远端核心确认'
            targets.append({'server_id': sid if sid in authorized else '',
                            'name': name if sid in authorized else '原节点配置清理', 'status': status, 'message': message})
        confirmed = sum(item['status'] == 'applied' for item in targets)
        state = 'applied' if confirmed == len(targets) else 'failed' if any(item['status'] == 'failed' for item in targets) else 'syncing'
    return {'revision': revision, 'total': len(targets), 'confirmed': confirmed, 'state': state, 'targets': targets}
