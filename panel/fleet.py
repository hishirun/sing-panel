"""Server inventory, one-use enrollment and scoped Agent reconciliation.

Agents receive only their server's configuration and may report counters that
have previously been issued to that server. Authentication credentials are
never stored in plaintext or returned to administrator templates.
"""
import hashlib
import hmac
import ipaddress
import json
import math
import re
import secrets
import threading
import time
import uuid
from pathlib import Path

from .core import connect

PROTOCOL = 1
LEASE_SECONDS = 90
ONLINE_SECONDS = 35
MAX_MESSAGE = 4 * 1024 * 1024
_locks = {}
_locks_lock = threading.Lock()
_SECRET = re.compile(r'^[A-Za-z0-9_-]{32,128}$')
_ID = re.compile(r'^[a-f0-9]{32}$')
_EPOCH = re.compile(r'^[A-Za-z0-9_.:-]{1,128}$')
_REDACTED = {'credential_hash', 'enroll_hash', 'enroll_used', 'credential_generation',
             'connection_generation', 'config_nonce', 'presence'}


class AuthenticationError(ValueError):
    pass


def locked(path, identity):
    key = (str(Path(path).resolve()), identity)
    with _locks_lock:
        return _locks.setdefault(key, threading.RLock())


def migrate(db):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS servers (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, host TEXT NOT NULL,
      enabled INTEGER NOT NULL DEFAULT 1,
      credential_hash TEXT NOT NULL DEFAULT '',
      credential_generation INTEGER NOT NULL DEFAULT 0,
      connection_generation INTEGER NOT NULL DEFAULT 0,
      enroll_hash TEXT NOT NULL DEFAULT '', enroll_expires INTEGER NOT NULL DEFAULT 0,
      enroll_used INTEGER NOT NULL DEFAULT 0,
      last_seen INTEGER NOT NULL DEFAULT 0, connected INTEGER NOT NULL DEFAULT 0,
      metrics TEXT NOT NULL DEFAULT '{}', desired_revision TEXT NOT NULL DEFAULT '',
      applied_revision TEXT NOT NULL DEFAULT '', error TEXT NOT NULL DEFAULT '',
      desired_state TEXT NOT NULL DEFAULT 'running', config_nonce INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL);
    CREATE UNIQUE INDEX IF NOT EXISTS server_enrollment_hash ON servers(enroll_hash) WHERE enroll_hash!='';
    CREATE TABLE IF NOT EXISTS server_counter_grants (
      server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      counter TEXT NOT NULL, PRIMARY KEY(server_id,counter));
    CREATE TABLE IF NOT EXISTS server_reports (
      server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      report_id TEXT NOT NULL, fingerprint TEXT NOT NULL, created_at INTEGER NOT NULL,
      PRIMARY KEY(server_id,report_id));
    CREATE TABLE IF NOT EXISTS server_commands (
      id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      action TEXT NOT NULL, user_id TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS server_command_history (
      id TEXT PRIMARY KEY, server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
      action TEXT NOT NULL, ok INTEGER NOT NULL, error TEXT NOT NULL DEFAULT '', completed_at INTEGER NOT NULL);
    ''')
    existing = {r[1] for r in db.execute('PRAGMA table_info(servers)')}
    for key, definition in {
        'monthly_quota': 'INTEGER NOT NULL DEFAULT 0',
        'traffic_direction': "TEXT NOT NULL DEFAULT 'both'",
        'reset_day': 'INTEGER NOT NULL DEFAULT 1',
        'presence': "TEXT NOT NULL DEFAULT '[]'",
        'connections_truncated': 'INTEGER NOT NULL DEFAULT 0',
    }.items():
        if key not in existing:
            db.execute(f'ALTER TABLE servers ADD COLUMN {key} {definition}')
    if 'source_ip' not in {r[1] for r in db.execute('PRAGMA table_info(server_commands)')}:
        db.execute("ALTER TABLE server_commands ADD COLUMN source_ip TEXT NOT NULL DEFAULT ''")
    from .routing_rollout import migrate as migrate_rollout
    migrate_rollout(db)


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _raw(path, identity):
    with connect(path) as db:
        row = db.execute('SELECT * FROM servers WHERE id=?', (identity,)).fetchone()
    if row is None:
        raise ValueError('服务器不存在')
    return dict(row)


def _counts(db):
    if 'server_id' not in {r[1] for r in db.execute('PRAGMA table_info(nodes)')}:
        return {}
    return dict(db.execute('SELECT server_id,COUNT(*) FROM nodes GROUP BY server_id'))


def _safe(row, now=None, nodes_count=0):
    now = int(time.time() if now is None else now)
    value = {key: data for key, data in row.items() if key not in _REDACTED}
    value['metrics'] = json.loads(row['metrics'])
    value['enabled'] = bool(value['enabled'])
    value['connections_truncated'] = bool(value['connections_truncated'])
    value['online'] = bool(row['enabled'] and row['connected'] and row['last_seen'] >= now - ONLINE_SECONDS)
    value['enrolled'] = bool(row['credential_hash'])
    value['enrollment_pending'] = bool(row['enroll_hash'] and not row['enroll_used'] and row['enroll_expires'] > now)
    value['enrollment_consumed'] = bool(row['enroll_used'])
    value['is_local'] = False
    value['nodes_count'] = nodes_count
    value['agent_version'] = value['metrics'].get('agent_version', '')
    value['core_version'] = value['metrics'].get('core_version', '')
    return value


def get_server(path, identity, safe=True):
    row = _raw(path, identity)
    if not safe:
        return row
    with connect(path) as db:
        count = _counts(db).get(identity, 0)
    value = _safe(row, nodes_count=count)
    from .server_traffic import summary
    value['traffic'] = summary(path, identity)
    value['last_command'] = last_command(path, identity)
    return value


def list_servers(path, now=None):
    with connect(path) as db:
        rows = [dict(row) for row in db.execute('SELECT * FROM servers ORDER BY created_at,rowid')]
        counts = _counts(db)
    from .server_traffic import summary
    return [{**_safe(row, now, counts.get(row['id'], 0)), 'traffic': summary(path, row['id'], now=now),
             'last_command': last_command(path, row['id'])} for row in rows]


def last_command(path, identity):
    with connect(path) as db:
        pending = db.execute('SELECT id,action,created_at FROM server_commands WHERE server_id=? ORDER BY created_at DESC,rowid DESC LIMIT 1', (identity,)).fetchone()
        if pending:
            return {**dict(pending), 'status': 'pending', 'error': '', 'completed_at': 0}
        row = db.execute('SELECT * FROM server_command_history WHERE server_id=? ORDER BY completed_at DESC,rowid DESC LIMIT 1', (identity,)).fetchone()
    return {**dict(row), 'status': 'succeeded' if row['ok'] else 'failed'} if row else None


def validate_host(value):
    value = str(value).strip().strip('[]')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        from .options import domain
        return domain(value)


def quota_policy(monthly_quota=0, traffic_direction='both', reset_day=1):
    if isinstance(monthly_quota, bool) or not isinstance(monthly_quota, int) or not 0 <= monthly_quota <= 10_000_000 * 1024**3:
        raise ValueError('月流量额度须为 0–10,000,000 GiB')
    if traffic_direction not in ('both', 'rx', 'tx'):
        raise ValueError('请选择有效的流量统计方向')
    if isinstance(reset_day, bool):
        raise ValueError('重置日须为 1–28')
    try:
        reset_day = int(reset_day)
    except (TypeError, ValueError):
        raise ValueError('重置日须为 1–28') from None
    if not 1 <= reset_day <= 28:
        raise ValueError('重置日须为 1–28')
    return {'monthly_quota': monthly_quota, 'traffic_direction': traffic_direction, 'reset_day': reset_day}


def local_policy(path):
    with connect(path) as db:
        row = db.execute("SELECT value FROM settings WHERE key='server_quota:local'").fetchone()
    return quota_policy(**json.loads(row[0])) if row else quota_policy()


def save_server(path, name, host, identity=None, monthly_quota=0, traffic_direction='both', reset_day=1):
    policy = quota_policy(monthly_quota, traffic_direction, reset_day)
    if identity == 'local':
        with connect(path) as db:
            db.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',
                       ('server_quota:local', json.dumps(policy)))
        return policy
    name = str(name).strip()
    if not name or len(name) > 80 or any(ord(ch) < 32 for ch in name):
        raise ValueError('服务器名称需要 1–80 个字符')
    host = validate_host(host)
    if identity:
        _raw(path, identity)
    else:
        identity = uuid.uuid4().hex
    with locked(path, identity), connect(path) as db:
        if db.execute('SELECT 1 FROM servers WHERE id=?', (identity,)).fetchone():
            db.execute('UPDATE servers SET name=?,host=?,monthly_quota=?,traffic_direction=?,reset_day=? WHERE id=?',
                       (name, host, policy['monthly_quota'], policy['traffic_direction'], policy['reset_day'], identity))
        else:
            if db.execute('SELECT COUNT(*) FROM servers').fetchone()[0] >= 100:
                raise ValueError('最多接入 100 台远程服务器')
            db.execute('INSERT INTO servers(id,name,host,created_at,monthly_quota,traffic_direction,reset_day) VALUES(?,?,?,?,?,?,?)',
                       (identity, name, host, int(time.time()), policy['monthly_quota'], policy['traffic_direction'], policy['reset_day']))
    return get_server(path, identity)


def issue_enrollment(path, identity, now=None):
    now = int(time.time() if now is None else now)
    _raw(path, identity)
    token = secrets.token_urlsafe(32)
    with locked(path, identity), connect(path) as db:
        db.execute('UPDATE servers SET enroll_hash=?,enroll_expires=?,enroll_used=0 WHERE id=?',
                   (_hash(token), now + 900, identity))
    return token, now + 900


def enroll(path, token, credential, now=None, expected_server_id=None):
    now = int(time.time() if now is None else now)
    if not isinstance(token, str) or not _SECRET.fullmatch(token):
        raise AuthenticationError('接入码无效或已过期')
    if not isinstance(credential, str) or not _SECRET.fullmatch(credential) or len(credential) < 43:
        raise AuthenticationError('Agent 凭据格式无效')
    token_hash = _hash(token)
    with connect(path) as db:
        match = db.execute('SELECT id FROM servers WHERE enroll_hash=?', (token_hash,)).fetchone()
    if not match:
        raise AuthenticationError('接入码无效或已过期')
    identity = match[0]
    if expected_server_id is not None and expected_server_id != identity:
        raise AuthenticationError('接入码不属于当前 Agent 绑定的服务器')
    with locked(path, identity), connect(path) as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT * FROM servers WHERE id=?', (identity,)).fetchone()
        if not row or row['enroll_expires'] <= now or not hmac.compare_digest(row['enroll_hash'], token_hash):
            raise AuthenticationError('接入码无效或已过期')
        credential_hash = _hash(credential)
        if row['enroll_used']:
            if not hmac.compare_digest(row['credential_hash'], credential_hash):
                raise AuthenticationError('接入码已使用')
        else:
            db.execute('''UPDATE servers SET credential_hash=?,credential_generation=credential_generation+1,
                          enroll_used=1,enabled=1,connected=0,last_seen=0,error='' WHERE id=?''',
                       (credential_hash, identity))
    return identity


def authenticate(path, bearer):
    if not isinstance(bearer, str) or not bearer.startswith('Bearer '):
        raise AuthenticationError('Agent 身份验证失败')
    value = bearer[7:]
    identity, separator, credential = value.partition('.')
    if not separator or not _ID.fullmatch(identity) or not _SECRET.fullmatch(credential):
        raise AuthenticationError('Agent 身份验证失败')
    try:
        row = _raw(path, identity)
    except ValueError:
        raise AuthenticationError('Agent 身份验证失败') from None
    if not row['enabled'] or not row['credential_hash'] or not hmac.compare_digest(row['credential_hash'], _hash(credential)):
        raise AuthenticationError('Agent 凭据已撤销')
    return identity, row['credential_generation']


def open_connection(path, identity, credential_generation):
    with locked(path, identity), connect(path) as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT * FROM servers WHERE id=?', (identity,)).fetchone()
        if not row or not row['enabled'] or row['credential_generation'] != credential_generation:
            raise AuthenticationError('Agent 凭据已撤销')
        generation = row['connection_generation'] + 1
        db.execute('UPDATE servers SET connection_generation=?,connected=1 WHERE id=?', (generation, identity))
    return generation


def close_connection(path, identity, connection_generation):
    with connect(path) as db:
        db.execute('UPDATE servers SET connected=0 WHERE id=? AND connection_generation=?',
                   (identity, connection_generation))


def reset_connections(path):
    with connect(path) as db:
        db.execute('UPDATE servers SET connected=0')


def enqueue_command(path, identity, action, user_id='', source_ip=''):
    if action not in ('restart', 'resync', 'disconnect_user', 'disconnect_ip', 'update_agent'):
        raise ValueError('不支持的服务器操作')
    if action in ('disconnect_user', 'disconnect_ip') and (not isinstance(user_id, str) or not _ID.fullmatch(user_id)):
        raise ValueError('用户标识无效')
    if action == 'disconnect_ip':
        try:
            if not isinstance(source_ip, str):
                raise ValueError('来源 IP 无效')
            source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError:
            raise ValueError('来源 IP 无效') from None
    else:
        source_ip = ''
    with locked(path, identity), connect(path) as db:
        row = db.execute('SELECT enabled,credential_hash FROM servers WHERE id=?', (identity,)).fetchone()
        if not row or not row['enabled'] or not row['credential_hash']:
            # User revocation fans out to all assigned machines. An unbound or
            # revoked machine already has no valid forwarding lease; queuing a
            # disconnect for it must not make the user's admin action fail.
            if action in ('disconnect_user', 'disconnect_ip'):
                return None
            raise ValueError('请先接入服务器')
        # Collapse repeated button clicks while an operation is outstanding.
        row = db.execute('SELECT id FROM server_commands WHERE server_id=? AND action=? AND user_id=? AND source_ip=?',
                         (identity, action, user_id, source_ip)).fetchone()
        if row:
            return row[0]
        if db.execute('SELECT COUNT(*) FROM server_commands WHERE server_id=?', (identity,)).fetchone()[0] >= 100:
            raise ValueError('待处理操作过多，请等待服务器连接')
        command_id = uuid.uuid4().hex
        db.execute('INSERT INTO server_commands(id,server_id,action,user_id,source_ip,created_at) VALUES(?,?,?,?,?,?)',
                   (command_id, identity, action, user_id, source_ip, int(time.time())))
    return command_id


def set_action(path, identity, action):
    if identity == 'local':
        raise ValueError('请在运行与维护页面操作主面板本机')
    with locked(path, identity):
        row = _raw(path, identity)
        if action in ('restart', 'resync', 'update_agent'):
            if not row['enabled'] or not row['credential_hash']:
                raise ValueError('请先接入服务器')
            return enqueue_command(path, identity, action)
        with connect(path) as db:
            if action in ('start', 'stop'):
                if not row['enabled'] or not row['credential_hash']:
                    raise ValueError('请先接入服务器')
                db.execute('UPDATE servers SET desired_state=? WHERE id=?',
                           ('running' if action == 'start' else 'stopped', identity))
            elif action == 'revoke':
                db.execute('''UPDATE servers SET enabled=0,credential_hash='',credential_generation=credential_generation+1,
                              enroll_hash='',enroll_expires=0,enroll_used=0,desired_state='stopped',connected=0 WHERE id=?''',
                           (identity,))
                db.execute('DELETE FROM server_commands WHERE server_id=?', (identity,))
            elif action == 'delete':
                if _counts(db).get(identity, 0):
                    raise ValueError('此服务器仍有节点，请先删除或迁移节点')
                db.execute('DELETE FROM servers WHERE id=?', (identity,))
                from .routing_rollout import retire_server
                retire_server(db, identity)
            else:
                raise ValueError('不支持的服务器操作')
    return None


def _number(value, maximum=2**63-1):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 <= value <= maximum


def sanitize_metrics(raw):
    if not isinstance(raw, dict):
        raise ValueError('机器状态格式无效')
    result = {}
    for key in ('hostname', 'os', 'arch', 'agent_version', 'core_version', 'boot_id'):
        value = raw.get(key)
        if isinstance(value, str):
            result[key] = ''.join(c for c in value[:200] if ord(c) >= 32)
    for key in ('cpu', 'uptime', 'rx', 'tx', 'rx_total', 'tx_total', 'cores', 'connection_count', 'online_users', 'sampled_at'):
        value = raw.get(key)
        if value is None:
            result[key] = None
        elif _number(value, 100 if key == 'cpu' else 2**63-1):
            result[key] = value
    for key in ('memory', 'disk'):
        value = raw.get(key)
        if isinstance(value, dict):
            result[key] = {name: number for name, number in value.items()
                           if name in ('used', 'total', 'percent') and _number(number, 100 if name == 'percent' else 2**63-1)}
        else:
            result[key] = None
    load = raw.get('load')
    if isinstance(load, list) and len(load) == 3 and all(_number(v, 1e9) for v in load):
        result['load'] = load
    if isinstance(raw.get('running'), bool):
        result['running'] = raw['running']
    interfaces = raw.get('interfaces')
    if isinstance(interfaces, list) and len(interfaces) <= 128:
        result['interfaces'] = []
        for interface in interfaces:
            if not isinstance(interface, dict) or not isinstance(interface.get('name'), str) or not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,64}', interface['name']):
                continue
            item = {'name': interface['name'], 'billable': interface.get('billable') is True}
            for key in ('rx_total', 'tx_total', 'rx', 'tx'):
                if _number(interface.get(key)):
                    item[key] = interface[key]
            result['interfaces'].append(item)
    return result


def _config_grants(document):
    stats = document.get('experimental', {}).get('v2ray_api', {}).get('stats', {})
    grants = []
    for category, key in (('user', 'users'), ('inbound', 'inbounds')):
        for name in stats.get(key, []):
            if not isinstance(name, str) or not name or '>>>' in name:
                raise ValueError('配置中的流量统计标识无效')
            grants.extend(f'{category}>>>{name}>>>traffic>>>{direction}' for direction in ('uplink', 'downlink'))
    return grants


def _authorized_pairs(db, identity, now=None):
    from .core import reason
    return {(row['node_id'], row['id']): row['max_ips']
            for row in db.execute('''SELECT u.*,n.id AS node_id FROM users u
                JOIN memberships m ON m.user_id=u.id JOIN nodes n ON n.id=m.node_id
                WHERE n.server_id=? AND n.enabled=1''', (identity,)) if not reason(dict(row), now)}


def _connections(db, identity, raw, allowed, now):
    """Accept only issued identities owned by this machine; discard revoked pairs."""
    if not isinstance(raw, list) or len(raw) > 1000:
        raise ValueError('在线连接快照过大或格式无效')
    active = _authorized_pairs(db, identity, now)
    owned = {row[0] for row in db.execute('SELECT id FROM nodes WHERE server_id=?', (identity,))}
    accepted = []
    seen = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError('在线连接格式无效')
        connection_id, node_id, user_id = entry.get('id'), entry.get('node_id'), entry.get('user_id')
        start = entry.get('start', '')
        if (not isinstance(connection_id, str) or not _EPOCH.fullmatch(connection_id)
                or not isinstance(node_id, str) or not _ID.fullmatch(node_id)
                or not isinstance(user_id, str) or not _ID.fullmatch(user_id)
                or not isinstance(start, str) or len(start) > 80 or any(ord(c) < 32 for c in start)):
            raise ValueError('在线连接身份格式无效')
        try:
            if not isinstance(entry.get('source_ip'), str):
                raise ValueError('在线连接来源 IP 无效')
            source_ip = str(ipaddress.ip_address(entry.get('source_ip', '')))
        except ValueError:
            raise ValueError('在线连接来源 IP 无效') from None
        name = node_id + ':' + user_id
        issued = any(f'{kind}>>>{name}>>>traffic>>>uplink' in allowed for kind in ('user', 'inbound'))
        if not issued:
            raise ValueError('Agent 不得上报其他服务器的在线用户')
        # Deleted nodes and revoked memberships can appear in the last snapshot
        # before a new config is applied; omit them without losing its counters.
        if node_id not in owned or (node_id, user_id) not in active or connection_id in seen:
            continue
        seen.add(connection_id)
        accepted.append({'id': connection_id, 'node_id': node_id, 'user_id': user_id,
                         'source_ip': source_ip, 'start': start})
    return accepted


def presence_connections(path, now=None):
    """Return bounded, live, revalidated remote connections in Clash shape."""
    now = int(time.time() if now is None else now)
    result = []
    with connect(path) as db:
        rows = db.execute('''SELECT id,presence FROM servers WHERE enabled=1 AND credential_hash!=''
                             AND connected=1 AND last_seen>=?''', (now - ONLINE_SECONDS,)).fetchall()
        for row in rows:
            active = _authorized_pairs(db, row['id'], now)
            for item in json.loads(row['presence']):
                if (item['node_id'], item['user_id']) not in active:
                    continue
                result.append({'id': 'agent:' + row['id'] + ':' + item['id'], 'server_id': row['id'],
                               'agent_connection_id': item['id'], 'start': item['start'],
                               'metadata': {'inboundTag': item['node_id'],
                                            'inboundUser': item['node_id'] + ':' + item['user_id'],
                                            'sourceIP': item['source_ip']}})
    return result


def process_report(path, identity, report, configuration_fn, account_fn, stats_port=19190,
                   credential_generation=None, connection_generation=None, now=None, traffic_fn=None):
    """Commit a cumulative report before acknowledging it; old reports are safe.

    The caller serializes this with the local runtime's reconciliation lock.
    Core epochs are namespaced by server, not by credential, so re-enrollment
    cannot turn an already-accounted spool replay into new traffic.
    """
    now = int(time.time() if now is None else now)
    if not isinstance(report, dict) or report.get('type') != 'report' or report.get('protocol') != PROTOCOL:
        raise ValueError('不支持的 Agent 协议')
    report_id, epoch = report.get('report_id'), report.get('epoch')
    if not isinstance(report_id, str) or not _EPOCH.fullmatch(report_id) or not isinstance(epoch, str) or not _EPOCH.fullmatch(epoch):
        raise ValueError('报告标识无效')
    counters = report.get('counters', {})
    if not isinstance(counters, dict) or len(counters) > 50000:
        raise ValueError('流量报告过大或格式无效')
    if any(not isinstance(k, str) or len(k) > 300 or not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= 2**63-1 for k, v in counters.items()):
        raise ValueError('流量计数器格式无效')
    metrics = sanitize_metrics(report.get('metrics', {}))
    truncated = report.get('connections_truncated', False)
    if not isinstance(truncated, bool):
        raise ValueError('在线连接截断标识无效')
    applied = report.get('applied_revision', '')
    error = report.get('error', '')
    if not isinstance(applied, str) or len(applied) > 128 or not isinstance(error, str) or len(error) > 4000:
        raise ValueError('应用状态格式无效')
    apply_result = report.get('apply_result')
    if apply_result is not None and (not isinstance(apply_result, dict)
            or not isinstance(apply_result.get('revision'), str)
            or not re.fullmatch(r'[a-f0-9]{64}', apply_result['revision'])
            or not isinstance(apply_result.get('ok'), bool)):
        raise ValueError('配置应用回执格式无效')
    command_acks = report.get('command_acks', [])
    if not isinstance(command_acks, list) or len(command_acks) > 100 or any(not isinstance(v, str) or not _ID.fullmatch(v) for v in command_acks):
        raise ValueError('操作回执格式无效')
    command_results = report.get('command_results', [])
    if not isinstance(command_results, list) or len(command_results) > 100:
        raise ValueError('操作结果格式无效')
    results = {}
    for item in command_results:
        if (not isinstance(item, dict) or not isinstance(item.get('id'), str) or not _ID.fullmatch(item['id'])
                or not isinstance(item.get('ok'), bool) or not isinstance(item.get('error', ''), str)):
            raise ValueError('操作结果格式无效')
        results[item['id']] = {'ok': item['ok'], 'error': item.get('error', '')[:2000]}
    fingerprint = _hash(json.dumps({'epoch': epoch, 'counters': counters}, sort_keys=True, separators=(',', ':')))
    with locked(path, identity):
        try:
            row = _raw(path, identity)
        except ValueError:
            raise AuthenticationError('Agent 凭据已撤销') from None
        if not row['enabled'] or not row['credential_hash']:
            raise AuthenticationError('Agent 凭据已撤销')
        if credential_generation is not None and row['credential_generation'] != credential_generation:
            raise AuthenticationError('Agent 凭据已更新')
        if connection_generation is not None and row['connection_generation'] != connection_generation:
            raise AuthenticationError('Agent 已在其他连接接入')
        with connect(path) as db:
            allowed = {r[0] for r in db.execute('SELECT counter FROM server_counter_grants WHERE server_id=?', (identity,))}
            previous = db.execute('SELECT fingerprint FROM server_reports WHERE server_id=? AND report_id=?', (identity, report_id)).fetchone()
            connections = _connections(db, identity, report.get('connections', []), allowed, now)
        if not set(counters) <= allowed:
            raise ValueError('Agent 不得上报其他服务器的流量')
        if previous and previous[0] != fingerprint:
            raise ValueError('重复报告的计数内容不一致')
        if not previous:
            account_fn(path, 'agent:' + identity + ':' + epoch, counters, server_id=identity, ignore_stale=True)
        with connect(path) as db:
            if not previous:
                db.execute('INSERT INTO server_reports(server_id,report_id,fingerprint,created_at) VALUES(?,?,?,?)',
                           (identity, report_id, fingerprint, now))
                db.execute('''DELETE FROM server_reports WHERE server_id=? AND rowid NOT IN
                              (SELECT rowid FROM server_reports WHERE server_id=? ORDER BY rowid DESC LIMIT 10000)''',
                           (identity, identity))
            for command_id in set(command_acks) | results.keys():
                pending = db.execute('SELECT action FROM server_commands WHERE id=? AND server_id=?', (command_id, identity)).fetchone()
                if not pending:
                    continue
                result = results.get(command_id, {'ok': True, 'error': ''})
                db.execute('INSERT OR IGNORE INTO server_command_history(id,server_id,action,ok,error,completed_at) VALUES(?,?,?,?,?,?)',
                           (command_id, identity, pending['action'], int(result['ok']), result['error'], now))
                db.execute('DELETE FROM server_commands WHERE id=? AND server_id=?', (command_id, identity))
            db.execute('''DELETE FROM server_command_history WHERE server_id=? AND rowid NOT IN
                          (SELECT rowid FROM server_command_history WHERE server_id=? ORDER BY rowid DESC LIMIT 100)''',
                       (identity, identity))
            db.execute('UPDATE servers SET last_seen=?,connected=1,metrics=?,applied_revision=?,error=?,presence=?,connections_truncated=? WHERE id=?',
                       (now, json.dumps(metrics, ensure_ascii=False), applied, error[:2000],
                        json.dumps(connections), int(truncated), identity))
        if traffic_fn is None:
            from .server_traffic import record as traffic_fn
        traffic = traffic_fn(path, identity, metrics)
        # Accounting may have exhausted a shared quota; compile after it commits.
        try:
            document = configuration_fn(path, identity, stats_port)
            revision = _hash(json.dumps(document, sort_keys=True, separators=(',', ':')))
            grants = _config_grants(document)
            issued_grants = set(grants)
            with connect(path) as db:
                db.executemany('INSERT OR IGNORE INTO server_counter_grants(server_id,counter) VALUES(?,?)',
                               ((identity, counter) for counter in grants))
                db.execute('UPDATE servers SET desired_revision=? WHERE id=?', (revision, identity))
                pairs = _authorized_pairs(db, identity, now)
            policy = {'max_ips': {uid: limit for (nid, uid), limit in pairs.items()
                                  if any(f'{kind}>>>{nid}:{uid}>>>traffic>>>uplink' in issued_grants for kind in ('user', 'inbound'))}}
        except Exception:
            # A bad central configuration must not stop acknowledgments of
            # traffic already committed, or renew a stale authorization lease.
            with connect(path) as db:
                db.execute("UPDATE servers SET error='主控配置生成失败，请检查节点或证书设置' WHERE id=?", (identity,))
            return {'type': 'desired', 'protocol': PROTOCOL, 'ack_report_id': report_id,
                    'revision': row['desired_revision'], 'state': 'stopped',
                    'lease_seconds': 0, 'commands': [], 'error': '主控配置生成失败'}
        with connect(path) as db:
            commands = [dict(r) for r in db.execute('SELECT id,action,user_id,source_ip FROM server_commands WHERE server_id=? ORDER BY created_at,rowid', (identity,))]
        for command in commands:
            if not command['user_id']:
                command.pop('user_id')
            if not command['source_ip']:
                command.pop('source_ip')
        desired = {'type': 'desired', 'protocol': PROTOCOL, 'ack_report_id': report_id,
                   'revision': revision, 'state': 'stopped' if traffic.get('blocked') else row['desired_state'], 'lease_seconds': LEASE_SECONDS,
                   'commands': commands, 'policy': policy}
        if traffic.get('blocked'):
            desired['reason'] = '机器月流量额度已用尽'
        if applied != revision or any(command['action'] == 'resync' for command in commands):
            desired['config'] = document
        from .routing_rollout import remember_delivery, observe
        observe(path, identity, applied, metrics.get('running') is True and desired['state'] == 'running',
                apply_result if desired['state'] == 'running' else None)
        if remember_delivery(path, identity, revision):
            desired['config'] = document
        return desired
