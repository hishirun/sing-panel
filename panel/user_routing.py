"""User-owned routing drafts, outbound grants and identity-scoped compilation.

Only ``applied`` documents enter the running core.  Customer-facing projections
are explicit allowlists: outbound connection settings never leave this module.
"""
import copy
import ipaddress
import json
import re
import time
import uuid

from .core import connect, reason
from . import routing as r

KINDS = ('geosite', 'geoip', 'domain_suffix', 'ip_cidr')
COLUMNS = ('user_id', 'allowed', 'max_rules', 'password_hash', 'auth_revision',
           'draft', 'revision', 'applied', 'applied_revision', 'status', 'error',
           'applied_at', 'updated_at')


class RevisionConflict(ValueError):
    """Another browser changed the draft since it was read."""


def migrate(db):
    db.execute('''CREATE TABLE IF NOT EXISTS user_routing (
        user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        allowed INTEGER NOT NULL DEFAULT 0,
        max_rules INTEGER NOT NULL DEFAULT 6,
        password_hash TEXT NOT NULL DEFAULT '',
        auth_revision INTEGER NOT NULL DEFAULT 0,
        draft TEXT NOT NULL DEFAULT '{"enabled":true,"rules":[]}',
        revision INTEGER NOT NULL DEFAULT 0,
        applied TEXT NOT NULL DEFAULT '{"enabled":false,"rules":[]}',
        applied_revision INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'applied',
        error TEXT NOT NULL DEFAULT '',
        applied_at INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL DEFAULT 0
    )''')


def _default(user_id):
    return dict(user_id=user_id, allowed=False, max_rules=6, password_hash='',
                auth_revision=0, draft={'enabled': True, 'rules': []}, revision=0,
                applied={'enabled': False, 'rules': []}, applied_revision=0,
                status='applied', error='', applied_at=0, updated_at=0, exists=False)


def _decode(row):
    data = dict(row)
    data['draft'] = json.loads(data['draft'])
    data['applied'] = json.loads(data['applied'])
    data['allowed'] = bool(data['allowed'])
    data['exists'] = True
    return data


def get_policy(path, user_id):
    with connect(path) as db:
        if not db.execute('SELECT 1 FROM users WHERE id=?', (user_id,)).fetchone():
            raise ValueError('用户不存在')
        row = db.execute('SELECT * FROM user_routing WHERE user_id=?', (user_id,)).fetchone()
    return _decode(row) if row else _default(user_id)


def restore_policy(path, user_id, policy):
    """Internal rollback helper. Caller holds the core runtime lock."""
    with connect(path) as db:
        if not policy.get('exists', True):
            db.execute('DELETE FROM user_routing WHERE user_id=?', (user_id,))
            return
        values = {key: policy[key] for key in COLUMNS}
        values['user_id'] = user_id
        for key in ('draft', 'applied'):
            values[key] = json.dumps(values[key], ensure_ascii=False)
        db.execute('INSERT OR REPLACE INTO user_routing (' + ','.join(COLUMNS) + ') VALUES (' +
                   ','.join('?' for _ in COLUMNS) + ')', tuple(values[key] for key in COLUMNS))


def configure_user(path, user_id, allowed, max_rules=6):
    if isinstance(max_rules, bool):
        raise ValueError('规则上限须为 1–50')
    try:
        max_rules = int(max_rules)
    except (ValueError, TypeError):
        raise ValueError('规则上限须为 1–50')
    if not 1 <= max_rules <= 50:
        raise ValueError('规则上限须为 1–50')
    with connect(path) as db:
        db.execute('BEGIN IMMEDIATE')
        if not db.execute('SELECT 1 FROM users WHERE id=?', (user_id,)).fetchone():
            raise ValueError('用户不存在')
        # Explicitly provide the new default even on databases whose original
        # table definition still declares DEFAULT 20. Legacy auth columns stay
        # untouched and are no longer used to authorize customer settings.
        db.execute('INSERT OR IGNORE INTO user_routing(user_id,max_rules) VALUES(?,?)', (user_id,6))
        db.execute('UPDATE user_routing SET allowed=?,max_rules=?,updated_at=? WHERE user_id=?',
                   (int(bool(allowed)), max_rules, int(time.time()), user_id))
    return get_policy(path, user_id)


def _audience(out, user):
    public = out.get('public', {})
    if not isinstance(public, dict) or not public.get('visible', False):
        return False
    audience = public.get('audience', 'all')
    return audience == 'all' or (audience == 'selected' and (
        user['id'] in public.get('user_ids', []) or
        bool(user.get('group_name')) and user.get('group_name') in public.get('groups', [])))


def allowed_outbound(out, user, policy):
    return bool(policy.get('allowed') and out.get('enabled') and _audience(out, user) and
                out.get('public', {}).get('allow_use', True))


def public_outbounds(path, user, settings=None):
    """Metadata only, including visible-but-disabled choices for clear feedback."""
    from .latency import cached
    settings = r.load(path) if settings is None else settings
    policy = get_policy(path, user['id'])
    result = []
    for out in sorted(settings['outbounds'], key=lambda entry: entry.get('public', {}).get('order', 0)):
        if not _audience(out, user):
            continue
        public = out['public']
        latency = cached(path, out)
        result.append({
            'id': out['id'], 'name': public.get('name') or out['name'],
            'region': public.get('region', ''), 'description': public.get('description', ''),
            'type': out['settings']['type'], 'enabled': bool(out['enabled']),
            'selectable': allowed_outbound(out, user, policy),
            'latency': {key: latency[key] for key in ('delay', 'checked_at') if key in latency},
        })
    return result


def _bool(value, label):
    if not isinstance(value, bool):
        raise ValueError(label + '无效')
    return value


def _strings(value, label, maximum, length=255):
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(label + '数量无效')
    if any(not isinstance(item, str) or not item.strip() or len(item) > length or
           any(ord(c) < 32 for c in item) for item in value):
        raise ValueError(label + '格式无效')
    return list(dict.fromkeys(item.strip() for item in value))


def validate_draft(path, user_id, document, settings=None, allow_unavailable=False):
    """Normalize untrusted input. Unknown fields are discarded, not compiled."""
    policy = get_policy(path, user_id)
    with connect(path) as db:
        user = dict(db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone())
        node_ids = {row[0] for row in db.execute('SELECT node_id FROM memberships WHERE user_id=?', (user_id,))}
    if not policy['allowed']:
        raise ValueError('管理员尚未开启自定义分流')
    if reason(user):
        raise ValueError('当前订阅不可用，分流设置为只读')
    if not isinstance(document, dict) or not isinstance(document.get('rules'), list):
        raise ValueError('分流配置格式无效')
    if len(document['rules']) > policy['max_rules']:
        raise ValueError('最多可设置 ' + str(policy['max_rules']) + ' 条规则')
    settings = r.load(path) if settings is None else settings
    permitted = {out['id'] for out in settings['outbounds'] if allowed_outbound(out, user, policy)}
    retained = {(rule['id'], rule['target']) for doc in (policy['draft'], policy['applied'])
                for rule in doc.get('rules', [])}
    enabled = _bool(document.get('enabled', True), '分流开关')
    normalized = []
    identities = set()
    geo_sets = set()
    total_values = 0
    for index, raw in enumerate(document['rules'], 1):
        if not isinstance(raw, dict):
            raise ValueError('规则格式无效')
        identity = raw.get('id') or uuid.uuid4().hex
        if not isinstance(identity, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', identity) or identity in identities:
            raise ValueError('规则标识无效或重复')
        identities.add(identity)
        active = _bool(raw.get('enabled', True), '规则开关')
        kind = raw.get('kind')
        if kind not in KINDS:
            raise ValueError('请选择网站服务、目标 IP 地区、域名或 IP 段')
        values = _strings(raw.get('values'), '匹配条件', 64 if kind in ('geoip', 'geosite') else 128)
        if not values:
            raise ValueError('第 ' + str(index) + ' 条规则尚未选择匹配条件')
        if kind in ('geoip', 'geosite'):
            values = [value.lower() for value in values]
            if not set(values) <= set(r.GEO_CATALOG[kind]):
                raise ValueError('请选择有效的 ' + kind + ' 分类')
        elif kind == 'ip_cidr':
            try:
                values = [str(ipaddress.ip_network(value, strict=False)) for value in values]
            except ValueError:
                raise ValueError('IP 段格式无效，例如 1.1.1.0/24')
        else:
            from .options import domain
            values = [domain(value.lower().lstrip('.')) for value in values]
        values = list(dict.fromkeys(values))
        total_values += len(values)
        if total_values > 256:
            raise ValueError('整份策略最多包含 256 个匹配条件')
        if kind in ('geoip', 'geosite'):
            geo_sets.update((kind, value) for value in values)
            if len(geo_sets) > 32:
                raise ValueError('整份策略最多选择 32 个不同的 GeoSite / GeoIP 分类')
        target = raw.get('target')
        if not isinstance(target, str) or len(target) > 64:
            raise ValueError('请选择已授权的出口')
        if target != 'reject' and target not in permitted:
            # A revoked target can remain visible while the user disables or
            # replaces it; a new rule can never invent an inaccessible target.
            retained_disabled = (not active or not enabled) and (identity, target) in retained
            if not retained_disabled and not (allow_unavailable and (identity, target) in retained):
                raise ValueError('第 ' + str(index) + ' 条规则的出口不可用或未授权')
        selected_nodes = _strings(raw.get('node_ids', []), '适用节点', 100, 64)
        if not set(selected_nodes) <= node_ids:
            # Old references to removed grants are inert in the compiler. Only
            # retained disabled rules/policies can preserve those references.
            retained_nodes = any(item.get('id') == identity and set(selected_nodes) == set(item.get('node_ids', []))
                                 for doc in (policy['draft'], policy['applied']) for item in doc.get('rules', []))
            if (active and enabled) or not retained_nodes:
                raise ValueError('请选择已授权的节点')
        name = raw.get('name', '')
        if not isinstance(name, str) or len(name) > 80 or any(ord(c) < 32 for c in name):
            raise ValueError('规则名称最多 80 个字符')
        name = name.strip() or (' / '.join(values[:2])[:75] + (' 等' if len(values) > 2 else ''))
        normalized.append(dict(id=identity, name=name, enabled=active, kind=kind,
                               values=values, target=target, node_ids=selected_nodes))
    return {'enabled': enabled, 'rules': normalized}


def save_draft(path, user_id, document, revision):
    normalized = validate_draft(path, user_id, document)
    if not isinstance(revision, int) or isinstance(revision, bool):
        raise RevisionConflict('页面版本无效，请刷新后重试')
    with connect(path) as db:
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT revision,status FROM user_routing WHERE user_id=?', (user_id,)).fetchone()
        if not row or row['revision'] != revision:
            raise RevisionConflict('设置已在其他页面更新，请刷新后重试')
        if row['status'] in ('queued', 'applying'):
            raise RevisionConflict('设置正在应用，请完成后再修改')
        db.execute('UPDATE user_routing SET draft=?,revision=revision+1,status=?,error=?,updated_at=? WHERE user_id=?',
                   (json.dumps(normalized, ensure_ascii=False), 'draft', '', int(time.time()), user_id))
    return get_policy(path, user_id)


def applied_references(path, outbound_id):
    with connect(path) as db:
        rows = db.execute('SELECT p.*,u.name FROM user_routing p JOIN users u ON u.id=p.user_id WHERE p.allowed=1').fetchall()
    return [{'id': row['user_id'], 'name': row['name']} for row in rows
            if (doc := json.loads(row['applied'])).get('enabled') and
            any(rule.get('enabled') and rule.get('target') == outbound_id for rule in doc.get('rules', []))]


def identity_scope(document, user_id, node_ids=None):
    """An OR of exact auth identities and dedicated inbounds, never a wildcard."""
    names, tags = [], []
    for inbound in document.get('inbounds', []):
        tag = inbound['tag']
        node_id = tag.split(':', 1)[0]
        if node_ids and node_id not in node_ids:
            continue
        name = node_id + ':' + user_id
        if tag == name:
            tags.append(tag)
        elif any(entry.get('name') == name for entry in inbound.get('users', [])):
            names.append(name)
    scopes = []
    if names:
        scopes.append({'auth_user': names})
    if tags:
        scopes.append({'inbound': tags})
    if not scopes:
        return None
    return scopes[0] if len(scopes) == 1 else {'type': 'logical', 'mode': 'or', 'rules': scopes}


def _condition(rule, sets):
    kind, values = rule['kind'], rule['values']
    if kind in ('geoip', 'geosite'):
        tags = []
        for value in values:
            if value not in r.GEO_CATALOG[kind]:
                raise ValueError('规则集分类已不可用：' + kind)
            tag = kind + '-' + value
            tags.append(tag)
            sets[tag] = {'type': 'remote', 'tag': tag, 'format': 'binary',
                         'url': 'https://raw.githubusercontent.com/SagerNet/sing-' + kind + '/rule-set/' + tag + '.srs',
                         'http_client': {'version': 1}, 'update_interval': '24h'}
        return {'rule_set': tags}
    return {kind: list(values)}


def compose(document, path, settings=None, policy_overrides=None):
    """Compile platform mandatory > personal > platform default rules.

    ``policy_overrides`` supplies candidate applied documents for validation.
    Existing platform rules remain mandatory until an admin explicitly changes
    their priority. The customer's draft is never consulted here.
    """
    settings = r.load(path) if settings is None else settings
    overrides = policy_overrides or {}
    with connect(path) as db:
        users = {row['id']: dict(row) for row in db.execute('SELECT * FROM users')}
        policies = {row['user_id']: _decode(row) for row in db.execute('SELECT * FROM user_routing')}
    forced = [rule for rule in settings['rules'] if rule.get('priority', 'forced') != 'default']
    normal = [rule for rule in settings['rules'] if rule.get('priority', 'forced') == 'default']
    forced_settings = {**settings, 'rules': forced}
    result = r.compile_into(document, forced_settings)
    # Reuse the established platform compiler while preventing duplicate
    # outbound entries or mutation of the original document.
    default_document = r.compile_into({'inbounds': copy.deepcopy(document.get('inbounds', [])), 'outbounds': []},
                                      {**settings, 'rules': normal, 'sniff': settings.get('sniff', False)})
    platform_defaults = default_document['route']['rules']
    if settings.get('sniff') and platform_defaults and platform_defaults[0].get('action') == 'sniff':
        platform_defaults = platform_defaults[1:]
    sets = {entry['tag']: entry for entry in result['route'].get('rule_set', [])}
    sets.update({entry['tag']: entry for entry in default_document['route'].get('rule_set', [])})
    own_rules, sniff_scopes, resolve_scopes = [], [], []
    outbounds = {out['id']: out for out in settings['outbounds']}
    for user_id, policy in policies.items():
        user = users.get(user_id)
        if not user or not policy['allowed'] or reason(user):
            continue
        selected = overrides.get(user_id, policy['applied'])
        if not selected.get('enabled'):
            continue
        for rule in selected.get('rules', []):
            if not rule.get('enabled'):
                continue
            scope = identity_scope(document, user_id, rule.get('node_ids'))
            if scope is None:
                continue
            condition = _condition(rule, sets)
            target = rule['target']
            permitted = target == 'reject' or target in outbounds and allowed_outbound(outbounds[target], user, policy)
            compiled = {'type': 'logical', 'mode': 'and', 'rules': [scope, condition]}
            # Revocations must never silently send matching traffic through the
            # platform fallback, which can have a different egress identity.
            if target == 'reject' or not permitted:
                compiled['action'] = 'reject'
            else:
                compiled.update(action='route', outbound='up-' + target)
            # Destination IP matching needs resolved addresses when clients
            # send a hostname. Resolve only at the first relevant personal
            # rule, after platform mandatory rules and earlier domain rules.
            if rule['kind'] in ('geoip', 'ip_cidr') and scope not in resolve_scopes:
                own_rules.append({**scope, 'action': 'resolve', 'strategy': 'prefer_ipv4'})
                resolve_scopes.append(scope)
            own_rules.append(compiled)
            if not settings.get('sniff') and rule['kind'] in ('geosite', 'domain_suffix') and scope not in sniff_scopes:
                sniff_scopes.append(scope)
    result['route']['rules'] = ([{**scope, 'action': 'sniff', 'timeout': '300ms'} for scope in sniff_scopes] +
                                result['route']['rules'] + own_rules + platform_defaults)
    if sets:
        result['route']['rule_set'] = list(sets.values())
        result.setdefault('experimental', {}).setdefault('cache_file', {})['enabled'] = True
    return result
