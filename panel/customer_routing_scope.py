"""Customer-safe node and machine metadata, restricted to memberships."""
import time

from .core import connect
from .fleet import ONLINE_SECONDS


def nodes(path, user_id, settings):
    with connect(path) as db:
        assigned = [dict(row) for row in db.execute('''
            SELECT n.*, s.name AS machine_name, s.enabled AS machine_enabled,
                   s.connected, s.last_seen, s.desired_state
            FROM nodes n JOIN memberships m ON m.node_id=n.id
            LEFT JOIN servers s ON s.id=n.server_id WHERE m.user_id=?
            ORDER BY n.server_id,n.rowid''', (user_id,))]
    now = int(time.time())
    result = []
    for node in assigned:
        local = node['server_id'] == 'local'
        machine_enabled = local or bool(node['machine_enabled'])
        running = local or node['desired_state'] == 'running'
        online = local or bool(machine_enabled and node['connected'] and node['last_seen'] >= now - ONLINE_SECONDS)
        locked = any(rule.get('enabled') and rule.get('priority', 'forced') != 'default'
                     and not rule.get('match') and (not rule.get('node_ids') or node['id'] in rule['node_ids'])
                     for rule in settings['rules'])
        result.append({'id': node['id'], 'name': node['name'], 'enabled': bool(node['enabled']),
                       'locked': locked, 'server_id': node['server_id'],
                       'server_name': '本机' if local else node['machine_name'] or '已移除机器',
                       'server_enabled': machine_enabled, 'online': online,
                       'available': bool(node['enabled'] and machine_enabled and running)})
    return result
