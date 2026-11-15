"""The customer preview must not promise routes blocked by system isolation."""
from types import SimpleNamespace

import pytest

from panel import routing, routing_preview, user_routing
from panel.core import records
from test_user_routing import policy_db, draft, publish_for_test


@pytest.mark.parametrize('target', ['127.0.0.1', '10.0.0.2', '169.254.169.254',
                                   '::1', '::ffff:127.0.0.1', 'fd00::1', 'localhost'])
@pytest.mark.parametrize('mode', ['draft', 'applied'])
def test_preview_reports_system_reject_before_admin_and_user_rules(policy_db, target, mode):
    settings = routing.load(policy_db)
    settings['rules'] = [{'id': 'forced', 'name': 'Direct all', 'enabled': True,
                         'priority': 'forced', 'match': {}, 'node_ids': [], 'target': 'direct'}]
    routing.write(policy_db, settings)
    publish_for_test(policy_db, 'alice', draft())
    model = SimpleNamespace(DB=policy_db, DIRECTORY=policy_db.parent, BINARY='unused')
    user = next(row for row in records(policy_db, 'users') if row['id'] == 'alice')
    result = routing_preview.preview(model, user, user_routing.get_policy(policy_db, 'alice'),
                                     target, 'shared', mode)
    assert result['matched'] is True
    assert result['source'] == 'system'
    assert result['outbound_name'] == '拦截'
    assert result['rule_id'] is None


def test_public_domain_preview_still_matches_personal_policy(policy_db):
    publish_for_test(policy_db, 'alice', draft())
    model = SimpleNamespace(DB=policy_db, DIRECTORY=policy_db.parent, BINARY='unused')
    user = next(row for row in records(policy_db, 'users') if row['id'] == 'alice')
    result = routing_preview.preview(model, user, user_routing.get_policy(policy_db, 'alice'),
                                     'www.example.com', 'shared')
    assert result['source'] == 'user'
    assert result['outbound_name'] == 'Seattle'
    assert '不代表连通性' in result['warning']
