"""Explicit isolation adapter for legacy loopback protocol/byte-count fixtures.

These tests intentionally forward to HTTP/UDP services on the same temporary
host. Production configurations always retain the system protection prefix;
test_routing_network_security exercises that default without this adapter.
"""
import copy
from unittest.mock import patch

from panel.core import current_config
from panel.runtime import Runtime
from panel import routing_security
from panel.routing_security import protection_rules


def unprotected_fixture(document):
    """Validate production protection first, then remove it from a test copy."""
    prefix = protection_rules(document)
    assert prefix, 'The production network protection prefix must exist'
    assert document['route']['rules'][:len(prefix)] == prefix, 'Unexpected/missing system protection prefix'
    fixture = copy.deepcopy(document)
    del fixture['route']['rules'][:len(prefix)]
    return fixture


def unprotected_fixture_config(builder, *args, **kwargs):
    """Exercise real protection, then restore pre-protection fixture routing.

    Production protection intentionally folds all resolution into its checked
    prefix. Keep the old fixture's business resolvers when removing that prefix,
    so byte-count and administrator-precedence tests retain their exact scope.
    """
    protect = routing_security.protect

    def fixture_protection(document):
        business_rules = copy.deepcopy(document.get('route', {}).get('rules', []))
        fixture = unprotected_fixture(protect(document))
        fixture['route']['rules'] = business_rules
        return fixture

    with patch('panel.routing_security.protect', side_effect=fixture_protection):
        return builder(*args, **kwargs)


class LoopbackFixtureRuntime(Runtime):
    """Strip protection only during this temporary runtime's config generation."""
    def apply(self):
        def fixture_config(*args, **kwargs):
            return unprotected_fixture_config(current_config, *args, **kwargs)

        # Scoped to this call, never installed as an autouse/global monkeypatch.
        # Other tests and later Runtime instances still use protected configs.
        with patch('panel.runtime.current_config', side_effect=fixture_config):
            return super().apply()
