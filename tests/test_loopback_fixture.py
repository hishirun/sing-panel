"""The local protocol-fixture adapter must never disable later security tests."""
import pytest

from panel import routing_security
from panel.core import current_config
from loopback_fixture import unprotected_fixture_config
from test_user_routing import policy_db


def test_fixture_adapter_is_scoped_and_keeps_production_protection(policy_db):
    original = routing_security.protect
    before = current_config(policy_db)
    prefix = routing_security.protection_rules(before)
    assert before['route']['rules'][:len(prefix)] == prefix
    fixture = unprotected_fixture_config(current_config, policy_db)
    assert fixture['route']['rules'][:len(prefix)] != prefix
    assert routing_security.protect is original
    assert current_config(policy_db) == before

    def broken_builder():
        raise ValueError('fixture generation failed')

    with pytest.raises(ValueError):
        unprotected_fixture_config(broken_builder)
    assert routing_security.protect is original
    assert current_config(policy_db) == before
