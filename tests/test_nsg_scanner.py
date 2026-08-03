import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from azure_guardian.nsg_scanner import evaluate_rule


class FakeRule:
    """Simulates an Azure SDK security rule object for testing."""
    def __init__(self, direction, access, source_address_prefix,
                 destination_port_range, name="test-rule"):
        self.direction = direction
        self.access = access
        self.source_address_prefix = source_address_prefix
        self.destination_port_range = destination_port_range
        self.name = name


def test_ssh_open_to_all_is_flagged():
    rule = FakeRule(
        direction="Inbound",
        access="Allow",
        source_address_prefix="*",
        destination_port_range="22",
        name="Allow-SSH",
    )
    result = evaluate_rule("test-nsg", "test-rg", rule)

    assert result is not None
    assert result["service"] == "SSH"
    assert result["severity"] == "HIGH"
    assert result["rule_name"] == "Allow-SSH"


def test_rdp_open_to_all_is_flagged():
    rule = FakeRule(
        direction="Inbound",
        access="Allow",
        source_address_prefix="0.0.0.0/0",
        destination_port_range="3389",
    )
    result = evaluate_rule("test-nsg", "test-rg", rule)

    assert result is not None
    assert result["service"] == "RDP"


def test_ssh_restricted_to_specific_ip_is_safe():
    rule = FakeRule(
        direction="Inbound",
        access="Allow",
        source_address_prefix="41.250.10.5/32",
        destination_port_range="22",
    )
    result = evaluate_rule("test-nsg", "test-rg", rule)

    assert result is None


def test_outbound_rule_is_ignored():
    rule = FakeRule(
        direction="Outbound",
        access="Allow",
        source_address_prefix="*",
        destination_port_range="22",
    )
    result = evaluate_rule("test-nsg", "test-rg", rule)

    assert result is None


def test_deny_rule_is_ignored():
    rule = FakeRule(
        direction="Inbound",
        access="Deny",
        source_address_prefix="*",
        destination_port_range="22",
    )
    result = evaluate_rule("test-nsg", "test-rg", rule)

    assert result is None


def test_http_port_is_not_flagged():
    rule = FakeRule(
        direction="Inbound",
        access="Allow",
        source_address_prefix="*",
        destination_port_range="80",
    )
    result = evaluate_rule("test-nsg", "test-rg", rule)

    assert result is None


def test_wildcard_port_range_flags_ssh():
    rule = FakeRule(
        direction="Inbound",
        access="Allow",
        source_address_prefix="*",
        destination_port_range="*",
    )
    result = evaluate_rule("test-nsg", "test-rg", rule)

    assert result is not None