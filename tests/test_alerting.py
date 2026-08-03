import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from azure_guardian.alerting import format_findings_as_text


def test_format_empty_findings():
    result = format_findings_as_text([], "Test Report")
    assert "No issues found" in result


def test_format_nsg_finding():
    findings = [{
        "nsg_name": "test-nsg",
        "resource_group": "test-rg",
        "rule_name": "Allow-SSH",
        "port": "22",
        "service": "SSH",
        "source": "*",
        "severity": "HIGH",
    }]
    result = format_findings_as_text(findings, "Test Report")
    assert "test-nsg" in result
    assert "SSH" in result


def test_format_cost_finding():
    findings = [{
        "resource_type": "VM",
        "resource_name": "test-vm",
        "resource_group": "test-rg",
        "issue": "Running for 6.0h",
        "severity": "MEDIUM",
    }]
    result = format_findings_as_text(findings, "Test Report")
    assert "test-vm" in result
    assert "Running for 6.0h" in result