import sys
import os
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from azure_guardian.cost_scanner import evaluate_vm_runtime, evaluate_orphan_disk


def test_vm_running_over_threshold_is_flagged():
    time_created = datetime.now(timezone.utc) - timedelta(hours=6)
    result = evaluate_vm_runtime(
        vm_name="test-vm",
        resource_group="test-rg",
        power_state="VM running",
        time_created=time_created,
        max_hours=4,
    )
    assert result is not None
    assert result["resource_type"] == "VM"
    assert "6.0h" in result["issue"]


def test_vm_running_under_threshold_is_safe():
    time_created = datetime.now(timezone.utc) - timedelta(hours=1)
    result = evaluate_vm_runtime(
        vm_name="test-vm",
        resource_group="test-rg",
        power_state="VM running",
        time_created=time_created,
        max_hours=4,
    )
    assert result is None


def test_deallocated_vm_is_ignored():
    time_created = datetime.now(timezone.utc) - timedelta(hours=10)
    result = evaluate_vm_runtime(
        vm_name="test-vm",
        resource_group="test-rg",
        power_state="VM deallocated",
        time_created=time_created,
        max_hours=4,
    )
    assert result is None


def test_missing_time_created_is_safely_ignored():
    result = evaluate_vm_runtime(
        vm_name="test-vm",
        resource_group="test-rg",
        power_state="VM running",
        time_created=None,
        max_hours=4,
    )
    assert result is None


def test_orphan_disk_is_flagged():
    result = evaluate_orphan_disk(
        disk_name="test-disk",
        resource_group="test-rg",
        managed_by=None,
    )
    assert result is not None
    assert result["resource_type"] == "Disk"


def test_attached_disk_is_safe():
    result = evaluate_orphan_disk(
        disk_name="test-disk",
        resource_group="test-rg",
        managed_by="/subscriptions/xxx/resourceGroups/test-rg/providers/Microsoft.Compute/virtualMachines/test-vm",
    )
    assert result is None