import os
from datetime import datetime, timezone
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient

load_dotenv()

MAX_VM_RUNTIME_HOURS = 4


def get_compute_client():
    credential = ClientSecretCredential(
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET"),
    )
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    return ComputeManagementClient(credential, subscription_id)


def evaluate_vm_runtime(vm_name, resource_group, power_state, time_created, max_hours=MAX_VM_RUNTIME_HOURS):
    if power_state != "VM running":
        return None

    if time_created is None:
        return None

    now = datetime.now(timezone.utc)
    runtime_hours = (now - time_created).total_seconds() / 3600

    if runtime_hours > max_hours:
        return {
            "resource_type": "VM",
            "resource_name": vm_name,
            "resource_group": resource_group,
            "issue": f"Running for {runtime_hours:.1f}h (threshold: {max_hours}h)",
            "severity": "MEDIUM",
        }

    return None


def evaluate_orphan_disk(disk_name, resource_group, managed_by):
    if managed_by is None or managed_by == "":
        return {
            "resource_type": "Disk",
            "resource_name": disk_name,
            "resource_group": resource_group,
            "issue": "Unattached (orphaned) managed disk",
            "severity": "LOW",
        }
    return None


def scan_long_running_vms():
    client = get_compute_client()
    findings = []

    for vm in client.virtual_machines.list_all():
        resource_group = vm.id.split("/")[4]
        instance_view = client.virtual_machines.instance_view(resource_group, vm.name)

        power_state = None
        for status in instance_view.statuses:
            if status.code.startswith("PowerState/"):
                power_state = status.code.replace("PowerState/", "").replace("/", " ")
                power_state = f"VM {power_state}" if not power_state.startswith("VM") else power_state

        time_created = getattr(vm.storage_profile.os_disk, "time_created", None) if vm.storage_profile else None

        finding = evaluate_vm_runtime(vm.name, resource_group, power_state, time_created)
        if finding:
            findings.append(finding)

    return findings


def scan_orphan_disks():
    client = get_compute_client()
    findings = []

    for disk in client.disks.list():
        resource_group = disk.id.split("/")[4]
        finding = evaluate_orphan_disk(disk.name, resource_group, disk.managed_by)
        if finding:
            findings.append(finding)

    return findings


def print_report(findings):
    if not findings:
        print("✅ No cost issues found.")
        return

    print(f"💰 Found {len(findings)} cost issue(s):\n")
    for f in findings:
        print(f"  [{f['severity']}] {f['resource_type']} '{f['resource_name']}' (RG: {f['resource_group']})")
        print(f"      {f['issue']}\n")


if __name__ == "__main__":
    vm_findings = scan_long_running_vms()
    disk_findings = scan_orphan_disks()
    all_findings = vm_findings + disk_findings
    print_report(all_findings)