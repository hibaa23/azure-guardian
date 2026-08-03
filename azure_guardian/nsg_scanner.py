import os
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient

load_dotenv()

DANGEROUS_PORTS = {
    "22": "SSH",
    "3389": "RDP",
    "3306": "MySQL",
    "5432": "PostgreSQL",
    "1433": "SQL Server",
}

RISKY_SOURCE_PREFIXES = ["*", "0.0.0.0/0", "Internet", "Any"]


def get_network_client():
    credential = ClientSecretCredential(
        tenant_id=os.getenv("AZURE_TENANT_ID"),
        client_id=os.getenv("AZURE_CLIENT_ID"),
        client_secret=os.getenv("AZURE_CLIENT_SECRET"),
    )
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    return NetworkManagementClient(credential, subscription_id)


def evaluate_rule(nsg_name, resource_group, rule):
    """
    Pure logic function: takes a single rule's data and returns
    a finding dict if risky, or None if safe.
    No Azure API calls happen here — this is what we unit test.
    """
    if rule.direction != "Inbound" or rule.access != "Allow":
        return None

    source = rule.source_address_prefix
    if source not in RISKY_SOURCE_PREFIXES:
        return None

    port_range = rule.destination_port_range or ""
    for port, service_name in DANGEROUS_PORTS.items():
        if port in port_range or port_range == "*":
            return {
                "nsg_name": nsg_name,
                "resource_group": resource_group,
                "rule_name": rule.name,
                "port": port,
                "service": service_name,
                "source": source,
                "severity": "HIGH",
            }

    return None


def scan_nsgs():
    """
    Fetches real NSGs from Azure and evaluates each rule.
    This function does the API calls; evaluate_rule() does the logic.
    """
    client = get_network_client()
    findings = []

    for nsg in client.network_security_groups.list_all():
        resource_group = nsg.id.split("/")[4]
        for rule in nsg.security_rules or []:
            finding = evaluate_rule(nsg.name, resource_group, rule)
            if finding:
                findings.append(finding)

    return findings


def print_report(findings):
    if not findings:
        print("✅ No risky NSG rules found.")
        return

    print(f"⚠️  Found {len(findings)} risky rule(s):\n")
    for f in findings:
        print(f"  [{f['severity']}] NSG '{f['nsg_name']}' (RG: {f['resource_group']})")
        print(f"      Rule '{f['rule_name']}' allows {f['service']} (port {f['port']}) from '{f['source']}'\n")


if __name__ == "__main__":
    results = scan_nsgs()
    print_report(results)