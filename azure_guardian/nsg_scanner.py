import os
from dotenv import load_dotenv
from azure.identity import ClientSecretCredential
from azure.mgmt.network import NetworkManagementClient

load_dotenv()

# Ports considérés comme sensibles s'ils sont ouverts à tout Internet
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


def scan_nsgs():
    client = get_network_client()
    findings = []

    for nsg in client.network_security_groups.list_all():
        for rule in nsg.security_rules or []:
            if rule.direction != "Inbound" or rule.access != "Allow":
                continue

            source = rule.source_address_prefix
            if source not in RISKY_SOURCE_PREFIXES:
                continue

            port_range = rule.destination_port_range or ""
            for port, service_name in DANGEROUS_PORTS.items():
                if port in port_range or port_range == "*":
                    findings.append({
                        "nsg_name": nsg.name,
                        "resource_group": nsg.id.split("/")[4],
                        "rule_name": rule.name,
                        "port": port,
                        "service": service_name,
                        "source": source,
                        "severity": "HIGH",
                    })

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