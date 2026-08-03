# Azure Guardian

A lightweight Python security scanner that connects to your Azure subscription and detects risky network configurations — starting with overly permissive Network Security Group (NSG) rules.

## Why this project exists

While building [`azure-iac-lab`](https://github.com/hibaa23/azure-iac-lab) — a Terraform/Azure CLI infrastructure lab — I repeatedly opened SSH (port 22) to `*` (any source) just to get things working quickly during testing. That's a real, common mistake: convenient for a lab, dangerous in production.

Azure Guardian was built to catch exactly that kind of misconfiguration automatically, before it becomes a real security incident.

## What it does (current scope)

- Connects read-only to an Azure subscription via a dedicated Service Principal
- Scans **all Network Security Groups** across the subscription
- Flags inbound rules that allow traffic from `*` / `Internet` / `Any` on sensitive ports:

| Port | Service |
|------|---------|
| 22   | SSH |
| 3389 | RDP |
| 3306 | MySQL |
| 5432 | PostgreSQL |
| 1433 | SQL Server |

- Prints a clear, human-readable report of findings (NSG name, resource group, rule name, exposed service, source)

## Example output

When a risky rule is found:

⚠️ Found 1 risky rule(s):

[HIGH] NSG 'azurelab-nsg' (RG: azurelab-rg)
Rule 'Allow-SSH' allows SSH (port 22) from '*'


When the subscription is clean:

✅ No risky NSG rules found.


## Architecture & security design

- Uses a **dedicated Service Principal with `Reader` role only** — this tool can never modify or delete anything in your subscription, by design (principle of least privilege)
- Credentials are loaded from a local `.env` file, never hardcoded, never committed (see `.gitignore`)
- Built on the official [Azure SDK for Python](https://github.com/Azure/azure-sdk-for-python) (`azure-mgmt-network`, `azure-identity`)

## Prerequisites

- Python 3.10+
- An Azure subscription
- A Service Principal with `Reader` access:

```bash
az ad sp create-for-rbac --name "azure-guardian-sp" --role reader --scopes /subscriptions/<your-subscription-id>
```

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/hibaa23/azure-guardian.git
cd azure-guardian

# 2. Create and activate a virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\Activate.ps1
# macOS/Linux:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure credentials
# Create a .env file with:
# AZURE_CLIENT_ID=<your-service-principal-app-id>
# AZURE_CLIENT_SECRET=<your-service-principal-password>
# AZURE_TENANT_ID=<your-tenant-id>
# AZURE_SUBSCRIPTION_ID=<your-subscription-id>
```

## Usage

## Usage

After installing the package (`pip install -e .`), use the `azure-guardian` command:

```bash
# Scan NSGs only
azure-guardian scan --nsg

# Scan for cost issues only
azure-guardian scan --costs

# Run all scans
azure-guardian scan --all
```

Alternatively, run modules directly without installing the package:

```bash
python -m azure_guardian.cli scan --all

```
## Testing

Unit tests cover the rule-evaluation logic in isolation (no live Azure connection needed):

```bash
pytest tests/ -v
```

Example output:

================================================= test session starts =================================================
platform win32 -- Python 3.14.6, pytest-9.1.1, pluggy-1.6.0 -- C:\Users\hibab\OneDrive\Documents\azure-guardian\venv\Scripts\python.exe
cachedir: .pytest_cache
rootdir: C:\Users\hibab\OneDrive\Documents\azure-guardian
configfile: pyproject.toml
plugins: mock-3.15.1
collected 15 items

tests/test_cli.py::test_scan_without_options_shows_warning PASSED                                                [  6%]
tests/test_cli.py::test_scan_help_lists_options PASSED                                                           [ 13%]
tests/test_cost_scanner.py::test_vm_running_over_threshold_is_flagged PASSED                                     [ 20%]
tests/test_cost_scanner.py::test_vm_running_under_threshold_is_safe PASSED                                       [ 26%]
tests/test_cost_scanner.py::test_deallocated_vm_is_ignored PASSED                                                [ 33%]
tests/test_cost_scanner.py::test_missing_time_created_is_safely_ignored PASSED                                   [ 40%]
tests/test_cost_scanner.py::test_orphan_disk_is_flagged PASSED                                                   [ 46%]
tests/test_cost_scanner.py::test_attached_disk_is_safe PASSED                                                    [ 53%]
tests/test_nsg_scanner.py::test_ssh_open_to_all_is_flagged PASSED                                                [ 60%]
tests/test_nsg_scanner.py::test_rdp_open_to_all_is_flagged PASSED                                                [ 66%]
tests/test_nsg_scanner.py::test_ssh_restricted_to_specific_ip_is_safe PASSED                                     [ 73%]
tests/test_nsg_scanner.py::test_outbound_rule_is_ignored PASSED                                                  [ 80%]
tests/test_nsg_scanner.py::test_deny_rule_is_ignored PASSED                                                      [ 86%]
tests/test_nsg_scanner.py::test_http_port_is_not_flagged PASSED                                                  [ 93%]
tests/test_nsg_scanner.py::test_wildcard_port_range_flags_ssh PASSED                                             [100%]

================================================= 15 passed in 0.34s ==================================================
```

Current coverage: 13 tests across both scanners — NSG rule detection (7 tests: SSH/RDP open to `*`, restricted IPs, outbound rules, deny rules, wildcard port ranges) and cost monitoring (6 tests: VM runtime thresholds, deallocated VMs, orphaned disks).
## Roadmap

- [x] Unit tests (`pytest`) for rule detection logic — 7 tests covering safe/risky rule combinations
- [x] Cost-monitoring module: detect long-running VMs and orphaned (unattached) disks
- [ ] Alerting: send findings via email or Slack/Discord webhook
- [x] CLI interface (`azure-guardian scan --nsg`, `azure-guardian scan --costs`)
- [ ] Scheduled scanning (cron / GitHub Actions on a timer)

## Author

Hiba Bensaid — Data Science & Computer Science Engineering Student | Cloud & Security Enthusiast