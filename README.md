\# Azure Guardian



A lightweight Python security scanner that connects to your Azure subscription and detects risky network configurations — starting with overly permissive Network Security Group (NSG) rules.



\## Why this project exists



While building \[`azure-iac-lab`](https://github.com/hibaa23/azure-iac-lab) — a Terraform/Azure CLI infrastructure lab — I repeatedly opened SSH (port 22) to `\*` (any source) just to get things working quickly during testing. That's a real, common mistake: convenient for a lab, dangerous in production.



Azure Guardian was built to catch exactly that kind of misconfiguration automatically, before it becomes a real security incident.



\## What it does (current scope)



\- Connects read-only to an Azure subscription via a dedicated Service Principal

\- Scans \*\*all Network Security Groups\*\* across the subscription

\- Flags inbound rules that allow traffic from `\*` / `Internet` / `Any` on sensitive ports:



| Port | Service |

|------|---------|

| 22   | SSH |

| 3389 | RDP |

| 3306 | MySQL |

| 5432 | PostgreSQL |

| 1433 | SQL Server |



\- Prints a clear, human-readable report of findings (NSG name, resource group, rule name, exposed service, source)



\## Example output

>> python azure\_guardian\\nsg\_scanner.py

⚠️  Found 1 risky rule(s):



&#x20; \[HIGH] NSG 'azurelab-nsg' (RG: azurelab-rg)

&#x20;     Rule 'Allow-SSH' allows SSH (port 22) from '\*'



Or, when the subscription is clean:

(venv) PS C:\\Users\\hibab\\OneDrive\\Documents\\azure-guardian> python azure\_guardian\\nsg\_scanner.py

✅ No risky NSG rules found.



\## Architecture \& security design



\- Uses a \*\*dedicated Service Principal with `Reader` role only\*\* — this tool can never modify or delete anything in your subscription, by design (principle of least privilege)

\- Credentials are loaded from a local `.env` file, never hardcoded, never committed (see `.gitignore`)

\- Built on the official \[Azure SDK for Python](https://github.com/Azure/azure-sdk-for-python) (`azure-mgmt-network`, `azure-identity`)



\## Prerequisites



\- Python 3.10+

\- An Azure subscription

\- A Service Principal with `Reader` access:



```bash

az ad sp create-for-rbac --name "azure-guardian-sp" --role reader --scopes /subscriptions/<your-subscription-id>

```



\## Setup



```bash

\# 1. Clone the repo

git clone https://github.com/hibaa23/azure-guardian.git

cd azure-guardian



\# 2. Create and activate a virtual environment

python -m venv venv

\# Windows:

.\\venv\\Scripts\\Activate.ps1

\# macOS/Linux:

source venv/bin/activate



\# 3. Install dependencies

pip install -r requirements.txt



\# 4. Configure credentials

\# Create a .env file with:

\# AZURE\_CLIENT\_ID=<your-service-principal-app-id>

\# AZURE\_CLIENT\_SECRET=<your-service-principal-password>

\# AZURE\_TENANT\_ID=<your-tenant-id>

\# AZURE\_SUBSCRIPTION\_ID=<your-subscription-id>

```



\## Usage



```bash

python azure\_guardian/nsg\_scanner.py

```



\## Project structure

```


azure-guardian/

├── azure\_guardian/

│ ├── init.py

│ └── nsg\_scanner.py # NSG rule scanner (current feature)

├── tests/ # Unit tests (in progress)

├── requirements.txt

├── .gitignore # Excludes venv/, .env, pycache

└── README.md



```

\## Roadmap



\- \[ ] Unit tests (`pytest`) for rule detection logic

\- \[ ] Cost-monitoring module: detect long-running VMs and orphaned (unattached) disks

\- \[ ] Alerting: send findings via email or Slack/Discord webhook

\- \[ ] CLI interface (`azure-guardian scan --nsg`, `azure-guardian scan --costs`)

\- \[ ] Scheduled scanning (cron / GitHub Actions on a timer)



\## Author



Hiba Bensaid — Data Science \& Computer Science Engineering Student | Cloud \& Security Enthusiast



