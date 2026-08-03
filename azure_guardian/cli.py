import click
from azure_guardian.nsg_scanner import scan_nsgs, print_report as print_nsg_report
from azure_guardian.cost_scanner import scan_long_running_vms, scan_orphan_disks, print_report as print_cost_report
from azure_guardian.alerting import send_email_alert


@click.group()
def cli():
    """Azure Guardian — security and cost monitoring for your Azure subscription."""
    pass


@cli.command()
@click.option("--nsg", is_flag=True, help="Scan NSGs for risky inbound rules.")
@click.option("--costs", is_flag=True, help="Scan for long-running VMs and orphaned disks.")
@click.option("--all", "scan_all", is_flag=True, help="Run every available scan.")
@click.option("--alert", is_flag=True, help="Send an email alert if issues are found.")
def scan(nsg, costs, scan_all, alert):
    """Run security and/or cost scans against your Azure subscription."""

    if not (nsg or costs or scan_all):
        click.echo("⚠️  No scan selected. Use --nsg, --costs, or --all.")
        click.echo("Run 'azure-guardian scan --help' for details.")
        return

    all_findings = []

    if nsg or scan_all:
        click.echo("\n🔎 Scanning NSGs for risky inbound rules...\n")
        nsg_findings = scan_nsgs()
        print_nsg_report(nsg_findings)
        all_findings.extend(nsg_findings)

    if costs or scan_all:
        click.echo("\n🔎 Scanning for cost issues (long-running VMs, orphaned disks)...\n")
        vm_findings = scan_long_running_vms()
        disk_findings = scan_orphan_disks()
        cost_findings = vm_findings + disk_findings
        print_cost_report(cost_findings)
        all_findings.extend(cost_findings)

    if alert and all_findings:
        click.echo("\n📧 Sending alert email...\n")
        send_email_alert(all_findings, title="Azure Guardian — Issues Detected")
    elif alert:
        click.echo("\n✅ No issues found — no alert needed.\n")


if __name__ == "__main__":
    cli()