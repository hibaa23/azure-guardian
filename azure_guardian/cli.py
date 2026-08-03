import click
from azure_guardian.nsg_scanner import scan_nsgs, print_report as print_nsg_report
from azure_guardian.cost_scanner import scan_long_running_vms, scan_orphan_disks, print_report as print_cost_report


@click.group()
def cli():
    """Azure Guardian — security and cost monitoring for your Azure subscription."""
    pass


@cli.command()
@click.option("--nsg", is_flag=True, help="Scan NSGs for risky inbound rules.")
@click.option("--costs", is_flag=True, help="Scan for long-running VMs and orphaned disks.")
@click.option("--all", "scan_all", is_flag=True, help="Run every available scan.")
def scan(nsg, costs, scan_all):
    """Run security and/or cost scans against your Azure subscription."""

    if not (nsg or costs or scan_all):
        click.echo("⚠️  No scan selected. Use --nsg, --costs, or --all.")
        click.echo("Run 'azure-guardian scan --help' for details.")
        return

    if nsg or scan_all:
        click.echo("\n🔎 Scanning NSGs for risky inbound rules...\n")
        findings = scan_nsgs()
        print_nsg_report(findings)

    if costs or scan_all:
        click.echo("\n🔎 Scanning for cost issues (long-running VMs, orphaned disks)...\n")
        vm_findings = scan_long_running_vms()
        disk_findings = scan_orphan_disks()
        print_cost_report(vm_findings + disk_findings)


if __name__ == "__main__":
    cli()