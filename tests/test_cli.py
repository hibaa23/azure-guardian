import sys
import os
from click.testing import CliRunner

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from azure_guardian.cli import cli


def test_scan_without_options_shows_warning():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan"])
    assert "No scan selected" in result.output


def test_scan_help_lists_options():
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert "--nsg" in result.output
    assert "--costs" in result.output
    assert "--all" in result.output