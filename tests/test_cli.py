import os
import pytest
from unittest.mock import patch
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts import cli  # noqa: E402


@patch("scripts.cli.run_arp_scan")
@patch("scripts.cli.check_permissions", return_value=True)
def test_cli_scan_arp_success(mock_check_permissions, mock_run_arp_scan, capsys):
    fake_results = [{"ip": "192.168.1.1", "mac": "AA:BB:CC:00:11:22"}]
    mock_run_arp_scan.return_value = fake_results

    sys.argv = ["cli.py", "scan-arp", "--cidr", "192.168.1.0/24"]

    cli.main()

    captured = capsys.readouterr()

    mock_run_arp_scan.assert_called_once_with("192.168.1.0/24")

    lines = captured.out.strip().splitlines()
    json_str = "\n".join(lines[1:]) if len(lines) > 1 else captured.out
    output_json = json.loads(json_str)
    assert output_json == fake_results


@patch("scripts.cli.check_permissions", return_value=False)
def test_cli_scan_arp_no_permissions(mock_check_permissions, capsys):
    sys.argv = ["cli.py", "scan-arp", "--cidr", "192.168.1.0/24"]

    with pytest.raises(SystemExit) as e:
        cli.main()

    assert e.value.code == 1
    captured = capsys.readouterr()
    assert "Error: El escaneo ARP requiere privilegios de" in captured.out


@patch("scripts.cli.nmap_scan")
def test_cli_scan_nmap_success(mock_nmap_scan, capsys):
    fake_ports = [80, 443]
    mock_nmap_scan.return_value = fake_ports

    sys.argv = ["cli.py", "scan-nmap", "--ip", "1.1.1.1", "--ports", "80,443"]

    cli.main()

    captured = capsys.readouterr()
    mock_nmap_scan.assert_called_once_with("1.1.1.1", port_range="80,443")

    lines = captured.out.strip().splitlines()
    json_str = "\n".join(lines[1:]) if len(lines) > 1 else captured.out
    output_json = json.loads(json_str)
    assert output_json == {"ip": "1.1.1.1", "open_ports": fake_ports}


@patch("scripts.cli.nmap_scan")
def test_cli_scan_nmap_default_ports(mock_nmap_scan, capsys):
    mock_nmap_scan.return_value = [22]

    sys.argv = ["cli.py", "scan-nmap", "--ip", "1.1.1.1"]

    cli.main()

    capsys.readouterr()
    mock_nmap_scan.assert_called_once_with("1.1.1.1", port_range="1-1024")


def test_cli_missing_arguments(capsys):
    sys.argv = ["cli.py", "scan-arp"]

    with pytest.raises(SystemExit):
        cli.main()

    captured = capsys.readouterr()
    assert "the following arguments are required: --cidr" in captured.err


def test_cli_no_command(capsys):
    sys.argv = ["cli.py"]

    with pytest.raises(SystemExit):
        cli.main()

    captured = capsys.readouterr()
    assert "the following arguments are required: command" in captured.err
