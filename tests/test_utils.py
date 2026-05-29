import os
import socket
import subprocess
import sys
import tempfile

import pytest
from unittest.mock import MagicMock, mock_open, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.utils import (  # noqa: E402
    assess_risk,
    export_csv,
    get_service_name,
    nmap_scan,
    reverse_dns,
    validate_cidr,
    vendor_lookup,
)


def test_validate_cidr_valid():
    assert validate_cidr("192.168.1.0/24") is True
    assert validate_cidr("10.0.0.0/8") is True
    assert validate_cidr("172.16.0.0/12") is True


def test_validate_cidr_invalid():
    assert validate_cidr("not-a-cidr") is False
    assert validate_cidr("192.168.1.999/24") is False
    assert validate_cidr("") is False
    assert validate_cidr("192.168.1.1/99") is False


def test_vendor_lookup_known_mac():
    assert vendor_lookup("00:0C:29:XX:YY:ZZ") == "VMware, Inc."


def test_vendor_lookup_known_mac_cisco():
    assert vendor_lookup("00:1C:42:AA:BB:CC") == "Cisco Systems"


def test_vendor_lookup_unknown_mac():
    assert vendor_lookup("AA:BB:CC:DD:EE:FF") == "Desconocido"


def test_vendor_lookup_case_insensitivity():
    result = vendor_lookup("b8-27-eb-aa-bb-cc")
    assert result == "Raspberry Pi Foundation"


def test_vendor_lookup_invalid_input():
    assert vendor_lookup(None) == "Desconocido"
    assert vendor_lookup(12345) == "Desconocido"


def test_get_service_name_known_ports():
    assert get_service_name(22) == "SSH"
    assert get_service_name(80) == "HTTP"
    assert get_service_name(443) == "HTTPS"
    assert get_service_name(3306) == "MySQL"
    assert get_service_name(3389) == "RDP"


def test_get_service_name_unknown_port():
    assert get_service_name(99999) == "Unknown"


def test_assess_risk_high():
    result = assess_risk([22, 445, 3389])
    assert result["level"] == "HIGH"
    assert 445 in result["high_risk_ports"] or 3389 in result["high_risk_ports"]


def test_assess_risk_medium():
    result = assess_risk([80, 25])
    assert result["level"] == "MEDIUM"


def test_assess_risk_low():
    result = assess_risk([22])
    assert result["level"] == "LOW"


def test_assess_risk_safe():
    result = assess_risk([])
    assert result["level"] == "SAFE"


def test_assess_risk_has_hints():
    result = assess_risk([23, 445])
    assert len(result["hints"]) >= 1
    hint_ports = [h["port"] for h in result["hints"]]
    assert 23 in hint_ports or 445 in hint_ports


@patch("socket.gethostbyaddr")
def test_reverse_dns_success(mock_gethostbyaddr):
    mock_gethostbyaddr.return_value = ("localhost", [], ["127.0.0.1"])
    assert reverse_dns("127.0.0.1") == "localhost"
    mock_gethostbyaddr.assert_called_once_with("127.0.0.1")


@patch("socket.gethostbyaddr")
def test_reverse_dns_failure(mock_gethostbyaddr):
    mock_gethostbyaddr.side_effect = socket.herror("Test error")
    assert reverse_dns("192.168.1.99") == "N/A"


@patch("subprocess.run")
def test_nmap_scan_subprocess_success(mock_run):
    nmap_output = (
        "# Nmap scan\n"
        "Host: 192.168.1.1 (router.local)\tStatus: Up\n"
        "Host: 192.168.1.1 (router.local)\t"
        "Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 443/open/tcp//https///\n"
        "# Nmap done\n"
    )
    mock_run.return_value = MagicMock(stdout=nmap_output, stderr="", returncode=0)

    with patch(
        "builtins.__import__",
        side_effect=lambda n, *a, **k: (
            (_ for _ in ()).throw(ImportError())
            if n == "nmap"
            else __import__(n, *a, **k)
        )
    ):
        try:
            result = nmap_scan("192.168.1.1", "1-1024")
        except ImportError:
            from scripts.utils import _nmap_scan_subprocess
            result = _nmap_scan_subprocess("192.168.1.1", "1-1024")

    assert 22 in result
    assert 80 in result
    assert 443 in result


@patch("subprocess.run")
def test_nmap_scan_subprocess_no_open_ports(mock_run):
    nmap_output = "# Nmap scan\nHost: 192.168.1.10 (host.local) Status: Up\n# done\n"
    mock_run.return_value = MagicMock(stdout=nmap_output, stderr="")

    from scripts.utils import _nmap_scan_subprocess
    result = _nmap_scan_subprocess("192.168.1.10", "1-1024")
    assert result == []


@patch("subprocess.run")
def test_nmap_scan_subprocess_file_not_found(mock_run):
    mock_run.side_effect = FileNotFoundError
    from scripts.utils import _nmap_scan_subprocess
    with pytest.raises(Exception, match="Nmap no está instalado"):
        _nmap_scan_subprocess("127.0.0.1", "22")


@patch("subprocess.run")
def test_nmap_scan_subprocess_called_process_error(mock_run):
    mock_run.side_effect = subprocess.CalledProcessError(1, "nmap", stderr="Error de Nmap")
    from scripts.utils import _nmap_scan_subprocess
    with pytest.raises(Exception, match="Nmap devolvió un error"):
        _nmap_scan_subprocess("127.0.0.1", "22")


@patch("subprocess.run")
def test_nmap_scan_subprocess_timeout(mock_run):
    mock_run.side_effect = subprocess.TimeoutExpired("nmap", 180)
    from scripts.utils import _nmap_scan_subprocess
    with pytest.raises(Exception, match="tiempo límite"):
        _nmap_scan_subprocess("127.0.0.1", "1-65535")


def test_export_csv_success():
    data = [
        {"ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF"},
        {"ip": "192.168.1.2", "mac": "11:22:33:44:55:66"},
    ]
    with tempfile.NamedTemporaryFile(mode="w+", delete=False, suffix=".csv") as tmp:
        filepath = tmp.name
    try:
        export_csv(data, filepath)
        with open(filepath, "r") as f:
            content = f.read()
            assert "ip,mac" in content
            assert "192.168.1.1,AA:BB:CC:DD:EE:FF" in content
    finally:
        os.remove(filepath)


def test_export_csv_empty_data():
    with pytest.raises(ValueError):
        export_csv([], "test.csv")


@patch("builtins.open", new_callable=mock_open)
def test_export_csv_io_error(mock_file):
    mock_file.side_effect = IOError("Permission denied")
    data = [{"ip": "1.1.1.1"}]
    with pytest.raises(IOError):
        export_csv(data, "/root/no_permission.csv")
