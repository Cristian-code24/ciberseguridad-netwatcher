# -*- coding: utf-8 -*-
"""
Pruebas Unitarias para scripts/utils.py

Se utilizan mocks para simular el comportamiento de herramientas externas
como Scapy y Nmap, permitiendo que las pruebas se ejecuten sin necesidad
de una red activa o privilegios de root.

Autor: Cristian-code24
Fecha: 2025-10-12
"""

import pytest
from unittest.mock import patch, MagicMock, mock_open
import subprocess
import tempfile
import os
import socket  # Necesario para simular socket.herror

# Añadir el directorio padre al path para poder importar utils
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Importar las funciones a probar desde el módulo utils
from scripts.utils import (
    vendor_lookup,
    reverse_dns,
    nmap_scan as _nmap_scan_subprocess, # Renombramos para que coincida con el test
    export_csv
)

# --- Pruebas para vendor_lookup ---

@patch('scripts.utils.requests.get')
def test_vendor_lookup_known_mac(mock_get):
    """Prueba que se encuentre un fabricante conocido."""
    mock_get.return_value = MagicMock(status_code=200, text="VMware, Inc.")
    assert vendor_lookup("00:0C:29:XX:YY:ZZ") == "VMware, Inc."

@patch('scripts.utils.requests.get')
def test_vendor_lookup_unknown_mac(mock_get):
    """Prueba que devuelva 'N/A' para una MAC no registrada."""
    mock_get.side_effect = Exception("Not Found")
    assert vendor_lookup("AA:BB:CC:DD:EE:FF") == "N/A"

@patch('scripts.utils.requests.get')
def test_vendor_lookup_case_insensitivity_and_format(mock_get):
    """Prueba que la función maneje diferentes formatos y mayúsculas/minúsculas."""
    mock_get.return_value = MagicMock(status_code=200, text="Raspberry Pi Foundation")
    assert vendor_lookup("b8-27-eb-aa-bb-cc") == "Raspberry Pi Foundation"

def test_vendor_lookup_invalid_input():
    """Prueba que maneje entradas inválidas (no string) de forma segura."""
    assert vendor_lookup(None) == "N/A"
    assert vendor_lookup(12345) == "N/A"

# --- Pruebas para reverse_dns ---

@patch('socket.gethostbyaddr')
def test_reverse_dns_success(mock_gethostbyaddr):
    """Prueba una resolución de DNS inversa exitosa."""
    mock_gethostbyaddr.return_value = ("localhost", [], ["127.0.0.1"])
    assert reverse_dns("127.0.0.1") == "localhost"
    mock_gethostbyaddr.assert_called_once_with("127.0.0.1")

@patch('socket.gethostbyaddr')
def test_reverse_dns_failure(mock_gethostbyaddr):
    """Prueba el manejo de errores cuando la IP no puede ser resuelta."""
    mock_gethostbyaddr.side_effect = socket.herror("Test error")
    assert reverse_dns("192.168.1.99") == "N/A"
    mock_gethostbyaddr.assert_called_once_with("192.168.1.99")

# --- Pruebas para _nmap_scan_subprocess ---

@patch('subprocess.run')
def test_nmap_scan_subprocess_success(mock_subprocess_run):
    """Prueba el parseo de una salida exitosa de Nmap."""
    nmap_output = """
# Nmap 7.92 scan initiated Tue Oct 12 10:00:00 2025 as: nmap -p 1-1024 -T4 -oG - 192.168.1.1
Host: 192.168.1.1 (router.local)    Status: Up
Host: 192.168.1.1 (router.local)    Ports: 22/open/tcp//ssh///, 80/open/tcp//http///, 443/open/tcp//https///
# Nmap done at Tue Oct 12 10:00:10 2025; 1 IP address (1 host up) scanned in 10.00 seconds
"""
    mock_subprocess_run.return_value = MagicMock(
        stdout=nmap_output, stderr="", returncode=0
    )
    
    result = _nmap_scan_subprocess("192.168.1.1", "1-1024")
    assert result == [22, 80, 443]
    mock_subprocess_run.assert_called_once()

@patch('subprocess.run')
def test_nmap_scan_subprocess_no_open_ports(mock_subprocess_run):
    """Prueba el parseo cuando Nmap no encuentra puertos abiertos."""
    nmap_output = """
# Nmap 7.92 scan initiated
Host: 192.168.1.10 (host.local) Status: Up
# Nmap done
"""
    mock_subprocess_run.return_value = MagicMock(stdout=nmap_output, stderr="")
    
    result = _nmap_scan_subprocess("192.168.1.10", "1-1024")
    assert result == []

@patch('subprocess.run')
def test_nmap_scan_subprocess_file_not_found(mock_subprocess_run):
    """Prueba que se lance una excepción si Nmap no está instalado."""
    mock_subprocess_run.side_effect = FileNotFoundError
    with pytest.raises(Exception, match="Nmap no está instalado o no se encuentra en el PATH."):
        _nmap_scan_subprocess("127.0.0.1", "22")

@patch('subprocess.run')
def test_nmap_scan_subprocess_called_process_error(mock_subprocess_run):
    """Prueba que se lance una excepción si Nmap devuelve un error."""
    mock_subprocess_run.side_effect = subprocess.CalledProcessError(1, "nmap", stderr="Error de Nmap")
    with pytest.raises(Exception, match="Error al ejecutar Nmap"):
        _nmap_scan_subprocess("127.0.0.1", "22")

# --- Pruebas para export_csv ---

def test_export_csv_success():
    """Prueba una exportación a CSV exitosa."""
    data = [
        {'ip': '192.168.1.1', 'mac': 'AA:BB:CC:DD:EE:FF'},
        {'ip': '192.168.1.2', 'mac': '11:22:33:44:55:66'}
    ]
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".csv") as tmp:
        filepath = tmp.name
    
    try:
        export_csv(data, filepath)
        
        with open(filepath, 'r') as f:
            content = f.read()
            assert "ip,mac" in content
            assert "192.168.1.1,AA:BB:CC:DD:EE:FF" in content
            assert "192.168.1.2,11:22:33:44:55:66" in content

    finally:
        os.remove(filepath)

def test_export_csv_empty_data():
    """Prueba que se lance un ValueError si los datos están vacíos."""
    with pytest.raises(ValueError):
        export_csv([], "test.csv")

@patch("builtins.open", new_callable=mock_open)
def test_export_csv_io_error(mock_file):
    """Prueba que se maneje un IOError al escribir el archivo."""
    mock_file.side_effect = IOError("Permission denied")
    data = [{'ip': '1.1.1.1'}]
    with pytest.raises(IOError):
        export_csv(data, "/root/no_permission.csv")

