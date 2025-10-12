# -*- coding: utf-8 -*-
"""
Pruebas Unitarias para scripts/cli.py

Se utiliza monkeypatch para interceptar y simular las llamadas a las funciones
de `utils`, permitiendo probar la lógica del parseo de argumentos y el flujo
de la CLI sin ejecutar escaneos reales.

Autor: Cristian-code24
Fecha: 2025-10-12
"""
import pytest
from unittest.mock import patch
import sys
import json

# Importar las funciones que la CLI va a llamar
from scripts import cli

# --- Pruebas para el subcomando scan-arp ---

@patch('scripts.cli.run_arp_scan')
@patch('scripts.cli.check_permissions', return_value=True)
def test_cli_scan_arp_success(mock_check_permissions, mock_run_arp_scan, capsys):
    """Prueba la ejecución exitosa de 'scan-arp' con los argumentos correctos."""
    fake_results = [{"ip": "192.168.1.1", "mac": "AA:BB:CC:00:11:22"}]
    mock_run_arp_scan.return_value = fake_results
    
    # Simular los argumentos de la línea de comandos
    sys.argv = ["cli.py", "scan-arp", "--cidr", "192.168.1.0/24"]
    
    cli.main()
    
    # Capturar la salida estándar
    captured = capsys.readouterr()
    
    # Verificar que la función de escaneo fue llamada con el CIDR correcto
    mock_run_arp_scan.assert_called_once_with("192.168.1.0/24")
    
    # Verificar que la salida JSON es correcta
    output_json = json.loads(captured.out)
    assert output_json == fake_results

@patch('scripts.cli.check_permissions', return_value=False)
def test_cli_scan_arp_no_permissions(mock_check_permissions, capsys):
    """Prueba que 'scan-arp' falle y muestre un error si no hay permisos de root."""
    sys.argv = ["cli.py", "scan-arp", "--cidr", "192.168.1.0/24"]
    
    with pytest.raises(SystemExit) as e:
        cli.main()
    
    assert e.value.code == 1 # Verificar que el código de salida es 1 (error)
    captured = capsys.readouterr()
    assert "Error: El escaneo ARP requiere privilegios de root" in captured.out

# --- Pruebas para el subcomando scan-nmap ---

@patch('scripts.cli.nmap_scan')
def test_cli_scan_nmap_success(mock_nmap_scan, capsys):
    """Prueba la ejecución exitosa de 'scan-nmap'."""
    fake_ports = [80, 443]
    mock_nmap_scan.return_value = fake_ports
    
    sys.argv = ["cli.py", "scan-nmap", "--ip", "1.1.1.1", "--ports", "80,443"]
    
    cli.main()
    
    captured = capsys.readouterr()
    mock_nmap_scan.assert_called_once_with("1.1.1.1", port_range="80,443")
    
    output_json = json.loads(captured.out)
    assert output_json == {"ip": "1.1.1.1", "open_ports": fake_ports}

@patch('scripts.cli.nmap_scan')
def test_cli_scan_nmap_default_ports(mock_nmap_scan, capsys):
    """Prueba que 'scan-nmap' use los puertos por defecto si no se especifican."""
    mock_nmap_scan.return_value = [22]
    
    sys.argv = ["cli.py", "scan-nmap", "--ip", "1.1.1.1"]
    
    cli.main()
    
    captured = capsys.readouterr()
    # Verifica que se llamó con el rango de puertos por defecto
    mock_nmap_scan.assert_called_once_with("1.1.1.1", port_range="1-1024")

# --- Pruebas para argumentos faltantes ---

def test_cli_missing_arguments(capsys):
    """Prueba que la CLI muestre un error si faltan argumentos requeridos."""
    sys.argv = ["cli.py", "scan-arp"] # Falta --cidr
    
    with pytest.raises(SystemExit):
        cli.main()
        
    captured = capsys.readouterr()
    # argparse debería imprimir un mensaje de error en stderr
    assert "the following arguments are required: --cidr" in captured.err

def test_cli_no_command(capsys):
    """Prueba que la CLI muestre un error si no se especifica un subcomando."""
    sys.argv = ["cli.py"]
    
    with pytest.raises(SystemExit):
        cli.main()
        
    captured = capsys.readouterr()
    assert "the following arguments are required: command" in captured.err
