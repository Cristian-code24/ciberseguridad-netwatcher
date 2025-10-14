# -*- coding: utf-8 -*-
"""
NetWatcher CLI - Interfaz de Línea de Comandos

Este script proporciona una interfaz de línea de comandos para interactuar
con las funciones de escaneo de NetWatcher.

Autor: Cristian-code24
Fecha: 2025-10-12
"""

# 1. Imports de la librería estándar
import argparse
import json
import os
import sys

# Importación condicional para la verificación de permisos en Windows
if os.name == "nt":
    import ctypes

# 2. Modificación del path (código ejecutable)
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 3. Imports de módulos locales
from scripts.utils import run_arp_scan, nmap_scan, export_csv


def check_permissions():
    """Verifica si el script se ejecuta con privilegios de administrador."""
    try:
        if os.name == "nt":  # Sistema operativo Windows
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        # Para Linux/macOS, el ID de usuario efectivo debe ser 0 (root)
        return os.geteuid() == 0
    except Exception:
        return False


def handle_arp_scan(args):
    """Maneja el subcomando 'scan-arp'."""
    if not check_permissions():
        print("Error: El escaneo ARP requiere privilegios de administrador.")
        sys.exit(1)

    print(f"Iniciando escaneo ARP en el rango: {args.cidr}...")
    try:
        results = run_arp_scan(args.cidr)
        print(json.dumps(results, indent=2))
    except Exception as e:
        print(f"Ocurrió un error durante el escaneo ARP: {e}")
        sys.exit(1)


def handle_nmap_scan(args):
    """Maneja el subcomando 'scan-nmap'."""
    print(f"Iniciando escaneo Nmap en {args.ip} para los puertos {args.ports}...")
    try:
        results = nmap_scan(args.ip, port_range=args.ports)
        output = {"ip": args.ip, "open_ports": results}
        print(json.dumps(output, indent=2))
    except Exception as e:
        print(f"Ocurrió un error durante el escaneo Nmap: {e}")
        sys.exit(1)


def handle_export(args):
    """Maneja el subcomando 'export' (función de ejemplo)."""
    # En un escenario real, aquí se leerían datos de un estado previo.
    # Para este ejemplo, creamos datos ficticios.
    print(f"Exportando datos de ejemplo a {args.file}...")
    sample_data = [
        {
            "IP": "192.168.1.1", "MAC": "AA:BB:CC:DD:EE:FF",
            "Hostname": "router.local", "Vendor": "Netgear",
            "Puertos Abiertos": "53, 80",
        },
        {
            "IP": "192.168.1.100", "MAC": "11:22:33:44:55:66",
            "Hostname": "mi-pc", "Vendor": "Intel",
            "Puertos Abiertos": "22",
        },
    ]
    try:
        export_csv(sample_data, args.file)
        print("Exportación completada exitosamente.")
    except Exception as e:
        print(f"Error al exportar: {e}")
        sys.exit(1)


def main():
    """Función principal que configura y parsea los argumentos de la CLI."""
    parser = argparse.ArgumentParser(
        description="NetWatcher CLI - Herramienta de escaneo de red.",
        epilog="Recuerda ejecutar 'scan-arp' como administrador.",
    )
    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Subcomandos disponibles"
    )

    # Subcomando para escaneo ARP
    parser_arp = subparsers.add_parser(
        "scan-arp", help="Realiza un escaneo ARP para descubrir hosts."
    )
    parser_arp.add_argument(
        "--cidr",
        required=True,
        help="El rango de red en formato CIDR (ej. 192.168.1.0/24).",
    )
    parser_arp.set_defaults(func=handle_arp_scan)

    # Subcomando para escaneo Nmap
    parser_nmap = subparsers.add_parser(
        "scan-nmap", help="Realiza un escaneo de puertos con Nmap."
    )
    parser_nmap.add_argument("--ip", required=True, help="La dirección IP del objetivo.")
    parser_nmap.add_argument(
        "--ports",
        default="1-1024",
        help="Rango de puertos a escanear (ej. '22,80,443' o '1-1024').",
    )
    parser_nmap.set_defaults(func=handle_nmap_scan)

    # Subcomando para exportar
    parser_export = subparsers.add_parser(
        "export", help="Exporta los resultados a un archivo CSV."
    )
    parser_export.add_argument(
        "--file",
        required=True,
        help="Nombre del archivo de salida (ej. 'resultados.csv').",
    )
    parser_export.set_defaults(func=handle_export)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
