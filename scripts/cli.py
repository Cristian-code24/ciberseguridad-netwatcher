import argparse
import json
import os
import sys

if os.name == "nt":
    import ctypes

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.utils import run_arp_scan, nmap_scan, export_csv  # noqa: E402


def check_permissions():
    try:
        if os.name == "nt":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def handle_arp_scan(args):
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
    print(f"Iniciando escaneo Nmap en {args.ip} para los puertos {args.ports}...")
    try:
        results = nmap_scan(args.ip, port_range=args.ports)
        output = {"ip": args.ip, "open_ports": results}
        print(json.dumps(output, indent=2))
    except Exception as e:
        print(f"Ocurrió un error durante el escaneo Nmap: {e}")
        sys.exit(1)


def handle_export(args):
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
    parser = argparse.ArgumentParser(
        description="NetWatcher CLI - Herramienta de escaneo de red.",
        epilog="Recuerda ejecutar 'scan-arp' como administrador.",
    )
    subparsers = parser.add_subparsers(
        dest="command", required=True, help="Subcomandos disponibles"
    )

    parser_arp = subparsers.add_parser(
        "scan-arp", help="Realiza un escaneo ARP para descubrir hosts."
    )
    parser_arp.add_argument(
        "--cidr",
        required=True,
        help="El rango de red en formato CIDR (ej. 192.168.1.0/24).",
    )
    parser_arp.set_defaults(func=handle_arp_scan)

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
