# -*- coding: utf-8 -*-
"""
Utilidades de NetWatcher - Lógica de Escaneo y Soporte

Este módulo contiene la lógica principal para realizar los escaneos de red
y otras funciones de apoyo, como la exportación de datos. Está diseñado
para ser independiente de la interfaz (GUI o CLI).

Autor: Cristian-code24
Fecha: 2025-10-12
"""

import csv
import subprocess
import socket
import json
import os
import sys

# --- Base de datos OUI (Organizationally Unique Identifier) simple ---
# Una base de datos real sería mucho más grande. Esto es solo para demostración.
OUI_DB = {
    "00:0C:29": "VMware, Inc.",
    "00:1C:42": "Cisco Systems, Inc",
    "00:50:56": "VMware, Inc.",
    "08:00:27": "Oracle Corporation",
    "3C:D9:2B": "Hewlett Packard",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "ASUSTek COMPUTER INC.",
}

# --- Funciones de Escaneo ---


def run_arp_scan(cidr: str) -> list:
    """
    Realiza un escaneo ARP en el rango CIDR especificado usando Scapy.
    Requiere privilegios de root.

    Args:
        cidr (str): El rango de red en notación CIDR (ej. "192.168.1.0/24").

    Returns:
        list: Una lista de diccionarios, donde cada uno representa un host encontrado.
              Ej: [{'ip': '...', 'mac': '...', 'hostname': '...', 'vendor': '...'}]

    Raises:
        ImportError: Si Scapy no está instalado.
        Exception: Si ocurre un error durante el escaneo.
    """
    try:
        from scapy.all import arping
    except ImportError:
        raise ImportError("Scapy no está instalado. Por favor, ejecuta 'pip install scapy'.")

    try:
        ans, unans = arping(cidr, verbose=0)
        hosts = []
        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc
            hostname = reverse_dns(ip)
            vendor = vendor_lookup(mac)
            hosts.append({"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor})
        return hosts
    except Exception as e:
        raise Exception(f"Fallo en el escaneo ARP: {e}")


def nmap_scan(ip: str, port_range: str = "1-1024") -> list:
    """
    Realiza un escaneo de puertos en la IP objetivo usando python-nmap o subprocess.

    Args:
        ip (str): La dirección IP del objetivo.
        port_range (str, optional): El rango de puertos a escanear. Defaults to "1-1024".

    Returns:
        list: Una lista de enteros representando los puertos abiertos.

    Raises:
        Exception: Si Nmap no se encuentra o falla.
    """
    try:
        import nmap

        scanner = nmap.PortScanner()
    except ImportError:
        # Fallback a subprocess si python-nmap no está instalado
        return _nmap_scan_subprocess(ip, port_range)

    try:
        # -T4 para un escaneo más rápido
        scanner.scan(ip, port_range, arguments="-T4")
        open_ports = []
        if ip in scanner.all_hosts() and "tcp" in scanner[ip]:
            open_ports = list(scanner[ip]["tcp"].keys())
        return open_ports
    except Exception as e:
        # Si python-nmap falla, intentar con el subprocess
        print(f"python-nmap falló ({e}), intentando con subprocess...", file=sys.stderr)
        return _nmap_scan_subprocess(ip, port_range)


def _nmap_scan_subprocess(ip: str, port_range: str) -> list:
    """Función de fallback para escanear con Nmap usando subprocess."""
    try:
        # Usamos -oG - para una salida "grepable" más fácil de parsear
        command = ["nmap", "-p", port_range, "-T4", ip, "-oG", "-"]
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=180)

        open_ports = []
        for line in result.stdout.splitlines():
            if "Ports:" in line and "Status: Open" not in line:  # Filtro para encontrar puertos abiertos
                parts = line.split("Ports: ")[1]
                ports_info = parts.split("\t")[0].strip()
                for port_info in ports_info.split(","):
                    port_str = port_info.strip().split("/")[0]
                    if port_str.isdigit():
                        open_ports.append(int(port_str))
        return open_ports

    except FileNotFoundError:
        raise Exception("Nmap no está instalado o no se encuentra en el PATH.")
    except subprocess.CalledProcessError as e:
        raise Exception(f"Nmap devolvió un error: {e.stderr}")
    except subprocess.TimeoutExpired:
        raise Exception("El escaneo Nmap excedió el tiempo límite.")


# --- Funciones de Utilidad ---


def reverse_dns(ip: str) -> str:
    """
    Intenta obtener el nombre de host (hostname) para una IP dada.

    Args:
        ip (str): La dirección IP.

    Returns:
        str: El nombre de host si se encuentra, de lo contrario "N/A".
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return "N/A"


def vendor_lookup(mac: str) -> str:
    """

    Busca el fabricante (vendor) basado en los primeros 3 bytes de la dirección MAC.
    Usa una base de datos OUI interna simple.

    Args:
        mac (str): La dirección MAC completa.

    Returns:
        str: El nombre del fabricante si se encuentra, de lo contrario "Desconocido".
    """
    if not isinstance(mac, str):
        return "Desconocido"

    # Normalizar la MAC a mayúsculas y usar ":" como separador
    oui = mac.upper().replace("-", ":")[:8]
    return OUI_DB.get(oui, "Desconocido")


def detect_local_cidr() -> str | None:
    """
    Intenta detectar el rango de red local (CIDR).
    Funciona obteniendo la IP local y asumiendo una máscara de subred /24.

    Returns:
        str | None: El CIDR detectado (ej. "192.168.1.0/24") o None si falla.
    """
    try:
        # Crea un socket para conectarse a un servidor externo (no envía datos)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()

        # Asume una máscara de subred /24, común en redes domésticas
        ip_parts = local_ip.split(".")
        network_base = ".".join(ip_parts[:3])
        return f"{network_base}.0/24"
    except Exception:
        return None


def export_csv(data: list, filepath: str):
    """
    Exporta una lista de diccionarios a un archivo CSV.

    Args:
        data (list): Lista de diccionarios con los datos.
        filepath (str): La ruta del archivo CSV de salida.

    Raises:
        ValueError: Si la lista de datos está vacía.
        IOError: Si ocurre un error al escribir el archivo.
    """
    if not data:
        raise ValueError("La lista de datos para exportar no puede estar vacía.")

    # Usar las claves del primer diccionario como encabezados
    headers = data[0].keys()

    try:
        with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data)
    except IOError as e:
        raise IOError(f"No se pudo escribir en el archivo {filepath}: {e}")
