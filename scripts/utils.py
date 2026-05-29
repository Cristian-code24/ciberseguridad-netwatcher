import csv
import ipaddress
import socket
import subprocess
import sys
from typing import Callable, Optional


OUI_DB = {
    "00:03:93": "Apple Inc.",
    "00:0A:27": "Apple Inc.",
    "00:0A:95": "Apple Inc.",
    "00:11:24": "Apple Inc.",
    "00:14:51": "Apple Inc.",
    "00:16:CB": "Apple Inc.",
    "00:17:F2": "Apple Inc.",
    "00:19:E3": "Apple Inc.",
    "00:1B:63": "Apple Inc.",
    "00:1C:B3": "Apple Inc.",
    "00:1D:4F": "Apple Inc.",
    "00:1E:52": "Apple Inc.",
    "00:1F:5B": "Apple Inc.",
    "00:21:E9": "Apple Inc.",
    "00:23:12": "Apple Inc.",
    "00:23:32": "Apple Inc.",
    "00:25:00": "Apple Inc.",
    "00:25:4B": "Apple Inc.",
    "00:07:AB": "Samsung Electronics",
    "00:12:47": "Samsung Electronics",
    "00:15:99": "Samsung Electronics",
    "00:16:32": "Samsung Electronics",
    "00:16:6B": "Samsung Electronics",
    "00:17:C9": "Samsung Electronics",
    "00:18:AF": "Samsung Electronics",
    "00:1A:8A": "Samsung Electronics",
    "00:1B:98": "Samsung Electronics",
    "00:1C:43": "Samsung Electronics",
    "00:1D:25": "Samsung Electronics",
    "00:1F:CC": "Samsung Electronics",
    "00:21:19": "Samsung Electronics",
    "70:F9:27": "Samsung Electronics",
    "8C:77:12": "Samsung Electronics",
    "D0:22:BE": "Samsung Electronics",
    "00:0C:29": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "00:05:69": "VMware, Inc.",
    "00:00:0C": "Cisco Systems",
    "00:1A:A1": "Cisco Systems",
    "00:1C:42": "Cisco Systems",
    "00:1E:13": "Cisco Systems",
    "00:1F:26": "Cisco Systems",
    "00:22:55": "Cisco Systems",
    "00:23:EA": "Cisco Systems",
    "00:24:14": "Cisco Systems",
    "00:25:45": "Cisco Systems",
    "58:F3:9C": "Cisco Systems",
    "70:10:5C": "Cisco Systems",
    "F8:72:EA": "Cisco Systems",
    "00:02:B3": "Intel Corporation",
    "00:07:E9": "Intel Corporation",
    "00:08:02": "Intel Corporation",
    "00:12:F0": "Intel Corporation",
    "00:13:E8": "Intel Corporation",
    "00:15:00": "Intel Corporation",
    "00:16:76": "Intel Corporation",
    "00:18:DE": "Intel Corporation",
    "00:19:D1": "Intel Corporation",
    "00:1B:21": "Intel Corporation",
    "00:1C:BF": "Intel Corporation",
    "00:1D:E0": "Intel Corporation",
    "00:1E:64": "Intel Corporation",
    "00:21:6A": "Intel Corporation",
    "00:22:FB": "Intel Corporation",
    "00:24:D7": "Intel Corporation",
    "8C:8D:28": "Intel Corporation",
    "A4:C3:F0": "Intel Corporation",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Ltd",
    "E4:5F:01": "Raspberry Pi Ltd",
    "28:CD:C1": "Raspberry Pi Ltd",
    "14:CC:20": "TP-Link Technologies",
    "50:C7:BF": "TP-Link Technologies",
    "54:AF:97": "TP-Link Technologies",
    "64:70:02": "TP-Link Technologies",
    "70:4F:57": "TP-Link Technologies",
    "74:DA:38": "TP-Link Technologies",
    "80:EA:96": "TP-Link Technologies",
    "90:F6:52": "TP-Link Technologies",
    "A0:F3:C1": "TP-Link Technologies",
    "C4:E9:84": "TP-Link Technologies",
    "D8:07:B6": "TP-Link Technologies",
    "E8:DE:27": "TP-Link Technologies",
    "00:09:5B": "NETGEAR",
    "00:0F:B5": "NETGEAR",
    "00:14:6C": "NETGEAR",
    "00:18:4D": "NETGEAR",
    "00:1B:2F": "NETGEAR",
    "00:1E:2A": "NETGEAR",
    "00:22:3F": "NETGEAR",
    "00:24:B2": "NETGEAR",
    "20:4E:7F": "NETGEAR",
    "28:C6:8E": "NETGEAR",
    "30:46:9A": "NETGEAR",
    "44:94:FC": "NETGEAR",
    "00:0C:6E": "ASUSTek Computer",
    "00:0E:A6": "ASUSTek Computer",
    "00:11:2F": "ASUSTek Computer",
    "00:13:D4": "ASUSTek Computer",
    "00:15:F2": "ASUSTek Computer",
    "00:17:31": "ASUSTek Computer",
    "00:1A:92": "ASUSTek Computer",
    "00:1D:60": "ASUSTek Computer",
    "00:1E:8C": "ASUSTek Computer",
    "00:22:15": "ASUSTek Computer",
    "04:D4:C4": "ASUSTek Computer",
    "08:60:6E": "ASUSTek Computer",
    "00:08:74": "Dell Technologies",
    "00:0B:DB": "Dell Technologies",
    "00:0D:56": "Dell Technologies",
    "00:11:43": "Dell Technologies",
    "00:13:72": "Dell Technologies",
    "00:14:22": "Dell Technologies",
    "00:15:C5": "Dell Technologies",
    "00:18:8B": "Dell Technologies",
    "00:19:B9": "Dell Technologies",
    "00:1C:23": "Dell Technologies",
    "18:66:DA": "Dell Technologies",
    "F8:DB:88": "Dell Technologies",
    "00:18:82": "Huawei Technologies",
    "00:1E:10": "Huawei Technologies",
    "00:25:9E": "Huawei Technologies",
    "28:6E:D4": "Huawei Technologies",
    "3C:F8:08": "Huawei Technologies",
    "48:46:FB": "Huawei Technologies",
    "54:89:98": "Huawei Technologies",
    "58:2A:F7": "Huawei Technologies",
    "5C:C3:07": "Huawei Technologies",
    "60:DE:44": "Huawei Technologies",
    "68:A0:F6": "Huawei Technologies",
    "70:72:CF": "Huawei Technologies",
    "00:12:5A": "Microsoft Corporation",
    "00:15:5D": "Microsoft Corporation",
    "00:17:FA": "Microsoft Corporation",
    "00:1D:D8": "Microsoft Corporation",
    "00:22:48": "Microsoft Corporation",
    "00:50:F2": "Microsoft Corporation",
    "28:18:78": "Microsoft Corporation",
    "7C:1E:52": "Microsoft Corporation",
    "00:0A:57": "Hewlett Packard",
    "00:0B:CD": "Hewlett Packard",
    "00:0D:9D": "Hewlett Packard",
    "00:11:0A": "Hewlett Packard",
    "00:14:38": "Hewlett Packard",
    "00:15:60": "Hewlett Packard",
    "00:17:08": "Hewlett Packard",
    "00:18:71": "Hewlett Packard",
    "00:1C:C4": "Hewlett Packard",
    "3C:D9:2B": "Hewlett Packard",
    "9C:8E:99": "Hewlett Packard",
    "FC:15:B4": "Hewlett Packard",
    "08:00:27": "Oracle Corporation",
    "00:03:BA": "Oracle Corporation",
    "08:00:20": "Oracle Corporation",
    "3C:5A:B4": "Google LLC",
    "54:60:09": "Google LLC",
    "F4:F5:D8": "Google LLC",
    "AC:67:B2": "Google LLC",
    "00:1A:11": "Google LLC",
    "40:B4:CD": "Amazon Technologies",
    "44:65:0D": "Amazon Technologies",
    "68:37:E9": "Amazon Technologies",
    "74:75:48": "Amazon Technologies",
    "A0:02:DC": "Amazon Technologies",
    "FC:A1:83": "Amazon Technologies",
    "00:9E:C8": "Xiaomi Communications",
    "0C:1D:AF": "Xiaomi Communications",
    "28:6C:07": "Xiaomi Communications",
    "34:80:B3": "Xiaomi Communications",
    "58:44:98": "Xiaomi Communications",
    "64:B4:73": "Xiaomi Communications",
    "F8:A4:5F": "Xiaomi Communications",
    "FC:64:BA": "Xiaomi Communications",
    "00:1A:6B": "Lenovo Group Limited",
    "6C:40:08": "Lenovo Group Limited",
    "88:70:8C": "Lenovo Group Limited",
    "C8:5B:76": "Lenovo Group Limited",
    "00:01:4A": "Sony Corporation",
    "00:04:1F": "Sony Corporation",
    "00:13:A9": "Sony Corporation",
    "00:19:4E": "Sony Corporation",
    "00:1D:BA": "Sony Corporation",
    "04:98:F3": "Sony Corporation",
    "00:1E:75": "LG Electronics",
    "20:16:D8": "LG Electronics",
    "40:B0:FA": "LG Electronics",
    "78:5D:C8": "LG Electronics",
    "00:15:6D": "Ubiquiti Networks",
    "00:27:22": "Ubiquiti Networks",
    "04:18:D6": "Ubiquiti Networks",
    "24:A4:3C": "Ubiquiti Networks",
    "44:D9:E7": "Ubiquiti Networks",
    "68:72:51": "Ubiquiti Networks",
    "78:8A:20": "Ubiquiti Networks",
    "DC:9F:DB": "Ubiquiti Networks",
    "F0:9F:C2": "Ubiquiti Networks",
    "FC:EC:DA": "Ubiquiti Networks",
    "00:05:5D": "D-Link Corporation",
    "00:0D:88": "D-Link Corporation",
    "00:0F:3D": "D-Link Corporation",
    "00:11:95": "D-Link Corporation",
    "00:13:46": "D-Link Corporation",
    "00:15:E9": "D-Link Corporation",
    "00:17:9A": "D-Link Corporation",
    "00:19:5B": "D-Link Corporation",
    "00:1B:11": "D-Link Corporation",
    "00:1C:F0": "D-Link Corporation",
    "00:1E:58": "D-Link Corporation",
    "1C:7E:E5": "D-Link Corporation",
}

PORT_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    514: "Syslog",
    515: "LPD",
    587: "SMTP-Sub",
    631: "IPP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle-DB",
    1723: "PPTP",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2222: "SSH-Alt",
    2375: "Docker",
    2376: "Docker-TLS",
    3000: "Dev-HTTP",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4444: "Metasploit",
    4848: "GlassFish",
    5432: "PostgreSQL",
    5900: "VNC",
    5901: "VNC-1",
    6379: "Redis",
    6443: "Kubernetes",
    7070: "HTTP-Alt",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8081: "HTTP-Alt2",
    8443: "HTTPS-Alt",
    8888: "Jupyter",
    9000: "PHP-FPM",
    9090: "Prometheus",
    9200: "Elasticsearch",
    9300: "ES-Cluster",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB-shard",
    50000: "SAP",
}

HIGH_RISK_PORTS = {
    23, 135, 137, 138, 139, 445, 1433, 2375, 3389,
    4444, 5432, 5900, 6379, 11211, 27017, 27018,
}
MEDIUM_RISK_PORTS = {
    21, 25, 80, 110, 143, 161, 389, 515, 1080,
    2049, 2082, 2083, 3306, 4848, 8080, 8888, 9200,
}

SECURITY_HINTS = {
    23: {
        "severity": "critical",
        "msg": "Telnet: Transmite datos en texto plano. Reemplaza con SSH."
    },
    21: {
        "severity": "high",
        "msg": "FTP: Credenciales sin cifrar. Usa SFTP o FTPS."
    },
    135: {
        "severity": "high",
        "msg": "MS-RPC: Vector de ataque común en sistemas Windows."
    },
    139: {
        "severity": "high",
        "msg": "NetBIOS: Protocolo antiguo, deshabilita si no es necesario."
    },
    445: {
        "severity": "critical",
        "msg": "SMB: Vulnerable a EternalBlue (MS17-010) / WannaCry."
    },
    3389: {
        "severity": "high",
        "msg": "RDP: Potencialmente vulnerable a BlueKeep (CVE-2019-0708)."
    },
    6379: {
        "severity": "critical",
        "msg": "Redis: Frecuentemente mal configurado sin autenticación."
    },
    27017: {
        "severity": "critical",
        "msg": "MongoDB: Frecuentemente mal configurado sin autenticación."
    },
    11211: {
        "severity": "critical",
        "msg": "Memcached: Puede usarse para ataques de amplificación DDoS."
    },
    4444: {
        "severity": "critical",
        "msg": "Puerto común de Metasploit/malware. ¡Posible backdoor activo!"
    },
    2375: {
        "severity": "critical",
        "msg": "Docker API sin TLS: Acceso completo a contenedores posible."
    },
    5900: {
        "severity": "high",
        "msg": "VNC: Asegúrate de tener contraseña fuerte configurada."
    },
    1433: {
        "severity": "high",
        "msg": "MSSQL: Base de datos expuesta. Restringe acceso externo."
    },
    5432: {
        "severity": "high",
        "msg": "PostgreSQL: Base de datos expuesta. Restringe acceso externo."
    },
    3306: {
        "severity": "medium",
        "msg": "MySQL: Base de datos expuesta. Asegura con firewall."
    },
    9200: {
        "severity": "high",
        "msg": "Elasticsearch: A menudo expuesto sin autenticación."
    },
    25: {
        "severity": "medium",
        "msg": "SMTP: Puede usarse para spam relay si no se configura bien."
    },
    8888: {
        "severity": "medium",
        "msg": "Jupyter Notebook: Acceso a código Python sin autenticación."
    },
}


def validate_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def vendor_lookup(mac: str) -> str:
    if not isinstance(mac, str):
        return "Desconocido"
    oui = mac.upper().replace("-", ":")[:8]
    return OUI_DB.get(oui, "Desconocido")


def get_service_name(port: int) -> str:
    return PORT_SERVICES.get(port, "Unknown")


def assess_risk(ports: list) -> dict:
    ports_set = set(ports)
    high = list(ports_set & HIGH_RISK_PORTS)
    medium = list(ports_set & MEDIUM_RISK_PORTS)

    if high:
        level = "HIGH"
    elif medium:
        level = "MEDIUM"
    elif ports:
        level = "LOW"
    else:
        level = "SAFE"

    hints = []
    for port in ports_set:
        if port in SECURITY_HINTS:
            hints.append({"port": port, **SECURITY_HINTS[port]})

    return {
        "level": level,
        "high_risk_ports": high,
        "medium_risk_ports": medium,
        "hints": hints,
    }


def reverse_dns(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return "N/A"


def detect_local_cidr() -> Optional[str]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(network)
    except Exception:
        return None


def run_arp_scan(cidr: str, callback: Optional[Callable] = None) -> list:
    if not validate_cidr(cidr):
        raise ValueError(f"Rango CIDR inválido: '{cidr}'. Ejemplo válido: 192.168.1.0/24")

    try:
        from scapy.all import arping
    except ImportError:
        raise ImportError(
            "Scapy no está instalado. Ejecuta: pip install scapy"
        )

    try:
        ans, _ = arping(cidr, verbose=0)
        hosts = []
        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc
            hostname = reverse_dns(ip)
            vendor = vendor_lookup(mac)
            host = {"ip": ip, "mac": mac, "hostname": hostname, "vendor": vendor}
            hosts.append(host)
            if callback:
                callback(host)
        return hosts
    except Exception as e:
        raise Exception(f"Fallo en el escaneo ARP: {e}")


def nmap_scan(ip: str, port_range: str = "1-1024") -> list:
    try:
        import nmap
        scanner = nmap.PortScanner()
    except ImportError:
        return _nmap_scan_subprocess(ip, port_range)

    try:
        scanner.scan(ip, port_range, arguments="-T4")
        open_ports = []
        if ip in scanner.all_hosts() and "tcp" in scanner[ip]:
            open_ports = list(scanner[ip]["tcp"].keys())
        return open_ports
    except Exception as e:
        print(f"python-nmap falló ({e}), intentando con subprocess...", file=sys.stderr)
        return _nmap_scan_subprocess(ip, port_range)


def _nmap_scan_subprocess(ip: str, port_range: str) -> list:
    try:
        command = ["nmap", "-p", port_range, "-T4", "-oG", "-", ip]
        result = subprocess.run(
            command, capture_output=True, text=True, check=True, timeout=180
        )

        open_ports = []
        for line in result.stdout.splitlines():
            if "Ports:" in line and "Status: Open" not in line:
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


def export_csv(data: list, filepath: str) -> None:
    if not data:
        raise ValueError("La lista de datos para exportar no puede estar vacía.")

    headers = data[0].keys()
    try:
        with open(filepath, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()
            writer.writerows(data)
    except IOError as e:
        raise IOError(f"No se pudo escribir en el archivo {filepath}: {e}")
