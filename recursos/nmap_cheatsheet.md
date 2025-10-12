Nmap - Hoja de Referencia Rápida (Cheatsheet)
Nmap ("Network Mapper") es la herramienta por excelencia para la exploración de redes y auditorías de seguridad.

Escaneos Básicos
Escanear un solo objetivo:

nmap 192.168.1.1

Escanear un nombre de host:

nmap scanme.nmap.org

Escanear un rango de IPs:

nmap 192.168.1.1-100

Escanear una subred completa (CIDR):

nmap 192.168.1.0/24

Escanear desde un archivo de objetivos:

nmap -iL lista_de_ips.txt

Descubrimiento de Hosts (Ping Scan)
Deshabilitar el sondeo de puertos (solo descubrir hosts):

nmap -sn 192.168.1.0/24

Útil para ver rápidamente qué hosts están activos.

No hacer ping (asumir que todos los hosts están activos):

nmap -Pn 192.168.1.1

Útil si el objetivo bloquea los pings ICMP.

Técnicas de Escaneo de Puertos
Escaneo TCP SYN (por defecto con sudo):
Rápido y sigiloso.

sudo nmap -sS 192.168.1.1

Escaneo TCP Connect (por defecto sin sudo):
Más lento y ruidoso, pero no requiere privilegios.

nmap -sT 192.168.1.1

Escaneo UDP:
Lento, pero necesario para encontrar servicios UDP abiertos.

sudo nmap -sU 192.168.1.1

Especificación de Puertos
Escanear un puerto específico:

nmap -p 80 192.168.1.1

Escanear un rango de puertos:

nmap -p 1-1000 192.168.1.1

Escanear puertos por nombre:

nmap -p http,https 192.168.1.1

Escanear los N puertos más comunes (rápido):

nmap --top-ports 100 192.168.1.1

Escanear todos los 65535 puertos:

nmap -p- 192.168.1.1

Detección de Versiones y OS
Detección de Sistema Operativo, Versión de Servicios y Traceroute:

nmap -A 192.168.1.1

Detección de Versión de Servicios:

nmap -sV 192.168.1.1

Detección de Sistema Operativo (requiere sudo):

sudo nmap -O 192.168.1.1

Control de Tiempos y Rendimiento
Plantillas de tiempo (T0 a T5):
T0 (paranoico, muy lento), T4 (agresivo, rápido), T5 (insano, muy rápido).

nmap -T4 192.168.1.1

Scripts (NSE - Nmap Scripting Engine)
Ejecutar scripts por defecto:

nmap -sC 192.168.1.1

Ejecutar scripts de la categoría "vuln":

nmap --script vuln 192.168.1.1

Obtener ayuda sobre un script:

nmap --script-help "http-*"

Formatos de Salida
Guardar en todos los formatos (Normal, Grepable, XML):

nmap -oA resultados_scan 192.168.1.1

Crea resultados_scan.nmap, resultados_scan.gnmap, y resultados_scan.xml.

Salida Grepable (útil para scripting):

nmap -oG resultados.gnmap 192.168.1.1
