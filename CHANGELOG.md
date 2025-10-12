Changelog
Todos los cambios notables en este proyecto serán documentados en este archivo.

El formato se basa en Keep a Changelog,
y este proyecto se adhiere al Versionamiento Semántico.

[1.0.0] - 2025-10-12
Added
Versión Inicial del Proyecto NetWatcher.

GUI (netwatcher.py):

Interfaz gráfica con PySimpleGUI para controles de escaneo.

Funcionalidad de escaneo ARP con sudo.

Funcionalidad de Nmap Quick Scan para puertos 1-1024.

Detección automática de CIDR local.

Tabla de resultados para mostrar hosts descubiertos.

Área de logs para notificaciones en tiempo real.

Exportación de resultados a formato CSV.

Hilos para escaneos para evitar el bloqueo de la GUI.

CLI (cli.py):

Interfaz de línea de comandos con argparse.

Subcomando scan-arp para descubrir hosts.

Subcomando scan-nmap para escanear puertos.

Subcomando export (ejemplo) para guardar resultados.

Utilidades (utils.py):

Lógica de escaneo ARP con Scapy.

Lógica de escaneo Nmap con python-nmap y fallback a subprocess.

Funciones auxiliares: reverse_dns, vendor_lookup y export_csv.

Testing:

Pruebas unitarias para utils.py y cli.py usando pytest.

Mocks para simular Scapy, Nmap y llamadas de red.

CI/CD:

Flujo de trabajo de GitHub Actions (python-ci.yml) para ejecutar flake8 y pytest.

Documentación:

README.md detallado con instrucciones de instalación y uso.

docs/architecture.md describiendo la estructura del proyecto.

docs/privacy_and_ethics.md con advertencias legales y éticas.

CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md.

Docker:

Dockerfile para crear un entorno de pruebas aislado.

Recursos:

recursos/nmap_cheatsheet.md y comandos_wifi.md.

Ejemplo de writeup en ctf/writeups/.