Arquitectura de NetWatcher
Este documento describe la arquitectura y el flujo de datos de la aplicación NetWatcher. El diseño se centra en la separación de responsabilidades para facilitar el mantenimiento, las pruebas y la extensibilidad.

Componentes Principales
El proyecto se divide en tres capas lógicas principales:

Capa de Presentación (Interfaz): Responsable de la interacción con el usuario.

Capa de Lógica de Negocio (Utilidades): Contiene el núcleo funcional de la aplicación.

Capa de Acceso a Datos/Red (Librerías Externas): Interactúa directamente con la red y las herramientas del sistema.

Diagrama de Flujo de Datos
+------------------+        +-------------------+        +---------------------+
|      Usuario     |        |      Usuario      |        |       Usuario       |
+--------+---------+        +---------+---------+        +----------+----------+
         |                            |                             |
         v                            v                             v
+------------------+        +-------------------+
| GUI (netwatcher.py)|        | CLI (cli.py)      |
|  (PySimpleGUI)   |        |   (argparse)      |
+--------+---------+        +---------+---------+
         |                            |
         +-------------+--------------+
                       |
                       v
+-------------------------------------------------+
|          Capa de Lógica (utils.py)              |
|                                                 |
| - run_arp_scan()                                |
| - nmap_scan()                                   |
| - reverse_dns(), vendor_lookup()                |
| - export_csv()                                  |
+----------------------+--------------------------+
                       |
         +-------------+-------------+
         |                           |
         v                           v
+-----------------+           +-----------------+
|  Scapy          |           |  Nmap           |
| (Paquetes ARP)  |           | (Escaneo Puertos)|
+-----------------+           +-----------------+

1. Capa de Presentación
Esta capa está compuesta por dos puntos de entrada principales para el usuario:

scripts/netwatcher.py (GUI):

Utiliza la librería PySimpleGUI para crear una interfaz gráfica de usuario intuitiva.

Maneja los eventos del usuario (clics en botones, selección en tablas).

Para operaciones de larga duración como los escaneos, crea hilos (threading) para no bloquear la interfaz. Esto mantiene la aplicación receptiva.

Comunica los resultados de los hilos de vuelta a la ventana principal mediante un sistema de eventos de PySimpleGUI (window.write_event_value).

Llama a las funciones de la capa de lógica (utils.py) para ejecutar las acciones.

scripts/cli.py (CLI):

Utiliza el módulo argparse de Python para definir y parsear argumentos de la línea de comandos.

Proporciona subcomandos (scan-arp, scan-nmap) para diferentes funcionalidades.

Invoca directamente las funciones de utils.py y muestra los resultados en la consola, generalmente en formato JSON para facilitar el scripting.

2. Capa de Lógica de Negocio (scripts/utils.py)
Este es el cerebro de la aplicación. Contiene toda la lógica reutilizable y es completamente independiente de la interfaz de usuario.

run_arp_scan(cidr): Orquesta el escaneo ARP. Llama a Scapy, procesa los resultados y los enriquece con información de reverse_dns() y vendor_lookup().

nmap_scan(ip, ports): Maneja el escaneo de puertos. Intenta usar la librería python-nmap. Si no está disponible o falla, tiene un mecanismo de fallback que llama al ejecutable de nmap directamente a través del módulo subprocess, parseando su salida.

Funciones de Apoyo:

reverse_dns(ip): Realiza una consulta de DNS inversa.

vendor_lookup(mac): Busca el fabricante a partir de una dirección MAC.

export_csv(): Maneja la lógica para guardar datos en un archivo CSV.

La separación de esta lógica permite:

Probarla de forma aislada: Las pruebas unitarias en tests/test_utils.py pueden verificar cada función sin necesidad de una GUI o una CLI.

Reutilizarla: Tanto la GUI como la CLI usan exactamente las mismas funciones, garantizando un comportamiento consistente.

3. Capa de Acceso a Datos/Red
Esta capa consiste en las librerías y herramientas externas que realizan el trabajo a bajo nivel:

Scapy: Utilizada para construir y enviar paquetes ARP personalizados. Esta es la razón por la que se requieren privilegios de root.

Nmap: La herramienta estándar de la industria para el escaneo de puertos. NetWatcher la utiliza como su motor de escaneo, ya sea a través de un wrapper de Python (python-nmap) o directamente.

Módulo socket: Utilizado para operaciones de red básicas como la resolución de DNS inversa.