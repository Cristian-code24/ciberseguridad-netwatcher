NetWatcher - Herramienta Educativa de Escaneo de Red
NetWatcher es una herramienta educativa de ciberseguridad desarrollada en Python para escanear dispositivos en una red local (escaneo ARP) y ejecutar análisis de puertos básicos con Nmap. Ofrece tanto una Interfaz Gráfica de Usuario (GUI) como una Interfaz de Línea de Comandos (CLI) para adaptarse a diferentes niveles de habilidad.

Propósito Principal: Facilitar el aprendizaje práctico de conceptos de redes y seguridad en un entorno controlado y legal.

ADVERTENCIA LEGAL: Esta herramienta está diseñada únicamente para fines educativos. Usarla en redes para las que no tienes permiso explícito es ilegal y poco ético. El autor no se hace responsable del mal uso de este software.

Tabla de Contenidos
Características Principales

Requisitos Previos

Instalación

Uso de la Herramienta

Interfaz Gráfica (GUI)

Línea de Comandos (CLI)

Permisos de Ejecución

Desarrollo y Pruebas

Subir a GitHub

Licencia

Características Principales
Escaneo ARP: Descubre dispositivos activos en tu red local usando Scapy.

Escaneo de Puertos: Realiza un escaneo rápido de los puertos más comunes (1-1024) en un objetivo específico usando Nmap.

Interfaz Dual: Utiliza la GUI amigable construida con PySimpleGUI o la CLI para automatización y scripting.

Detección de Fabricante: Identifica el fabricante de la tarjeta de red a partir de la dirección MAC.

Exportación de Resultados: Guarda los resultados del escaneo en formato CSV.

Educativo: Código claro y comentado, acompañado de documentación sobre arquitectura y ética.

Requisitos Previos
Sistema Operativo: Diseñado para Kali Linux o distribuciones similares de Linux. Puede funcionar en otros sistemas, pero podría requerir ajustes.

Python: Versión 3.11 o superior.

Nmap: Debe estar instalado en tu sistema.

sudo apt update && sudo apt install nmap -y

Librerías de Desarrollo: Necesarias para compilar algunas dependencias.

sudo apt install python3-dev libpcap-dev -y

Instalación
Sigue estos pasos para configurar el entorno y las dependencias del proyecto.

Clona el repositorio (o descomprime los archivos):

git clone [https://github.com/Cristian-code24/ciberseguridad-netwatcher.git](https://github.com/Cristian-code24/ciberseguridad-netwatcher.git)
cd ciberseguridad-netwatcher

Crea y activa un entorno virtual:
Es una buena práctica para aislar las dependencias del proyecto.

python3 -m venv venv
source venv/bin/activate

Para desactivar el entorno, simplemente ejecuta deactivate.

Instala las dependencias:
El archivo requirements.txt contiene todas las librerías de Python necesarias.

pip install -r requirements.txt

Uso de la Herramienta
Interfaz Gráfica (GUI)
La GUI es la forma más sencilla de interactuar con NetWatcher.

IMPORTANTE: El escaneo ARP requiere privilegios de root para crear paquetes raw. Ejecútalo con sudo.

sudo python3 scripts/netwatcher.py

Funcionalidades:

Detectar CIDR: Intenta autodetectar el rango de tu red local (ej. 192.168.1.0/24).

Scan ARP: Inicia el escaneo de dispositivos en el rango CIDR especificado.

Nmap Quick Scan: Selecciona un dispositivo de la tabla y haz clic en este botón para escanear sus puertos (1-1024).

Exportar a CSV: Guarda los resultados visibles en la tabla en un archivo CSV.

Detener Scan: Detiene el proceso de escaneo actual.

Línea de Comandos (CLI)
La CLI es ideal para scripting y usuarios avanzados.

# Ayuda general
python3 scripts/cli.py --help

# Escaneo ARP (requiere sudo)
sudo python3 scripts/cli.py scan-arp --cidr 192.168.1.0/24

# Escaneo Nmap
python3 scripts/cli.py scan-nmap --ip 192.168.1.1 --ports 1-1024

# Exportar el último resultado de un escaneo a un archivo (función de ejemplo)
python3 scripts/cli.py export --file mis_resultados.csv

Permisos de Ejecución
El escaneo ARP con Scapy funciona enviando paquetes ARP a bajo nivel, una operación que los sistemas operativos modernos restringen a usuarios con privilegios elevados. Por esta razón, debes ejecutar los scripts que usan esta función con sudo.

Si no se ejecuta con sudo, la aplicación te notificará que el escaneo ARP no puede continuar. El escaneo Nmap, por otro lado, generalmente no requiere sudo para escaneos TCP básicos.

Desarrollo y Pruebas
Si deseas contribuir al proyecto o simplemente verificar la integridad del código, puedes ejecutar las pruebas y el linter.

Activa el entorno virtual:

source venv/bin/activate

Ejecuta el linter (Flake8):
Verifica que el código siga las guías de estilo.

flake8 .

Ejecuta las pruebas unitarias (Pytest):
Las pruebas están diseñadas para no requerir sudo ni una conexión de red activa (usan mocks).

pytest

Subir a GitHub
Si descargaste los archivos como un ZIP y quieres crear tu propio repositorio en GitHub:

Inicializa un repositorio Git local:

git init -b main

Añade todos los archivos al área de preparación:

git add .

Crea tu primer commit:

git commit -m "Initial commit: Proyecto NetWatcher"

Crea un nuevo repositorio en GitHub (ej. ciberseguridad-netwatcher).

Enlaza tu repositorio local con el remoto:
Reemplaza tu-usuario y tu-repositorio con tus datos.

git remote add origin [https://github.com/Cristian-code24/ciberseguridad-netwatcher.git](https://github.com/Cristian-code24/ciberseguridad-netwatcher.git)

Sube tus archivos a GitHub:

git push -u origin main

Licencia
Este proyecto está bajo la Licencia MIT. Consulta el archivo LICENSE para más detalles.
creado por cristian lucas:)