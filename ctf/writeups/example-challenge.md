Writeup de Ejemplo: "Descubrimiento de Servicios" (CTF Básico)
Este documento es un ejemplo de cómo se podría usar NetWatcher en las primeras etapas de un desafío de Capture The Flag (CTF).

Descripción del Desafío
Nombre: "First Contact"
Objetivo: Encontrar un servicio web oculto en un servidor de la red del CTF y obtener la primera bandera.
Red: Se nos proporciona acceso a la red 10.10.10.0/24.

Paso 1: Reconocimiento Inicial con NetWatcher (GUI)
El primer paso en cualquier CTF de red es el reconocimiento: averiguar qué máquinas están activas.

Lanzamos NetWatcher con sudo:

sudo python3 scripts/netwatcher.py

Configuramos el escaneo:

En el campo "Rango de Red (CIDR)", introducimos la red del desafío: 10.10.10.0/24.

Hacemos clic en el botón "Scan ARP".

Análisis de Resultados ARP:
NetWatcher escanea la red y la tabla de resultados se llena. Observamos varios hosts, pero uno parece ser nuestro objetivo principal:

IP

MAC

Hostname

Vendor

Puertos Abiertos

10.10.10.1

00:0C:29:..:..:..

gateway

VMware, Inc.



10.10.10.137

08:00:27:..:..:..

target.ctf

Oracle Corporation



...

...

...

...



El host 10.10.10.137 con el hostname target.ctf parece prometedor.

Paso 2: Escaneo de Puertos con NetWatcher
Ahora que hemos identificado nuestro objetivo, necesitamos saber qué servicios está ejecutando.

Seleccionamos el objetivo: En la tabla de NetWatcher, hacemos clic en la fila correspondiente a 10.10.10.137.

Iniciamos el escaneo de puertos:

Hacemos clic en el botón "Nmap Quick Scan".

Análisis de Puertos Abiertos:
Después de unos segundos, la columna "Puertos Abiertos" se actualiza.

IP

MAC

Hostname

Vendor

Puertos Abiertos

...

...

...

...



10.10.10.137

08:00:27:..:..:..

target.ctf

Oracle Corporation

22, 80, 8080

...

...

...

...



El escaneo rápido nos revela tres puertos abiertos:

Puerto 22: Probablemente SSH (acceso por shell).

Puerto 80: Servidor web HTTP estándar.

Puerto 8080: Otro puerto comúnmente usado para servicios web alternativos o de desarrollo.

Paso 3: Exploración Manual y Obtención de la Bandera
Con la información obtenida, ahora podemos investigar estos servicios.

Investigamos el puerto 80:

Abrimos un navegador web y vamos a http://10.10.10.137.

Nos encontramos con una página de Apache por defecto. "Página en construcción". Parece un callejón sin salida.

Investigamos el puerto 8080:

En el navegador, vamos a http://10.10.10.137:8080.

¡Éxito! Encontramos una página simple que dice: "Bienvenido al panel de administración. Aquí está tu bandera:"

Bandera: flag{n3tw4tch3r_d1sc0v3ry_p0w3r}

Conclusión
NetWatcher nos permitió realizar de manera rápida y eficiente las fases iniciales de reconocimiento y enumeración. La combinación del escaneo ARP para descubrir el host y el escaneo Nmap para identificar los servicios abiertos fue clave para resolver este desafío.

Para un análisis más profundo en un escenario más complejo, podríamos haber usado la CLI de NetWatcher o directamente Nmap con opciones más avanzadas, como la detección de versiones (-sV) o la ejecución de scripts (-sC).