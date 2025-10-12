# Usar una imagen base de Python delgada
FROM python:3.11-slim

# Establecer el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar los archivos de requisitos primero para aprovechar el caché de capas de Docker
COPY requirements.txt .

# Instalar las dependencias del proyecto y herramientas de sistema necesarias
# En este caso, no instalamos nmap o libpcap-dev porque los tests usan mocks
# y no necesitan hardware de red real. Esto hace la imagen más ligera.
RUN pip install --no-cache-dir -r requirements.txt

# Copiar el resto del código de la aplicación al contenedor
COPY . .

# El contenedor está diseñado para ejecutar pruebas o linting,
# por lo que no definimos un CMD o ENTRYPOINT por defecto.
# Se puede ejecutar un comando al iniciar el contenedor, por ejemplo:
#
# Para ejecutar las pruebas:
# docker build -t netwatcher-test .
# docker run --rm netwatcher-test pytest
#
# Para ejecutar el linter:
# docker run --rm netwatcher-test flake8 .
