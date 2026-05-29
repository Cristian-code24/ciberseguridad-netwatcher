# NetWatcher 🛡️

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Educational](https://img.shields.io/badge/Purpose-Educational-orange)]()

> **Herramienta educativa de ciberseguridad** para descubrir dispositivos en redes locales y analizar puertos. Diseñada para aprender conceptos de redes y seguridad en un entorno controlado y legal.

---

> [!CAUTION]
> **Solo para fines educativos.** Usar esta herramienta en redes para las que no tienes permiso explícito es **ilegal**. El autor no se responsabiliza del mal uso.

---

## ✨ Características

| Función | Descripción |
|---|---|
| 🌐 **Escaneo ARP** | Descubre dispositivos activos en tu red local con Scapy |
| 🔬 **Escaneo de Puertos** | Analiza puertos con Nmap (1-1024 o rango personalizado) |
| 🎨 **Dashboard Web** | Interfaz premium oscura con actualizaciones en tiempo real (SSE) |
| 🏭 **Identificación de Vendor** | Base de datos OUI con +200 fabricantes |
| ⚠️ **Evaluación de Riesgo** | Clasifica hosts en ALTO / MEDIO / BAJO / SEGURO |
| 💡 **Pistas de Seguridad** | Alertas educativas para puertos peligrosos |
| 💾 **Exportación** | CSV y JSON con un clic |
| 💻 **CLI** | Interfaz de línea de comandos para scripting |

---

## 📋 Requisitos

- **Python** 3.11+
- **Nmap** instalado en el sistema
- **Privilegios de administrador** para escaneo ARP

### Sistema operativo
- **Linux/macOS**: Recomendado (Kali Linux ideal)
- **Windows**: Compatible, requiere [Npcap](https://npcap.com/) para Scapy

---

## 🚀 Instalación

```bash
# 1. Clonar el repositorio
git clone https://github.com/Cristian-code24/ciberseguridad-netwatcher.git
cd ciberseguridad-netwatcher

# 2. Crear entorno virtual
python3 -m venv venv
source venv/bin/activate    # Linux/macOS
# venv\Scripts\activate     # Windows

# 3. Instalar dependencias
pip install -r requirements.txt

# 4. Instalar Nmap (si no está instalado)
# Linux:
sudo apt install nmap -y
# macOS:
brew install nmap
```

---

## 💻 Uso

### 🌐 Dashboard Web (Recomendado)

```bash
# Requiere privilegios de administrador para escaneo ARP
sudo python3 app.py
```

Luego abre **http://localhost:5000** en tu navegador.

**Funcionalidades del dashboard:**
- **Auto-detectar CIDR**: detecta automáticamente tu rango de red
- **Presets rápidos**: 192.168.0.x, 192.168.1.x, 10.0.0.x, etc.
- **Escaneo en tiempo real**: los hosts aparecen conforme se descubren
- **Evaluación de riesgo**: código de colores por nivel de riesgo
- **Panel de detalles**: haz clic en un host para ver sus puertos
- **Exportar CSV/JSON**: descarga los resultados con un clic
- **Log de actividad**: rastrea todas las acciones en tiempo real

### 🖥️ GUI Legada (PySimpleGUI)

```bash
sudo python3 scripts/netwatcher.py
```

### ⌨️ CLI

```bash
# Ayuda general
python3 scripts/cli.py --help

# Escaneo ARP (requiere sudo)
sudo python3 scripts/cli.py scan-arp --cidr 192.168.1.0/24

# Escaneo de puertos
python3 scripts/cli.py scan-nmap --ip 192.168.1.1 --ports 1-1024

# Exportar resultados
python3 scripts/cli.py export --file resultados.csv
```

---

## 🔐 Permisos

El escaneo ARP usa Scapy para enviar paquetes a bajo nivel, lo que requiere **privilegios de root/administrador**.

```bash
# Linux/macOS
sudo python3 app.py

# Windows (PowerShell como Administrador)
python app.py
```

> El escaneo Nmap generalmente **no** requiere sudo para escaneos TCP básicos.

---

## 🏗️ Arquitectura

```
netwatcher/
├── app.py              # 🌐 Flask web app (entrada principal)
├── scripts/
│   ├── utils.py        # 🧠 Lógica de negocio (ARP, Nmap, OUI, riesgo)
│   ├── netwatcher.py   # 🖥️ GUI PySimpleGUI (legada)
│   └── cli.py          # ⌨️ CLI argparse
├── templates/
│   └── index.html      # 🎨 Dashboard web
├── static/
│   ├── css/style.css   # 💅 Tema dark cyber
│   └── js/app.js       # ⚡ Frontend con SSE
├── tests/              # ✅ Pruebas unitarias
├── docs/               # 📚 Documentación técnica
└── recursos/           # 📖 Cheatsheets
```

---

## 🧪 Desarrollo

```bash
# Activar entorno virtual
source venv/bin/activate

# Ejecutar pruebas (no requieren sudo ni red activa)
pytest tests/ -v

# Linter
flake8 .
```

---

## 📚 Recursos

- [`recursos/nmap_cheatsheet.md`](recursos/nmap_cheatsheet.md) — Referencia rápida de Nmap
- [`recursos/comandos_wifi.md`](recursos/comandos_wifi.md) — Comandos WiFi útiles
- [`docs/architecture.md`](docs/architecture.md) — Arquitectura del sistema
- [`docs/privacy_and_ethics.md`](docs/privacy_and_ethics.md) — Ética y privacidad

---

## 📄 Licencia

MIT — Ver [LICENSE](LICENSE) para detalles.

---

*Creado con ❤️ por [Cristian-code24](https://github.com/Cristian-code24)*