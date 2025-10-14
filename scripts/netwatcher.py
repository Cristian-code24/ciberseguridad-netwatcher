# -*- coding: utf-8 -*-
"""
NetWatcher GUI - Herramienta Educativa de Escaneo de Red

Este script lanza una interfaz gráfica de usuario (GUI) para realizar escaneos
de red de forma sencilla. Permite descubrir hosts mediante ARP y escanear
puertos básicos con Nmap.

Autor: Cristian-code24
Fecha: 2025-10-12
"""

# 1. Imports de la librería estándar
import os
import sys
import threading
if os.name == "nt":
    import ctypes

# 2. Imports de librerías de terceros
import PySimpleGUI as sg

# 3. Modificación del path y imports locales
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.utils import detect_local_cidr, export_csv, nmap_scan, run_arp_scan


# --- Constantes y Configuración ---
APP_TITLE = "NetWatcher - Escáner de Red Educativo"
TABLE_HEADINGS = ["IP", "MAC", "Hostname", "Vendor", "Puertos Abiertos"]
DEFAULT_THEME = "DarkBlue3"
LOG_LEVELS = {"INFO": "green", "WARN": "yellow", "ERROR": "red", "DEBUG": "lightblue"}


# --- Funciones de Soporte ---


def check_permissions():
    """Verifica si el script se ejecuta con privilegios de administrador."""
    try:
        if os.name == "nt":  # Sistema operativo Windows
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def log_message(window, message, level="INFO"):
    """Añade un mensaje al área de logs de la GUI con color."""
    color = LOG_LEVELS.get(level, "white")
    window["-LOG-"].print(f"[{level}] {message}", text_color=color)


def run_scan_in_thread(window, scan_function, *args):
    """
    Ejecuta una función de escaneo en un hilo separado para no bloquear la GUI.
    """
    try:
        results = scan_function(*args)
        window.write_event_value(("-SCAN-COMPLETE-", results), None)
    except Exception as e:
        window.write_event_value(("-SCAN-ERROR-", str(e)), None)


# --- Layout de la GUI ---


def create_main_window():
    """Crea y devuelve el objeto ventana principal de PySimpleGUI."""
    sg.theme(DEFAULT_THEME)

    controls_layout = [
        sg.Text("Rango de Red (CIDR):"),
        sg.Input(key="-CIDR-", size=(20, 1)),
        sg.Button("Detectar", key="-DETECT-"),
        sg.Button("Scan ARP", key="-ARP-SCAN-", button_color=("white", "green")),
        sg.Button("Nmap Quick Scan", key="-NMAP-SCAN-", disabled=True),
        sg.Button("Detener Scan", key="-STOP-", button_color=("white", "red"), disabled=True),
    ]

    table_layout = [
        sg.Table(
            values=[], headings=TABLE_HEADINGS, key="-RESULTS-",
            display_row_numbers=True, auto_size_columns=False,
            col_widths=[15, 15, 20, 20, 30], justification="left",
            enable_events=True, num_rows=15,
        )
    ]

    log_layout = [
        sg.Text("Logs y Notificaciones:"),
        sg.Multiline(
            key="-LOG-", size=(100, 8), autoscroll=True, disabled=True,
        ),
        sg.Button("Exportar a CSV", key="-EXPORT-", disabled=True),
    ]

    layout = [
        [sg.Frame("Controles de Escaneo", [controls_layout])],
        [sg.Frame("Resultados", [table_layout])],
        [sg.Frame("Actividad", [log_layout])],
    ]

    return sg.Window(APP_TITLE, layout, finalize=True)


# --- Lógica Principal de la Aplicación ---


def main():
    """Bucle principal de eventos de la aplicación."""
    if not check_permissions():
        sg.popup_error(
            "Permisos Insuficientes",
            "El escaneo ARP requiere privilegios de Administrador.\n"
            "Por favor, ejecuta el script como administrador.",
        )
        return

    window = create_main_window()
    hosts_data = []

    while True:
        event, values = window.read()
        event_key, event_data = event if isinstance(event, tuple) else (event, None)

        if event_key == sg.WIN_CLOSED:
            break

        if event_key == "-DETECT-":
            log_message(window, "Intentando detectar CIDR local...")
            cidr = detect_local_cidr()
            if cidr:
                window["-CIDR-"].update(cidr)
                log_message(window, f"CIDR detectado: {cidr}", "INFO")
            else:
                log_message(
                    window,
                    "No se pudo detectar el CIDR. Introdúcelo manualmente.",
                    "WARN",
                )

        elif event_key == "-ARP-SCAN-":
            cidr_input = values["-CIDR-"]
            if not cidr_input:
                log_message(window, "Por favor, introduce un rango CIDR.", "ERROR")
                continue

            log_message(window, f"Iniciando escaneo ARP en {cidr_input}...")
            window["-ARP-SCAN-"].update(disabled=True)
            window["-STOP-"].update(disabled=False)

            hosts_data.clear()
            window["-RESULTS-"].update(values=[])
            window["-EXPORT-"].update(disabled=True)
            window["-NMAP-SCAN-"].update(disabled=True)

            threading.Thread(
                target=run_scan_in_thread,
                args=(window, run_arp_scan, cidr_input),
                daemon=True,
            ).start()

        elif event_key == "-SCAN-COMPLETE-":
            scan_results = event_data
            log_message(window, f"Escaneo ARP completado. {len(scan_results)} hosts encontrados.", "INFO")
            hosts_data = [
                [host.get(k, "N/A") for k in ["ip", "mac", "hostname", "vendor"]] + [""]
                for host in scan_results
            ]
            window["-RESULTS-"].update(values=hosts_data)
            window["-EXPORT-"].update(disabled=not hosts_data)
            window["-ARP-SCAN-"].update(disabled=False)
            window["-STOP-"].update(disabled=True)

        elif event_key == "-SCAN-ERROR-":
            log_message(window, f"Error durante el escaneo: {event_data}", "ERROR")
            window["-ARP-SCAN-"].update(disabled=False)
            window["-STOP-"].update(disabled=True)

        elif event_key == "-RESULTS-":
            # Habilita el botón si hay filas seleccionadas, deshabilita si no.
            window["-NMAP-SCAN-"].update(disabled=not values["-RESULTS-"])

        elif event_key == "-NMAP-SCAN-":
            selected_rows = values["-RESULTS-"]
            if not selected_rows:
                log_message(window, "Selecciona un host para escanear.", "WARN")
                continue

            row_index = selected_rows[0]
            target_ip = hosts_data[row_index][0]
            log_message(window, f"Iniciando Nmap Quick Scan en {target_ip}...")
            window["-NMAP-SCAN-"].update(disabled=True)

            threading.Thread(
                target=run_scan_in_thread,
                args=(window, nmap_scan, target_ip, row_index),
                daemon=True,
            ).start()

        elif event_key == "-NMAP-COMPLETE-":
            row_index, open_ports = event_data
            target_ip = hosts_data[row_index][0]
            log_message(window, f"Escaneo Nmap para {target_ip} completado.", "INFO")
            ports_str = ", ".join(map(str, open_ports)) if open_ports else "Ninguno"
            hosts_data[row_index][4] = ports_str
            window["-RESULTS-"].update(values=hosts_data)
            window["-NMAP-SCAN-"].update(disabled=False)

        elif event_key == "-NMAP-ERROR-":
            log_message(window, f"Error en Nmap: {event_data}", "ERROR")
            window["-NMAP-SCAN-"].update(disabled=False)

        elif event_key == "-EXPORT-":
            if not hosts_data:
                log_message(window, "No hay datos para exportar.", "WARN")
                continue

            filepath = sg.popup_get_file(
                "Guardar como", save_as=True, no_window=True,
                file_types=(("CSV Files", "*.csv"),), default_extension=".csv"
            )
            if filepath:
                try:
                    export_data = [dict(zip(TABLE_HEADINGS, row)) for row in hosts_data]
                    export_csv(export_data, filepath)
                    log_message(window, f"Datos exportados a {filepath}", "INFO")
                except Exception as e:
                    log_message(window, f"Error al exportar: {e}", "ERROR")

    window.close()


if __name__ == "__main__":
    main()

